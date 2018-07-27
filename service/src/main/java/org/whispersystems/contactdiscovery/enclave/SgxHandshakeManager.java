/*
 * Copyright (C) 2017 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.contactdiscovery.enclave;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.client.IntelClient;
import org.whispersystems.contactdiscovery.client.IntelClient.QuoteSignatureResponse;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;
import org.whispersystems.contactdiscovery.util.Constants;
import org.whispersystems.dispatch.util.Util;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import io.dropwizard.lifecycle.Managed;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Maintains and periodically refreshes the signed quotes for each
 * enclave in the SgxEnclaveManager.
 *
 * @author Moxie Marlinspike
 */
public class SgxHandshakeManager implements Managed, Runnable {

  private final Logger logger = LoggerFactory.getLogger(SgxHandshakeManager.class);

  private static final MetricRegistry metricRegistry              = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Meter          getQuoteSignatureMeter      = metricRegistry.meter(name(SgxHandshakeManager.class, "getQuoteSignature"));
  private static final Meter          getQuoteSignatureErrorMeter = metricRegistry.meter(name(SgxHandshakeManager.class, "getQuoteSignatureError"));
  private static final Meter          needsMicrocodeUpdateMeter   = metricRegistry.meter(name(SgxHandshakeManager.class, "needsMicrocodeUpdate"));
  private static final Meter          needsPSWUpdateMeter         = metricRegistry.meter(name(SgxHandshakeManager.class, "needsPSWUpdate"));

  private final Map<String, SgxSignedQuote> quotes = new HashMap<>();

  private final SgxEnclaveManager        sgxEnclaveManager;
  private final SgxRevocationListManager sgxRevocationListManager;
  private final IntelClient              client;

  private ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();

  public SgxHandshakeManager(SgxEnclaveManager        sgxEnclaveManager,
                             SgxRevocationListManager sgxRevocationListManager,
                             IntelClient              client)
  {
    this.sgxEnclaveManager        = sgxEnclaveManager;
    this.sgxRevocationListManager = sgxRevocationListManager;
    this.client                   = client;
  }

  @Override
  public void run() {
    for (Map.Entry<String, SgxEnclave> entry : sgxEnclaveManager.getEnclaves().entrySet()) {
      String     enclaveId      = entry.getKey();
      SgxEnclave enclave        = entry.getValue();
      boolean    complete       = false;

      while (!complete) {
        try {
          byte[]                 revocationList = sgxRevocationListManager.getRevocationList(enclave.getGid());
          byte[]                 quote          = enclave.getNextQuote(revocationList);
          QuoteSignatureResponse signature      = client.getQuoteSignature(quote);

          synchronized (quotes) {
            quotes.put(enclaveId, new SgxSignedQuote(quote, signature));
            enclave.setCurrentQuote();
          }

          getQuoteSignatureMeter.mark();

          try {
            reportPlatformAttestationStatus(signature.getPlatformInfoBlob(), true);
          } catch (IntelClient.QuoteVerificationException | SgxException | IllegalArgumentException e) {
            logger.warn("Problems decoding platform info blob", e);
          }

          complete = true;
        } catch (SgxException e) {
          getQuoteSignatureErrorMeter.mark();

          logger.warn("Problem calling enclave", e);
          complete = true;
        } catch (IntelClient.GroupOutOfDateException e) {
          getQuoteSignatureErrorMeter.mark();

          try {
            byte[] platformInfoBlob = e.getPlatformInfoBlob();
            if (platformInfoBlob != null) {
              reportPlatformAttestationStatus(platformInfoBlob, false);
            } else {
              logger.warn("Platform needs update: "+e.getMessage()+", but didn't get platform info blob from IAS");
            }
          } catch (IntelClient.QuoteVerificationException | SgxException | IllegalArgumentException e2) {
            logger.warn("Platform needs update: "+e.getMessage()+", but problems finding which component", e2);
          }
          complete = true;
        } catch (IntelClient.QuoteVerificationException e) {
          getQuoteSignatureErrorMeter.mark();

          logger.warn("Problem retrieving quote", e);
          Util.sleep(2000);
        } catch (NoSuchRevocationListException | StaleRevocationListException e) {
          getQuoteSignatureErrorMeter.mark();

          logger.warn("Stale or missing revocation list, refetching...", e);
          sgxRevocationListManager.refreshRevocationList(enclave.getGid());
          Util.sleep(1000);
        }
      }
    }
  }
  private void reportPlatformAttestationStatus(byte[] platformInfoBlob, boolean attestationSuccess)
    throws SgxException {
    if (platformInfoBlob == null) {
      return;
    }
    Set<SgxNeedsUpdateFlag> needsUpdateFlags =
      SgxEnclave.reportPlatformAttestationStatus(platformInfoBlob, attestationSuccess);
    if (needsUpdateFlags.contains(SgxNeedsUpdateFlag.UCODE_UPDATE)) {
      needsMicrocodeUpdateMeter.mark();
      logger.warn("Platform CPU microcode needs update");
    }
    if (needsUpdateFlags.contains(SgxNeedsUpdateFlag.CSME_FW_UPDATE)) {
      logger.warn("Platform CSME FW needs update");
    }
    if (needsUpdateFlags.contains(SgxNeedsUpdateFlag.PSW_UPDATE)) {
      needsPSWUpdateMeter.mark();
      logger.warn("SGX Platform Software (PSW) needs update");
    }
  }

  public RemoteAttestationResponse getHandshake(String enclaveId, byte[] clientPublic)
    throws SgxException, NoSuchEnclaveException, SignedQuoteUnavailableException {
    SgxEnclave enclave = sgxEnclaveManager.getEnclave(enclaveId);

    SgxSignedQuote                signedQuote;
    SgxRequestNegotiationResponse response;

    synchronized (quotes) {
      signedQuote = quotes.get(enclaveId);
      if (signedQuote == null) {
        throw new SignedQuoteUnavailableException("No IAS Signed Quote available");
      }
      response    = enclave.negotiateRequest(clientPublic);
    }

    return new RemoteAttestationResponse(response.getServerEphemeralPublicKey(),
                                         response.getServerStaticPublicKey(),
                                         response.getPendingRequestIdIv(),
                                         response.getPendingRequestIdCiphertext(),
                                         response.getPendingRequestIdTag(),
                                         signedQuote.getQuote(),
                                         signedQuote.getSignature().getSignature(),
                                         signedQuote.getSignature().getCertificates(),
                                         signedQuote.getSignature().getResponse());
  }

  @Override
  public void start() throws Exception {
    run();
    executorService.scheduleAtFixedRate(this, 1, 1, TimeUnit.MINUTES);
  }

  @Override
  public void stop() throws Exception {}

  private static class SgxSignedQuote {

    private final byte[]                 quote;
    private final QuoteSignatureResponse signature;

    private SgxSignedQuote(byte[] quote, QuoteSignatureResponse signature) {
      this.quote     = quote;
      this.signature = signature;
    }

    public byte[] getQuote() {
      return quote;
    }
    public QuoteSignatureResponse getSignature() {
      return signature;
    }
  }

}
