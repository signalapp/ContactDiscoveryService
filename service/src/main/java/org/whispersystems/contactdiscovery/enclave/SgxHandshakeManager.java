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

import com.codahale.metrics.Gauge;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import io.dropwizard.lifecycle.Managed;
import org.assertj.core.util.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.client.GroupOutOfDateException;
import org.whispersystems.contactdiscovery.client.IasVersion;
import org.whispersystems.contactdiscovery.client.IntelClient;
import org.whispersystems.contactdiscovery.client.QuoteSignatureResponse;
import org.whispersystems.contactdiscovery.client.QuoteVerificationException;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;
import org.whispersystems.contactdiscovery.util.Constants;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Maintains and periodically refreshes the signed quotes for each
 * enclave in the SgxEnclaveManager.
 *
 * @author Moxie Marlinspike
 */
public class SgxHandshakeManager implements Managed {

  private final Logger logger = LoggerFactory.getLogger(SgxHandshakeManager.class);

  private static final MetricRegistry metricRegistry              = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Meter          getQuoteSignatureMeter      = metricRegistry.meter(name(SgxHandshakeManager.class, "getQuoteSignature"));
  private static final Meter          getQuoteSignatureErrorMeter = metricRegistry.meter(name(SgxHandshakeManager.class, "getQuoteSignatureError"));
  private static final Meter          needsMicrocodeUpdateMeter   = metricRegistry.meter(name(SgxHandshakeManager.class, "needsMicrocodeUpdate"));
  private static final Meter          needsPSWUpdateMeter         = metricRegistry.meter(name(SgxHandshakeManager.class, "needsPSWUpdate"));

  private static final long REFRESH_INTERVAL_MS = 60_000L;

  private final Map<String, SgxSignedQuote> iasV3Quotes = new HashMap<>();
  private final Map<String, SgxSignedQuote> iasV4Quotes = new HashMap<>();

  private final SgxEnclaveManager        sgxEnclaveManager;
  private final SgxRevocationListManager sgxRevocationListManager;
  private final IntelClient              client;

  private final ScheduledExecutorService executorService;
  private ScheduledFuture<?> refreshQuotesFuture;

  public SgxHandshakeManager(SgxEnclaveManager sgxEnclaveManager,
                             SgxRevocationListManager sgxRevocationListManager,
                             IntelClient client,
                             ScheduledExecutorService executorService)
  {
    this.sgxEnclaveManager        = sgxEnclaveManager;
    this.sgxRevocationListManager = sgxRevocationListManager;
    this.client                   = client;
    this.executorService          = executorService;
  }

  public RemoteAttestationResponse getHandshake(String enclaveId, byte[] clientPublic, IasVersion iasVersion)
      throws SgxException, NoSuchEnclaveException, SignedQuoteUnavailableException
  {
    SgxEnclave enclave = sgxEnclaveManager.getEnclave(enclaveId);

    SgxSignedQuote                signedQuote;
    SgxRequestNegotiationResponse response;

    final Map<String, SgxSignedQuote> quotes = getSignedQuoteMap(iasVersion);

    // `quotes` is guaranteed to be one of `iasV3Quotes` or `iasV4Quotes`
    //noinspection SynchronizationOnLocalVariableOrMethodParameter
    synchronized (quotes) {
      signedQuote = quotes.get(enclaveId);
      if (signedQuote == null) {
        throw new SignedQuoteUnavailableException("No IAS Signed Quote available");
      }
      response = enclave.negotiateRequest(clientPublic);
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
  public synchronized void start() throws Exception {
    for (Map.Entry<String, SgxEnclave> enclaveMapEntry : sgxEnclaveManager.getEnclaves().entrySet()) {
      refreshQuote(enclaveMapEntry.getKey(), enclaveMapEntry.getValue());
    }

    if (this.refreshQuotesFuture != null) {
      refreshQuotesFuture.cancel(false);
    }

    refreshQuotesFuture = executorService.scheduleAtFixedRate(
            this::refreshAllQuotes, REFRESH_INTERVAL_MS, REFRESH_INTERVAL_MS, TimeUnit.MILLISECONDS);

    metricRegistry.register(name(getClass(), "oldestSignedQuoteAge"), (Gauge<Long>)() -> {
      final long oldestSignedQuoteTimestamp = Stream.concat(iasV3Quotes.values().stream(), iasV4Quotes.values().stream())
              .mapToLong(SgxSignedQuote::getTimestamp)
              .min()
              .orElse(0);

      return System.currentTimeMillis() - oldestSignedQuoteTimestamp;
    });
  }

  @Override
  public synchronized void stop() throws Exception {
    if (this.refreshQuotesFuture != null) {
      refreshQuotesFuture.cancel(false);
    }

    refreshQuotesFuture = null;
  }

  private void handleGroupOutOfDateException(GroupOutOfDateException e) {
    try {
      byte[] platformInfoBlob = e.getPlatformInfoBlob();
      if (platformInfoBlob != null) {
        reportPlatformAttestationStatus(platformInfoBlob, false);
      } else {
        logger.warn("Platform needs update: " + e.getMessage() + ", but didn't get platform info blob from IAS");
      }
    } catch (QuoteVerificationException | SgxException | IllegalArgumentException e2) {
      logger.warn("Platform needs update: " + e.getMessage() + ", but problems finding which component", e2);
    }
  }

  @VisibleForTesting
  public void refreshAllQuotes() {
    try {
      for (Map.Entry<String, SgxEnclave> enclaveMapEntry : sgxEnclaveManager.getEnclaves().entrySet()) {
        try {
          refreshQuote(enclaveMapEntry.getKey(), enclaveMapEntry.getValue());
        } catch (SgxException e) {
          getQuoteSignatureErrorMeter.mark();

          logger.warn("Problem calling enclave", e);
        } catch (GroupOutOfDateException e) {
          getQuoteSignatureErrorMeter.mark();

          handleGroupOutOfDateException(e);
        } catch (StaleRevocationListException e) {
          getQuoteSignatureErrorMeter.mark();

          // Refresh the list; we'll miss refreshing the quote this time, but we'll come back to it on the next pass
          logger.warn("Stale revocation list; will refresh on next pass", e);
          sgxRevocationListManager.expireRevocationList(enclaveMapEntry.getValue().getGid());
        } catch (Throwable t) {
          getQuoteSignatureErrorMeter.mark();

          logger.warn("Problem retrieving quote", t);
        }
      }
    } catch (Throwable t) {
      logger.error("Unexpected exception while refreshing quotes", t);
    }
  }

  private void refreshQuote(String enclaveId, SgxEnclave enclave)
          throws QuoteVerificationException, SgxException, StaleRevocationListException, IOException, InterruptedException {

    byte[] revocationList = sgxRevocationListManager.getRevocationList(enclave.getGid());
    byte[] quote = enclave.getNextQuote(revocationList);

    for (final IasVersion iasVersion : IasVersion.values()) {
      QuoteSignatureResponse signature;

      try {
        signature = client.getQuoteSignature(quote, iasVersion);
      } catch (GroupOutOfDateException e) {
        handleGroupOutOfDateException(e);
        throw e;
      }

      final Map<String, SgxSignedQuote> quotes = getSignedQuoteMap(iasVersion);

      // `quotes` is guaranteed to be one of `iasV3Quotes` or `iasV4Quotes`
      //noinspection SynchronizationOnLocalVariableOrMethodParameter
      synchronized (quotes) {
        quotes.put(enclaveId, new SgxSignedQuote(quote, signature, System.currentTimeMillis()));
        enclave.setCurrentQuote();
      }

      getQuoteSignatureMeter.mark();

      try {
        reportPlatformAttestationStatus(signature.getPlatformInfoBlob(), true);
      } catch (QuoteVerificationException | SgxException | IllegalArgumentException e) {
        logger.warn("Problems decoding platform info blob", e);
      }
    }
  }

  private void reportPlatformAttestationStatus(byte[] platformInfoBlob, boolean attestationSuccess)
      throws SgxException
  {
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

  private Map<String, SgxSignedQuote> getSignedQuoteMap(IasVersion iasVersion) {
    switch (iasVersion) {
      case IAS_V3: {
        return iasV3Quotes;
      }
      case IAS_V4: {
        return iasV4Quotes;
      }
      default: {
        throw new AssertionError("Unexpected IAS version: " + iasVersion);
      }
    }
  }

  private static class SgxSignedQuote {

    private final byte[] quote;
    private final QuoteSignatureResponse signature;
    private final long timestamp;

    private SgxSignedQuote(byte[] quote, QuoteSignatureResponse signature, final long timestamp) {
      this.quote = quote;
      this.signature = signature;
      this.timestamp = timestamp;
    }

    public byte[] getQuote() {
      return quote;
    }

    public QuoteSignatureResponse getSignature() {
      return signature;
    }

    public long getTimestamp() {
      return timestamp;
    }
  }
}
