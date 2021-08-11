/**
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
package org.whispersystems.contactdiscovery.client;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.glassfish.jersey.SslConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.enclave.StaleRevocationListException;
import org.whispersystems.contactdiscovery.util.ByteUtils;
import org.whispersystems.contactdiscovery.util.SystemMapper;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.Period;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Client interface for communication with IAS
 *
 * @author Moxie Marlinspike
 */
public class IntelClient {

  private final Logger logger = LoggerFactory.getLogger(IntelClient.class);

  private final Client client;
  private final String host;
  private final String apiKey;
  private final boolean acceptGroupOutOfDate;

  private static final String SUBSCRIPTION_KEY_HEADER = "Ocp-Apim-Subscription-Key";

  public IntelClient(String host, String apiKey, boolean acceptGroupOutOfDate) {
    this.client = ClientBuilder.newBuilder()
            .sslContext(SslConfigurator.newInstance()
                    .securityProtocol("TLSv1.2")
                    .createSSLContext())
            .build();

    this.host = host;
    this.apiKey = apiKey;
    this.acceptGroupOutOfDate = acceptGroupOutOfDate;
  }

  public byte[] getSignatureRevocationList(long gid) {
    String encodedRevocationList = client.target(host)
                                         .path(String.format("/attestation/sgx/v3/sigrl/%08x", gid))
                                         .request()
                                         .header(SUBSCRIPTION_KEY_HEADER, apiKey)
                                         .get(String.class);

    if (encodedRevocationList != null && encodedRevocationList.trim().length() != 0) {
      return Base64.decodeBase64(encodedRevocationList);
    } else {
      return new byte[0];
    }
  }

  public QuoteSignatureResponse getQuoteSignature(byte[] quote) throws QuoteVerificationException, StaleRevocationListException {
    try {
      Response response = client.target(host)
                                .path("/attestation/sgx/v3/report")
                                .request(MediaType.APPLICATION_JSON)
                                .header(SUBSCRIPTION_KEY_HEADER, apiKey)
                                .post(Entity.json(new QuoteSignatureRequest(quote)));

      String responseBodyString = response.readEntity(String.class);
      String signature          = response.getHeaderString("X-IASReport-Signature");
      String raw_certificate    = response.getHeaderString("X-IASReport-Signing-Certificate");
      String certificate        = java.net.URLDecoder.decode(raw_certificate, java.nio.charset.StandardCharsets.UTF_8);

      if (response.getStatus() != 200) {
        throw new QuoteVerificationException("Non-successful quote verification response: " +
                                             response.getStatus() + " " + response.getStatusInfo().getReasonPhrase());
      }

      if (responseBodyString == null || responseBodyString.trim().length() == 0) {
        throw new QuoteVerificationException("Received empty quote verification body!");
      }

      QuoteSignatureResponseBody responseBody = SystemMapper.getMapper().readValue(responseBodyString, QuoteSignatureResponseBody.class);

      if (responseBody.getVersion() != 3) {
        throw new QuoteVerificationException("Bad response version: " + responseBody.getVersion());
      }

      if (!MessageDigest.isEqual(ByteUtils.truncate(responseBody.getIsvEnclaveQuoteBody(), 432), ByteUtils.truncate(quote, 432))) {
        throw new QuoteVerificationException("Signed quote is not the same as RA quote: " + Hex.encodeHexString(responseBody.getIsvEnclaveQuoteBody()) + " vs " + Hex.encodeHexString(quote));
      }

      if ("SIGRL_VERSION_MISMATCH".equals(responseBody.getIsvEnclaveQuoteStatus())) {
        throw new StaleRevocationListException(responseBodyString);
      } else if ("GROUP_OUT_OF_DATE".equals(responseBody.getIsvEnclaveQuoteStatus()) ||
                 "CONFIGURATION_NEEDED".equals(responseBody.getIsvEnclaveQuoteStatus())) {
        logger.warn("Platform needs update: " + responseBody.getIsvEnclaveQuoteStatus());
        if (!acceptGroupOutOfDate) {
          throw new GroupOutOfDateException(responseBody.getIsvEnclaveQuoteStatus(), responseBody.getPlatformInfoBlob());
        }
      } else if ("GROUP_REVOKED".equals(responseBody.getIsvEnclaveQuoteStatus())) {
        throw new GroupOutOfDateException(responseBody.getIsvEnclaveQuoteStatus(), responseBody.getPlatformInfoBlob());
      } else if (!"OK".equals(responseBody.getIsvEnclaveQuoteStatus())) {
        throw new QuoteVerificationException("Bad response: " + responseBodyString);
      }

      if (Instant.from(ZonedDateTime.of(LocalDateTime.from(DateTimeFormatter.ofPattern("yyy-MM-dd'T'HH:mm:ss.SSSSSS").parse(responseBody.getTimestamp())), ZoneId.of("UTC")))
                 .plus(Period.ofDays(1))
                 .isBefore(Instant.now())) {
        throw new QuoteVerificationException("Response signature is expired: " + responseBody.getTimestamp());
      }

      return new QuoteSignatureResponse(signature, responseBodyString, certificate, responseBody.getPlatformInfoBlob());
    } catch (IOException e) {
      throw new QuoteVerificationException(e);
    }
  }

  static byte[] unwrapPlatformInfoBlob(String platformInfoBlobHex) throws QuoteVerificationException {
    if (platformInfoBlobHex == null || platformInfoBlobHex.length() == 0) {
      return null;
    }
    byte[] platformInfoBlobTlv;
    try {
      platformInfoBlobTlv = Hex.decodeHex(platformInfoBlobHex.toCharArray());
    } catch (DecoderException e) {
      throw new QuoteVerificationException(e);
    }
    if (platformInfoBlobTlv.length < 4) {
      throw new QuoteVerificationException("platform info blob TLV too short: " + platformInfoBlobTlv.length);
    }
    if ((platformInfoBlobTlv[0] & 0xFF) != 21) {
      throw new QuoteVerificationException("bad platform info blob TLV identifier: " + platformInfoBlobTlv[0]);
    }
    if ((platformInfoBlobTlv[1] & 0xFF) > 2) {
      throw new QuoteVerificationException("unknown platform info blob TLV version: " + platformInfoBlobTlv[1]);
    }
    int platformInfoBlobTlvLength = ((platformInfoBlobTlv[2] & 0xFF) << 8) | (platformInfoBlobTlv[3] & 0xFF);
    if (platformInfoBlobTlvLength != platformInfoBlobTlv.length - 4) {
      throw new QuoteVerificationException("invalid platform info blob TLV length: " + platformInfoBlobTlvLength + "!=" + platformInfoBlobTlv.length);
    }
    byte[] platformInfoBlob = new byte[platformInfoBlobTlvLength];
    System.arraycopy(platformInfoBlobTlv, 4, platformInfoBlob, 0, platformInfoBlob.length);
    return platformInfoBlob;
  }
}
