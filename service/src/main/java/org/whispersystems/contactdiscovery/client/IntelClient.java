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

import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.glassfish.jersey.SslConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.enclave.StaleRevocationListException;
import org.whispersystems.contactdiscovery.util.ByteUtils;
import org.whispersystems.contactdiscovery.util.SystemMapper;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.time.Duration;
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

  private final HttpClient client;
  private final String apiKey;
  private final boolean acceptGroupOutOfDate;

  private final URI signatureRevocationListBaseUri;
  private final URI quoteSignatureUri;

  @VisibleForTesting
  static final String SUBSCRIPTION_KEY_HEADER = "Ocp-Apim-Subscription-Key";

  public IntelClient(String baseUri, String apiKey, boolean acceptGroupOutOfDate) {
    this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .version(HttpClient.Version.HTTP_1_1)
            .sslContext(SslConfigurator.newInstance()
                    .securityProtocol("TLSv1.2")
                    .createSSLContext())
            .build();

    this.apiKey = apiKey;
    this.acceptGroupOutOfDate = acceptGroupOutOfDate;

    this.signatureRevocationListBaseUri = URI.create(baseUri).resolve("/attestation/sgx/v3/sigrl/");
    this.quoteSignatureUri = URI.create(baseUri).resolve("/attestation/sgx/v3/report");
  }

  public byte[] getSignatureRevocationList(long gid) throws IOException, InterruptedException {
    final HttpRequest request = HttpRequest.newBuilder(signatureRevocationListBaseUri.resolve(String.format("%08x", gid)))
            .timeout(Duration.ofSeconds(10))
            .header(SUBSCRIPTION_KEY_HEADER, apiKey)
            .GET()
            .build();

    final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      throw new IOException("Failed to get signature revocation list (HTTP/" + response.statusCode() + ")");
    }

    final String encodedRevocationList = response.body();

    return StringUtils.isNotBlank(encodedRevocationList) ? Base64.decodeBase64(encodedRevocationList) : new byte[0];
  }

  public QuoteSignatureResponse getQuoteSignature(byte[] quote) throws QuoteVerificationException, StaleRevocationListException {
    try {
      final HttpRequest request = HttpRequest.newBuilder(quoteSignatureUri)
              .timeout(Duration.ofSeconds(10))
              .header("Content-Type", MediaType.APPLICATION_JSON)
              .header(SUBSCRIPTION_KEY_HEADER, apiKey)
              .POST(HttpRequest.BodyPublishers.ofString(SystemMapper.getMapper().writeValueAsString(new QuoteSignatureRequest(quote))))
              .build();

      final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

      String responseBodyString = response.body();
      String signature = response.headers().firstValue("X-IASReport-Signature")
              .orElseThrow(() -> new IOException("Missing X-IASReport-Signature header"));

      String rawCertificate = response.headers().firstValue("X-IASReport-Signing-Certificate")
              .orElseThrow(() -> new IOException("Missing X-IASReport-Signing-Certificate header"));

      String certificate = java.net.URLDecoder.decode(rawCertificate, java.nio.charset.StandardCharsets.UTF_8);

      if (response.statusCode() != 200) {
        throw new QuoteVerificationException("Non-successful quote verification response: " +
                                             response.statusCode() + " " + response.body());
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
    } catch (IOException | InterruptedException e) {
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
