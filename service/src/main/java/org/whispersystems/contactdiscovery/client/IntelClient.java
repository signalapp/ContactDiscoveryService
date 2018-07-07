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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.glassfish.jersey.SslConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.enclave.StaleRevocationListException;
import org.whispersystems.contactdiscovery.util.ByteArrayAdapter;
import org.whispersystems.contactdiscovery.util.SystemMapper;

import javax.net.ssl.SSLContext;
import javax.validation.constraints.NotNull;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Client interface for communication with IAS
 *
 * @author Moxie Marlinspike
 */
public class IntelClient {

  private final Logger logger = LoggerFactory.getLogger(IntelClient.class);

  private final Client  client;
  private final String  host;
  private final boolean acceptGroupOutOfDate;

  public IntelClient(String host, String clientCertificate, String clientKey, boolean acceptGroupOutOfDate)
      throws CertificateException, KeyStoreException, IOException
  {
    byte[]     synthesizedKeyStore = initializeKeyStore(clientCertificate, clientKey);
    SSLContext sslContext          = SslConfigurator.newInstance()
                                                    .keyStoreBytes(synthesizedKeyStore)
                                                    .keyStorePassword("insecure")
                                                    .keyPassword("insecure")
                                                    .securityProtocol("TLSv1.2")
                                                    .createSSLContext();

    this.host   = host;
    this.client = ClientBuilder.newBuilder()
                               .sslContext(sslContext)
                               .build();

    this.acceptGroupOutOfDate = acceptGroupOutOfDate;
  }

  public byte[] getSignatureRevocationList(long gid) {
    String encodedRevocationList = client.target(host)
                                         .path(String.format("/attestation/sgx/v2/sigrl/%08x", gid))
                                         .request()
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
                                .path("/attestation/sgx/v2/report")
                                .request(MediaType.APPLICATION_JSON)
                                .post(Entity.json(new QuoteSignatureRequest(quote)));

      String responseBodyString = response.readEntity(String.class);
      String signature          = response.getHeaderString("X-IASReport-Signature");
      String certificate        = response.getHeaderString("X-IASReport-Signing-Certificate");

      if (response.getStatus() != 200) {
        throw new QuoteVerificationException("Non-successful quote verification response: " +
                                             response.getStatus() + " " + response.getStatusInfo().getReasonPhrase());
      }

      if (responseBodyString == null || responseBodyString.trim().length() == 0) {
        throw new QuoteVerificationException("Received empty quote verification body!");
      }

      QuoteSignatureResponseBody responseBody = SystemMapper.getMapper().readValue(responseBodyString, QuoteSignatureResponseBody.class);

      if ("SIGRL_VERSION_MISMATCH".equals(responseBody.getIsvEnclaveQuoteStatus())) {
        throw new StaleRevocationListException(responseBodyString);
      }

      if ("GROUP_OUT_OF_DATE".equals(responseBody.getIsvEnclaveQuoteStatus()) && !acceptGroupOutOfDate) {
        throw new GroupOutOfDateException(responseBody.getPlatformInfoBlob(), false);
      }
      if ("GROUP_REVOKED".equals(responseBody.getIsvEnclaveQuoteStatus())) {
        throw new GroupOutOfDateException(responseBody.getPlatformInfoBlob(), true);
      }

      if (!"OK".equals(responseBody.getIsvEnclaveQuoteStatus()) &&
          !"GROUP_OUT_OF_DATE".equals(responseBody.getIsvEnclaveQuoteStatus())) {
        throw new QuoteVerificationException("Bad response: " + responseBodyString);
      }

      return new QuoteSignatureResponse(signature, responseBodyString, certificate, responseBody.getPlatformInfoBlob());
    } catch (IOException e) {
      throw new QuoteVerificationException(e);
    }
  }

  private byte[] initializeKeyStore(String pemCertificate, String pemKey)
      throws IOException, KeyStoreException, CertificateException
  {
    try {
      PEMParser             reader            = new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemCertificate.getBytes())));
      X509CertificateHolder certificateHolder = (X509CertificateHolder) reader.readObject();
      X509Certificate       certificate       = new JcaX509CertificateConverter().getCertificate(certificateHolder);
      Certificate[]         certificateChain  = {certificate};

      reader = new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemKey.getBytes())));
      KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) reader.readObject());
      KeyStore keyStore = KeyStore.getInstance("pkcs12");
      keyStore.load(null);
      keyStore.setEntry("intel",
                        new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), certificateChain),
                        new KeyStore.PasswordProtection("insecure".toCharArray()));
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      keyStore.store(baos, "insecure".toCharArray());
      return baos.toByteArray();
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  private static class QuoteSignatureRequest {

    @JsonProperty
    @NotNull
    @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
    @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
    private byte[] isvEnclaveQuote;

    public QuoteSignatureRequest() {}

    public QuoteSignatureRequest(byte[] isvEnclaveQuote) {
      this.isvEnclaveQuote = isvEnclaveQuote;
    }

  }

  public static class QuoteSignatureResponse {

    private final String signature;
    private final String response;
    private final String certificates;
    private final String platformInfoBlob;

    public QuoteSignatureResponse(String signature, String response, String certificates, String platformInfoBlob) {
      this.signature        = signature;
      this.response         = response;
      this.certificates     = certificates;
      this.platformInfoBlob = platformInfoBlob;
    }

    public String getSignature() {
      return signature;
    }

    public String getResponse() {
      return response;
    }

    public String getCertificates() {
      return certificates;
    }

    public byte[] getPlatformInfoBlob() throws QuoteVerificationException {
      return unwrapPlatformInfoBlob(platformInfoBlob);
    }
  }

  private static class QuoteSignatureResponseBody {
    @JsonProperty
    private String isvEnclaveQuoteStatus;

    @JsonProperty
    private String isvEnclaveQuoteBody;

    @JsonProperty
    private String platformInfoBlob;


    public String getIsvEnclaveQuoteStatus() {
      return isvEnclaveQuoteStatus;
    }

    public String getIsvEnclaveQuoteBody() {
      return isvEnclaveQuoteBody;
    }

    public String getPlatformInfoBlob() {
      return platformInfoBlob;
    }
  }

  public static class QuoteVerificationException extends Exception {
    public QuoteVerificationException(String message) {
      super(message);
    }

    public QuoteVerificationException(Exception e) {
      super(e);
    }
  }

  public static class GroupOutOfDateException extends QuoteVerificationException {
    private final String  platformInfoBlob;
    private final boolean revoked;

    public GroupOutOfDateException(String platformInfoBlob, boolean revoked) {
      super("group "+(revoked? "revoked" : "out of date"));
      this.platformInfoBlob = platformInfoBlob;
      this.revoked          = revoked;
    }
    public byte[] getPlatformInfoBlob() throws QuoteVerificationException {
      return unwrapPlatformInfoBlob(platformInfoBlob);
    }
    public boolean getRevoked() {
      return revoked;
    }
  }

  private static byte[] unwrapPlatformInfoBlob(String platformInfoBlobHex) throws QuoteVerificationException {
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
      throw new QuoteVerificationException("platform info blob TLV too short: "+platformInfoBlobTlv.length);
    }
    if ((platformInfoBlobTlv[0] & 0xFF) != 21) {
      throw new QuoteVerificationException("bad platform info blob TLV identifier: "+platformInfoBlobTlv[0]);
    }
    if ((platformInfoBlobTlv[1] & 0xFF) > 2) {
      throw new QuoteVerificationException("unknown platform info blob TLV version: "+platformInfoBlobTlv[1]);
    }
    int platformInfoBlobTlvLength = ((platformInfoBlobTlv[2] & 0xFF) << 8) | (platformInfoBlobTlv[3] & 0xFF);
    if (platformInfoBlobTlvLength != platformInfoBlobTlv.length - 4) {
      throw new QuoteVerificationException("invalid platform info blob TLV length: "+platformInfoBlobTlvLength+"!="+platformInfoBlobTlv.length);
    }
    byte[] platformInfoBlob = new byte[platformInfoBlobTlvLength];
    System.arraycopy(platformInfoBlobTlv, 4, platformInfoBlob, 0, platformInfoBlob.length);
    return platformInfoBlob;
  }
}
