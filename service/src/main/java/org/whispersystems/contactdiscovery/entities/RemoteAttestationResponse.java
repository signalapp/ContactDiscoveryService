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
package org.whispersystems.contactdiscovery.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.whispersystems.contactdiscovery.util.ByteArrayAdapter;
import org.whispersystems.contactdiscovery.validation.ByteLength;

import javax.validation.constraints.NotNull;
import java.util.Arrays;
import java.util.Objects;

/**
 * An entity representing a remote attestation and handshake response
 *
 * @author Moxie Marlinspike
 */
public class RemoteAttestationResponse {

  @JsonProperty
  @NotNull
  @ByteLength(min = 32, max = 32)
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] serverEphemeralPublic;

  @JsonProperty
  @NotNull
  @ByteLength(min = 32, max = 32)
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] serverStaticPublic;


  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] quote;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] iv;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] ciphertext;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] tag;

  @JsonProperty
  @NotNull
  private String signature;

  @JsonProperty
  @NotNull
  private String certificates;

  @JsonProperty
  @NotNull
  private String signatureBody;

  public RemoteAttestationResponse(byte[] serverEphemeralPublic, byte[] serverStaticPublic,
                                   byte[] iv, byte[] ciphertext, byte[] tag,
                                   byte[] quote, String signature, String certificates, String signatureBody)
  {
    this.serverEphemeralPublic = serverEphemeralPublic;
    this.serverStaticPublic = serverStaticPublic;
    this.iv = iv;
    this.ciphertext = ciphertext;
    this.tag = tag;
    this.quote = quote;
    this.signature = signature;
    this.certificates = certificates;
    this.signatureBody = signatureBody;
  }

  public RemoteAttestationResponse() {
  }

  public byte[] getServerEphemeralPublic() {
    return serverEphemeralPublic;
  }

  public byte[] getServerStaticPublic() {
    return serverStaticPublic;
  }

  public byte[] getQuote() {
    return quote;
  }

  public byte[] getIv() {
    return iv;
  }

  public byte[] getCiphertext() {
    return ciphertext;
  }

  public byte[] getTag() {
    return tag;
  }

  public String getSignature() {
    return signature;
  }

  public String getCertificates() {
    return certificates;
  }

  public String getSignatureBody() {
    return signatureBody;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    RemoteAttestationResponse that = (RemoteAttestationResponse) o;
    return Arrays.equals(serverEphemeralPublic, that.serverEphemeralPublic) &&
           Arrays.equals(serverStaticPublic, that.serverStaticPublic) &&
           Arrays.equals(quote, that.quote) &&
           Arrays.equals(iv, that.iv) &&
           Arrays.equals(ciphertext, that.ciphertext) &&
           Arrays.equals(tag, that.tag) &&
           Objects.equals(signature, that.signature) &&
           Objects.equals(certificates, that.certificates) &&
           Objects.equals(signatureBody, that.signatureBody);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(signature, certificates, signatureBody);
    result = 31 * result + Arrays.hashCode(serverEphemeralPublic);
    result = 31 * result + Arrays.hashCode(serverStaticPublic);
    result = 31 * result + Arrays.hashCode(quote);
    result = 31 * result + Arrays.hashCode(iv);
    result = 31 * result + Arrays.hashCode(ciphertext);
    result = 31 * result + Arrays.hashCode(tag);
    return result;
  }
}
