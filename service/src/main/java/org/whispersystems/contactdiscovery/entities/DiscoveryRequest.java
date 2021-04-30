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
import org.apache.commons.codec.binary.Hex;
import org.whispersystems.contactdiscovery.util.ByteArrayAdapter;
import org.whispersystems.contactdiscovery.validation.ByteLength;

import javax.validation.Valid;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

/**
 * Entity representing an encrypted contact discovery request
 *
 * @author Moxie Marlinspike
 */
public class DiscoveryRequest {

  @JsonProperty
  @NotNull
  @Min(1)
  private int addressCount;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  @ByteLength(min = 12, max = 12)
  private byte[] iv;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] data;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  @ByteLength(min = 16, max = 16)
  private byte[] mac;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  @ByteLength(min = 32, max = 32)
  private byte[] commitment;

  @JsonProperty
  @NotNull
  @Size(min = 1, max = 3)
  private Map<String, @Valid DiscoveryRequestEnvelope> envelopes;

  @JsonProperty
  private String context = "Default";

  public DiscoveryRequest() {

  }

  public DiscoveryRequest(int addressCount, byte[] iv, byte[] data, byte[] mac, byte[] commitment, Map<String, DiscoveryRequestEnvelope> envelopes) {
    this.addressCount = addressCount;
    this.iv = iv;
    this.data = data;
    this.mac = mac;
    this.commitment = commitment;
    this.envelopes = envelopes;
  }

  public int getAddressCount() {
    return addressCount;
  }

  public byte[] getIv() {
    return iv;
  }

  public byte[] getData() {
    return data;
  }

  public byte[] getMac() {
    return mac;
  }

  public byte[] getCommitment() {
    return commitment;
  }

  public Map<String, DiscoveryRequestEnvelope> getEnvelopes() {
    return envelopes;
  }

  public String getContext() { return context; }

  public String toString() {
    return "{ addressCount: " + addressCount + ", iv: " + Hex.encodeHexString(iv) + ", data: " + Hex.encodeHexString(data) + ", mac: " + Hex.encodeHexString(mac) + ", commitment: " + Hex.encodeHexString(commitment) + ", envelopes: " + envelopes + ", context: " + context + "   }";
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    DiscoveryRequest that = (DiscoveryRequest) o;
    return addressCount == that.addressCount &&
           Arrays.equals(iv, that.iv) &&
           Arrays.equals(data, that.data) &&
           Arrays.equals(mac, that.mac) &&
           Arrays.equals(commitment, that.commitment) &&
           Objects.equals(envelopes, that.envelopes) &&
           Objects.equals(context, that.context);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(addressCount, envelopes, context);
    result = 31 * result + Arrays.hashCode(iv);
    result = 31 * result + Arrays.hashCode(data);
    result = 31 * result + Arrays.hashCode(mac);
    result = 31 * result + Arrays.hashCode(commitment);
    return result;
  }
}
