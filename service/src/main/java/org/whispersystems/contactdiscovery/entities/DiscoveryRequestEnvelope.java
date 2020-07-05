/*
 * Copyright (C) 2019 Open Whisper Systems
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

import javax.validation.constraints.NotNull;
import java.util.Arrays;

public class DiscoveryRequestEnvelope {

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] requestId;

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
  @ByteLength(min = 32, max = 32)
  private byte[] data;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  @ByteLength(min = 16, max = 16)
  private byte[] mac;

  public DiscoveryRequestEnvelope() {
  }

  public DiscoveryRequestEnvelope(byte[] requestId, byte[] iv, byte[] data, byte[] mac) {
    this.requestId = requestId;
    this.iv = iv;
    this.data = data;
    this.mac = mac;
  }

  public byte[] getRequestId() {
    return requestId;
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

  public String toString() {
    return "{ requestId: " + requestId + ", iv: " + Hex.encodeHexString(iv) + ", data: " + Hex.encodeHexString(data) + ", mac: " + Hex.encodeHexString(mac) + " }";
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    DiscoveryRequestEnvelope that = (DiscoveryRequestEnvelope) o;
    return Arrays.equals(requestId, that.requestId) &&
           Arrays.equals(iv, that.iv) &&
           Arrays.equals(data, that.data) &&
           Arrays.equals(mac, that.mac);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(requestId);
    result = 31 * result + Arrays.hashCode(iv);
    result = 31 * result + Arrays.hashCode(data);
    result = 31 * result + Arrays.hashCode(mac);
    return result;
  }
}
