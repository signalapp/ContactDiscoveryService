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

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

/**
 * Entity representing an encrypted contact discovery request
 *
 * @author Moxie Marlinspike
 */
public class DiscoveryRequest {

  @JsonProperty
  @NotNull
  @Min(1)
  @Max(2048)
  private int addressCount;

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
  private byte[] data;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  @ByteLength(min = 16, max = 16)
  private byte[] mac;

  public DiscoveryRequest() {

  }

  public DiscoveryRequest(int addressCount, byte[] requestId, byte[] iv, byte[] data, byte[] mac) {
    this.addressCount = addressCount;
    this.requestId    = requestId;
    this.iv           = iv;
    this.data         = data;
    this.mac          = mac;
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

  public int getAddressCount() {
    return addressCount;
  }

  public String toString() {
    return "{ addressCount: " + addressCount + ", ticket: " + Hex.encodeHexString(requestId) + ", iv: " + Hex.encodeHexString(iv) + ", data: " + Hex.encodeHexString(data) + ", mac: " + Hex.encodeHexString(mac) + "}";
  }

}
