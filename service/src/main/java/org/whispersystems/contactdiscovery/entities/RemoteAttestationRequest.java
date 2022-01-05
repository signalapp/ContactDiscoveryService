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
import org.hibernate.validator.constraints.Length;
import org.whispersystems.contactdiscovery.util.ByteArrayAdapter;
import org.whispersystems.contactdiscovery.validation.ByteLength;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

/**
 * An entity representing a client remote attestation and handshake request
 *
 * @author Moxie Marlinspike
 */
public class RemoteAttestationRequest {

  @JsonProperty
  @NotNull
  @ByteLength(min=32, max=32)
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] clientPublic;

  @JsonProperty
  @Min(3)
  @Max(4)
  private int iasVersion = 3;

  public RemoteAttestationRequest() {}

  public RemoteAttestationRequest(byte[] clientPublic, int iasVersion) {
    this.clientPublic = clientPublic;
    this.iasVersion = iasVersion;
  }

  public byte[] getClientPublic() {
    return clientPublic;
  }

  public int getIasVersion() {
    return iasVersion;
  }
}
