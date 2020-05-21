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

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Map;

public class MultipleRemoteAttestationResponse {

  @JsonProperty
  @NotNull
  @Size(min = 1, max = 3)
  Map<String, RemoteAttestationResponse> attestations;

  public MultipleRemoteAttestationResponse() {
  }

  public MultipleRemoteAttestationResponse(Map<String, RemoteAttestationResponse> attestations) {
    this.attestations = attestations;
  }

  public Map<String, RemoteAttestationResponse> getAttestations() {
    return attestations;
  }
}
