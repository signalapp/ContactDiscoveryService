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
package org.whispersystems.contactdiscovery.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.Valid;
import javax.validation.constraints.Min;
import java.util.List;

/**
 * Configuration for all enclaves
 *
 * @author Moxie Marlinspike
 */
public class EnclaveConfiguration {

  @JsonProperty
  @NotEmpty
  private String spid;

  @JsonProperty
  @NotEmpty
  private String apiKey;

  @JsonProperty
  @NotEmpty
  private String iasBaseUri;

  @JsonProperty
  @Min(1024)
  private int targetBatchSize = 4096;

  @JsonProperty
  private boolean acceptGroupOutOfDate = false;

  @JsonProperty
  @Valid
  private List<EnclaveInstanceConfiguration> instances;

  public byte[] getSpid() {
    try {
      return Hex.decodeHex(spid.toCharArray());
    } catch (DecoderException e) {
      throw new AssertionError(e);
    }
  }

  public int getTargetBatchSize() {
    return targetBatchSize;
  }

  public String getApiKey() {
    return apiKey;
  }

  public List<EnclaveInstanceConfiguration> getInstances() {
    return instances;
  }

  public String getIasBaseUri() {
    return iasBaseUri;
  }

  public boolean getAcceptGroupOutOfDate() {
    return acceptGroupOutOfDate;
  }
}
