/*
 * Copyright (C) 2018 Open Whisper Systems
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
import org.hibernate.validator.constraints.NotEmpty;
import org.whispersystems.contactdiscovery.util.ByteArrayAdapter;

import javax.validation.constraints.NotNull;
import java.util.List;

class QuoteSignatureResponseBody {

  @JsonProperty
  private String isvEnclaveQuoteStatus;

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] isvEnclaveQuoteBody;

  @JsonProperty
  @NotNull
  private Long version;

  @JsonProperty
  @NotEmpty
  private String timestamp;

  @JsonProperty
  private String platformInfoBlob;

  @JsonProperty
  private String advisoryURL;

  @JsonProperty
  private List<String> advisoryIDs;

  public QuoteSignatureResponseBody() {
  }

  public String getIsvEnclaveQuoteStatus() {
    return isvEnclaveQuoteStatus;
  }

  public byte[] getIsvEnclaveQuoteBody() {
    return isvEnclaveQuoteBody;
  }

  public Long getVersion() {
    return version;
  }

  public String getTimestamp() {
    return timestamp;
  }

  public String getPlatformInfoBlob() {
    return platformInfoBlob;
  }

  public String getAdvisoryURL() {
    return advisoryURL;
  }

  public List<String> getAdvisoryIDs() {
    return advisoryIDs;
  }
}
