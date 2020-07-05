package org.whispersystems.contactdiscovery.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.whispersystems.contactdiscovery.util.ByteArrayAdapter;
import org.whispersystems.contactdiscovery.validation.ByteLength;

import javax.validation.constraints.NotNull;

public class EnclaveRateLimitRequest {

  @JsonProperty
  @NotNull
  @ByteLength(min=32, max=32)
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] clientPublic;

  public EnclaveRateLimitRequest(byte[] clientPublic) {
    this.clientPublic = clientPublic;
  }
}
