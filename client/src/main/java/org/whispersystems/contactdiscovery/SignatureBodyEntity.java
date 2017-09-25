package org.whispersystems.contactdiscovery;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import org.hibernate.validator.constraints.NotEmpty;
import org.whispersystems.contactdiscovery.util.ByteArrayAdapter;

import javax.validation.constraints.NotNull;

public class SignatureBodyEntity {

  @JsonProperty
  @NotNull
  @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
  @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
  private byte[] isvEnclaveQuoteBody;

  @JsonProperty
  @NotEmpty
  private String isvEnclaveQuoteStatus;

  public byte[] getIsvEnclaveQuoteBody() {
    return isvEnclaveQuoteBody;
  }

  public String getIsvEnclaveQuoteStatus() {
    return isvEnclaveQuoteStatus;
  }

}
