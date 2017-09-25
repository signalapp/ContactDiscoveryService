package org.whispersystems.contactdiscovery.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.hibernate.validator.constraints.NotEmpty;

public class SignalServiceConfiguration {

  @JsonProperty
  @NotEmpty
  private String userToken;

  @JsonProperty
  @NotEmpty
  private String serverToken;

  public byte[] getUserAuthenticationToken() throws DecoderException {
    return Hex.decodeHex(userToken.toCharArray());
  }

  public String getServerAuthenticationToken() {
    return serverToken;
  }
}
