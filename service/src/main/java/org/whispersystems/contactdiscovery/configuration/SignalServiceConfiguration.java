package org.whispersystems.contactdiscovery.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.List;
import java.util.stream.Collectors;

public class SignalServiceConfiguration {

  @JsonProperty
  @NotEmpty
  private List<String> userTokens;

  @JsonProperty
  @NotEmpty
  private String serverToken;

  private byte[] hexStringToByteArray(String token) {
    try {
      return Hex.decodeHex(token.toCharArray());
    } catch (DecoderException e) {
      throw new IllegalArgumentException("Invalid user authentication token", e);
    }
  }

  public List<byte[]> getUserAuthenticationTokens() throws IllegalArgumentException {
    return userTokens.stream().map(this::hexStringToByteArray).collect(Collectors.toList());
  }

  public String getServerAuthenticationToken() {
    return serverToken;
  }
}
