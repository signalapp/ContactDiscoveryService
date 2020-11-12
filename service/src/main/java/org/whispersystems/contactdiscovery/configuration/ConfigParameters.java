package org.whispersystems.contactdiscovery.configuration;

import java.util.Optional;

public class ConfigParameters {

  public static Optional<String> getString(String property) {
    String result = null;

    if (System.getProperties().containsKey(property)) {
      result = System.getProperty(property);
    }

    return Optional.ofNullable(result);
  }

  public static Optional<Integer> getInteger(String property) {
    return getString(property).map(Integer::parseInt);
  }
}
