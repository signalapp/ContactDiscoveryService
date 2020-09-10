package org.whispersystems.contactdiscovery.resources;

/**
 * Thrown when the {@link RequestLimiterTask} encounters invalid input.
 */
public class RequestLimiterTaskException extends Exception {
  public RequestLimiterTaskException(String message) {
    super(message);
  }
}
