package org.whispersystems.contactdiscovery.requests;

/**
 * Thrown when the {@link RequestManager} decides it has enough work to do and shouldn't accept
 * any additional work at the moment.
 */
public class RequestManagerFullException extends Exception {
  public RequestManagerFullException() {
  }

  public RequestManagerFullException(String message) {
    super(message);
  }

  public RequestManagerFullException(String message, Throwable cause) {
    super(message, cause);
  }

  public RequestManagerFullException(Throwable cause) {
    super(cause);
  }
}
