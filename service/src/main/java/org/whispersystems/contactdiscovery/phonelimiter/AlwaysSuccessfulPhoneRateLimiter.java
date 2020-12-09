package org.whispersystems.contactdiscovery.phonelimiter;

import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * AlwaysSuccessfulPhoneRateLimiter is a PhoneRateLimiter that always succeeeds. The attest method always returns a
 * normally completed future with an empty, mutable Map. The discoveryAllowed method always returns a normally completed
 * future containing true.
 */
public class AlwaysSuccessfulPhoneRateLimiter implements PhoneRateLimiter {

  @Override
  public CompletableFuture<Map<String, RemoteAttestationResponse>> attest(User user, String authHeader, String enclaveId, byte[] clientPublic) {
    return CompletableFuture.completedFuture(new HashMap<>());
  }

  @Override
  public CompletableFuture<Boolean> discoveryAllowed(User user, String authHeader, String enclaveId, DiscoveryRequest discRequest) {
    return CompletableFuture.completedFuture(true);
  }
}
