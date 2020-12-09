package org.whispersystems.contactdiscovery.phonelimiter;

import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * PhoneRateLimiter defines how to talk with an SGX enclave service that rate limits discovery requests by the total
 * unique number of phone numbers the user has looked up. Clients will need to call #attest first, gather responses from
 * user's clients and then follow up with #discoveryAllowed.
 */
public interface PhoneRateLimiter {

  CompletableFuture<Map<String, RemoteAttestationResponse>> attest(User user, String authHeader, String enclaveId, byte[] clientPublic);

  CompletableFuture<Boolean> discoveryAllowed(User user, String authHeader, String enclaveId, DiscoveryRequest discRequest);

}
