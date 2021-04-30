/**
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.contactdiscovery.auth;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.basic.BasicCredentials;
import org.whispersystems.contactdiscovery.util.Constants;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Authenticator for calls from a peer CDS service
 */
public class PeerServiceAuthenticator implements Authenticator<BasicCredentials, PeerService> {

  private final MetricRegistry metricRegistry = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);

  private final Meter authenticationFailedMeter    = metricRegistry.meter(name(getClass(), "authentication", "failed"));
  private final Meter authenticationSucceededMeter = metricRegistry.meter(name(getClass(), "authentication", "succeeded"));
  private final byte[] peerAuthenticationToken;

  public PeerServiceAuthenticator(String peerAuthenticationToken) {
    this.peerAuthenticationToken = peerAuthenticationToken.getBytes();
  }

  @Override
  public Optional<PeerService> authenticate(BasicCredentials basicCredentials)
      throws AuthenticationException
  {
    if (MessageDigest.isEqual(basicCredentials.getPassword().getBytes(StandardCharsets.UTF_8), peerAuthenticationToken)) {
      authenticationSucceededMeter.mark();
      return Optional.of(new PeerService());
    }

    authenticationFailedMeter.mark();
    return Optional.empty();
  }
}
