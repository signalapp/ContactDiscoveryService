/**
 * Copyright (C) 2017 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.contactdiscovery.auth;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import io.dropwizard.auth.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.util.Constants;

import java.security.MessageDigest;
import java.util.Optional;

import static com.codahale.metrics.MetricRegistry.name;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.basic.BasicCredentials;

/**
 * Authenticator for calls from the Signal service
 *
 * @author Moxie Marlinspike
 */
public class SignalServiceAuthenticator implements Authenticator<BasicCredentials, SignalService> {

  private final MetricRegistry metricRegistry = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);

  private final Meter authenticationFailedMeter    = metricRegistry.meter(name(getClass(), "authentication", "failed"));
  private final Meter authenticationSucceededMeter = metricRegistry.meter(name(getClass(), "authentication", "succeeded"));

  private final Logger logger = LoggerFactory.getLogger(SignalServiceAuthenticator.class);

  private final byte[] serverAuthenticationToken;

  public SignalServiceAuthenticator(String serverAuthenticationToken) {
    this.serverAuthenticationToken = serverAuthenticationToken.getBytes();
  }

  @Override
  public Optional<SignalService> authenticate(BasicCredentials basicCredentials)
      throws AuthenticationException
  {
    if (MessageDigest.isEqual(basicCredentials.getPassword().getBytes(), serverAuthenticationToken)) {
      authenticationSucceededMeter.mark();
      return Optional.of(new SignalService());
    }

    authenticationFailedMeter.mark();
    return Optional.empty();
  }
}
