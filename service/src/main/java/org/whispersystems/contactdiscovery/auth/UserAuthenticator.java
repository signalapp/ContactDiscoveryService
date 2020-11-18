package org.whispersystems.contactdiscovery.auth;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import io.dropwizard.auth.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.util.Constants;

import static com.codahale.metrics.MetricRegistry.name;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.basic.BasicCredentials;

import java.util.Optional;

public class UserAuthenticator implements Authenticator<BasicCredentials, User> {

  private final MetricRegistry metricRegistry               = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private final Meter          authenticationFailedMeter    = metricRegistry.meter(name(getClass(), "authentication", "failed"   ));
  private final Meter          authenticationSucceededMeter = metricRegistry.meter(name(getClass(), "authentication", "succeeded"));

  private final Logger logger = LoggerFactory.getLogger(UserAuthenticator.class);

  private final AuthorizationTokenVerifier verifier;

  public UserAuthenticator(byte[] userAuthenticationToken) {
    this.verifier = new AuthorizationTokenVerifier(userAuthenticationToken);
  }

  @Override
  public Optional<User> authenticate(BasicCredentials basicCredentials)
      throws AuthenticationException
  {
    if (!verifier.isValid(basicCredentials.getPassword(),
                          basicCredentials.getUsername(),
                          System.currentTimeMillis()))
    {
      authenticationFailedMeter.mark();
      return Optional.empty();
    }

    authenticationSucceededMeter.mark();
    return Optional.of(new User(basicCredentials.getUsername()));
  }
}
