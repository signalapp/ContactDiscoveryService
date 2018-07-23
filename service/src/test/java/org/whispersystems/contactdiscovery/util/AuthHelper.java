package org.whispersystems.contactdiscovery.util;

import org.apache.commons.codec.binary.Base64;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.whispersystems.contactdiscovery.auth.SignalService;
import org.whispersystems.contactdiscovery.auth.SignalServiceAuthenticator;
import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.auth.UserAuthenticator;
import org.whispersystems.dropwizard.simpleauth.AuthDynamicFeature;
import org.whispersystems.dropwizard.simpleauth.BasicCredentialAuthFilter;

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.basic.BasicCredentials;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthHelper {

  public static final String VALID_NUMBER     = "+14150000000";
  public static final String VALID_NUMBER_TWO = "+14152222222";
  public static final String VALID_TOKEN      = "foo";

  public static final String INVVALID_NUMBER  = "+14151111111";
  public static final String INVALID_PASSWORD = "bar";

  public static final String VALID_SERVER_TOKEN = "foo";
  public static final String INVALID_SERVER_TOKEN = "bar";

  public static AuthDynamicFeature getAuthFilter() {
    try {
      UserAuthenticator          userAuthenticator          = mock(UserAuthenticator.class         );
      SignalServiceAuthenticator signalServiceAuthenticator = mock(SignalServiceAuthenticator.class);

      when (userAuthenticator.authenticate(any(BasicCredentials.class))).thenAnswer(new Answer<Optional<User>>() {
        @Override
        public Optional<User> answer(InvocationOnMock invocationOnMock) throws Throwable {
          BasicCredentials credentials = invocationOnMock.getArgument(0);

          if (credentials.getUsername().equals(VALID_NUMBER) && credentials.getPassword().equals(VALID_TOKEN)) {
            return Optional.of(new User(VALID_NUMBER));
          }

          if (credentials.getUsername().equals(VALID_NUMBER_TWO) && credentials.getPassword().equals(VALID_TOKEN)) {
            return Optional.of(new User(VALID_NUMBER_TWO));
          }

          return Optional.empty();
        }
      });

      when(signalServiceAuthenticator.authenticate(any(BasicCredentials.class))).thenAnswer(new Answer<Optional<SignalService>>() {

        @Override
        public Optional<SignalService> answer(InvocationOnMock invocationOnMock) throws Throwable {
          BasicCredentials credentials = invocationOnMock.getArgument(0);

          if (credentials.getPassword().equals(VALID_SERVER_TOKEN)) {
            return Optional.of(new SignalService());
          }

          return Optional.empty();
        }
      });


      return new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<User>()
                                        .setAuthenticator(userAuthenticator)
                                        .setPrincipal(User.class)
                                        .buildAuthFilter(),
                                    new BasicCredentialAuthFilter.Builder<SignalService>()
                                        .setAuthenticator(signalServiceAuthenticator)
                                        .setPrincipal(SignalService.class)
                                        .buildAuthFilter());
    } catch (AuthenticationException e) {
      throw new AssertionError(e);
    }
  }

  public static String getAuthHeader(String number, String token) {
    return "Basic " + Base64.encodeBase64String((number + ":" + token).getBytes());
  }
}
