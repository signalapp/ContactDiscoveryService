package org.whispersystems.contactdiscovery.auth;

import org.junit.Test;

import io.dropwizard.auth.basic.BasicCredentials;

import java.util.Optional;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

public class SignalServiceAuthenticatorTest {

  @Test
  public void testValidService() throws Exception {
    String                     authToken     = "thisisanauthtoken";
    SignalServiceAuthenticator authenticator = new SignalServiceAuthenticator(authToken);

    Optional<SignalService> service = authenticator.authenticate(new BasicCredentials("anything", authToken));
    assertTrue(service.isPresent());
  }

  @Test
  public void testInvalidService() throws Exception {
    String                     authToken     = "thisisanauthtoken";
    SignalServiceAuthenticator authenticator = new SignalServiceAuthenticator(authToken);

    Optional<SignalService> service = authenticator.authenticate(new BasicCredentials("anything", "somethingelse"));
    assertFalse(service.isPresent());
  }

}
