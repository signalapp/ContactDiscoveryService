package org.whispersystems.contactdiscovery.auth;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.whispersystems.contactdiscovery.util.ByteUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import io.dropwizard.auth.basic.BasicCredentials;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

public class UserAuthenticatorTest {

  @Test
  public void testValidUser() throws Exception {
    List<byte[]> userAuthenticationTokens = Arrays.asList(new byte[32], new byte[32]);
    UserAuthenticator userAuthenticator       = new UserAuthenticator(userAuthenticationTokens);

    String number = "+14152222222";
    long   time   = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    String token  = constructAuthToken(userAuthenticationTokens.get(0), number, time);

    Optional<User> user = userAuthenticator.authenticate(new BasicCredentials(number, token));

    assertTrue(user.isPresent());
    assertEquals(user.get().getNumber(), number);
  }

  @Test
  public void testNumberMismatch() throws Exception {
    List<byte[]> userAuthenticationTokens = Arrays.asList(new byte[32], new byte[32]);

    UserAuthenticator userAuthenticator       = new UserAuthenticator(userAuthenticationTokens);

    String number = "+14152222222";
    long   time   = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    String token  = constructAuthToken(userAuthenticationTokens.get(0), number, time);

    Optional<User> user = userAuthenticator.authenticate(new BasicCredentials("+14151111111", token));

    assertFalse(user.isPresent());
  }

  @Test
  public void testBadToken() throws Exception {
    List<byte[]> userAuthenticationTokens = Arrays.asList(new byte[32], new byte[32]);

    String number                  = "+14152222222";
    long   time                    = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    String token                   = constructAuthToken(userAuthenticationTokens.get(0), number, time);

    List<byte[]> badTokens = userAuthenticationTokens.stream().map(userAuthenticationToken -> {
      userAuthenticationToken[0] = (byte)0x01;
      return userAuthenticationToken;
    }).collect(Collectors.toList());
    UserAuthenticator userAuthenticator = new UserAuthenticator(badTokens);

    Optional<User> user = userAuthenticator.authenticate(new BasicCredentials(number, token));

    assertFalse(user.isPresent());
  }

  private String constructAuthToken(byte[] key, String number, long time) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));

    byte[] signature = mac.doFinal((number + ":" + time).getBytes());
    return number + ":" + time + ":" + Hex.encodeHexString(ByteUtils.truncate(signature, 10));
  }

}
