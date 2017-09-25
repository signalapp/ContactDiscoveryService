package org.whispersystems.contactdiscovery.auth;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.whispersystems.contactdiscovery.util.ByteUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

public class AuthorizationTokenVerifierTest {

  @Test
  public void testGoodToken() throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] key = new byte[32];
    AuthorizationTokenVerifier authorizationTokenVerifier = new AuthorizationTokenVerifier(key);

    String number = "+14152222222";
    long   time   = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    String token  = calculateToken(key, number, String.valueOf(time));

    assertTrue(authorizationTokenVerifier.isValid(token, number, System.currentTimeMillis()));
  }

  @Test
  public void testExpiredToken() throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] key = new byte[32];
    AuthorizationTokenVerifier authorizationTokenVerifier = new AuthorizationTokenVerifier(key);

    String number    = "+14152222222";
    long   time      = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    String token     = calculateToken(key, number, String.valueOf(time));

    assertFalse(authorizationTokenVerifier.isValid(token, number, System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1)));
  }

  @Test
  public void testWrongNumberToken() throws Exception {
    byte[] key = new byte[32];
    AuthorizationTokenVerifier authorizationTokenVerifier = new AuthorizationTokenVerifier(key);

    String number = "+14152222222";
    long   time   = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    String token  = calculateToken(key, number, String.valueOf(time));

    assertFalse(authorizationTokenVerifier.isValid(token, "+14151111111", System.currentTimeMillis()));;
  }

  @Test
  public void testBadTimestampToken() throws Exception {
    byte[] key = new byte[32];
    AuthorizationTokenVerifier authorizationTokenVerifier = new AuthorizationTokenVerifier(key);

    String number = "+14152222222";
    String time   = "boop";
    String token  = calculateToken(key, number, time);

    assertFalse(authorizationTokenVerifier.isValid(token, number, System.currentTimeMillis()));;
  }

  @Test
  public void testBadKeyToken() throws Exception {
    byte[] key = new byte[32];
    String number = "+14152222222";
    long   time   = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    String token  = calculateToken(key, number, String.valueOf(time));

    key[0] = (byte)0x01;
    AuthorizationTokenVerifier authorizationTokenVerifier = new AuthorizationTokenVerifier(key);

    assertFalse(authorizationTokenVerifier.isValid(token, number, System.currentTimeMillis()));;
  }

  @Test
  public void testLongToken() throws Exception {
    byte[] key = new byte[32];
    String number = "+14152222222";
    long   time   = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    String token  = calculateToken(key, number, String.valueOf(time));

    token = token + ":0cool";

    AuthorizationTokenVerifier authorizationTokenVerifier = new AuthorizationTokenVerifier(key);
    assertFalse(authorizationTokenVerifier.isValid(token, number, System.currentTimeMillis()));;
  }

  @Test
  public void testNotHexSignature() throws Exception {
    byte[] key = new byte[32];
    String number = "+14152222222";
    long   time   = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    String token  = number + ":" + time + ":ACGZZZ/+";

    AuthorizationTokenVerifier authorizationTokenVerifier = new AuthorizationTokenVerifier(key);
    assertFalse(authorizationTokenVerifier.isValid(token, number, System.currentTimeMillis()));
  }

  private String calculateToken(byte[] key, String number, String time) throws NoSuchAlgorithmException, InvalidKeyException {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));

    byte[] signature = mac.doFinal((number + ":" + time).getBytes());
    return number + ":" + time + ":" + Hex.encodeHexString(ByteUtils.truncate(signature, 10));
  }
}
