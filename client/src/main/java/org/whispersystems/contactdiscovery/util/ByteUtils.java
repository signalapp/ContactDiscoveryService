package org.whispersystems.contactdiscovery.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class ByteUtils {

  public static byte[] getRandomBytes(int size) {
    byte[] result = new byte[size];
    new SecureRandom().nextBytes(result);

    return result;
  }

  public static byte[] truncate(byte[] input, int size) {
    byte[] result = new byte[Math.min(size, input.length)];
    System.arraycopy(input, 0, result, 0, result.length);

    return result;
  }

  public static byte[] reverseTruncate(byte[] input, int size) {
    byte[] result = new byte[size];
    System.arraycopy(input, input.length-size, result, 0, size);

    return result;
  }

  public static byte[] combine(byte[]... elements) {
    try {
      int sum = 0;

      for (byte[] element : elements) {
        sum += element.length;
      }

      ByteArrayOutputStream baos = new ByteArrayOutputStream(sum);

      for (byte[] element : elements) {
        baos.write(element);
      }

      return baos.toByteArray();
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

}
