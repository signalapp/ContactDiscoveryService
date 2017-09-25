package org.whispersystems.contactdiscovery.util;

public class IntegerUtil {

  public static byte[] longToByteArray(long l) {
    byte[] bytes = new byte[8];
    longToByteArray(bytes, 0, l);
    return bytes;
  }

  public static int longToByteArray(byte[] bytes, int offset, long value) {
    bytes[offset + 7] = (byte)value;
    bytes[offset + 6] = (byte)(value >> 8);
    bytes[offset + 5] = (byte)(value >> 16);
    bytes[offset + 4] = (byte)(value >> 24);
    bytes[offset + 3] = (byte)(value >> 32);
    bytes[offset + 2] = (byte)(value >> 40);
    bytes[offset + 1] = (byte)(value >> 48);
    bytes[offset]     = (byte)(value >> 56);
    return 8;
  }

}
