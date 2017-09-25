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

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.util.ByteUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

/**
 * Helper class for verifying signed authorization tokens from the
 * main Signal service.
 *
 * @author Moxie Marlinspike
 */
public class AuthorizationTokenVerifier {

  private final Logger logger = LoggerFactory.getLogger(AuthorizationTokenVerifier.class);

  private final byte[] key;

  public AuthorizationTokenVerifier(byte[] key) {
    this.key = key;
  }

  public boolean isValid(String token, String number, long currentTimeMillis) {
    String[] parts = token.split(":");

    if (parts.length != 3) {
      return false;
    }

    if (!number.equals(parts[0])) {
      return false;
    }

    if (!isValidTime(parts[1], currentTimeMillis)) {
      return false;
    }

    return isValidSignature(parts[0] + ":" + parts[1], parts[2]);
  }

  private boolean isValidTime(String timeString, long currentTimeMillis) {
    try {
      long tokenTime = Long.parseLong(timeString);
      long ourTime   = TimeUnit.MILLISECONDS.toSeconds(currentTimeMillis);

      return TimeUnit.SECONDS.toHours(Math.abs(ourTime - tokenTime)) < 24;
    } catch (NumberFormatException e) {
      logger.warn("Number Format", e);
      return false;
    }
  }

  private boolean isValidSignature(String prefix, String suffix) {
    try {
      Mac hmac = Mac.getInstance("HmacSHA256");
      hmac.init(new SecretKeySpec(key, "HmacSHA256"));

      byte[] ourSuffix   = ByteUtils.truncate(hmac.doFinal(prefix.getBytes()), 10);
      byte[] theirSuffix = Hex.decodeHex(suffix.toCharArray());

      return MessageDigest.isEqual(ourSuffix, theirSuffix);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError(e);
    } catch (DecoderException e) {
      logger.warn("Authorizationtoken", e);
      return false;
    }
  }

}
