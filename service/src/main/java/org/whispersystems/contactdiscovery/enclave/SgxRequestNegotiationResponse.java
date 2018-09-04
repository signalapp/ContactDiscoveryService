/*
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
package org.whispersystems.contactdiscovery.enclave;

import com.google.common.annotations.VisibleForTesting;

/**
 * Enclave response for handshake request
 *
 * @author Jeff Griffin
 */
public class SgxRequestNegotiationResponse {

  private final byte[] serverStaticPublicKey;
  private final byte[] serverEphemeralPublicKey;
  private final byte[] pendingRequestIdCiphertext;
  private final byte[] pendingRequestIdIv;
  private final byte[] pendingRequestIdTag;

  public SgxRequestNegotiationResponse(byte[] serverStaticPublicKey, byte[] serverEphemeralPublicKey,
                                       byte[] pendingRequestIdCiphertext, byte[] pendingRequestIdIv,
                                       byte[] pendingRequestIdTag) {
    if (serverStaticPublicKey == null || serverEphemeralPublicKey == null || pendingRequestIdCiphertext == null ||
        pendingRequestIdIv == null || pendingRequestIdTag == null) {
      throw new IllegalArgumentException();
    }
    this.serverStaticPublicKey      = serverStaticPublicKey;
    this.serverEphemeralPublicKey   = serverEphemeralPublicKey;
    this.pendingRequestIdCiphertext = pendingRequestIdCiphertext;
    this.pendingRequestIdIv         = pendingRequestIdIv;
    this.pendingRequestIdTag        = pendingRequestIdTag;
  }

  public byte[] getServerStaticPublicKey() {
    return serverStaticPublicKey;
  }

  public byte[] getServerEphemeralPublicKey() {
    return serverEphemeralPublicKey;
  }

  public byte[] getPendingRequestIdCiphertext() {
    return pendingRequestIdCiphertext;
  }

  public byte[] getPendingRequestIdIv() {
    return pendingRequestIdIv;
  }

  public byte[] getPendingRequestIdTag() {
    return pendingRequestIdTag;
  }
}
