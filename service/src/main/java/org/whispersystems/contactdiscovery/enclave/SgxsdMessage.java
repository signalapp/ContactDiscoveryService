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

/**
 * Wrapper for encrypted message to an enclave
 *
 * @author Jeff Griffin
 */
public class SgxsdMessage {
  private final byte[] data;
  private final byte[] iv;
  private final byte[] mac;

  public SgxsdMessage(byte[] data, byte[] iv, byte[] mac) {
    if (data == null || iv == null || mac == null) {
      throw new IllegalArgumentException();
    }
    this.data = data;
    this.iv   = iv;
    this.mac  = mac;
  }

  public byte[] getData() {
    return data;
  }

  public byte[] getIv() {
    return iv;
  }

  public byte[] getMac() {
    return mac;
  }
}
