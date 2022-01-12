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

import org.whispersystems.contactdiscovery.client.IntelClient;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Maintains and refreshes the sigRL value for each enclave in the
 * SgxEnclaveManager.
 *
 * @author Moxie Marlinspike
 */
public class SgxRevocationListManager {

  private final Map<Long, byte[]> revocationLists = new ConcurrentHashMap<>();

  private final IntelClient intelClient;

  public SgxRevocationListManager(IntelClient intelClient) {
    this.intelClient = intelClient;
  }

  public byte[] getRevocationList(long groupId) throws IOException, InterruptedException {
    final AtomicReference<Exception> cause = new AtomicReference<>();

    final byte[] revocationList = revocationLists.computeIfAbsent(groupId, gid -> {
      try {
        return intelClient.getSignatureRevocationList(gid);
      } catch (IOException | InterruptedException e) {
        cause.set(e);
        return null;
      }
    });

    if (revocationList == null) {
      if (cause.get() instanceof IOException) {
        throw (IOException) cause.get();
      } else if (cause.get() instanceof InterruptedException) {
        throw (InterruptedException) cause.get();
      } else {
        throw new RuntimeException("Failed to retrieve revocation list");
      }
    }

    return revocationList;
  }

  public void expireRevocationList(long groupId) {
    revocationLists.remove(groupId);
  }
}
