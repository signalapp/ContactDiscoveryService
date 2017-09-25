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

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.dropwizard.lifecycle.Managed;

/**
 * Maintains and refreshes the sigRL value for each enclave in the
 * SgxEnclaveManager.
 *
 * @author Moxie Marlinspike
 */
public class SgxRevocationListManager implements Managed {

  private final Map<Long, byte[]> revocationLists = new ConcurrentHashMap<>();

  private final IntelClient       intelClient;
  private final SgxEnclaveManager enclaveManager;

  public SgxRevocationListManager(SgxEnclaveManager enclaveManager, IntelClient intelClient) {
    this.intelClient    = intelClient;
    this.enclaveManager = enclaveManager;
  }

  public byte[] getRevocationList(long groupId) throws NoSuchRevocationListException {
    byte[] revocationList = revocationLists.get(groupId);

    if (revocationList == null) throw new NoSuchRevocationListException(String.valueOf(groupId));
    else                        return revocationList;
  }

  public byte[] refreshRevocationList(long groupId) {
    byte[] refreshedList = intelClient.getSignatureRevocationList(groupId);
    revocationLists.put(groupId, refreshedList);

    return refreshedList;
  }

  @Override
  public void start() throws Exception {
    for (SgxEnclave enclave : enclaveManager.getEnclaves().values()) {
      if (!revocationLists.containsKey(enclave.getGid())) {
        revocationLists.put(enclave.getGid(), intelClient.getSignatureRevocationList(enclave.getGid()));
      }
    }
  }

  @Override
  public void stop() throws Exception {

  }
}
