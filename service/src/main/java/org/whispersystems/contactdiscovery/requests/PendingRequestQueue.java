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
package org.whispersystems.contactdiscovery.requests;

import org.whispersystems.contactdiscovery.enclave.SgxEnclave;
import org.whispersystems.contactdiscovery.util.ThreadUtils;

import java.util.LinkedList;
import java.util.List;

/**
 * A FIFO queue of pending requests for a given SGX enclave
 *
 * @author Moxie Marlinspike
 */
public class PendingRequestQueue {

  private final LinkedList<PendingRequest> queue = new LinkedList<>();
  private final SgxEnclave enclave;

  private int  addressCount = 0;
  private long lastGet      = 0;

  public PendingRequestQueue(SgxEnclave enclave) {
    this.enclave = enclave;
  }

  public synchronized void put(PendingRequest pendingRequest) {
    addressCount += pendingRequest.getRequest().getAddressCount();
    queue.add(pendingRequest);

    if (lastGet == 0) {
      lastGet = System.currentTimeMillis();
    }

    notifyAll();
  }

  public synchronized List<PendingRequest> get(int maxAddressCount) {
    int                  resultAddressCount = 0;
    List<PendingRequest> results            = new LinkedList<>();

    while (queue.isEmpty()) {
      ThreadUtils.wait(this);
    }

    PendingRequest first = queue.removeFirst();
    resultAddressCount  += first.getRequest().getAddressCount();
    addressCount        -= first.getRequest().getAddressCount();

    results.add(first);

    while (!queue.isEmpty() && queue.getFirst().getRequest().getAddressCount() + resultAddressCount <= maxAddressCount) {
      PendingRequest request = queue.removeFirst();
      resultAddressCount    += request.getRequest().getAddressCount();
      addressCount          -= request.getRequest().getAddressCount();

      results.add(request);
    }

    lastGet = System.currentTimeMillis();

    return results;
  }

  public synchronized int getPendingAddresses() {
    return addressCount;
  }

  public synchronized  boolean isEmpty() {
    return addressCount <= 0;
  }

  public synchronized long getElapsedTimeMillis(long currentTime) {
    return currentTime - lastGet;
  }

  public SgxEnclave getEnclave() {
    return enclave;
  }

  public synchronized int flush() {
    int oldAddressCount = addressCount;
    queue.forEach(request -> request.getResponse().completeExceptionally(new PendingRequestFlushException()));
    queue.clear();
    addressCount = 0;
    lastGet = 0;
    return oldAddressCount;
  }
}
