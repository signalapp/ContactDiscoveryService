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

import com.google.common.annotations.VisibleForTesting;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.util.ThreadUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * An interface to a collection of PendingRequestQueues. Attempts to "fairly" hand out
 * pending requests to worker threads consuming the queues
 *
 * @author Moxie Marlinspike
 */
class PendingRequestQueueSet {

  private static final long MAX_WAIT = TimeUnit.SECONDS.toMillis(7);

  private final Map<String, PendingRequestQueue> queues;
  private final long                             maxWait;

  PendingRequestQueueSet(Map<String, PendingRequestQueue> queues) {
    this(queues, MAX_WAIT);
  }

  @VisibleForTesting
  PendingRequestQueueSet(Map<String, PendingRequestQueue> queues, long maxWait) {
    this.queues = queues;
    this.maxWait = maxWait;
  }

  CompletableFuture<DiscoveryResponse> put(String enclaveId, DiscoveryRequest request)
      throws NoSuchEnclaveException
  {
    CompletableFuture<DiscoveryResponse> response       = new CompletableFuture<>();
    PendingRequest                       pendingRequest = new PendingRequest(request, response);
    PendingRequestQueue                  queue          = queues.get(enclaveId);

    if (queue == null) {
      throw new NoSuchEnclaveException(enclaveId);
    }

    synchronized (this) {
      queue.put(pendingRequest);
      notifyAll();
    }

    return response;
  }

  PendingRequestQueueSetGetResult get(int maxAddressCount) {
    var queues = new ArrayList<>(this.queues.entrySet());
    Collections.shuffle(queues);

    synchronized (this) {
      while (true) {
        long currentTime = System.currentTimeMillis();

        var oldestQueue = queues.stream()
                                .filter(q -> !q.getValue().isEmpty())
                                .filter(q -> q.getValue().getElapsedTimeMillis(currentTime) > maxWait)
                                .reduce((oldest, candidate) -> oldest.getValue().getElapsedTimeMillis(currentTime) > candidate.getValue().getElapsedTimeMillis(currentTime) ? oldest : candidate);


        if (oldestQueue.isPresent()) {
          return new PendingRequestQueueSetGetResult(oldestQueue.get().getKey(),
                                                     oldestQueue.get().getValue().getEnclave(),
                                                     oldestQueue.get().getValue().get(maxAddressCount));
        }

        var batchSizeReadyQueue = queues.stream()
                                        .filter(q -> q.getValue().getPendingAddresses() >= maxAddressCount)
                                        .findFirst();

        if (batchSizeReadyQueue.isPresent()) {
          return new PendingRequestQueueSetGetResult(batchSizeReadyQueue.get().getKey(),
                                                     batchSizeReadyQueue.get().getValue().getEnclave(),
                                                     batchSizeReadyQueue.get().getValue().get(maxAddressCount));
        }

        var largestQueue = queues.stream()
                                 .filter(q -> !q.getValue().isEmpty())
                                 .reduce((firstQueue, secondQueue) -> firstQueue.getValue().getPendingAddresses() > secondQueue.getValue().getPendingAddresses() ? firstQueue : secondQueue);

        if (largestQueue.isPresent()) {
          return new PendingRequestQueueSetGetResult(largestQueue.get().getKey(),
                                                     largestQueue.get().getValue().getEnclave(),
                                                     largestQueue.get().getValue().get(maxAddressCount));
        }

        ThreadUtils.wait(this);
      }
    }
  }

  int flushQueues() {
    var queues = this.queues.values();
    int flushedRequests = 0;

    synchronized (this) {
      flushedRequests = queues.stream().reduce(0, (subtotal, queue) -> subtotal + queue.flush(), Integer::sum);
    }

    return flushedRequests;
  }
}
