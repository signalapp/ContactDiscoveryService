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
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.enclave.SgxEnclave;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.util.ThreadUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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

  Pair<SgxEnclave, List<PendingRequest>> get(int maxAddressCount) {
    ArrayList<PendingRequestQueue> queues = new ArrayList<>(this.queues.values());
    Collections.shuffle(queues);

    synchronized (this) {
      while (true) {
        long currentTime = System.currentTimeMillis();

        Optional<PendingRequestQueue> oldestQueue = queues.stream()
                                                          .filter(q -> !q.isEmpty())
                                                          .filter(q -> q.getElapsedTimeMillis(currentTime) > maxWait)
                                                          .reduce((oldest, candidate) -> oldest.getElapsedTimeMillis(currentTime) > candidate.getElapsedTimeMillis(currentTime) ? oldest : candidate);


        if (oldestQueue.isPresent()) {
          return new ImmutablePair<>(oldestQueue.get().getEnclave(),
                                     oldestQueue.get().get(maxAddressCount));
        }

        Optional<PendingRequestQueue> batchSizeReadyQueue = queues.stream()
                                                                  .filter(q -> q.getPendingAddresses() >= maxAddressCount)
                                                                  .findFirst();

        if (batchSizeReadyQueue.isPresent()) {
          return new ImmutablePair<>(batchSizeReadyQueue.get().getEnclave(),
                                     batchSizeReadyQueue.get().get(maxAddressCount));
        }

        Optional<PendingRequestQueue> largestQueue = queues.stream()
                                                           .filter(q -> !q.isEmpty())
                                                           .reduce((firstQueue, secondQueue) -> firstQueue.getPendingAddresses() > secondQueue.getPendingAddresses() ? firstQueue : secondQueue);

        if (largestQueue.isPresent()) {
          return new ImmutablePair<>(largestQueue.get().getEnclave(),
                                     largestQueue.get().get(maxAddressCount));
        }

        ThreadUtils.wait(this);
      }
    }
  }


}
