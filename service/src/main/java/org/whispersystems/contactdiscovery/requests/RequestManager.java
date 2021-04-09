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

import com.codahale.metrics.Counter;
import com.codahale.metrics.ExponentiallyDecayingReservoir;
import com.codahale.metrics.Gauge;
import com.codahale.metrics.Histogram;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import com.google.common.collect.ImmutableMap;
import io.dropwizard.lifecycle.Managed;
import net.openhft.affinity.Affinity;
import net.openhft.affinity.AffinityLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.directory.DirectoryManager;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.enclave.SgxEnclave;
import org.whispersystems.contactdiscovery.enclave.SgxEnclaveManager;
import org.whispersystems.contactdiscovery.enclave.SgxsdMessage;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequestEnvelope;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.util.Constants;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Starts and manages worker threads that drain the pending request queue set
 * and execute the work in its corresponding SGX enclave
 *
 * @author Moxie Marlinspike
 */
public class RequestManager implements Managed {

  /**
   * LOCAL_ENCLAVE_HOST_ID is just faked out key for the attestations map that will only hold one enclave. This
   * will go away when we work out the routing code to the new rate limiter service.
   */
  public static final String LOCAL_ENCLAVE_HOST_ID = UUID.randomUUID().toString();
  private static final long MIN_BACKLOG_SIZE_DEFAULT = 10_000;
  private static final long MIN_BACKLOG_SIZE_PRIORITY = 12_000;
  private static final Duration MAX_BACKLOG_TIME = Duration.ofSeconds(15);
  private static final Duration MAX_BACKLOG_TIME_PRIORITY = Duration.ofSeconds(20);

  private static final String REQUEST_CONTEXT_INITIAL = "Initial";
  private static final String REQUEST_CONTEXT_INTERACTIVE = "Interactive";

  private final Logger logger = LoggerFactory.getLogger(RequestManager.class);

  private static final MetricRegistry metricRegistry        = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Meter          processedNumbersMeter = metricRegistry.meter(name(RequestManager.class, "processedNumbers"));
  private static final Timer          processBatchTimer     = metricRegistry.timer(name(RequestManager.class, "processBatch"));
  private static final Histogram      batchSizeHistogram    = metricRegistry.histogram(name(RequestManager.class, "batchSize"));
  private static final Counter        pendingRequests       = metricRegistry.counter(name(RequestManager.class, "pendingRequests"));
  private static final Counter        pendingPhoneNumbers   = metricRegistry.counter(name(RequestManager.class, "pendingPhoneNumbers"));
  @SuppressWarnings("unused")
  private static final Gauge hostIdGauge = metricRegistry.register(name(RequestManager.class, "hostId"), (Gauge<String>) () -> LOCAL_ENCLAVE_HOST_ID);

  private static final ConcurrentMap<String, Counter> perEnclavePendingRequests     = new ConcurrentHashMap<>();
  private static final ConcurrentMap<String, Counter> perEnclavePendingPhoneNumbers = new ConcurrentHashMap<>();

  private final ImmutableMap<String, Meter> perEnclaveProcessedNumbersMeter;
  private final ImmutableMap<String, Timer> perEnclaveProcessBatchTimer;
  private final ImmutableMap<String, Histogram> perEnclaveBatchSizeHistogram;

  private final DirectoryManager       directoryManager;
  private final PendingRequestQueueSet pending;
  private final int                    targetBatchSize;

  public RequestManager(DirectoryManager directoryManager, SgxEnclaveManager enclaveManager, int targetBatchSize) {
    logger.info("Using LOCAL_ENCLAVE_HOST_ID: " + LOCAL_ENCLAVE_HOST_ID);

    var queueMap = new HashMap<String, PendingRequestQueue>();
    var perEnclaveProcessedNumbersMeterBuilder = ImmutableMap.<String, Meter>builder();
    var perEnclaveProcessBatchTimerBuilder = ImmutableMap.<String, Timer>builder();
    var perEnclaveBatchSizeHistogramBuilder = ImmutableMap.<String, Histogram>builder();

    for (Map.Entry<String, SgxEnclave> entry : enclaveManager.getEnclaves().entrySet()) {
      queueMap.put(entry.getKey(), new PendingRequestQueue(entry.getValue()));
      perEnclaveProcessedNumbersMeterBuilder.put(entry.getKey(), new Meter());
      perEnclaveProcessBatchTimerBuilder.put(entry.getKey(), new Timer());
      perEnclaveBatchSizeHistogramBuilder.put(entry.getKey(), new Histogram(new ExponentiallyDecayingReservoir()));
    }

    this.perEnclaveProcessedNumbersMeter = perEnclaveProcessedNumbersMeterBuilder.build();
    this.perEnclaveProcessBatchTimer = perEnclaveProcessBatchTimerBuilder.build();
    this.perEnclaveBatchSizeHistogram = perEnclaveBatchSizeHistogramBuilder.build();
    this.directoryManager = directoryManager;
    this.pending = new PendingRequestQueueSet(queueMap);
    this.targetBatchSize  = targetBatchSize;
  }

  public CompletableFuture<DiscoveryResponse> submit(String enclaveId, DiscoveryRequest request)
      throws NoSuchEnclaveException, RequestManagerFullException {
    final var addressCount = request.getAddressCount();

    if (shouldLoadShedRequest(request)) {
      throw new RequestManagerFullException();
    }
    pendingRequests.inc();
    pendingPhoneNumbers.inc(addressCount);
    var perEnclaveRequests = perEnclavePendingRequests.computeIfAbsent(enclaveId,
                                              key -> metricRegistry.counter(name(RequestManager.class, "pendingRequests", "perEnclave", key)));
    var perEnclaveNumbers = perEnclavePendingPhoneNumbers.computeIfAbsent(enclaveId,
                                                  key -> metricRegistry.counter(name(RequestManager.class, "pendingPhoneNumbers", "perEnclave", key)));
    perEnclaveRequests.inc();
    perEnclaveNumbers.inc(addressCount);
    return pending.put(enclaveId, request).whenComplete((resp, t) -> {
      pendingRequests.dec();
      perEnclaveRequests.dec();
      pendingPhoneNumbers.dec(addressCount);
      perEnclaveNumbers.dec(addressCount);
    });
  }

  @Override
  public void start() {
    for (Map.Entry<String, Meter> entry : perEnclaveProcessedNumbersMeter.entrySet()) {
      metricRegistry.register(name(RequestManager.class, "processedNumbers", entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, Timer> entry : perEnclaveProcessBatchTimer.entrySet()) {
      metricRegistry.register(name(RequestManager.class, "processBatch", entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, Histogram> entry : perEnclaveBatchSizeHistogram.entrySet()) {
      metricRegistry.register(name(RequestManager.class, "batchSize", entry.getKey()), entry.getValue());
    }

    final int threadCount = AffinityLock.cpuLayout().sockets() * AffinityLock.cpuLayout().coresPerSocket();
    for (int i = 0; i < threadCount; i++) {
      new EnclaveThread(directoryManager, i).start();
    }
  }

  @Override
  public void stop() {
    for (Map.Entry<String, Meter> entry : perEnclaveProcessedNumbersMeter.entrySet()) {
      metricRegistry.remove(name(RequestManager.class, "processedNumbers", entry.getKey()));
    }
    for (Map.Entry<String, Timer> entry : perEnclaveProcessBatchTimer.entrySet()) {
      metricRegistry.remove(name(RequestManager.class, "processBatch", entry.getKey()));
    }
    for (Map.Entry<String, Histogram> entry : perEnclaveBatchSizeHistogram.entrySet()) {
      metricRegistry.remove(name(RequestManager.class, "batchSize", entry.getKey()));
    }
  }

  private boolean shouldLoadShedRequest(DiscoveryRequest request) {
    boolean priorityContext = REQUEST_CONTEXT_INITIAL.equals(request.getContext()) || REQUEST_CONTEXT_INTERACTIVE.equals(request.getContext());
    long backlogSizeThreshold  = priorityContext ? MIN_BACKLOG_SIZE_PRIORITY : MIN_BACKLOG_SIZE_DEFAULT;
    Duration maxBacklogDuration = priorityContext ? MAX_BACKLOG_TIME_PRIORITY : MAX_BACKLOG_TIME;
    final long backlog = request.getAddressCount() + pendingPhoneNumbers.getCount();
    return backlog >= backlogSizeThreshold && estimateTimeToProcessBacklog(backlog).compareTo(maxBacklogDuration) >= 0;
  }

  private Duration estimateTimeToProcessBacklog(long backlog) {
    // assume rates less than 1000 per second are bad measuring or startup error
    final var backlogItemsPerSecond = Math.max(processedNumbersMeter.getOneMinuteRate(), 1000);
    return Duration.ofSeconds((long) (backlog / backlogItemsPerSecond));
  }

  public int flushPendingQueues() {
    return pending.flushQueues();
  }

  private class EnclaveThread extends Thread {

    private final int              threadId;
    private final DirectoryManager directoryManager;

    private EnclaveThread(DirectoryManager directoryManager, int threadId) {
      this.directoryManager = directoryManager;
      this.threadId         = threadId;
    }

    @Override
    public void run() {
      try (AffinityLock lock = Affinity.acquireCore()) {
        logger.info(this.getClass().getSimpleName() + " on CPU: " + lock.cpuId());

        for (;;) {
          PendingRequestQueueSetGetResult work = pending.get(targetBatchSize);
          processBatch(work.getEnclaveId(), work.getEnclave(), work.getRequests());
        }
      }
    }

    private void processBatch(String enclaveId, SgxEnclave enclave, List<PendingRequest> requests) {
      try {
        int batchSize = requests.stream().mapToInt(r -> r.getRequest().getAddressCount()).sum();
        try (SgxEnclave.SgxsdBatch batch = enclave.newBatch(threadId, batchSize)) {

          for (PendingRequest request : requests) {
            int                      addressCount = request.getRequest().getAddressCount();
            byte[]                   commitment   = request.getRequest().getCommitment();
            DiscoveryRequestEnvelope envelope     = request.getRequest().getEnvelopes().get(LOCAL_ENCLAVE_HOST_ID);
            byte[]                   requestId    = envelope.getRequestId();

            SgxsdMessage queryMessage    = new SgxsdMessage(request.getRequest().getData(),
                                                            request.getRequest().getIv(),
                                                            request.getRequest().getMac());
            SgxsdMessage envelopeMessage = new SgxsdMessage(envelope.getData(),
                                                            envelope.getIv(),
                                                            envelope.getMac());

            batch.add(envelopeMessage, requestId, queryMessage, addressCount, commitment)
                 .thenApply(response -> request.getResponse().complete(new DiscoveryResponse(requestId,
                                                                                             response.getIv(),
                                                                                             response.getData(),
                                                                                             response.getMac())))
                 .exceptionally(exception -> request.getResponse().completeExceptionally(exception));
          }

          processedNumbersMeter.mark(batchSize);
          batchSizeHistogram.update(batchSize);

          try (Timer.Context ignored1 = updatePerEnclaveMetrics(enclaveId, batchSize);
               Timer.Context ignored2 = processBatchTimer.time()) {
            directoryManager.borrow(batch::process);
          }
        }
      } catch (Throwable t) {
        logger.warn("Exception processing request batch", t);

        requests.stream()
                .map(PendingRequest::getResponse)
                .forEach(future -> future.completeExceptionally(t));
      }
    }

    private Timer.Context updatePerEnclaveMetrics(String enclaveId, int batchSize) {
      var meter = perEnclaveProcessedNumbersMeter.get(enclaveId);
      var histogram = perEnclaveBatchSizeHistogram.get(enclaveId);
      var timer = perEnclaveProcessBatchTimer.get(enclaveId);

      if (meter != null) {
        meter.mark(batchSize);
      } else {
        logger.error("Missing meter for enclave " + enclaveId + " yet still processing a batch for it");
      }
      if (histogram != null) {
        histogram.update(batchSize);
      } else {
        logger.error("Missing histogram for enclave " + enclaveId + " yet still processing a batch for it");
      }
      if (timer != null) {
        return timer.time();
      } else {
        logger.error("Missing timer for enclave " + enclaveId + " yet still processing a batch for it");
        return null;
      }
    }
  }
}
