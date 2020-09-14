package org.whispersystems.contactdiscovery.requests;

import org.junit.Test;
import org.whispersystems.contactdiscovery.enclave.SgxEnclave;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.resources.RequestLimiterTaskException;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PendingRequestQueueTest {

  @Test
  public void testPutGetCombined() {
    SgxEnclave          enclave = mock(SgxEnclave.class);
    PendingRequestQueue queue   = new PendingRequestQueue(enclave);

    assertEquals(queue.getEnclave(), enclave);

    DiscoveryRequest requestOne = mock(DiscoveryRequest.class);
    DiscoveryRequest requestTwo = mock(DiscoveryRequest.class);

    PendingRequest pendingOne = new PendingRequest(requestOne, null);
    PendingRequest pendingTwo = new PendingRequest(requestTwo, null);

    when(requestOne.getAddressCount()).thenReturn(1000);
    when(requestTwo.getAddressCount()).thenReturn(721);

    queue.put(pendingOne);
    assertEquals(1000, queue.getPendingAddresses());
    assertFalse(queue.isEmpty());

    queue.put(pendingTwo);
    assertEquals(1721, queue.getPendingAddresses());
    assertFalse(queue.isEmpty());

    List<PendingRequest> requests = queue.get(2000);
    assertEquals(2, requests.size());

    assertEquals(requests.get(0), pendingOne);
    assertEquals(requests.get(1), pendingTwo);
    assertEquals(0, queue.getPendingAddresses());
    assertTrue(queue.isEmpty());

    assertTrue(queue.getElapsedTimeMillis(System.currentTimeMillis()) < 1000);
  }

  @Test
  public void testPutGetPartial() {
    SgxEnclave          enclave = mock(SgxEnclave.class);
    PendingRequestQueue queue   = new PendingRequestQueue(enclave);

    DiscoveryRequest requestOne   = mock(DiscoveryRequest.class);
    DiscoveryRequest requestTwo   = mock(DiscoveryRequest.class);
    DiscoveryRequest requestThree = mock(DiscoveryRequest.class);

    PendingRequest pendingOne   = new PendingRequest(requestOne, null  );
    PendingRequest pendingTwo   = new PendingRequest(requestTwo, null  );
    PendingRequest pendingThree = new PendingRequest(requestThree, null);

    when(requestOne.getAddressCount()).thenReturn(1000);
    when(requestTwo.getAddressCount()).thenReturn(721);
    when(requestThree.getAddressCount()).thenReturn(50);

    assertTrue(queue.isEmpty());

    queue.put(pendingOne);
    assertEquals(1000, queue.getPendingAddresses());
    assertFalse(queue.isEmpty());

    queue.put(pendingTwo);
    assertEquals(1721, queue.getPendingAddresses());
    assertFalse(queue.isEmpty());

    queue.put(pendingThree);
    assertEquals(1771, queue.getPendingAddresses());
    assertFalse(queue.isEmpty());

    List<PendingRequest> requests = queue.get(1770);
    assertEquals(2, requests.size());

    assertEquals(requests.get(0), pendingOne);
    assertEquals(requests.get(1), pendingTwo);
    assertEquals(50, queue.getPendingAddresses());
    assertFalse(queue.isEmpty());

    assertTrue(queue.getElapsedTimeMillis(System.currentTimeMillis()) < 1000);

    List<PendingRequest> requestsTwo = queue.get(1000);
    assertEquals(1, requestsTwo.size());
    assertEquals(requestsTwo.get(0), pendingThree);
    assertEquals(0, queue.getPendingAddresses());
    assertTrue(queue.isEmpty());

    assertTrue(queue.getElapsedTimeMillis(System.currentTimeMillis()) < 1000);
  }

  @Test
  public void testBlockingGet() throws ExecutionException, InterruptedException, TimeoutException {
    SgxEnclave          enclave = mock(SgxEnclave.class);
    PendingRequestQueue queue   = new PendingRequestQueue(enclave);

    ExecutorService executorService = Executors.newSingleThreadExecutor();
    Future<List<PendingRequest>> future = executorService.submit(new Callable<List<PendingRequest>>() {
      @Override
      public List<PendingRequest> call() throws Exception {
        return queue.get(500);
      }
    });

    try {
      future.get(500, TimeUnit.MILLISECONDS);
      throw new AssertionError("Queue should block!");
    } catch (TimeoutException e) {
      // good
    }

    DiscoveryRequest discoveryRequest = mock(DiscoveryRequest.class);
    PendingRequest   pendingRequest   = new PendingRequest(discoveryRequest, null);

    when(discoveryRequest.getAddressCount()).thenReturn(50);

    queue.put(pendingRequest);

    List<PendingRequest> fromFuture= future.get(500, TimeUnit.MILLISECONDS);
    assertEquals(1, fromFuture.size());
    assertEquals(fromFuture.get(0), pendingRequest);
  }

  @Test
  public void testFlush() throws ExecutionException, InterruptedException {
    SgxEnclave enclave = mock(SgxEnclave.class);
    PendingRequestQueue queue = new PendingRequestQueue(enclave);

    DiscoveryRequest requestOne = mock(DiscoveryRequest.class);
    DiscoveryRequest requestTwo = mock(DiscoveryRequest.class);

    CompletableFuture<DiscoveryResponse> responseOne = new CompletableFuture<>();
    CompletableFuture<DiscoveryResponse> responseTwo = new CompletableFuture<>();

    PendingRequest pendingOne = new PendingRequest(requestOne, responseOne);
    PendingRequest pendingTwo = new PendingRequest(requestTwo, responseTwo);

    when(requestOne.getAddressCount()).thenReturn(1000);
    when(requestTwo.getAddressCount()).thenReturn(721);

    queue.put(pendingOne);
    assertEquals(1000, queue.getPendingAddresses());
    assertFalse(queue.isEmpty());

    queue.put(pendingTwo);
    assertEquals(1721, queue.getPendingAddresses());
    assertFalse(queue.isEmpty());

    int flushedAddressCount = queue.flush();
    assertEquals(1721, flushedAddressCount);
    assertTrue(queue.isEmpty());

    try {
      var response1 = responseOne.get();
      fail("Missing exception for flushed queue");
    } catch (ExecutionException e) {
      assertTrue(e.getCause() instanceof PendingRequestFlushException);
    }

    try {
      var response1 = responseTwo.get();
      fail("Missing exception for flushed queue");
    } catch (ExecutionException e) {
      assertTrue(e.getCause() instanceof PendingRequestFlushException);
    }
  }
}
