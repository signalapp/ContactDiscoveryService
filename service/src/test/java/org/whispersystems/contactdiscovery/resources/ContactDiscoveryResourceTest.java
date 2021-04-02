package org.whispersystems.contactdiscovery.resources;

import com.google.common.collect.ImmutableSet;
import io.dropwizard.auth.PolymorphicAuthValueFactoryProvider;
import io.dropwizard.testing.junit.ResourceTestRule;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.whispersystems.contactdiscovery.auth.SignalService;
import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.directory.DirectoryUnavailableException;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequestEnvelope;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.limits.RateLimitExceededException;
import org.whispersystems.contactdiscovery.limits.RateLimiter;
import org.whispersystems.contactdiscovery.mappers.DirectoryUnavailableExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.NoSuchEnclaveExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.RequestManagerFullExceptionMapper;
import org.whispersystems.contactdiscovery.phonelimiter.RateLimitServiceClient;
import org.whispersystems.contactdiscovery.requests.RequestManager;
import org.whispersystems.contactdiscovery.requests.RequestManagerFullException;
import org.whispersystems.contactdiscovery.util.AuthHelper;
import org.whispersystems.contactdiscovery.util.SystemMapper;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class ContactDiscoveryResourceTest {

  private static final String validEnclaveId = "valid_enclave";
  private static final String invalidEnclaveId = "invalid_enclave";

  private final RequestManager requestManager = mock(RequestManager.class);
  private final RateLimiter rateLimiter = mock(RateLimiter.class);
  private final RateLimitServiceClient rateLimitClient = mock(RateLimitServiceClient.class);


  private final byte[] requestId = new byte[32];
  private final byte[] iv = new byte[12];
  private final byte[] data = new byte[512];
  private final byte[] mac = new byte[32];

  private DiscoveryRequest validDiscoveryRequest;
  private DiscoveryRequest invalidDiscoveryRequest;
  private DiscoveryRequest validMultipleAttestDiscRequest;

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addProvider(AuthHelper.getAuthFilter())
                                                            .addProvider(new PolymorphicAuthValueFactoryProvider.Binder<>(ImmutableSet.of(User.class, SignalService.class)))
                                                            .setMapper(SystemMapper.getMapper())
                                                            .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
                                                            .addProvider(new NoSuchEnclaveExceptionMapper())
                                                            .addProvider(new RateLimitExceededExceptionMapper())
                                                            .addProvider(new RequestManagerFullExceptionMapper())
                                                            .addProvider(new DirectoryUnavailableExceptionMapper())
                                                            .addResource(new ContactDiscoveryResource(rateLimiter, requestManager, rateLimitClient, Set.of(validEnclaveId)))
                                                            .build();

  @Before
  public void setup() throws Exception {
    new SecureRandom().nextBytes(requestId);
    new SecureRandom().nextBytes(iv);
    new SecureRandom().nextBytes(data);
    new SecureRandom().nextBytes(mac);

    DiscoveryRequestEnvelope validEnvelope = new DiscoveryRequestEnvelope(requestId, new byte[12], new byte[32], new byte[16]);
    DiscoveryRequestEnvelope invalidEnvelope = new DiscoveryRequestEnvelope(requestId, null, null, null);

    validDiscoveryRequest = new DiscoveryRequest(64, new byte[12], new byte[512], new byte[16], new byte[32], Map.of(RequestManager.LOCAL_ENCLAVE_HOST_ID, validEnvelope));
    invalidDiscoveryRequest = new DiscoveryRequest(64, new byte[10], new byte[512], new byte[16], new byte[32], Map.of(RequestManager.LOCAL_ENCLAVE_HOST_ID, validEnvelope));

    var envelopes = Map.of(RequestManager.LOCAL_ENCLAVE_HOST_ID, validEnvelope, "fakehostid", validEnvelope);
    validMultipleAttestDiscRequest = new DiscoveryRequest(64, new byte[12], new byte[512], new byte[16], new byte[32], envelopes);

    DiscoveryResponse discoveryResponse = new DiscoveryResponse(requestId, iv, data, mac);
    CompletableFuture<DiscoveryResponse> responseFuture = CompletableFuture.completedFuture(discoveryResponse);
    CompletableFuture<DiscoveryResponse> exceptionFuture = new CompletableFuture<>();
    exceptionFuture.completeExceptionally(new NoSuchEnclaveException("bad enclave id"));

    when(rateLimitClient.discoveryAllowed(any(), any(), eq(validEnclaveId), any())).thenReturn(CompletableFuture.completedFuture(true));
    when(requestManager.submit(eq(validEnclaveId), any())).thenReturn(responseFuture);
    when(requestManager.submit(eq(invalidEnclaveId), any())).thenReturn(exceptionFuture);

    doThrow(new RateLimitExceededException("too many", 100)).when(rateLimiter).validate(eq(AuthHelper.VALID_NUMBER_TWO), anyInt());
  }


  @Test
  public void testDiscovery() throws Exception {
    DiscoveryResponse response = resources.getJerseyTest()
                                          .target("/v1/discovery/" + validEnclaveId)
                                          .request(MediaType.APPLICATION_JSON_TYPE)
                                          .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                          .put(Entity.entity(validDiscoveryRequest, MediaType.APPLICATION_JSON_TYPE),
                                               DiscoveryResponse.class);

    verify(rateLimiter, times(1)).validate(AuthHelper.VALID_NUMBER, validDiscoveryRequest.getAddressCount());
    verify(requestManager, times(1)).submit(eq(validEnclaveId), any());

    assertArrayEquals(requestId, response.getRequestId());
    assertArrayEquals(iv, response.getIv());
    assertArrayEquals(data, response.getData());
    assertArrayEquals(mac, response.getMac());
  }

  @Test
  public void testMultipleAttestationsDiscovery() throws RateLimitExceededException, NoSuchEnclaveException, RequestManagerFullException {
    String authHeader = AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN);

    when(rateLimitClient.discoveryAllowed(any(), eq(authHeader), eq(validEnclaveId), eq(validMultipleAttestDiscRequest)))
        .thenReturn(CompletableFuture.completedFuture(true));

    DiscoveryResponse response = resources.getJerseyTest()
                                          .target("/v1/discovery/" + validEnclaveId)
                                          .request(MediaType.APPLICATION_JSON_TYPE)
                                          .header("Authorization", authHeader)
                                          .put(Entity.entity(validMultipleAttestDiscRequest, MediaType.APPLICATION_JSON_TYPE),
                                               DiscoveryResponse.class);

    verify(rateLimiter, times(1)).validate(AuthHelper.VALID_NUMBER, validMultipleAttestDiscRequest.getAddressCount());
    verify(requestManager, times(1)).submit(eq(validEnclaveId), any());

    assertArrayEquals(requestId, response.getRequestId());
    assertArrayEquals(iv, response.getIv());
    assertArrayEquals(data, response.getData());
    assertArrayEquals(mac, response.getMac());
  }

  @Test(expected = BadRequestException.class)
  public void testNoLocalHostIdGiven() {
    String authHeader = AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN);

    var validEnvelope = new DiscoveryRequestEnvelope(requestId, new byte[12], new byte[32], new byte[16]);
    var envelopes = Map.of("nope", validEnvelope, "fakehostid", validEnvelope);
    var request = new DiscoveryRequest(64, new byte[12], new byte[512], new byte[16], new byte[32], envelopes);
    DiscoveryResponse response = resources.getJerseyTest()
                                          .target("/v1/discovery/" + validEnclaveId)
                                          .request(MediaType.APPLICATION_JSON_TYPE)
                                          .header("Authorization", authHeader)
                                          .put(Entity.entity(request, MediaType.APPLICATION_JSON_TYPE),
                                               DiscoveryResponse.class);
  }

  @Test
  public void testNoSuchEnclave() throws Exception {
    Response response = resources.getJerseyTest()
                                 .target("/v1/discovery/" + invalidEnclaveId)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(validDiscoveryRequest, MediaType.APPLICATION_JSON_TYPE));

    assertEquals(404, response.getStatus());
  }

  @Test
  public void testBadRequest() throws Exception {
    Response response = resources.getJerseyTest()
                                 .target("/v1/discovery/" + validEnclaveId)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(invalidDiscoveryRequest, MediaType.APPLICATION_JSON_TYPE));

    assertEquals(422, response.getStatus());
  }

  @Test
  public void testBadRequestEnvelope() {
    List<DiscoveryRequestEnvelope> envelopes = List.of(new DiscoveryRequestEnvelope(requestId, new byte[12], new byte[32], null),
                                                       new DiscoveryRequestEnvelope(requestId, new byte[12], null, new byte[16]),
                                                       new DiscoveryRequestEnvelope(requestId, null, new byte[32], new byte[16]));


    for (DiscoveryRequestEnvelope badEnvelope : envelopes) {
      DiscoveryRequest request = new DiscoveryRequest(64, new byte[12], new byte[512], new byte[16], new byte[32],
                                                                 Map.of(RequestManager.LOCAL_ENCLAVE_HOST_ID, badEnvelope));

      Response response = resources.getJerseyTest()
                                   .target("/v1/discovery/" + validEnclaveId)
                                   .request(MediaType.APPLICATION_JSON_TYPE)
                                   .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                   .put(Entity.entity(request, MediaType.APPLICATION_JSON_TYPE));

      assertEquals(422, response.getStatus());
    }

    verifyNoMoreInteractions(requestManager);
  }

  @Test
  public void testMissingFrontendAttestation() {
    var validEnvelope = new DiscoveryRequestEnvelope(requestId, new byte[12], new byte[32], new byte[16]);
    var missingHostIdRequest = new DiscoveryRequest(64, new byte[12], new byte[512], new byte[16], new byte[32], Map.of("nope", validEnvelope));
    Response response = resources.getJerseyTest()
                                 .target("/v1/discovery/" + validEnclaveId)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(missingHostIdRequest, MediaType.APPLICATION_JSON_TYPE));

    assertEquals(400, response.getStatus());
  }

  @Test
  public void testRateLimit() throws Exception {
    Response response = resources.getJerseyTest()
                                 .target("/v1/discovery/" + validEnclaveId)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER_TWO, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(validDiscoveryRequest, MediaType.APPLICATION_JSON_TYPE));

    assertEquals(429, response.getStatus());
  }

  @Test
  public void testDirectoryUnavailable() throws Exception {
    CompletableFuture<DiscoveryResponse> exceptionFuture = new CompletableFuture<>();
    exceptionFuture.completeExceptionally(new DirectoryUnavailableException());
    when(requestManager.submit(eq(validEnclaveId), any())).thenReturn(exceptionFuture);

    Response response = resources.getJerseyTest()
                                 .target("/v1/discovery/" + validEnclaveId)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(validDiscoveryRequest, MediaType.APPLICATION_JSON_TYPE));

    assertEquals(503, response.getStatus());
  }

  @Test
  public void testTooManyRequestsQueued() throws Exception {
    doThrow(new RequestManagerFullException()).when(requestManager).submit(eq(validEnclaveId), any());
    var response = resources.getJerseyTest()
                            .target("/v1/discovery/" + validEnclaveId)
                            .request(MediaType.APPLICATION_JSON_TYPE)
                            .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                            .put(Entity.entity(validDiscoveryRequest, MediaType.APPLICATION_JSON_TYPE));

    verify(rateLimiter, times(1)).validate(AuthHelper.VALID_NUMBER, validDiscoveryRequest.getAddressCount());
    assertEquals(503, response.getStatus());
  }
}
