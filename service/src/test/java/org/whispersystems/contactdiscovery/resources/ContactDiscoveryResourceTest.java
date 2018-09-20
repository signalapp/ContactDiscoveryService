package org.whispersystems.contactdiscovery.resources;

import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.whispersystems.contactdiscovery.directory.DirectoryUnavailableException;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.limits.RateLimitExceededException;
import org.whispersystems.contactdiscovery.limits.RateLimiter;
import org.whispersystems.contactdiscovery.mappers.DirectoryUnavailableExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.NoSuchEnclaveExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.contactdiscovery.requests.RequestManager;
import org.whispersystems.contactdiscovery.util.AuthHelper;
import org.whispersystems.contactdiscovery.util.SystemMapper;
import org.whispersystems.dropwizard.simpleauth.AuthValueFactoryProvider;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;

import io.dropwizard.testing.junit.ResourceTestRule;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class ContactDiscoveryResourceTest {

  private static final String validEnclaveId = "valid_enclave";
  private static final String invalidEnclaveId = "invalid_enclave";

  private final RequestManager requestManager = mock(RequestManager.class);
  private final RateLimiter    rateLimiter    = mock(RateLimiter.class);

  private final byte[] iv   = new byte[12];
  private final byte[] data = new byte[512];
  private final byte[] mac  = new byte[32];

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addProvider(AuthHelper.getAuthFilter())
                                                            .addProvider(new AuthValueFactoryProvider.Binder())
                                                            .setMapper(SystemMapper.getMapper())
                                                            .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
                                                            .addProvider(new NoSuchEnclaveExceptionMapper())
                                                            .addProvider(new RateLimitExceededExceptionMapper())
                                                            .addProvider(new DirectoryUnavailableExceptionMapper())
                                                            .addResource(new ContactDiscoveryResource(rateLimiter, requestManager))
                                                            .build();

  @Before
  public void setup() throws Exception {
    new SecureRandom().nextBytes(iv);
    new SecureRandom().nextBytes(data);
    new SecureRandom().nextBytes(mac);

    DiscoveryResponse                    discoveryResponse = new DiscoveryResponse(iv, data, mac);
    CompletableFuture<DiscoveryResponse> responseFuture    = CompletableFuture.completedFuture(discoveryResponse);
    CompletableFuture<DiscoveryResponse> exceptionFuture   = new CompletableFuture<>();
    exceptionFuture.completeExceptionally(new NoSuchEnclaveException("bad enclave id"));

    when(requestManager.submit(eq(validEnclaveId), any())).thenReturn(responseFuture);
    when(requestManager.submit(eq(invalidEnclaveId), any())).thenReturn(exceptionFuture);

    doThrow(new RateLimitExceededException("too many", 100)).when(rateLimiter).validate(eq(AuthHelper.VALID_NUMBER_TWO), eq(2047));
  }


  @Test
  public void testDiscovery() throws Exception {
    DiscoveryResponse response = resources.getJerseyTest()
                                          .target("/v1/discovery/" + validEnclaveId)
                                          .request(MediaType.APPLICATION_JSON_TYPE)
                                          .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                          .put(Entity.entity(new DiscoveryRequest(50, new byte[32], new byte[12], new byte[512], new byte[16]), MediaType.APPLICATION_JSON_TYPE),
                                               DiscoveryResponse.class);

    verify(rateLimiter, times(1)).validate(AuthHelper.VALID_NUMBER, 50);
    verify(requestManager, times(1)).submit(eq(validEnclaveId), any());

    assertArrayEquals(iv, response.getIv());
    assertArrayEquals(data, response.getData());
    assertArrayEquals(mac, response.getMac());
  }

  @Test
  public void testNoSuchEnclave() throws Exception {
    Response response = resources.getJerseyTest()
                                 .target("/v1/discovery/" + invalidEnclaveId)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(new DiscoveryRequest(50, new byte[32], new byte[12], new byte[512], new byte[16]), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(404, response.getStatus());
  }

  @Test
  public void testBadRequest() throws Exception {
    Response response = resources.getJerseyTest()
                                 .target("/v1/discovery/" + validEnclaveId)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(new DiscoveryRequest(50, new byte[32], new byte[10], new byte[512], new byte[16]), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(422, response.getStatus());
  }

  @Test
  public void testRateLimit() throws Exception {
    Response response = resources.getJerseyTest()
                                 .target("/v1/discovery/" + validEnclaveId)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER_TWO, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(new DiscoveryRequest(2047, new byte[32], new byte[12], new byte[512], new byte[16]), MediaType.APPLICATION_JSON_TYPE));

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
                                 .put(Entity.entity(new DiscoveryRequest(50, new byte[32], new byte[12], new byte[512], new byte[16]), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(503, response.getStatus());
  }

}
