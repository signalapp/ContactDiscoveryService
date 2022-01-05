package org.whispersystems.contactdiscovery.resources;

import com.google.common.collect.ImmutableSet;
import io.dropwizard.auth.PolymorphicAuthValueFactoryProvider;
import io.dropwizard.testing.junit.ResourceTestRule;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.whispersystems.contactdiscovery.auth.SignalService;
import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.client.IasVersion;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.enclave.SgxHandshakeManager;
import org.whispersystems.contactdiscovery.entities.MultipleRemoteAttestationResponse;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationRequest;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;
import org.whispersystems.contactdiscovery.limits.RateLimiter;
import org.whispersystems.contactdiscovery.mappers.NoSuchEnclaveExceptionMapper;
import org.whispersystems.contactdiscovery.phonelimiter.RateLimitServiceClient;
import org.whispersystems.contactdiscovery.util.AuthHelper;
import org.whispersystems.contactdiscovery.util.SystemMapper;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;
import static org.whispersystems.contactdiscovery.requests.RequestManager.LOCAL_ENCLAVE_HOST_ID;

@RunWith(JUnitParamsRunner.class)
public class RemoteAttestationResourceTest {

  private static final String VALID_ENCLAVE_ID = "mrenclavevalue";
  private static final String INVALID_ENCLAVE_ID = "randomvalue";

  private final SgxHandshakeManager handshakeManager = mock(SgxHandshakeManager.class);
  private final RateLimiter rateLimiter = mock(RateLimiter.class);
  private final RequestLimiterFilter requestLimiterFilter = new RequestLimiterFilter();
  private final RateLimitServiceClient rateLimitClient = mock(RateLimitServiceClient.class);

  private byte[] serverEphemeral;
  private byte[] serverPublic;
  private byte[] quote;
  private byte[] iv;
  private byte[] ciphertext;
  private byte[] tag;

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addProvider(AuthHelper.getAuthFilter())
                                                            .addProvider(new PolymorphicAuthValueFactoryProvider.Binder<>(ImmutableSet.of(User.class, SignalService.class)))
                                                            .addProvider(new RequestLimiterFeature(requestLimiterFilter))
                                                            .setMapper(SystemMapper.getMapper())
                                                            .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
                                                            .addProvider(new NoSuchEnclaveExceptionMapper())
                                                            .addResource(new RemoteAttestationResource(handshakeManager, rateLimiter, rateLimitClient))
                                                            .build();

  @Before
  public void setup() throws Exception {
    this.serverEphemeral = new byte[32];
    this.serverPublic = new byte[32];
    this.quote = new byte[16];
    this.iv = new byte[12];
    this.ciphertext = new byte[16];
    this.tag = new byte[16];

    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(this.serverPublic);
    secureRandom.nextBytes(this.serverEphemeral);
    secureRandom.nextBytes(this.quote);
    secureRandom.nextBytes(this.iv);
    secureRandom.nextBytes(this.ciphertext);
    secureRandom.nextBytes(this.tag);

    when(handshakeManager.getHandshake(eq(VALID_ENCLAVE_ID), any(), any()))
        .thenReturn(new RemoteAttestationResponse(serverEphemeral,
                                                  serverPublic,
                                                  iv,
                                                  ciphertext,
                                                  tag,
                                                  quote,
                                                  "foo", "bar", "baz"));

    when(handshakeManager.getHandshake(eq(INVALID_ENCLAVE_ID), any(), any()))
        .thenThrow(new NoSuchEnclaveException("nse"));
  }

  @Test
  @Parameters({"IAS_V3", "IAS_V4"})
  public void testRemoteAttestation(IasVersion iasVersion) throws Exception {
    byte[] clientPublic = new byte[32];
    new SecureRandom().nextBytes(clientPublic);

    var rateLimitSvcResults = new HashMap<String, RemoteAttestationResponse>();
    rateLimitSvcResults.put("fakehostid", new RemoteAttestationResponse(serverEphemeral,
                                                                        serverPublic,
                                                                        iv,
                                                                        ciphertext,
                                                                        tag,
                                                                        quote,
                                                                        "foo", "bar", "baz"));
    String authHeader = AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN);
    when(rateLimitClient.attest(any(), eq(authHeader), eq(VALID_ENCLAVE_ID), eq(clientPublic)))
        .thenReturn(CompletableFuture.completedFuture(rateLimitSvcResults));

    MultipleRemoteAttestationResponse response =
        resources.getJerseyTest()
                 .target("/v1/attestation/" + VALID_ENCLAVE_ID)
                 .request(MediaType.APPLICATION_JSON_TYPE)
                 .header("Authorization", authHeader)
                 .put(Entity.entity(new RemoteAttestationRequest(clientPublic, iasVersion.getVersionNumber()), MediaType.APPLICATION_JSON_TYPE),
                      MultipleRemoteAttestationResponse.class);

    assertEquals(response.getAttestations().size(), 2);

    RemoteAttestationResponse attestation = response.getAttestations().get(LOCAL_ENCLAVE_HOST_ID);

    assertNotNull("attestation didn't have the expected key", attestation);
    assertArrayEquals(attestation.getQuote(), this.quote);
    assertArrayEquals(attestation.getTag(), this.tag);
    assertArrayEquals(attestation.getIv(), this.iv);

    assertEquals(attestation.getCertificates(), "bar");
    assertEquals(attestation.getSignature(), "foo");
    assertEquals(attestation.getSignatureBody(), "baz");

    verify(handshakeManager, times(1)).getHandshake(eq(VALID_ENCLAVE_ID), eq(clientPublic), eq(iasVersion));
  }

  @Test
  @Parameters({"IAS_V3", "IAS_V4"})
  public void testRateLimitSvcFailureDoesntAffectResults(IasVersion iasVersion) throws Exception {
    // This test will have to change once we're using CDS rate limit service in production. That's likely around 2020-07
    byte[] clientPublic = new byte[32];
    new SecureRandom().nextBytes(clientPublic);

    String authHeader = AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN);
    when(rateLimitClient.attest(any(), eq(authHeader), eq(VALID_ENCLAVE_ID), eq(clientPublic)))
        .thenReturn(CompletableFuture.failedFuture(new RuntimeException("failed future stuff")));

    MultipleRemoteAttestationResponse response =
        resources.getJerseyTest()
                 .target("/v1/attestation/" + VALID_ENCLAVE_ID)
                 .request(MediaType.APPLICATION_JSON_TYPE)
                 .header("Authorization", authHeader)
                 .put(Entity.entity(new RemoteAttestationRequest(clientPublic, iasVersion.getVersionNumber()), MediaType.APPLICATION_JSON_TYPE),
                      MultipleRemoteAttestationResponse.class);

    assertEquals(response.getAttestations().size(), 1);

    RemoteAttestationResponse attestation = response.getAttestations().get(LOCAL_ENCLAVE_HOST_ID);

    assertNotNull("attestation didn't have the expected host id key", attestation);
    assertArrayEquals(attestation.getQuote(), this.quote);
    assertArrayEquals(attestation.getTag(), this.tag);
    assertArrayEquals(attestation.getIv(), this.iv);

    assertEquals(attestation.getCertificates(), "bar");
    assertEquals(attestation.getSignature(), "foo");
    assertEquals(attestation.getSignatureBody(), "baz");

    verify(handshakeManager, times(1)).getHandshake(eq(VALID_ENCLAVE_ID), eq(clientPublic), eq(iasVersion));
  }

  @Test
  public void testBadCredentials() throws Exception {
    byte[] clientPublic = new byte[32];
    new SecureRandom().nextBytes(clientPublic);

    Response response = resources.getJerseyTest()
                                 .target("/v1/attestation/" + VALID_ENCLAVE_ID)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.INVALID_PASSWORD))
                                 .put(Entity.entity(new RemoteAttestationRequest(clientPublic, 3), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(response.getStatus(), 401);

    verifyNoMoreInteractions(handshakeManager);
  }

  @Test
  public void testBadKey() throws Exception {
    byte[] clientPublic = new byte[16];
    new SecureRandom().nextBytes(clientPublic);

    Response response = resources.getJerseyTest()
                                 .target("/v1/attestation/" + VALID_ENCLAVE_ID)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(new RemoteAttestationRequest(clientPublic, 3), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(response.getStatus(), 422);

    verifyNoMoreInteractions(handshakeManager);
  }

  @Test
  public void testBadIasVersion() throws Exception {
    byte[] clientPublic = new byte[32];
    new SecureRandom().nextBytes(clientPublic);

    Response response = resources.getJerseyTest()
            .target("/v1/attestation/" + VALID_ENCLAVE_ID)
            .request(MediaType.APPLICATION_JSON_TYPE)
            .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
            .put(Entity.entity(new RemoteAttestationRequest(clientPublic, -43), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(422, response.getStatus());

    verifyNoMoreInteractions(handshakeManager);
  }

  @Test
  @Parameters({"IAS_V3", "IAS_V4"})
  public void testBadEnclaveId(IasVersion iasVersion) throws Exception {
    byte[] clientPublic = new byte[32];
    new SecureRandom().nextBytes(clientPublic);

    Response response = resources.getJerseyTest()
                                 .target("/v1/attestation/" + INVALID_ENCLAVE_ID)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(new RemoteAttestationRequest(clientPublic, iasVersion.getVersionNumber()), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(response.getStatus(), 404);

    verify(handshakeManager, times(1)).getHandshake(eq(INVALID_ENCLAVE_ID), eq(clientPublic), eq(iasVersion));
  }

  @Test
  public void testRequestLimiter() throws Exception {
    byte[] clientPublic = new byte[32];
    new SecureRandom().nextBytes(clientPublic);

    requestLimiterFilter.getAndSet(100);

    Response response = resources.getJerseyTest()
            .target("/v1/attestation/" + VALID_ENCLAVE_ID)
            .request(MediaType.APPLICATION_JSON_TYPE)
            .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
            .put(Entity.entity(new RemoteAttestationRequest(clientPublic, 3), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), response.getStatus());

    verifyNoMoreInteractions(handshakeManager);
  }
}
