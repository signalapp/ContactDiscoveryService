package org.whispersystems.contactdiscovery.resources;

import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.whispersystems.contactdiscovery.client.QuoteVerificationException;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.enclave.NoSuchRevocationListException;
import org.whispersystems.contactdiscovery.enclave.SgxException;
import org.whispersystems.contactdiscovery.enclave.SgxHandshakeManager;
import org.whispersystems.contactdiscovery.enclave.SignedQuoteUnavailableException;
import org.whispersystems.contactdiscovery.enclave.StaleRevocationListException;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationRequest;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;
import org.whispersystems.contactdiscovery.limits.RateLimiter;
import org.whispersystems.contactdiscovery.mappers.NoSuchEnclaveExceptionMapper;
import org.whispersystems.contactdiscovery.util.AuthHelper;
import org.whispersystems.contactdiscovery.util.SystemMapper;
import org.whispersystems.dropwizard.simpleauth.AuthValueFactoryProvider;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.SecureRandom;

import io.dropwizard.testing.junit.ResourceTestRule;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.internal.verification.VerificationModeFactory.times;

public class RemoteAttestationResourceTest {

  private static final String VALID_ENCLAVE_ID   = "mrenclavevalue";
  private static final String INVALID_ENCLAVE_ID = "randomvalue";

  private final SgxHandshakeManager handshakeManager = mock(SgxHandshakeManager.class);
  private final RateLimiter         rateLimiter      = mock(RateLimiter.class);

  private byte[] serverEphemeral;
  private byte[] serverPublic;
  private byte[] quote;
  private byte[] iv;
  private byte[] ciphertext;
  private byte[] tag;

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addProvider(AuthHelper.getAuthFilter())
                                                            .addProvider(new AuthValueFactoryProvider.Binder())
                                                            .setMapper(SystemMapper.getMapper())
                                                            .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
                                                            .addProvider(new NoSuchEnclaveExceptionMapper())
                                                            .addResource(new RemoteAttestationResource(handshakeManager, rateLimiter))
                                                            .build();

  @Before
  public void setup() throws NoSuchEnclaveException, SgxException, NoSuchRevocationListException, SignedQuoteUnavailableException, StaleRevocationListException, QuoteVerificationException {
    this.serverEphemeral = new byte[32];
    this.serverPublic    = new byte[32];
    this.quote           = new byte[16];
    this.iv              = new byte[12];
    this.ciphertext      = new byte[16];
    this.tag             = new byte[16];

    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(this.serverPublic);
    secureRandom.nextBytes(this.serverEphemeral);
    secureRandom.nextBytes(this.quote);
    secureRandom.nextBytes(this.iv);
    secureRandom.nextBytes(this.ciphertext);
    secureRandom.nextBytes(this.tag);

    when(handshakeManager.getHandshake(eq(VALID_ENCLAVE_ID), any()))
        .thenReturn(new RemoteAttestationResponse(serverEphemeral,
                                                  serverPublic,
                                                  iv,
                                                  ciphertext,
                                                  tag,
                                                  quote,
                                                  "foo", "bar", "baz"));

    when(handshakeManager.getHandshake(eq(INVALID_ENCLAVE_ID), any()))
        .thenThrow(new NoSuchEnclaveException("nse"));
  }

  @Test
  public void testRemoteAttestation() throws Exception {
    byte[] clientPublic = new byte[32];
    new SecureRandom().nextBytes(clientPublic);

    RemoteAttestationResponse response = resources.getJerseyTest()
                                                  .target("/v1/attestation/" + VALID_ENCLAVE_ID)
                                                  .request(MediaType.APPLICATION_JSON_TYPE)
                                                  .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                                  .put(Entity.entity(new RemoteAttestationRequest(clientPublic), MediaType.APPLICATION_JSON_TYPE),
                                                       RemoteAttestationResponse.class);

    assertArrayEquals(response.getQuote(), this.quote);
    assertArrayEquals(response.getTag(), this.tag);
    assertArrayEquals(response.getIv(), this.iv);

    assertEquals(response.getCertificates(), "bar");
    assertEquals(response.getSignature(), "foo");
    assertEquals(response.getSignatureBody(), "baz");

    verify(handshakeManager, times(1)).getHandshake(eq(VALID_ENCLAVE_ID), eq(clientPublic));
  }

  @Test
  public void testBadCredentials() throws Exception {
    byte[] clientPublic = new byte[32];
    new SecureRandom().nextBytes(clientPublic);

    Response response = resources.getJerseyTest()
                                 .target("/v1/attestation/" + VALID_ENCLAVE_ID)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.INVALID_PASSWORD))
                                 .put(Entity.entity(new RemoteAttestationRequest(clientPublic), MediaType.APPLICATION_JSON_TYPE));

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
                                 .put(Entity.entity(new RemoteAttestationRequest(clientPublic), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(response.getStatus(), 422);

    verifyNoMoreInteractions(handshakeManager);
  }

  @Test
  public void testBadEnclaveId() throws Exception {
    byte[] clientPublic = new byte[32];
    new SecureRandom().nextBytes(clientPublic);

    Response response = resources.getJerseyTest()
                                 .target("/v1/attestation/" + INVALID_ENCLAVE_ID)
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.entity(new RemoteAttestationRequest(clientPublic), MediaType.APPLICATION_JSON_TYPE));

    assertEquals(response.getStatus(), 404);

    verify(handshakeManager, times(1)).getHandshake(eq(INVALID_ENCLAVE_ID), eq(clientPublic));
  }


}
