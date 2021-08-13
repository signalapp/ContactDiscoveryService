package org.whispersystems.contactdiscovery.enclave;

import org.junit.Before;
import org.junit.Test;
import org.whispersystems.contactdiscovery.client.IntelClient;
import org.whispersystems.contactdiscovery.client.QuoteSignatureResponse;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SgxHandshakeManagerTest {

  private SgxEnclaveManager enclaveManager;
  private SgxRevocationListManager revocationListManager;
  private IntelClient intelClient;
  private QuoteSignatureResponse intelResponse;

  private SgxHandshakeManager handshakeManager;

  private static final byte[] QUOTE = new byte[32];

  private static final byte[] SIGRL = new byte[0];
  private static final byte[] REQUEST_ID_CIPHERTEXT = new byte[32];
  private static final byte[] REQUEST_ID_IV = new byte[12];
  private static final byte[] REQUEST_ID_TAG = new byte[16];

  private static final byte[] SERVER_EPHEMERAL = new byte[32];
  private static final byte[] SERVER_STATIC = new byte[32];

  static {
    new SecureRandom().nextBytes(QUOTE);
  }

  @Before
  public void setUp() throws Exception {
    enclaveManager = mock(SgxEnclaveManager.class);
    revocationListManager = mock(SgxRevocationListManager.class);
    intelClient = mock(IntelClient.class);
    intelResponse = mock(QuoteSignatureResponse.class);

    SgxEnclave enclave = mock(SgxEnclave.class);
    SgxRequestNegotiationResponse enclaveResponse = mock(SgxRequestNegotiationResponse.class);
    ScheduledExecutorService executorService = mock(ScheduledExecutorService.class);

    when(enclaveManager.getEnclaves()).thenReturn(Map.of("mrenclave_valid", enclave));
    when(enclaveManager.getEnclave(eq("mrenclave_valid"))).thenReturn(enclave);
    when(enclave.getNextQuote(eq(SIGRL))).thenReturn(QUOTE);
    when(enclave.getGid()).thenReturn(1L);
    when(enclave.negotiateRequest(any())).thenReturn(enclaveResponse);
    when(revocationListManager.getRevocationList(eq(1L))).thenReturn(SIGRL);

    when(intelResponse.getCertificates()).thenReturn("foo");
    when(intelResponse.getResponse()).thenReturn("bar");
    when(intelResponse.getSignature()).thenReturn("baz");
    when(enclaveResponse.getPendingRequestIdCiphertext()).thenReturn(REQUEST_ID_CIPHERTEXT);
    when(enclaveResponse.getPendingRequestIdIv()).thenReturn(REQUEST_ID_IV);
    when(enclaveResponse.getPendingRequestIdTag()).thenReturn(REQUEST_ID_TAG);
    when(enclaveResponse.getServerEphemeralPublicKey()).thenReturn(SERVER_EPHEMERAL);
    when(enclaveResponse.getServerStaticPublicKey()).thenReturn(SERVER_STATIC);

    handshakeManager = new SgxHandshakeManager(enclaveManager, revocationListManager, intelClient, executorService);
  }

  @Test
  public void testGetQuote() throws Exception {
    when(intelClient.getQuoteSignature(QUOTE)).thenReturn(intelResponse);

    handshakeManager.refreshAllQuotes();

    verify(revocationListManager).getRevocationList(eq(1L));
    verify(enclaveManager).getEnclaves();
    verify(intelClient).getQuoteSignature(QUOTE);

    RemoteAttestationResponse response = handshakeManager.getHandshake("mrenclave_valid", new byte[32]);
    assertThat(response.getCertificates()).isEqualTo("foo");
    assertThat(response.getSignatureBody()).isEqualTo("bar");
    assertThat(response.getSignature()).isEqualTo("baz");
    assertThat(response.getCiphertext()).isEqualTo(REQUEST_ID_CIPHERTEXT);
    assertThat(response.getIv()).isEqualTo(REQUEST_ID_IV);
    assertThat(response.getTag()).isEqualTo(REQUEST_ID_TAG);
    assertThat(response.getQuote()).isEqualTo(QUOTE);
    assertThat(response.getServerEphemeralPublic()).isEqualTo(SERVER_EPHEMERAL);
    assertThat(response.getServerStaticPublic()).isEqualTo(SERVER_STATIC);
  }

  @Test
  public void testGetQuoteStaleRevocationList() throws Exception {
    when(intelClient.getQuoteSignature(QUOTE)).thenThrow(StaleRevocationListException.class);

    handshakeManager.refreshAllQuotes();

    verify(revocationListManager).getRevocationList(eq(1L));
    verify(revocationListManager).expireRevocationList(eq(1L));
    verify(enclaveManager).getEnclaves();
    verify(intelClient).getQuoteSignature(QUOTE);

    assertThatExceptionOfType(SignedQuoteUnavailableException.class)
            .isThrownBy(() -> handshakeManager.getHandshake("mrenclave_valid", new byte[32]));
  }

  @Test
  public void testGetQuoteStaleRevocationListRetry() throws Exception {
    when(intelClient.getQuoteSignature(QUOTE))
            .thenThrow(StaleRevocationListException.class)
            .thenReturn(intelResponse);

    handshakeManager.refreshAllQuotes();
    handshakeManager.refreshAllQuotes();

    verify(revocationListManager, times(2)).getRevocationList(eq(1L));
    verify(revocationListManager, times(1)).expireRevocationList(eq(1L));
    verify(enclaveManager, times(2)).getEnclaves();
    verify(intelClient, times(2)).getQuoteSignature(QUOTE);

    RemoteAttestationResponse response = handshakeManager.getHandshake("mrenclave_valid", new byte[32]);
    assertThat(response.getCertificates()).isEqualTo("foo");
    assertThat(response.getSignatureBody()).isEqualTo("bar");
    assertThat(response.getSignature()).isEqualTo("baz");
    assertThat(response.getCiphertext()).isEqualTo(REQUEST_ID_CIPHERTEXT);
    assertThat(response.getIv()).isEqualTo(REQUEST_ID_IV);
    assertThat(response.getTag()).isEqualTo(REQUEST_ID_TAG);
    assertThat(response.getQuote()).isEqualTo(QUOTE);
    assertThat(response.getServerEphemeralPublic()).isEqualTo(SERVER_EPHEMERAL);
    assertThat(response.getServerStaticPublic()).isEqualTo(SERVER_STATIC);
  }

  @Test
  public void testUnexpectedException() throws Exception {
    when(intelClient.getQuoteSignature(any())).thenThrow(new RuntimeException("OH NO"));

    // We're happy as long as this doesn't throw an exception
    handshakeManager.refreshAllQuotes();
  }
}
