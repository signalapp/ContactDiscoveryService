package org.whispersystems.contactdiscovery.enclave;

import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.whispersystems.contactdiscovery.client.IntelClient;
import org.whispersystems.contactdiscovery.client.QuoteSignatureResponse;
import org.whispersystems.contactdiscovery.client.QuoteVerificationException;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class SgxHandshakeManagerTest {

  @Test
  public void testGetQuote() throws SgxException, NoSuchRevocationListException, NoSuchEnclaveException, SignedQuoteUnavailableException, StaleRevocationListException, QuoteVerificationException {
    SgxEnclaveManager             enclaveManager        = mock(SgxEnclaveManager.class                 );
    SgxRevocationListManager      revocationListManager = mock(SgxRevocationListManager.class          );
    IntelClient                   intelClient           = mock(IntelClient.class                       );
    SgxEnclave                    enclave               = mock(SgxEnclave.class                        );
    QuoteSignatureResponse        intelResponse         = mock(QuoteSignatureResponse.class);
    SgxRequestNegotiationResponse enclaveResponse       = mock(SgxRequestNegotiationResponse.class);

    Map<String, SgxEnclave> enclaveMap = new HashMap<String, SgxEnclave>() {{
      put("mrenclave_valid", enclave);
    }};

    byte[] quote = new byte[32];
    new SecureRandom().nextBytes(quote);

    byte[] sigrl = new byte[0];
    byte[] requestIdCiphertext = new byte[32];
    byte[] requestIdIv = new byte[12];
    byte[] requestIdTag = new byte[16];

    byte[] serverEphemeral = new byte[32];
    byte[] serverStatic = new byte[32];

    when(enclaveManager.getEnclaves()).thenReturn(enclaveMap);
    when(enclaveManager.getEnclave(eq("mrenclave_valid"))).thenReturn(enclave);
    when(enclave.getNextQuote(eq(sigrl))).thenReturn(quote);
    when(enclave.getGid()).thenReturn(1L);
    when(enclave.negotiateRequest(any())).thenReturn(enclaveResponse);
    when(revocationListManager.getRevocationList(eq(1L))).thenReturn(sigrl);

    when(intelClient.getQuoteSignature(eq(quote))).thenAnswer(new Answer<QuoteSignatureResponse>() {
      private int invocationTime = 0;

      @Override
      public QuoteSignatureResponse answer(InvocationOnMock invocationOnMock) throws Throwable {
        if (invocationTime++ == 0) {
          throw new StaleRevocationListException("Stale!");
        }

        return intelResponse;
      }
    });


    when(intelResponse.getCertificates()).thenReturn("foo");
    when(intelResponse.getResponse()).thenReturn("bar");
    when(intelResponse.getSignature()).thenReturn("baz");
    when(enclaveResponse.getPendingRequestIdCiphertext()).thenReturn(requestIdCiphertext);
    when(enclaveResponse.getPendingRequestIdIv()).thenReturn(requestIdIv);
    when(enclaveResponse.getPendingRequestIdTag()).thenReturn(requestIdTag);
    when(enclaveResponse.getServerEphemeralPublicKey()).thenReturn(serverEphemeral);
    when(enclaveResponse.getServerStaticPublicKey()).thenReturn(serverStatic);

    SgxHandshakeManager handshakeManager = new SgxHandshakeManager(enclaveManager, revocationListManager, intelClient);
    handshakeManager.setRunning(true);
    handshakeManager.refreshAllQuotes();

    verify(revocationListManager, times(2)).getRevocationList(eq(1L));
    verify(revocationListManager, times(1)).refreshRevocationList(eq(1L));
    verify(enclaveManager, times(1)).getEnclaves();
    verify(intelClient, times(2)).getQuoteSignature(eq(quote));

    RemoteAttestationResponse response = handshakeManager.getHandshake("mrenclave_valid", new byte[32]);
    assertThat(response.getCertificates()).isEqualTo("foo");
    assertThat(response.getSignatureBody()).isEqualTo("bar");
    assertThat(response.getSignature()).isEqualTo("baz");
    assertThat(response.getCiphertext()).isEqualTo(requestIdCiphertext);
    assertThat(response.getIv()).isEqualTo(requestIdIv);
    assertThat(response.getTag()).isEqualTo(requestIdTag);
    assertThat(response.getQuote()).isEqualTo(quote);
    assertThat(response.getServerEphemeralPublic()).isEqualTo(serverEphemeral);
    assertThat(response.getServerStaticPublic()).isEqualTo(serverStatic);
  }
}
