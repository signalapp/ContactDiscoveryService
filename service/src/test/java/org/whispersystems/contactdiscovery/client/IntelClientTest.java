package org.whispersystems.contactdiscovery.client;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.whispersystems.contactdiscovery.util.SystemMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;


public class IntelClientTest {

    private static final String API_KEY = "api-key";

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(WireMockConfiguration.options().dynamicPort());

    private IntelClient intelClient;

    @Before
    public void setUp() {
        intelClient = new IntelClient(wireMockRule.baseUrl() + "/foo/bar/", API_KEY, true);
    }

    @Test
    public void getSignatureRevocationList() throws Exception {
        wireMockRule.stubFor(get(urlMatching("/foo/bar/attestation/v3/sigrl/.*"))
                .willReturn(aResponse().withStatus(200).withBody("")));

        assertThat(intelClient.getSignatureRevocationList(0x00000077)).isEmpty();

        verify(getRequestedFor(urlEqualTo("/foo/bar/attestation/v3/sigrl/00000077"))
                .withHeader(IntelClient.SUBSCRIPTION_KEY_HEADER, equalTo(API_KEY)));
    }

    @Test
    public void getSignatureRevocationListBadStatus() {
        wireMockRule.stubFor(get(urlMatching("/foo/bar/attestation/v3/sigrl/.*"))
                .willReturn(aResponse().withStatus(401).withBody("")));

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> intelClient.getSignatureRevocationList(0x00000077));

        verify(getRequestedFor(urlEqualTo("/foo/bar/attestation/v3/sigrl/00000077"))
                .withHeader(IntelClient.SUBSCRIPTION_KEY_HEADER, equalTo(API_KEY)));
    }

    @Test
    public void getSignatureRevocationListBadResponse() throws Exception {
        wireMockRule.stubFor(get(urlMatching("/foo/bar/attestation/v3/sigrl/.*"))
                .willReturn(aResponse().withStatus(200).withBody("This is not valid base64 data")));

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> intelClient.getSignatureRevocationList(0x00000077));

        verify(getRequestedFor(urlEqualTo("/foo/bar/attestation/v3/sigrl/00000077"))
                .withHeader(IntelClient.SUBSCRIPTION_KEY_HEADER, equalTo(API_KEY)));
    }

    @Test
    public void getQuoteSignature() throws Exception {
        wireMockRule.stubFor(post(urlEqualTo("/foo/bar/attestation/v3/report"))
                .willReturn(aResponse().withStatus(200).withBody("")));

        final byte[] quote = "A test quote".getBytes(StandardCharsets.UTF_8);

        try {
            intelClient.getQuoteSignature(quote);
        } catch (final Exception ignored) {
        }

        final String expectedBody = SystemMapper.getMapper().writeValueAsString(new QuoteSignatureRequest(quote));

        verify(postRequestedFor(urlEqualTo("/foo/bar/attestation/v3/report"))
                .withHeader(IntelClient.SUBSCRIPTION_KEY_HEADER, equalTo(API_KEY))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalTo(expectedBody)));
    }
}
