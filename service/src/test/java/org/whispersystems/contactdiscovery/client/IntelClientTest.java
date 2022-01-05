package org.whispersystems.contactdiscovery.client;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
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

@RunWith(JUnitParamsRunner.class)
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
        wireMockRule.stubFor(get(urlEqualTo("/foo/bar/attestation/v4/sigrl/00000077"))
                .willReturn(aResponse().withStatus(200).withBody("")));

        assertThat(intelClient.getSignatureRevocationList(0x00000077)).isEmpty();

        verify(getRequestedFor(urlEqualTo("/foo/bar/attestation/v4/sigrl/00000077"))
                .withHeader(IntelClient.SUBSCRIPTION_KEY_HEADER, equalTo(API_KEY)));
    }

    @Test
    public void getSignatureRevocationListBadStatus() {
        wireMockRule.stubFor(get(urlMatching("/foo/bar/attestation/v4/sigrl/.*"))
                .willReturn(aResponse().withStatus(401).withBody("")));

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> intelClient.getSignatureRevocationList(0x00000077));

        verify(getRequestedFor(urlEqualTo("/foo/bar/attestation/v4/sigrl/00000077"))
                .withHeader(IntelClient.SUBSCRIPTION_KEY_HEADER, equalTo(API_KEY)));
    }

    @Test
    public void getSignatureRevocationListBadResponse() {
        wireMockRule.stubFor(get(urlMatching("/foo/bar/attestation/v4/sigrl/.*"))
                .willReturn(aResponse().withStatus(200).withBody("This is not valid base64 data")));

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> intelClient.getSignatureRevocationList(0x00000077));

        verify(getRequestedFor(urlEqualTo("/foo/bar/attestation/v4/sigrl/00000077"))
                .withHeader(IntelClient.SUBSCRIPTION_KEY_HEADER, equalTo(API_KEY)));
    }

    @Test
    @Parameters(method = "parametersForGetQuoteSignature")
    public void getQuoteSignature(IasVersion iasVersion, String expectedUrl) throws Exception {
        wireMockRule.stubFor(post(urlEqualTo(expectedUrl))
                .willReturn(aResponse().withStatus(200).withBody("")));

        final byte[] quote = "A test quote".getBytes(StandardCharsets.UTF_8);

        try {
            intelClient.getQuoteSignature(quote, iasVersion);
        } catch (final Exception ignored) {
        }

        final String expectedBody = SystemMapper.getMapper().writeValueAsString(new QuoteSignatureRequest(quote));

        verify(postRequestedFor(urlEqualTo(expectedUrl))
                .withHeader(IntelClient.SUBSCRIPTION_KEY_HEADER, equalTo(API_KEY))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalTo(expectedBody)));
    }

    private Object parametersForGetQuoteSignature() {
        return new Object[] {
                new Object[] { IasVersion.IAS_V3, "/foo/bar/attestation/v3/report" },
                new Object[] { IasVersion.IAS_V4, "/foo/bar/attestation/v4/report" }
        };
    }

    @Test
    public void parseIasV3QuoteSignatureBody() throws IOException {
        final String iasV3QuoteSignatureJson = "{\n" +
                "  \"id\" : \"209233327740233584162290707625918281075\",\n" +
                "  \"version\" : 3,\n" +
                "  \"isvEnclaveQuoteBody\" : \"dGVzdA==\",\n" +
                "  \"isvEnclaveQuoteStatus\" : \"OK\",\n" +
                "  \"timestamp\" : \"2022-01-05T19:49:37.077708\"\n" +
                "}";

        // We're happy as long as this doesn't throw an exception
        SystemMapper.getMapper().readValue(iasV3QuoteSignatureJson, QuoteSignatureResponseBody.class);
    }

    @Test
    public void parseIasV4QuoteSignatureBody() throws IOException {
        final String iasV4QuoteSignatureJson = "{\n" +
                "  \"id\" : \"205564072213566131998524126786371242774\",\n" +
                "  \"version\" : 4,\n" +
                "  \"isvEnclaveQuoteBody\" : \"dGVzdA==\",\n" +
                "  \"isvEnclaveQuoteStatus\" : \"SW_HARDENING_NEEDED\",\n" +
                "  \"timestamp\" : \"2022-01-05T18:54:51.692056\",\n" +
                "  \"advisoryURL\" : \"https://security-center.intel.com\",\n" +
                "  \"advisoryIDs\" : [ \"INTEL-SA-00334\" ]\n" +
                "}";

        // We're happy as long as this doesn't throw an exception
        SystemMapper.getMapper().readValue(iasV4QuoteSignatureJson, QuoteSignatureResponseBody.class);
    }
}
