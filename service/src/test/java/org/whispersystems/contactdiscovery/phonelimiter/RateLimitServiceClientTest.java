package org.whispersystems.contactdiscovery.phonelimiter;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequestEnvelope;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class RateLimitServiceClientTest {

  @Rule
  public WireMockRule server1 = new WireMockRule(WireMockConfiguration.options().dynamicPort());
  @Rule
  public WireMockRule server2 = new WireMockRule(WireMockConfiguration.options().dynamicPort());
  @Rule
  public ExpectedException thrown = ExpectedException.none();

  User user = new User("111111");
  Duration requestTimeout = Duration.ofMillis(500);

  @Test
  public void testAttestationGoldenPath() {
    server1.stubFor(put(urlPathEqualTo("/v1/attestation/fakeenclave"))
                        .willReturn(aResponse().withHeader("Content-Type", "application/json").withBody(OKAY_ATTEST)));
    var httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(200)).build();

    var hostsToHostIds = Map.of("fakehostid", URI.create(server1.baseUrl()));
    var parter = Mockito.mock(PhoneLimiterPartitioner.class);
    when(parter.lookup(user.getNumber())).thenReturn(hostsToHostIds);
    var client = new RateLimitServiceClient(parter, httpClient, requestTimeout);
    var key = newKey();
    var resp = client.attest(user, "", "fakeenclave", key).orTimeout(5, TimeUnit.SECONDS).join();
    Map<String, RemoteAttestationResponse> expectedMap = new HashMap<>();
    expectedMap.put("fakehostid", okayResponse());
    assertEquals(expectedMap, resp);

    var hostsToHostIds2 = Map.of("fakehostid", hostsToHostIds.get("fakehostid"),
                                 "fakehostid2", hostsToHostIds.get("fakehostid")
    );
    when(parter.lookup(user.getNumber())).thenReturn(hostsToHostIds2);
    resp = client.attest(user, "", "fakeenclave", key).orTimeout(5, TimeUnit.SECONDS).join();
    expectedMap.put("fakehostid2", okayResponse());

    assertEquals(expectedMap, resp);
  }

  @Test
  public void testAttestationErrorFromOneServer() {
    server1.stubFor(put(urlPathEqualTo("/v1/attestation/fakeenclave"))
                        .willReturn(aResponse().withHeader("Content-Type", "application/json").withBody(OKAY_ATTEST)));
    server2.stubFor(put(urlPathEqualTo("/v1/attestation/fakeenclave"))
                        .willReturn(aResponse().withHeader("Content-Type", "application/json").withStatus(500)));

    var httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(200)).build();
    var hostsToHostIds = Map.of("fakehostid", URI.create(server1.baseUrl()),
                                "fakehostid2", URI.create(server2.baseUrl()));
    var parter = Mockito.mock(PhoneLimiterPartitioner.class);
    when(parter.lookup(user.getNumber())).thenReturn(hostsToHostIds);

    var client = new RateLimitServiceClient(parter, httpClient, requestTimeout);
    var key = newKey();
    var resp = client.attest(user, "", "fakeenclave", key).orTimeout(5, TimeUnit.SECONDS).join();

    var expectedMap = new HashMap<String, RemoteAttestationResponse>();
    expectedMap.put("fakehostid", okayResponse());
    assertEquals(expectedMap, resp);
  }

  @Test
  public void testAttestationErrorFromAllServers() {
    thrown.expect(RuntimeException.class);
    thrown.expectMessage("the rate limit service machines failed to respond or we were unable to parse their responses");

    server1.stubFor(put(urlPathEqualTo("/v1/attestation/fakeenclave"))
                        .willReturn(aResponse().withHeader("Content-Type", "application/json").withStatus(500)));
    server2.stubFor(put(urlPathEqualTo("/v1/attestation/fakeenclave"))
                        .willReturn(aResponse().withHeader("Content-Type", "application/json").withStatus(400)));

    var httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(200)).build();
    var hostsToHostIds = Map.of("fakehostid", URI.create(server1.baseUrl()),
                                "fakehostid2", URI.create(server2.baseUrl()));
    var parter = Mockito.mock(PhoneLimiterPartitioner.class);
    when(parter.lookup(user.getNumber())).thenReturn(hostsToHostIds);

    var client = new RateLimitServiceClient(parter, httpClient, requestTimeout);
    var key = newKey();
    client.attest(user, "", "fakeenclave", key).orTimeout(5, TimeUnit.SECONDS).join();
  }

  @Test
  public void testDiscoveryAllowedGoldenPath() {
    server1.stubFor(put(urlPathEqualTo("/v1/discovery/fakeenclave")).willReturn(aResponse().withHeader("Content-Type", "application/json").withStatus(200)));
    var httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(200)).build();
    var hostsToHostIds = Map.of("anotherfakehostid", URI.create(server1.baseUrl()));

    var parter = Mockito.mock(PhoneLimiterPartitioner.class);
    when(parter.lookup(user.getNumber())).thenReturn(hostsToHostIds);

    var client = new RateLimitServiceClient(parter, httpClient, requestTimeout);
    var envelopes = Map.of(
        "anotherfakehostid", new DiscoveryRequestEnvelope(randBytes(32), randBytes(12), randBytes(32), randBytes(16)),
        "unusedhostid", new DiscoveryRequestEnvelope(randBytes(32), randBytes(12), randBytes(32), randBytes(16)));
    var discRequest = new DiscoveryRequest(10, null, null, null, null, envelopes);
    var isAllowed = client.discoveryAllowed(user, "", "fakeenclave", discRequest).orTimeout(5, TimeUnit.SECONDS).join();
    assertTrue("should be allowed", isAllowed);
  }

  @Test
  public void testDiscoveryAllowedOneFailingServer() {
    server1.stubFor(put(urlPathEqualTo("/v1/discovery/fakeenclave"))
                        .willReturn(aResponse().withHeader("Content-Type", "application/json").withStatus(200)));
    server2.stubFor(put(urlPathEqualTo("/v1/discovery/fakeenclave"))
                        .willReturn(aResponse().withHeader("Content-Type", "application/json").withStatus(500)));
    var httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(200)).build();
    var hostsToHostIds = Map.of("anotherfakehostid", URI.create(server1.baseUrl()), "onemorehostid", URI.create(server2.baseUrl()));
    var parter = Mockito.mock(PhoneLimiterPartitioner.class);
    when(parter.lookup(user.getNumber())).thenReturn(hostsToHostIds);
    var client = new RateLimitServiceClient(parter, httpClient, requestTimeout);

    var envelopes = Map.of(
        "anotherfakehostid", new DiscoveryRequestEnvelope(randBytes(32), randBytes(12), randBytes(32), randBytes(16)),
        "unusedhostid", new DiscoveryRequestEnvelope(randBytes(32), randBytes(12), randBytes(32), randBytes(16)),
        "onemorehostid", new DiscoveryRequestEnvelope(randBytes(32), randBytes(12), randBytes(32), randBytes(16))
    );
    var discRequest = new DiscoveryRequest(10, null, null, null, null, envelopes);
    var isAllowed = client.discoveryAllowed(user, "", "fakeenclave", discRequest).orTimeout(5, TimeUnit.SECONDS).join();
    assertTrue("should be allowed", isAllowed);
  }


  @Test
  public void testDiscoveryAllowedDisallowedCase() {
    server1.stubFor(put(urlPathEqualTo("/v1/discovery/fakeenclave"))
                        .willReturn(aResponse().withHeader("Content-Type", "application/json").withStatus(429)));
    var httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(200)).build();
    var hostsToHostIds = Map.of("anotherfakehostid", URI.create(server1.baseUrl()), "onemorehostid", URI.create(server2.baseUrl()));
    var parter = Mockito.mock(PhoneLimiterPartitioner.class);
    when(parter.lookup(user.getNumber())).thenReturn(hostsToHostIds);
    var client = new RateLimitServiceClient(parter, httpClient, requestTimeout);

    var envelopes = Map.of(
        "anotherfakehostid", new DiscoveryRequestEnvelope(randBytes(32), randBytes(12), randBytes(32), randBytes(16)),
        "unusedhostid", new DiscoveryRequestEnvelope(randBytes(32), randBytes(12), randBytes(32), randBytes(16))
    );
    var discRequest = new DiscoveryRequest(10, null, null, null, null, envelopes);
    var isAllowed = client.discoveryAllowed(user, "", "fakeenclave", discRequest).orTimeout(5, TimeUnit.SECONDS).join();
    assertFalse("should not be allowed", isAllowed);
  }

  @Test
  public void testDiscoveryAllowedNot200Not500Case() {
    server1.stubFor(put(urlPathEqualTo("/v1/discovery/fakeenclave"))
                        .willReturn(aResponse().withHeader("Content-Type", "application/json").withStatus(400)));
    var httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(200)).build();
    var hostsToHostIds = Map.of("anotherfakehostid", URI.create(server1.baseUrl()), "onemorehostid", URI.create(server2.baseUrl()));
    var parter = Mockito.mock(PhoneLimiterPartitioner.class);
    when(parter.lookup(user.getNumber())).thenReturn(hostsToHostIds);
    var client = new RateLimitServiceClient(parter, httpClient, requestTimeout);

    var envelopes = Map.of(
        "anotherfakehostid", new DiscoveryRequestEnvelope(randBytes(32), randBytes(12), randBytes(32), randBytes(16))
    );
    var discRequest = new DiscoveryRequest(10, null, null, null, null, envelopes);
    var isAllowed = client.discoveryAllowed(user, "", "fakeenclave", discRequest).orTimeout(5, TimeUnit.SECONDS).join();
    assertFalse("should not be allowed", isAllowed);
  }

  private byte[] randBytes(int count) {
    var rand = new SecureRandom();
    var bytes = new byte[count];
    rand.nextBytes(bytes);
    return bytes;
  }

  private byte[] newKey() {
    return randBytes(32);
  }

  private static final String OKAY_ATTEST = "{\"serverEphemeralPublic\":\"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\",\"serverStaticPublic\":\"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\",\"quote\":\"MDEyMzQ1Njc4OTAxMjM0NQ==\",\"iv\":\"MDEyMzQ1Njc4OTAx\",\"ciphertext\":\"MDEyMzQ1Njc4OTAxMjM0NQ==\",\"tag\":\"MDEyMzQ1Njc4OTAxMjM0NQ==\",\"signature\":\"foo\",\"certificates\":\"bar\",\"signatureBody\":\"baz\"}";

  private static RemoteAttestationResponse okayResponse() {
    var serverEphemeral = "01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8);
    var serverPublic = "01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8);
    var quote = "0123456789012345".getBytes(StandardCharsets.UTF_8);
    var iv = "012345678901".getBytes(StandardCharsets.UTF_8);
    var ciphertext = "0123456789012345".getBytes(StandardCharsets.UTF_8);
    var tag = "0123456789012345".getBytes(StandardCharsets.UTF_8);
    return new RemoteAttestationResponse(serverEphemeral, serverPublic, iv, ciphertext, tag, quote, "foo", "bar",
                                         "baz");
  }
}