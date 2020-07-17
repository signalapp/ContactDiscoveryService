package org.whispersystems.contactdiscovery.phonelimiter;

import com.codahale.metrics.Counter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.base.Preconditions;
import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequestEnvelope;
import org.whispersystems.contactdiscovery.entities.EnclaveRateLimitRequest;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;
import org.whispersystems.contactdiscovery.util.ByteArrayAdapter;
import org.whispersystems.contactdiscovery.util.Constants;
import org.whispersystems.contactdiscovery.validation.ByteLength;

import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * RateLimitServiceClient is an implementation of PhoneRateLimiter that talks to one or more hosts running the rate
 * limit service.
 */
public class RateLimitServiceClient implements PhoneRateLimiter {

  private static final ValidatorFactory FACTORY = Validation.buildDefaultValidatorFactory();
  private static final Validator VALIDATOR = FACTORY.getValidator();
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  private static final MetricRegistry METRIC_REGISTRY = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private final Logger LOGGER = LoggerFactory.getLogger(RateLimitServiceClient.class);

  private static final Timer ATTEST_TIMER = METRIC_REGISTRY.timer(name(RateLimitServiceClient.class, "attest", "latency"));
  private static final Counter ATTEST_ATTEMPTS = METRIC_REGISTRY.counter(name(RateLimitServiceClient.class, "attest", "attempts"));
  private static final Counter ATTEST_SUCCESSES = METRIC_REGISTRY.counter(name(RateLimitServiceClient.class, "attest", "successes"));
  private static final Counter ATTEST_ERRORS = METRIC_REGISTRY.counter(name(RateLimitServiceClient.class, "attest", "errors"));
  private static final Counter ATTEST_PARTIAL_FAILURES = METRIC_REGISTRY.counter(name(RateLimitServiceClient.class, "attest", "partial_failures"));

  private static final Timer DISCOVERY_TIMER = METRIC_REGISTRY.timer(name(RateLimitServiceClient.class, "discovery", "latency"));
  private static final Counter DISCOVERY_ATTEMPTS = METRIC_REGISTRY.counter(name(RateLimitServiceClient.class, "discovery", "attempts"));
  private static final Counter DISCOVERY_SUCCESSES = METRIC_REGISTRY.counter(name(RateLimitServiceClient.class, "discovery", "successes"));
  private static final Counter DISCOVERY_ERRORS = METRIC_REGISTRY.counter(name(RateLimitServiceClient.class, "discovery", "errors"));
  private static final Counter DISCOVERY_PARTIAL_FAILURES = METRIC_REGISTRY.counter(name(RateLimitServiceClient.class, "discovery", "partial_failures"));


  private final PhoneLimiterPartitioner parter;
  private final HttpClient client;
  private final Duration requestTimeout;

  public RateLimitServiceClient(PhoneLimiterPartitioner parter, HttpClient client, Duration requestTimeout) {
    this.parter = parter;
    this.client = client;
    this.requestTimeout = requestTimeout;
  }

  @Override
  public CompletableFuture<Map<String, RemoteAttestationResponse>> attest(User user, String authHeader, String enclaveId, byte[] clientPublic) {
    return withMetrics("attest", ATTEST_TIMER, ATTEST_ATTEMPTS, ATTEST_SUCCESSES, ATTEST_ERRORS, attestTimed(user, authHeader, enclaveId, clientPublic));
  }

  public CompletableFuture<Map<String, RemoteAttestationResponse>> attestTimed(User user, String authHeader, String enclaveId, byte[] clientPublic) {
    byte[] body;
    try {
      body = OBJECT_MAPPER.writeValueAsBytes(new EnclaveRateLimitRequest(clientPublic));
    } catch (JsonProcessingException e) {
      return CompletableFuture.failedFuture(e);
    }

    var builder = HttpRequest.newBuilder().timeout(Duration.ofSeconds(2))
                             .header(HttpHeaders.CONTENT_TYPE, "application/json")
                             .header(HttpHeaders.AUTHORIZATION, authHeader)
                             .PUT(BodyPublishers.ofByteArray(body));

    var hostIdToFutures = new HashMap<String, CompletableFuture<RemoteAttestationResponse>>();
    var hostIdToHostAddress = parter.lookup(user.getNumber());
    for (var entry : hostIdToHostAddress.entrySet()) {
      var uri = entry.getValue();
      var request = builder.copy().uri(uri.resolve("/v1/attestation/" + enclaveId)).build();
      final var hostId = entry.getKey();
      // TODO(CDS-153): add retries
      CompletableFuture<RemoteAttestationResponse> fut = client.sendAsync(request, BodyHandlers.ofByteArray())
                                                               .thenApply(this::handleAttestationResponse)
                                                               .orTimeout(requestTimeout.toMillis(), TimeUnit.MILLISECONDS)
                                                               .whenComplete((resp, t) -> {
                                                                 logWhenFailed("attestation", uri, t, ATTEST_PARTIAL_FAILURES);
                                                               });
      hostIdToFutures.put(hostId, fut);
    }

    // We would like to receive all of the responses, but are happy with one.
    // The exceptionally here is to allow thenCompose to always run when all of the
    // futures complete (exceptionally, or not).
    var allFutures = hostIdToFutures.values();
    return CompletableFuture.allOf(allFutures.toArray(CompletableFuture[]::new)).exceptionally((t) -> null)
                            .thenCompose((Void v) -> composeAttestationResponses(hostIdToFutures));
  }

  private void logWhenFailed(String requestType, URI uri, Throwable t, Counter partialFailCount) {
    if (t == null) {
      return;
    }
    partialFailCount.inc();
    LOGGER.warn(String.format("%s: partial failure occurred when requesting %s", requestType, uri, t));
  }

  private CompletableFuture<Map<String, RemoteAttestationResponse>> composeAttestationResponses(Map<String, CompletableFuture<RemoteAttestationResponse>> hostIdToFutures) {
    var allFutures = hostIdToFutures.values();
    var someNotDone = allFutures.stream().anyMatch((fut) -> !fut.isDone());
    if (someNotDone) {
      var ex = new RuntimeException(
          "allOf called with a different set of futures than the ones we're extracting responses from");
      return CompletableFuture.failedFuture(ex);
    }
    var responses = new HashMap<String, RemoteAttestationResponse>();
    for (var entry : hostIdToFutures.entrySet()) {
      var fut = entry.getValue();
      String hostId = entry.getKey();
      if (!fut.isCompletedExceptionally()) {
        responses.put(hostId, fut.join());
      }
    }
    if (responses.size() < 1) {
      return CompletableFuture
          .failedFuture(new RuntimeException("the rate limit service machines failed to respond or we were unable to parse their responses"));
    }
    return CompletableFuture.completedFuture(responses);
  }

  @Override
  public CompletableFuture<Boolean> discoveryAllowed(User user, String authHeader, String enclaveId, DiscoveryRequest discRequest) {
    return withMetrics("discoveryAllowed", DISCOVERY_TIMER, DISCOVERY_ATTEMPTS, DISCOVERY_SUCCESSES, DISCOVERY_ERRORS, discoveryAllowedTimed(user, authHeader, enclaveId, discRequest));
  }

  public CompletableFuture<Boolean> discoveryAllowedTimed(User user, String authHeader, String enclaveId, DiscoveryRequest discRequest) {
    var hostIdToHostAddress = parter.lookup(user.getNumber());
    Map<String, DiscoveryRequestEnvelope> envelopes = discRequest.getEnvelopes();
    var entries = envelopes.entrySet().stream()
                           .filter((e) ->
                                       hostIdToHostAddress.containsKey(e.getKey())
                           ).collect(Collectors.toList());
    Preconditions.checkArgument(entries.size() > 0, "No rate limit host IDs given.");

    var builder = HttpRequest.newBuilder()
                             .timeout(this.requestTimeout)
                             .header(HttpHeaders.CONTENT_TYPE, "application/json")
                             .header(HttpHeaders.AUTHORIZATION, authHeader);

    var allFutures = new ArrayList<CompletableFuture<Boolean>>();
    for (var entry : entries) {
      var uri = hostIdToHostAddress.get(entry.getKey());
      var envelope = entry.getValue();

      byte[] body;
      try {
        body = OBJECT_MAPPER.writeValueAsBytes(new DiscoveryAllowedRequest(discRequest.getAddressCount(),
                                                                           discRequest.getIv(), discRequest.getData(), discRequest.getMac(), discRequest.getCommitment(), envelope));
      } catch (JsonProcessingException e) {
        return CompletableFuture.failedFuture(e);
      }
      var request = builder.copy().uri(uri.resolve("/v1/discovery/" + enclaveId)).PUT(BodyPublishers.ofByteArray(body))
                           .build();
      // TODO(CDS-153): add retries
      CompletableFuture<Boolean> fut = client.sendAsync(request, BodyHandlers.ofByteArray())
                                             .thenCompose(this::handleDiscoveryAllowedResponse)
                                             .orTimeout(requestTimeout.toMillis(), TimeUnit.MILLISECONDS)
                                             .whenComplete((resp, t) -> {
                                               logWhenFailed("discovery", uri, t, DISCOVERY_PARTIAL_FAILURES);
                                             });
      allFutures.add(fut);
    }

    return firstNormalOf(new ArrayList<>(allFutures));
  }

  private <U> CompletableFuture<U> withMetrics(String stage, Timer timer, Counter attempts, Counter successes, Counter errors, CompletableFuture<U> future) {
    attempts.inc();
    Timer.Context context = timer.time();
    future.whenComplete((resp, t) -> {
      if (!future.isCompletedExceptionally()) {
        successes.inc();
      } else {
        LOGGER.warn(String.format("error while calling %s", stage), t);
        errors.inc();
      }
      context.stop();
    });
    return future;
  }

  /**
   * firstNormalOf returns the first normal result from the list of
   * CompletionStages (e.g. CompletionFutures) given to it or the last exceptional
   * result if none of them are successful.
   *
   * @param stages The stages to check.
   * @param <T>    The inner type of the CompletionStages and return value.
   * @return A CompletableFuture with either the first normal result or the last
   * exceptional result.
   */
  private static <T> CompletableFuture<T> firstNormalOf(List<? extends CompletionStage<? extends T>> stages) {
    CompletableFuture<T> f = new CompletableFuture<>();
    Consumer<T> complete = f::complete;
    CompletableFuture.allOf(stages.stream().map(s -> s.thenAccept(complete)).toArray(CompletableFuture<?>[]::new))
                     .exceptionally(ex -> {
                       f.completeExceptionally(ex);
                       return null;
                     });
    return f;
  }

  private CompletableFuture<Boolean> handleDiscoveryAllowedResponse(HttpResponse<byte[]> response) {
    if (response.statusCode() >= 500) {
      return CompletableFuture.failedFuture(new RuntimeException("internal server error response"));
    }
    return CompletableFuture.completedFuture(response.statusCode() == 200);
  }

  private RemoteAttestationResponse handleAttestationResponse(HttpResponse<byte[]> resp) {
    if (resp.statusCode() != 200) {
      throw new RuntimeException(String.format("attestation response code was %d, not 200", resp.statusCode()));
    }

    // We use RemoteAttestationResponse to out of laziness. If this schema needs to differ from the public CDS API and
    // this one, we'll have to add some EnclaveRateLimiterResponse type.
    RemoteAttestationResponse remoteResp;
    try {
      var objectMapper = new ObjectMapper();
      remoteResp = objectMapper.readValue(resp.body(), RemoteAttestationResponse.class);
    } catch (IOException e) {
      throw new RuntimeException("Unable to parse RemoteAttestationResponse in RateLimitServiceClient", e);
    }
    var violations = VALIDATOR.validate(remoteResp);
    if (!violations.isEmpty()) {
      throw new RuntimeException(
          "validations failed during JSON parse of RemoteAttestationResponse in RateLimitServiceClient: " + violations.toString());
    }
    return remoteResp;
  }

  public static class DiscoveryAllowedRequest {

    @JsonProperty
    @NotNull
    @Min(1)
    public int addressCount;

    @JsonProperty
    @NotNull
    @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
    @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
    @ByteLength(min = 12, max = 12)
    public byte[] iv;

    @JsonProperty
    @NotNull
    @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
    @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
    public byte[] data;

    @JsonProperty
    @NotNull
    @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
    @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
    @ByteLength(min = 16, max = 16)
    public byte[] mac;

    @JsonProperty
    @NotNull
    @JsonSerialize(using = ByteArrayAdapter.Serializing.class)
    @JsonDeserialize(using = ByteArrayAdapter.Deserializing.class)
    @ByteLength(min = 32, max = 32)
    public byte[] commitment;

    @JsonProperty
    @NotNull
    public DiscoveryRequestEnvelope envelope;

    public DiscoveryAllowedRequest() {

    }

    public DiscoveryAllowedRequest(int addressCount, byte[] iv, byte[] data, byte[] mac, byte[] commitment,
                                   DiscoveryRequestEnvelope envelope)
    {
      this.addressCount = addressCount;
      this.iv = iv;
      this.data = data;
      this.mac = mac;
      this.commitment = commitment;
      this.envelope = envelope;
    }
  }
}
