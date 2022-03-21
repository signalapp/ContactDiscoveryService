/**
 * Copyright (C) 2017 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.contactdiscovery;

import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.jvm.CachedThreadStatesGaugeSet;
import com.codahale.metrics.jvm.GarbageCollectorMetricSet;
import com.codahale.metrics.jvm.MemoryUsageGaugeSet;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import io.dropwizard.Application;
import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.PolymorphicAuthDynamicFeature;
import io.dropwizard.auth.PolymorphicAuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.auth.basic.BasicCredentials;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.apache.commons.codec.DecoderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.auth.PeerService;
import org.whispersystems.contactdiscovery.auth.PeerServiceAuthenticator;
import org.whispersystems.contactdiscovery.auth.SignalService;
import org.whispersystems.contactdiscovery.auth.SignalServiceAuthenticator;
import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.auth.UserAuthenticator;
import org.whispersystems.contactdiscovery.client.IntelClient;
import org.whispersystems.contactdiscovery.configuration.EnclaveInstanceConfiguration;
import org.whispersystems.contactdiscovery.directory.DirectoryCache;
import org.whispersystems.contactdiscovery.directory.DirectoryManager;
import org.whispersystems.contactdiscovery.directory.DirectoryMapFactory;
import org.whispersystems.contactdiscovery.directory.DirectoryPeerManager;
import org.whispersystems.contactdiscovery.directory.DirectoryQueue;
import org.whispersystems.contactdiscovery.directory.DirectoryQueueManager;
import org.whispersystems.contactdiscovery.enclave.SgxEnclaveManager;
import org.whispersystems.contactdiscovery.enclave.SgxHandshakeManager;
import org.whispersystems.contactdiscovery.enclave.SgxRevocationListManager;
import org.whispersystems.contactdiscovery.limits.RateLimiter;
import org.whispersystems.contactdiscovery.mappers.AEADBadTagExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.CompletionExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.DirectoryUnavailableExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.IOExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.InvalidAddressExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.InvalidRequestSizeExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.NoSuchEnclaveExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.NoSuchPendingRequestExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.PendingRequestFlushExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.RequestLimiterTaskExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.RequestManagerFullExceptionMapper;
import org.whispersystems.contactdiscovery.mappers.SignedQuoteUnavailableExceptionMapper;
import org.whispersystems.contactdiscovery.metrics.CpuUsageGauge;
import org.whispersystems.contactdiscovery.metrics.FileDescriptorGauge;
import org.whispersystems.contactdiscovery.metrics.FreeMemoryGauge;
import org.whispersystems.contactdiscovery.metrics.NetworkReceivedGauge;
import org.whispersystems.contactdiscovery.metrics.NetworkSentGauge;
import org.whispersystems.contactdiscovery.phonelimiter.AlwaysSuccessfulPhoneRateLimiter;
import org.whispersystems.contactdiscovery.phonelimiter.PhoneLimiterPartitioner;
import org.whispersystems.contactdiscovery.phonelimiter.PhoneRateLimiter;
import org.whispersystems.contactdiscovery.phonelimiter.RateLimitServiceClient;
import org.whispersystems.contactdiscovery.phonelimiter.RateLimitServicePartitioner;
import org.whispersystems.contactdiscovery.providers.RedisClientFactory;
import org.whispersystems.contactdiscovery.requests.RequestManager;
import org.whispersystems.contactdiscovery.resources.ContactDiscoveryResource;
import org.whispersystems.contactdiscovery.resources.DirectoryManagementResource;
import org.whispersystems.contactdiscovery.resources.DirectoryManagementV3Resource;
import org.whispersystems.contactdiscovery.resources.DirectorySnapshotResource;
import org.whispersystems.contactdiscovery.resources.HealthCheckOverride;
import org.whispersystems.contactdiscovery.resources.LegacyDirectoryManagementResource;
import org.whispersystems.contactdiscovery.resources.PendingRequestsFlushTask;
import org.whispersystems.contactdiscovery.resources.PingResource;
import org.whispersystems.contactdiscovery.resources.RemoteAttestationResource;
import org.whispersystems.contactdiscovery.resources.RequestLimiterFeature;
import org.whispersystems.contactdiscovery.resources.RequestLimiterFilter;
import org.whispersystems.contactdiscovery.resources.RequestLimiterTask;
import org.whispersystems.contactdiscovery.util.Constants;
import org.whispersystems.contactdiscovery.util.NativeUtils;
import org.whispersystems.contactdiscovery.util.UncaughtExceptionHandler;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Main entry point for the service
 *
 * @author Moxie Marlinspike
 */
public class ContactDiscoveryService extends Application<ContactDiscoveryConfiguration> {

  public static void main(String[] args) throws Exception {
    new ContactDiscoveryService().run(args);
  }

  @Override
  public String getName() {
    return "contact-discovery-service";
  }

  @Override
  public void initialize(Bootstrap<ContactDiscoveryConfiguration> bootstrap) {
  }

  @Override
  public void run(ContactDiscoveryConfiguration configuration, Environment environment)
      throws CertificateException, KeyStoreException, IOException, DecoderException, URISyntaxException, NoSuchAlgorithmException
  {
    NativeUtils.loadNativeResource("/enclave-jni.so");

    UncaughtExceptionHandler.register();

    SharedMetricRegistries.add(Constants.METRICS_NAME, environment.metrics());

    environment.getObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    Logger           logger  = LoggerFactory.getLogger(ContactDiscoveryService.class);
    Optional<String> version = Optional.ofNullable(getClass().getPackage()).map(Package::getImplementationVersion);
    logger.info("starting " + getName() + " version " + version.orElse("unknown"));

    UserAuthenticator          userAuthenticator          = new UserAuthenticator(configuration.getSignalServiceConfiguration().getUserAuthenticationToken());
    SignalServiceAuthenticator signalServiceAuthenticator = new SignalServiceAuthenticator(configuration.getSignalServiceConfiguration().getServerAuthenticationToken());
    PeerServiceAuthenticator   peerServiceAuthenticator   = new PeerServiceAuthenticator(configuration.getDirectoryConfiguration().getPeerAuthenticationToken());

    IntelClient intelClient = new IntelClient(configuration.getEnclaveConfiguration().getIasBaseUri(),
                                              configuration.getEnclaveConfiguration().getApiKey(),
                                              configuration.getEnclaveConfiguration().getAcceptGroupOutOfDate());

    ScheduledExecutorService refreshQuoteExecutor = environment.lifecycle().scheduledExecutorService("RefreshQuote").threads(1).build();

    RedisClientFactory       cacheClientFactory       = new RedisClientFactory(configuration.getRedisConfiguration());
    SgxEnclaveManager        sgxEnclaveManager        = new SgxEnclaveManager(configuration.getEnclaveConfiguration());
    SgxRevocationListManager sgxRevocationListManager = new SgxRevocationListManager(intelClient);
    SgxHandshakeManager      sgxHandshakeManager      = new SgxHandshakeManager(sgxEnclaveManager, sgxRevocationListManager, intelClient, refreshQuoteExecutor);
    DirectoryCache           directoryCache           = new DirectoryCache();
    DirectoryMapFactory      directoryMapFactory      = new DirectoryMapFactory(configuration.getDirectoryConfiguration().getInitialCapacity(), configuration.getDirectoryConfiguration().getMinLoadFactor(), configuration.getDirectoryConfiguration().getMaxLoadFactor());
    DirectoryPeerManager     directoryPeerManager     = new DirectoryPeerManager(configuration.getDirectoryConfiguration().getMapBuilderLoadBalancer(), configuration.getDirectoryConfiguration().getMapBuilderDns(), configuration.getDirectoryConfiguration().getMapBuilderPort(), configuration.getDirectoryConfiguration().getPeerAuthenticationToken(), configuration.getDirectoryConfiguration().isPeerReadEligible());
    DirectoryManager         directoryManager         = new DirectoryManager(cacheClientFactory, directoryCache, directoryMapFactory, directoryPeerManager, configuration.getDirectoryConfiguration().isReconciliationEnabled());
    RequestManager           requestManager           = new RequestManager(directoryManager, sgxEnclaveManager, configuration.getEnclaveConfiguration().getTargetBatchSize());
    DirectoryQueue           directoryQueue           = new DirectoryQueue(configuration.getDirectoryConfiguration().getSqsConfiguration());
    DirectoryQueueManager    directoryQueueManager    = new DirectoryQueueManager(directoryQueue, directoryManager, configuration.getDirectoryConfiguration().getSqsConfiguration().isQueueProcessingEnabled());

    RateLimiter discoveryRateLimiter   = new RateLimiter(cacheClientFactory.getRedisClientPool(), "contactDiscovery", configuration.getLimitsConfiguration().getContactQueries().getBucketSize(), configuration.getLimitsConfiguration().getContactQueries().getLeakRatePerMinute());
    RateLimiter attestationRateLimiter = new RateLimiter(cacheClientFactory.getRedisClientPool(), "remoteAttestation", configuration.getLimitsConfiguration().getRemoteAttestations().getBucketSize(), configuration.getLimitsConfiguration().getRemoteAttestations().getLeakRatePerMinute());

    // While we productionize the rate limiter service, it's nice to not need it up to boot this code. So, we just let
    // the configuration guide us on actually using it.
    PhoneRateLimiter              phoneLimiter     = new AlwaysSuccessfulPhoneRateLimiter();
    RateLimitServiceConfiguration rateLimitSvcConf = configuration.getRateLimitSvc();
    if (rateLimitSvcConf != null) {
      var ranges = PhoneLimiterPartitioner.configToHostRanges(rateLimitSvcConf.getHostRanges());
      var parter = new RateLimitServicePartitioner(ranges);
      var executorService = environment.lifecycle()
                                       .executorService("RateLimiterServiceClient")
                                       // These numbers need some reworking when we have latency numbers, but are
                                       // based on numbers from other Dropwizard HTTP client work.
                                       .maxThreads(128)
                                       .workQueue(new LinkedBlockingQueue<>(8))
                                       .build();
      var client = HttpClient.newBuilder()
                             .executor(executorService)
                             .connectTimeout(Duration.ofMillis(rateLimitSvcConf.getConnectTimeoutMs()))
                             .build();
      var requestTimeout = Duration.ofMillis(rateLimitSvcConf.getRequestTimeoutMs());
      phoneLimiter = new RateLimitServiceClient(parter, client, requestTimeout);
    }

    Set<String> enclaves = configuration.getEnclaveConfiguration()
                                        .getInstances().stream()
                                        .map(EnclaveInstanceConfiguration::getMrenclave)
                                        .collect(Collectors.toSet());

    RemoteAttestationResource remoteAttestationResource = new RemoteAttestationResource(sgxHandshakeManager, attestationRateLimiter, phoneLimiter);
    ContactDiscoveryResource contactDiscoveryResource = new ContactDiscoveryResource(discoveryRateLimiter, requestManager, phoneLimiter, enclaves);
    DirectoryManagementResource directoryManagementResource = new DirectoryManagementResource(directoryManager);
    DirectorySnapshotResource directorySnapshotResource = new DirectorySnapshotResource(directoryManager);
    LegacyDirectoryManagementResource legacyDirectoryManagementResource = new LegacyDirectoryManagementResource();
    DirectoryManagementV3Resource directoryManagementV3Resource = new DirectoryManagementV3Resource(directoryManager);

    RequestLimiterFilter requestLimiterFilter = new RequestLimiterFilter();

    var healthCheckOverride = new AtomicBoolean(true);
    var onResource          = new HealthCheckOverride.HealthCheckOn(healthCheckOverride);
    var offResource         = new HealthCheckOverride.HealthCheckOff(healthCheckOverride);
    var pingResource        = new PingResource(healthCheckOverride);
    var requestLimiterTask  = new RequestLimiterTask(requestLimiterFilter);
    var flushRequestsTask   = new PendingRequestsFlushTask(requestManager);

    environment.lifecycle().manage(sgxEnclaveManager);
    environment.lifecycle().manage(sgxHandshakeManager);
    environment.lifecycle().manage(requestManager);
    environment.lifecycle().manage(directoryManager);
    environment.lifecycle().manage(directoryQueueManager);
    var updaterExec = environment.lifecycle().scheduledExecutorService("DirectoryHashMapUpdater").threads(1).build();
    updaterExec.scheduleAtFixedRate(directoryManager::commitIfIsConnected, 30, 30, TimeUnit.SECONDS);

    AuthFilter<BasicCredentials, User> userAuthFilter = new BasicCredentialAuthFilter.Builder<User>()
        .setAuthenticator(userAuthenticator)
        .buildAuthFilter();
    AuthFilter<BasicCredentials, SignalService> signalServiceAuthFilter = new BasicCredentialAuthFilter.Builder<SignalService>()
        .setAuthenticator(signalServiceAuthenticator)
        .buildAuthFilter();
    AuthFilter<BasicCredentials, PeerService> peerServiceAuthFilter = new BasicCredentialAuthFilter.Builder<PeerService>()
        .setAuthenticator(peerServiceAuthenticator)
        .buildAuthFilter();
    environment.jersey().register(new PolymorphicAuthDynamicFeature<>(ImmutableMap.of(User.class,          userAuthFilter,
                                                                                      SignalService.class, signalServiceAuthFilter,
                                                                                      PeerService.class,   peerServiceAuthFilter)));
    environment.jersey().register(new PolymorphicAuthValueFactoryProvider.Binder<>(ImmutableSet.of(User.class, SignalService.class, PeerService.class)));

    environment.jersey().register(new RequestLimiterFeature(requestLimiterFilter));

    environment.jersey().register(remoteAttestationResource);
    environment.jersey().register(contactDiscoveryResource);
    environment.jersey().register(directoryManagementResource);
    environment.jersey().register(directorySnapshotResource);
    environment.jersey().register(legacyDirectoryManagementResource);
    environment.jersey().register(pingResource);
    environment.jersey().register(directoryManagementV3Resource);

    environment.jersey().register(new IOExceptionMapper());
    environment.jersey().register(new NoSuchEnclaveExceptionMapper());
    environment.jersey().register(new RateLimitExceededExceptionMapper());
    environment.jersey().register(new RequestManagerFullExceptionMapper());
    environment.jersey().register(new SignedQuoteUnavailableExceptionMapper());
    environment.jersey().register(new NoSuchPendingRequestExceptionMapper());
    environment.jersey().register(new AEADBadTagExceptionMapper());
    environment.jersey().register(new InvalidRequestSizeExceptionMapper());
    environment.jersey().register(new InvalidAddressExceptionMapper());
    environment.jersey().register(new DirectoryUnavailableExceptionMapper());
    environment.jersey().register(new CompletionExceptionMapper());
    environment.jersey().register(new RequestLimiterTaskExceptionMapper());
    environment.jersey().register(new PendingRequestFlushExceptionMapper());

    environment.metrics().register("gc", new GarbageCollectorMetricSet());
    environment.metrics().register("threads", new CachedThreadStatesGaugeSet(10, TimeUnit.SECONDS));
    environment.metrics().register("memory", new MemoryUsageGaugeSet());
    environment.metrics().register(name(CpuUsageGauge.class, "cpu"), new CpuUsageGauge());
    environment.metrics().register(name(FreeMemoryGauge.class, "free_memory"), new FreeMemoryGauge());
    environment.metrics().register(name(NetworkSentGauge.class, "bytes_sent"), new NetworkSentGauge());
    environment.metrics().register(name(NetworkReceivedGauge.class, "bytes_received"), new NetworkReceivedGauge());
    environment.metrics().register(name(FileDescriptorGauge.class, "fd_count"), new FileDescriptorGauge());

    environment.admin().addTask(onResource);
    environment.admin().addTask(offResource);
    environment.admin().addTask(requestLimiterTask);
    environment.admin().addTask(flushRequestsTask);
  }

}
