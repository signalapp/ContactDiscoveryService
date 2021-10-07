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
package org.whispersystems.contactdiscovery.directory;

import com.codahale.metrics.Counter;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.dropwizard.lifecycle.Managed;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.directory.DirectoryProtos.PubSubMessage;
import org.whispersystems.contactdiscovery.enclave.SgxException;
import org.whispersystems.contactdiscovery.providers.RedisClientFactory;
import org.whispersystems.contactdiscovery.util.Constants;
import org.whispersystems.contactdiscovery.util.Util;
import org.whispersystems.dispatch.redis.PubSubConnection;
import org.whispersystems.dispatch.redis.PubSubReply;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.ScanResult;
import redis.clients.util.Pool;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Manages the system directory of all registered users
 *
 * @author Moxie Marlinspike
 */
public class DirectoryManager implements Managed {

  private final Logger logger = LoggerFactory.getLogger(DirectoryManager.class);

  private static final String DIRECTORY_SIZE_GAUGE_NAME = name(DirectoryManager.class, "directorySize");
  private static final String DIRECTORY_CAPACITY_GAUGE_NAME = name(DirectoryManager.class, "directoryCapacity");
  private static final String REDIS_USER_COUNT_GAUGE_NAME = name(DirectoryManager.class, "redisUserCount");

  private static final MetricRegistry metricRegistry = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Meter reconcileAddsMeter = metricRegistry.meter(name(DirectoryManager.class, "reconcileAdds"));
  private static final Meter reconcileRemovesMeter = metricRegistry.meter(name(DirectoryManager.class, "reconcileRemoves"));
  private static final Timer addUserTimer = metricRegistry.timer(name(DirectoryManager.class, "addUser"));
  private static final Timer removeUserTimer = metricRegistry.timer(name(DirectoryManager.class, "removeUser"));
  private static final Timer getAllUsersTimer = metricRegistry.timer(name(DirectoryManager.class, "getAllUsers"));
  private static final Timer reconcileGetUsersTimer = metricRegistry.timer(name(DirectoryManager.class, "reconcile", "getUsersInRange"));
  private static final Timer rebuildLocalDataTimer = metricRegistry.timer(name(DirectoryManager.class, "rebuildLocalData"));
  private static final Timer rebuildFromPeerTimer = metricRegistry.timer(name(DirectoryManager.class, "rebuildfromPeer"));
  private static final Counter rebuildLocalDataNullUUID = metricRegistry.counter(name(DirectoryManager.class, "obsolesence", "rebuildLocalData", "nullUUIDs"));
  private static final Counter obsoluteTypeAdded = metricRegistry.counter(name(DirectoryManager.class, "obsolesence", "sqsMessages", "obsoleteTypeAdded"));
  private static final Timer reconcileExistsUsersTimer = metricRegistry.timer(name(DirectoryManager.class, "reconcile", "getExistingUsers"));

  private static final String CHANNEL = "signal_address_update";

  private static final int SCAN_CHUNK_SIZE = 5_000;
  private static final int PUBSUB_SYNC_TIMEOUT_MILLIS = 30_000;

  private final RedisClientFactory      redisFactory;
  private final DirectoryMapFactory     directoryMapFactory;
  private final boolean                 isReconciliationEnabled;

  private final AtomicBoolean built = new AtomicBoolean(false);
  private final AtomicBoolean bootstrapping = new AtomicBoolean(false);

  private final AtomicReference<Optional<DirectoryMapNative>> currentDirectoryMap;

  private Pool<Jedis>      jedisPool;
  private DirectoryCache   directoryCache;
  private PubSubConnection pubSubConnection;
  private PubSubConsumer   pubSubConsumer;
  private KeepAliveSender  keepAliveSender;
  private DirectoryPeerManager directoryPeerManager;

  public DirectoryManager(RedisClientFactory redisFactory, DirectoryCache directoryCache, DirectoryMapFactory directoryMapFactory, DirectoryPeerManager directoryPeerManager, boolean isReconciliationEnabled) {
    this.redisFactory            = redisFactory;
    this.directoryCache          = directoryCache;
    this.directoryMapFactory     = directoryMapFactory;
    this.currentDirectoryMap     = new AtomicReference<>(Optional.empty());
    this.isReconciliationEnabled = isReconciliationEnabled;
    this.directoryPeerManager = directoryPeerManager;

    metricRegistry.gauge(DIRECTORY_SIZE_GAUGE_NAME, () -> () ->
            currentDirectoryMap.get().map(DirectoryMapNative::size).orElse(0L));

    metricRegistry.gauge(DIRECTORY_CAPACITY_GAUGE_NAME, () -> () ->
      currentDirectoryMap.get().map(DirectoryMapNative::capacity).orElse(0L));
  }

  public boolean isConnected() {
    return currentDirectoryMap.get().isPresent();
  }

  public void commitIfIsConnected() {
    currentDirectoryMap.get().ifPresent(DirectoryMapNative::commit);
  }

  public void addUser(UUID uuid, String address) throws InvalidAddressException, DirectoryUnavailableException {
    if (uuid == null) {
      throw new IllegalArgumentException("addUser expects all users to have a non-null UUID associated");
    }
    try (Jedis         jedis = jedisPool.getResource();
         Timer.Context timer = addUserTimer.time()) {
      addUser(jedis, uuid, address);
    }
  }

  public void removeUser(UUID uuid, String address) throws InvalidAddressException, DirectoryUnavailableException {
    if (uuid == null) {
      throw new IllegalArgumentException("removeUser expects all users to have a non-null UUID associated");
    }

    try (Jedis jedis         = jedisPool.getResource();
         Timer.Context timer = removeUserTimer.time()) {
      removeUser(jedis, uuid, address);
    }
  }

  public boolean isBootstrapping() {
    return bootstrapping.get();
  }

  public void generateSnapshot(OutputStream stream) throws IOException, DirectoryUnavailableException {
    try {
      bootstrapping.set(true);
    DirectoryMapNative directoryMap = getCurrentDirectoryMap();

      try (Jedis jedis = jedisPool.getResource();
           Timer.Context timer = rebuildFromPeerTimer.time()) {
        String syncToken = UUID.randomUUID().toString();
        logger.info("generateSnapshot with syncToken: {}", syncToken);

        // Register the "message received" event
        Future<Void> redisSyncComplete = this.pubSubConsumer.waitForSyncComplete(syncToken);

        // Publish the sync message
        PubSubMessage message = PubSubMessage.newBuilder()
                .setContent(ByteString.copyFrom(syncToken.getBytes(StandardCharsets.UTF_8)))
                .setType(PubSubMessage.Type.KEEPALIVE)
                .build();

        long publishResult = jedis.publish(CHANNEL.getBytes(), message.toByteArray());
        if (publishResult == -1) {
          logger.error("Failed to publish syncToken message");
          throw new DirectoryUnavailableException();
        }

        // wait for the sync message to be received
        try {
          redisSyncComplete.get(PUBSUB_SYNC_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
          throw new DirectoryUnavailableException();
        }
      }
      logger.info("writing directory out. size=" + directoryMap.size());
      directoryMap.write(stream);
    } finally {
      bootstrapping.set(false);
    }
  }

  public boolean reconcile(Optional<UUID> fromUuid, Optional<UUID> toUuid, List<Pair<UUID, String>> users)
      throws InvalidAddressException, DirectoryUnavailableException
  {
    if (!isReconciliationEnabled) {
      return true;
    }

    try (Jedis jedis = jedisPool.getResource()) {
      if (fromUuid.isPresent()) {
        Optional<UUID> lastUuidReconciled = directoryCache.getUuidLastReconciled(jedis);
        if (!lastUuidReconciled.isPresent() ||
            fromUuid.get().toString().compareTo(lastUuidReconciled.get().toString()) > 0) {
          logger.warn("reconciliation data was skipped; triggering reconciliation restart: " +
                      "got chunk " + fromUuid + " to " + toUuid + " expected " + lastUuidReconciled);
          return false;
        }
      }

      if (!fromUuid.isPresent() && !toUuid.isPresent()) {
        logger.warn("invalid reconciliation chunk with unbounded range; triggering reconciliation restart");
        return false;
      }

      List<Pair<UUID, String>> usersInRange;
      try (final Timer.Context context = reconcileGetUsersTimer.time()) {
        usersInRange = directoryCache.getUsersInRange(jedis, fromUuid, toUuid);
      }

      Set<Pair<UUID, String>>  removeUsers  = new HashSet<>(usersInRange);
      Set<Pair<UUID, String>>  addUsers     = new HashSet<>(users);

      removeUsers.removeAll(users);
      addUsers.removeAll(usersInRange);

      for (Pair<UUID, String> removeUser : removeUsers) {
        try {
          removeUser(jedis, removeUser.getLeft(), removeUser.getRight());
          reconcileRemovesMeter.mark();
        } catch (InvalidAddressException ex) {
          logger.error("invalid user " + removeUser);
        }
      }

      for (Pair<UUID, String> addUser : addUsers) {
        addUser(jedis, addUser.getLeft(), addUser.getRight());
        reconcileAddsMeter.mark();
      }

      directoryCache.setUuidLastReconciled(jedis, toUuid);

      return true;
    }
  }

  public void existsReconcile(List<Pair<UUID, String>> users)
      throws InvalidAddressException, DirectoryUnavailableException
  {
    try (Jedis jedis = jedisPool.getResource()) {
      Set<Pair<UUID, String>> newUsers = new HashSet<>(users);
      Set<Pair<UUID, String>> knownUsers;
      try (final Timer.Context timer = reconcileExistsUsersTimer.time()) {
        knownUsers = directoryCache.getKnownUsers(jedis, users);
      }

      newUsers.removeAll(knownUsers);
      for (Pair<UUID, String> newUser : newUsers) {
        addUser(jedis, newUser.getLeft(), newUser.getRight());
      }
      logReconcileSet(newUsers, "Exists Reconcile Adding");
    }
  }

  public void deletesReconcile(List<Pair<UUID, String>> users)
      throws InvalidAddressException, DirectoryUnavailableException
  {
    try (Jedis jedis = jedisPool.getResource()) {
      Set<Pair<UUID, String>> knownUsers;
      try (final Timer.Context timer = reconcileExistsUsersTimer.time()) {
        knownUsers = directoryCache.getKnownUsers(jedis, users);
      }

      for (Pair<UUID, String> knownUser : knownUsers) {
        removeUser(jedis, knownUser.getLeft(), knownUser.getRight());
      }
      logReconcileSet(knownUsers, "Delete Reconcile Removing");
    }
  }

  private void logReconcileSet(Set<Pair<UUID, String>> users, String prefix) {
    logger.info(prefix +": size={}", users.size());
  }

  public void markReconcileComplete() {
    try (Jedis jedis = jedisPool.getResource()) {
      directoryCache.markUserSetBuild(jedis);
    }
  }

  @FunctionalInterface
  public interface Borrow {
    void accept(DirectoryMapNative directoryMapNative) throws SgxException;
  }

  public void borrow(Borrow consumer) throws DirectoryUnavailableException, SgxException {
    if (!isBuilt()) {
      throw new DirectoryUnavailableException();
    }
    consumer.accept(getCurrentDirectoryMap());
  }

  @Override
  public void start() throws Exception {
    this.jedisPool        = redisFactory.getRedisClientPool();
    this.pubSubConnection = redisFactory.connect();
    this.pubSubConsumer   = new PubSubConsumer();
    this.keepAliveSender  = new KeepAliveSender();

    this.pubSubConnection.subscribe(CHANNEL);
    this.keepAliveSender.start();

    rebuildLocalData();

    this.pubSubConsumer.start();

    metricRegistry.gauge(REDIS_USER_COUNT_GAUGE_NAME, () -> () -> {
      try (Jedis jedis = jedisPool.getResource()) {
        return directoryCache.getUserCount(jedis);
      }
    });
  }

  @Override
  public void stop() throws Exception {
    keepAliveSender.shutdown();
    pubSubConsumer.shutdown();
    pubSubConnection.close();
  }

  private DirectoryMapNative getCurrentDirectoryMap() throws DirectoryUnavailableException {
    return currentDirectoryMap.get().orElseThrow(DirectoryUnavailableException::new);
  }

  private boolean isBuilt() {
    if (!built.get()) {
      try (Jedis jedis = jedisPool.getResource()) {
        if (directoryCache.isUserSetBuilt(jedis)) {
          built.set(true);
          logger.info("directory cache is now built");
        }
      }
    }

    return built.get();
  }

  private void addUser(Jedis jedis, UUID uuid, String address) throws InvalidAddressException, DirectoryUnavailableException {
    long directoryAddress = parseAddress(address);

    DirectoryMapNative directoryMap = getCurrentDirectoryMap();

    if (directoryCache.addUser(jedis, uuid, address)) {
      jedis.publish(CHANNEL.getBytes(),
                    PubSubMessage.newBuilder()
                                 .setContent(ByteString.copyFrom(DirectoryCache.encodeUser(uuid, address).getBytes()))
                                 .setType(PubSubMessage.Type.ADDED_USER)
                                 .build()
                                 .toByteArray());
    }

    directoryMap.insert(directoryAddress, uuid);
  }

  private void removeUser(Jedis jedis, UUID uuid, String address) throws InvalidAddressException, DirectoryUnavailableException {
    long directoryAddress = parseAddress(address);

    DirectoryMapNative directoryMap = getCurrentDirectoryMap();

    boolean removedUser = directoryCache.removeUser(jedis, uuid, address);

    if (removedUser) {
      jedis.publish(CHANNEL.getBytes(),
                    PubSubMessage.newBuilder()
                                 .setContent(ByteString.copyFrom(address.getBytes()))
                                 .setType(PubSubMessage.Type.REMOVED)
                                 .build()
                                 .toByteArray());
    }

    directoryMap.remove(directoryAddress);
  }

  private void rebuildLocalData() {
    if (directoryPeerManager.loadFromPeer()) {
      try {
        logger.info("building from peer service");
        directoryPeerManager.startPeerLoadAttempt();
        rebuildLocalDataFromPeer();
        directoryPeerManager.markPeerLoadSuccessful();
      } catch (Exception e) {
        logger.warn("peer build failed with error=" + e);
        Util.sleep(directoryPeerManager.getBackoffTime().toMillis());
        rebuildLocalData();
      }
    } else {
      logger.info("building from redis");
      rebuildLocalDataFromRedis();
    }
  }

  private void rebuildLocalDataFromPeer() throws Exception {
    try (Timer.Context timer = rebuildFromPeerTimer.time()) {
      String fullUrl = String.format("%s/v1/snapshot/", directoryPeerManager.getPeerBuildRequestUrl());
      HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .version(HttpClient.Version.HTTP_1_1)
                .build();
      HttpRequest request = HttpRequest.newBuilder()
              .GET()
              .uri(URI.create(fullUrl))
              // 10 minutes is very long, but we just want something non-infinite
              .timeout(Duration.ofMinutes(10))
              .header("Authorization", directoryPeerManager.getAuthHeader())
              .build();
      HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
      if (response.statusCode() == 503) {
        throw new IOException("map node is busy trying again");
      } else if (response.statusCode() != 200) {
        throw new IOException(String.format("unexpected peer build response code: %d  %s", response.statusCode(), response.toString()));
      };
      long startTime = timer.stop();

      final Optional<DirectoryMapNative> optionalDirectoryMap = currentDirectoryMap.get();
      final DirectoryMapNative directoryMap = optionalDirectoryMap.orElseGet(() -> directoryMapFactory.create(0));
      directoryMap.read(response.body());
      directoryMap.commit();
      if (optionalDirectoryMap.isEmpty()) {
        currentDirectoryMap.compareAndSet(optionalDirectoryMap, Optional.of(directoryMap));
      }
      long elapsedReadTime = timer.stop() - startTime;
      logger.info("finished directory build from peer, users=" + directoryMap.size()
              + " elapsed time=" + Duration.ofNanos(elapsedReadTime).toMillis());
      built.set(true);
    }
  }

  private void rebuildLocalDataFromRedis() {
    try (Jedis         jedis = jedisPool.getResource();
         Timer.Context timer = rebuildLocalDataTimer.time()) {
      boolean userSetBuilt    = directoryCache.isUserSetBuilt(jedis);
      built.set(userSetBuilt);

      final long directorySize;
      if (userSetBuilt) {
        directorySize = directoryCache.getUserCount(jedis);
        var directoryMap = directoryMapFactory.create(directorySize);

        logger.warn("starting directory cache rebuild of " + directorySize + " users, built=" + userSetBuilt);

        rebuildLocalUsersFromRedis(jedis, directoryMap);
        directoryMap.commit();
        this.currentDirectoryMap.set(Optional.of(directoryMap));
        logger.info("finished directory cache rebuild");
      } else {
        logger.info("finished directory cache rebuild (but the user zset wasn't built, yet)");
      }
    }
  }

  private void rebuildLocalUsersFromRedis(Jedis jedis, DirectoryMapNative directoryMap) {
    String cursor = "0";
    do {
      ScanResult<Pair<UUID, String>> result;
      try (Timer.Context timer = getAllUsersTimer.time()) {
        result = directoryCache.getAllUsers(jedis, cursor, SCAN_CHUNK_SIZE);
      }
      cursor = result.getStringCursor();

      for (Pair<UUID, String> user : result.getResult()) {
        if (user.getRight() == null) {
          // Somehow a user without a UUID got this far. Dropping it;
          rebuildLocalDataNullUUID.inc();
          logger.error("rebuildLocalUsers somehow got a null user UUID when those should no longer exist in any Signal system");
          continue;
        }
        try {
          long directoryAddress = parseAddress(user.getRight());
          directoryMap.insert(directoryAddress, user.getLeft());
        } catch (InvalidAddressException e) {
          logger.warn("Invalid address for user: " + user, e);
        }
      }
    } while (!cursor.equals("0"));
  }

  private long parseAddress(String address) throws InvalidAddressException {
    try {
      return Long.parseLong(address.replaceAll("[^\\d.]", ""));
    } catch (NumberFormatException e) {
      throw new InvalidAddressException(address);
    }
  }

  private class PubSubConsumer extends Thread {

    private AtomicBoolean running = new AtomicBoolean(true);

    private Dictionary<String, List<CompletableFuture<Void>>> syncTokens = new Hashtable<>();

    @Override
    public void run() {
      while (running.get()) {
        try {
          PubSubReply reply = pubSubConnection.read();

          switch (reply.getType()) {
            case SUBSCRIBE:   break;
            case UNSUBSCRIBE: break;
            case MESSAGE:     processMessage(reply);
          }
        } catch (Throwable t) {
          logger.warn("PubSub error", t);
          pubSubConnection.close();

          connect();
        }
      }
    }

    private void connect() {
      while (running.get()) {
        pubSubConnection = redisFactory.connect();

        try {
          pubSubConnection.subscribe(CHANNEL);
          rebuildLocalData();
          return;
        } catch (Throwable t) {
          logger.warn("directory cache rebuild error", t);
          pubSubConnection.close();
          Util.sleep(30_000L);
        }
      }
    }

    public void shutdown() {
      running.set(false);
    }

    private void processMessage(PubSubReply message) throws DirectoryUnavailableException {
      try {
        if (message.getContent().isPresent()) {
          PubSubMessage update = PubSubMessage.parseFrom(message.getContent().get());

          if (update.getType() == PubSubMessage.Type.ADDED) {
            // No longer supported.
            logger.error("Obsolete PubSubMessage type ADDED sent over SQS from the Signal Service. Should no longer be sent now that all users have UUID an use ADDED_USER instead.");
            obsoluteTypeAdded.inc();
          } else if (update.getType() == PubSubMessage.Type.ADDED_USER) {
            Pair<UUID, String> addedUser;
            try {
              addedUser = DirectoryCache.decodeUser(new String(update.getContent().toByteArray()));
            } catch (Exception ex) {
              logger.warn("Badly formatted user", ex);
              return;
            }
            getCurrentDirectoryMap().insert(parseAddress(addedUser.getRight()), addedUser.getLeft());
          } else if (update.getType() == PubSubMessage.Type.REMOVED) {
            getCurrentDirectoryMap().remove(parseAddress(new String(update.getContent().toByteArray())));
          } else if (update.getType() == PubSubMessage.Type.KEEPALIVE) {
            if (update.getContent() != null) {
              try {
                String syncToken = new String(update.getContent().toByteArray(), StandardCharsets.UTF_8);
                synchronized (syncTokens) {
                  List<CompletableFuture<Void>> waiters = syncTokens.get(syncToken);
                  syncTokens.remove(syncToken);
                  if (waiters != null) {
                    logger.info("Sync token received - notifying waiter threads");
                    for (CompletableFuture<Void> waiter : waiters) {
                      waiter.complete(null);
                    }
                  }
                }
              } catch (Exception ex) {
                logger.warn("Bad KeepAlive content", ex);
                return;
              }
            }
          }
        }
      } catch (InvalidProtocolBufferException e) {
        logger.warn("Bad protobuf!", e);
      } catch (InvalidAddressException e) {
        logger.warn("Badly formatted address", e);
      }
    }

    public Future<Void> waitForSyncComplete(String syncToken) {
      synchronized (syncTokens) {
        List<CompletableFuture<Void>> tokenWaiters = syncTokens.get(syncToken);
        if (tokenWaiters == null) {
          tokenWaiters = new ArrayList<>();
          syncTokens.put(syncToken, tokenWaiters);
        }

        CompletableFuture<Void> future = new CompletableFuture<>();
        tokenWaiters.add(future);
        return future;
      }
    }
  }

  private class KeepAliveSender extends Thread {

    private final AtomicBoolean running = new AtomicBoolean(true);

    @Override
    public void run() {
      while (running.get()) {
        PubSubMessage message = PubSubMessage.newBuilder()
                                             .setContent(ByteString.copyFrom("keep alive".getBytes()))
                                             .setType(PubSubMessage.Type.KEEPALIVE)
                                             .build();

        if (!publish(CHANNEL, message)) {
          logger.warn("Nobody subscribed to keepalive!");
        }

        Util.sleep(30000);
      }
    }

    public void shutdown() {
      running.set(false);
    }

    private boolean publish(String channel, PubSubMessage message) {
      try (Jedis jedis = jedisPool.getResource()) {
        long result = jedis.publish(channel.getBytes(), message.toByteArray());

        if (result < 0) {
          logger.warn("**** Jedis publish result < 0");
        }

        return result > 0;
      }
    }
  }

}
