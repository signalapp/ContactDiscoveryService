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
import org.whispersystems.contactdiscovery.providers.RedisClientFactory;
import org.whispersystems.contactdiscovery.util.Constants;
import org.whispersystems.contactdiscovery.util.Util;
import org.whispersystems.dispatch.redis.PubSubConnection;
import org.whispersystems.dispatch.redis.PubSubReply;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.ScanResult;
import redis.clients.jedis.Tuple;
import redis.clients.util.Pool;

import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Manages the system directory of all registered users
 *
 * @author Moxie Marlinspike
 */
public class DirectoryManager implements Managed {

  private final Logger logger = LoggerFactory.getLogger(RedisClientFactory.class);

  private static final MetricRegistry metricRegistry        = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Meter          reconcileAddsMeter    = metricRegistry.meter(name(DirectoryManager.class, "reconcileAdds"));
  private static final Meter          reconcileRemovesMeter = metricRegistry.meter(name(DirectoryManager.class, "reconcileRemoves"));
  private static final Timer          addUserTimer          = metricRegistry.timer(name(DirectoryManager.class, "addUser"));
  private static final Timer          removeUserTimer       = metricRegistry.timer(name(DirectoryManager.class, "removeUser"));
  private static final Timer          getAllAddressesTimer  = metricRegistry.timer(name(DirectoryManager.class, "getAllAddresses"));
  private static final Timer          getAllUsersTimer      = metricRegistry.timer(name(DirectoryManager.class, "getAllUsers"));
  private static final Timer          rebuildLocalDataTimer = metricRegistry.timer(name(DirectoryManager.class, "rebuildLocalData"));

  private static final String CHANNEL = "signal_address_update";

  private static final int SCAN_CHUNK_SIZE = 5_000;

  private final RedisClientFactory      redisFactory;
  private final DirectoryHashSetFactory directoryHashSetFactory;

  private final AtomicBoolean built = new AtomicBoolean(false);

  private final AtomicReference<Optional<DirectoryHashSet>> currentDirectoryHashSet = new AtomicReference(Optional.empty());

  private Pool<Jedis>      jedisPool;
  private DirectoryCache   directoryCache;
  private PubSubConnection pubSubConnection;
  private PubSubConsumer   pubSubConsumer;
  private KeepAliveSender  keepAliveSender;

  public DirectoryManager(RedisClientFactory redisFactory, DirectoryCache directoryCache, DirectoryHashSetFactory directoryHashSetFactory) {
    this.redisFactory            = redisFactory;
    this.directoryCache          = directoryCache;
    this.directoryHashSetFactory = directoryHashSetFactory;
  }

  public boolean isConnected() {
    return currentDirectoryHashSet.get().isPresent();
  }

  public void addUser(Optional<UUID> uuid, String address) throws InvalidAddressException, DirectoryUnavailableException {
    try (Jedis         jedis = jedisPool.getResource();
         Timer.Context timer = addUserTimer.time()) {
      addUser(jedis, uuid, address);
    }
  }

  public void removeUser(Optional<UUID> uuid, String address) throws InvalidAddressException, DirectoryUnavailableException {
    try (Jedis jedis         = jedisPool.getResource();
         Timer.Context timer = removeUserTimer.time()) {
      removeUser(jedis, uuid, address);
    }
  }

  public boolean reconcile(Optional<UUID> fromUuid, Optional<UUID> toUuid, List<Pair<UUID, String>> users)
      throws InvalidAddressException, DirectoryUnavailableException
  {
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

      List<Pair<UUID, String>> usersInRange = directoryCache.getUsersInRange(jedis, fromUuid, toUuid);
      Set<Pair<UUID, String>>  removeUsers  = new HashSet<>(usersInRange);
      Set<Pair<UUID, String>>  addUsers     = new HashSet<>(users);

      removeUsers.removeAll(users);
      addUsers.removeAll(usersInRange);

      for (Pair<UUID, String> removeUser : removeUsers) {
        try {
          removeUser(jedis, Optional.of(removeUser.getLeft()), removeUser.getRight());
          reconcileRemovesMeter.mark();
        } catch (InvalidAddressException ex) {
          logger.error("invalid user " + removeUser);
        }
      }

      for (Pair<UUID, String> addUser : addUsers) {
        addUser(jedis, Optional.of(addUser.getLeft()), addUser.getRight());
        reconcileAddsMeter.mark();
      }

      directoryCache.setUuidLastReconciled(jedis, toUuid);

      return true;
    }
  }

  public Pair<Pair<ByteBuffer, ByteBuffer>, Long> getAddressList() throws DirectoryUnavailableException {
    if (!isBuilt()) {
      throw new DirectoryUnavailableException();
    }
    DirectoryHashSet directoryHashSet = getCurrentDirectoryHashSet();
    return Pair.of(directoryHashSet.getDirectByteBuffers(), directoryHashSet.capacity());
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
  }

  @Override
  public void stop() throws Exception {
    keepAliveSender.shutdown();
    pubSubConsumer.shutdown();
    pubSubConnection.close();
  }

  private DirectoryHashSet getCurrentDirectoryHashSet() throws DirectoryUnavailableException {
    return currentDirectoryHashSet.get().orElseThrow(DirectoryUnavailableException::new);
  }

  private boolean isBuilt() {
    if (!built.get()) {
      try (Jedis jedis = jedisPool.getResource()) {
        if (directoryCache.isAddressSetBuilt(jedis)) {
          built.set(true);
          logger.info("directory cache is now built");
        }
      }
    }

    return built.get();
  }

  private void addUser(Jedis jedis, Optional<UUID> uuid, String address) throws InvalidAddressException, DirectoryUnavailableException {
    long directoryAddress = parseAddress(address);

    DirectoryHashSet directoryHashSet = getCurrentDirectoryHashSet();

    if (uuid.isPresent()) {
      if (directoryCache.addUser(jedis, uuid.get(), address)) {
        jedis.publish(CHANNEL.getBytes(),
                      PubSubMessage.newBuilder()
                                   .setContent(ByteString.copyFrom(DirectoryCache.encodeUser(uuid.get(), address).getBytes()))
                                   .setType(PubSubMessage.Type.ADDED_USER)
                                   .build()
                                   .toByteArray());
      }
    } else {
      if (directoryCache.addAddress(jedis, address)) {
        jedis.publish(CHANNEL.getBytes(),
                      PubSubMessage.newBuilder()
                                   .setContent(ByteString.copyFrom(address.getBytes()))
                                   .setType(PubSubMessage.Type.ADDED)
                                   .build()
                                   .toByteArray());
      }
    }

    directoryHashSet.insert(directoryAddress, uuid.orElse(null));
  }

  private void removeUser(Jedis jedis, Optional<UUID> uuid, String address) throws InvalidAddressException, DirectoryUnavailableException {
    long directoryAddress = parseAddress(address);

    DirectoryHashSet directoryHashSet = getCurrentDirectoryHashSet();

    boolean removedUser;
    if (uuid.isPresent()) {
      removedUser = directoryCache.removeUser(jedis, uuid.get(), address);
    } else {
      removedUser = directoryCache.removeAddress(jedis, address);
    }

    if (removedUser) {
      jedis.publish(CHANNEL.getBytes(),
                    PubSubMessage.newBuilder()
                                 .setContent(ByteString.copyFrom(address.getBytes()))
                                 .setType(PubSubMessage.Type.REMOVED)
                                 .build()
                                 .toByteArray());
    }

    directoryHashSet.remove(directoryAddress);
  }

  private void rebuildLocalData() {
    try (Jedis         jedis = jedisPool.getResource();
         Timer.Context timer = rebuildLocalDataTimer.time()) {
      boolean userSetBuilt    = directoryCache.isUserSetBuilt(jedis);
      boolean addressSetBuilt = directoryCache.isAddressSetBuilt(jedis);
      built.set(userSetBuilt || addressSetBuilt);

      final long             directorySize;
      final DirectoryHashSet directoryHashSet;
      if (!userSetBuilt && addressSetBuilt) {
        directorySize    = directoryCache.getAddressCount(jedis);
        directoryHashSet = directoryHashSetFactory.createDirectoryHashSet(directorySize);

        logger.warn("starting directory cache rebuild of " + directorySize + " addresses, built=" + addressSetBuilt);

        rebuildLocalAddresses(jedis, directoryHashSet);
      } else {
        directorySize    = directoryCache.getUserCount(jedis);
        directoryHashSet = directoryHashSetFactory.createDirectoryHashSet(directorySize);

        logger.warn("starting directory cache rebuild of " + directorySize + " users, built=" + userSetBuilt);

        rebuildLocalUsers(jedis, directoryHashSet);
      }

      logger.info("finished directory cache rebuild");

      this.currentDirectoryHashSet.set(Optional.of(directoryHashSet));
    }
  }

  private void rebuildLocalAddresses(Jedis jedis, DirectoryHashSet directoryHashSet) {
    String cursor = "0";
    do {
      ScanResult<Tuple> result;
      try (Timer.Context timer = getAllAddressesTimer.time()) {
        result = directoryCache.getAllAddresses(jedis, cursor, SCAN_CHUNK_SIZE);
      }
      cursor = result.getStringCursor();

      for (Tuple tuple : result.getResult()) {
        String address = tuple.getElement();
        try {
          long directoryAddress = parseAddress(address);
          directoryHashSet.insert(directoryAddress, null);
        } catch (InvalidAddressException e) {
          logger.warn("Invalid address: " + address, e);
        }
      }
    } while (!cursor.equals("0"));
  }

  private void rebuildLocalUsers(Jedis jedis, DirectoryHashSet directoryHashSet) {
    String cursor = "0";
    do {
      ScanResult<Pair<UUID, String>> result;
      try (Timer.Context timer = getAllUsersTimer.time()) {
        result = directoryCache.getAllUsers(jedis, cursor, SCAN_CHUNK_SIZE);
      }
      cursor = result.getStringCursor();

      for (Pair<UUID, String> user : result.getResult()) {
        try {
          long directoryAddress = parseAddress(user.getRight());
          directoryHashSet.insert(directoryAddress, user.getLeft());
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
          currentDirectoryHashSet.set(Optional.empty());

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
            getCurrentDirectoryHashSet().insert(parseAddress(new String(update.getContent().toByteArray())), null);
          } else if (update.getType() == PubSubMessage.Type.ADDED_USER) {
            Pair<UUID, String> addedUser;
            try {
              addedUser = DirectoryCache.decodeUser(new String(update.getContent().toByteArray()));
            } catch (Exception ex) {
              logger.warn("Badly formatted user", ex);
              return;
            }
            getCurrentDirectoryHashSet().insert(parseAddress(addedUser.getRight()), addedUser.getLeft());
          } else if (update.getType() == PubSubMessage.Type.REMOVED) {
            getCurrentDirectoryHashSet().remove(parseAddress(new String(update.getContent().toByteArray())));
          }
        }
      } catch (InvalidProtocolBufferException e) {
        logger.warn("Bad protobuf!", e);
      } catch (InvalidAddressException e) {
        logger.warn("Badly formatted address", e);
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
