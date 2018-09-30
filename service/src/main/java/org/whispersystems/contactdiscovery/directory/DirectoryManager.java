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
import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.dropwizard.lifecycle.Managed;
import org.apache.commons.lang3.tuple.ImmutablePair;
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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Manages the system directory of all registered users
 *
 * @author Moxie Marlinspike
 */
public class DirectoryManager implements Managed {

  private final Logger logger = LoggerFactory.getLogger(RedisClientFactory.class);

  private static final MetricRegistry metricRegistry         = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Meter          reconciledNumbersMeter = metricRegistry.meter(name(DirectoryManager.class, "reconciledNumbers"));
  private static final Timer          getAllAddressesTimer   = metricRegistry.timer(name(DirectoryManager.class, "getAllAddresses"));
  private static final Timer          rebuildLocalDataTimer  = metricRegistry.timer(name(DirectoryManager.class, "rebuildLocalData"));

  private static final String CHANNEL = "signal_address_update";

  private static final int SCAN_CHUNK_SIZE = 5_000;

  private final RedisClientFactory redisFactory;
  private final DirectoryHashSets  directories;

  private final AtomicBoolean connected = new AtomicBoolean(false);
  private final AtomicBoolean built     = new AtomicBoolean(false);

  private Pool<Jedis>      jedisPool;
  private DirectoryCache   directoryCache;
  private PubSubConnection pubSubConnection;
  private PubSubConsumer   pubSubConsumer;
  private KeepAliveSender  keepAliveSender;

  public DirectoryManager(RedisClientFactory redisFactory, long initialCapacity, float loadFactor) {
    this.redisFactory   = redisFactory;
    this.directoryCache = new DirectoryCache();
    this.directories    = new DirectoryHashSets(new DirectoryHashSet(initialCapacity, loadFactor));
  }

  @VisibleForTesting
  public DirectoryManager(RedisClientFactory redisFactory, DirectoryCache directoryCache, DirectoryHashSet directory) {
    this.redisFactory   = redisFactory;
    this.directoryCache = directoryCache;
    this.directories    = new DirectoryHashSets(directory);
  }

  public boolean isReady() {
    return connected.get() && built.get();
  }

  public void addAddress(String address) throws InvalidAddressException {
    try (Jedis jedis = jedisPool.getResource()) {
      addAddress(jedis, address);
    }
  }

  public void removeAddress(String address) throws InvalidAddressException {
    try (Jedis jedis = jedisPool.getResource()) {
      removeAddress(jedis, address);
    }
  }

  public boolean reconcile(Optional<String> fromNumber, Optional<String> toNumber, List<String> addresses)
      throws InvalidAddressException
  {
    try (Jedis jedis = jedisPool.getResource()) {
      addresses = Optional.ofNullable(addresses).orElse(Collections.emptyList());

      if (fromNumber.isPresent()) {
        Optional<String> lastNumberReconciled = directoryCache.getAddressLastReconciled(jedis);
        if (!lastNumberReconciled.isPresent() ||
            fromNumber.get().compareTo(lastNumberReconciled.get()) > 0) {
          logger.warn("reconciliation data was skipped; triggering reconciliation restart");
          return false;
        }
      }

      Set<String> removeAddresses = directoryCache.getAddressesInRange(jedis, fromNumber, toNumber);
      Set<String> addAddresses    = new HashSet<>(addresses);

      addAddresses.removeAll(removeAddresses);
      removeAddresses.removeAll(addresses);

      for (String removeAddress : removeAddresses) {
        try {
          removeAddress(jedis, removeAddress);
          reconciledNumbersMeter.mark();
        } catch (InvalidAddressException ex) {
          logger.error("invalid address: ", removeAddress);
        }
      }

      for (String addAddress : addAddresses) {
        addAddress(jedis, addAddress);
        reconciledNumbersMeter.mark();
      }

      directoryCache.setAddressLastReconciled(jedis, toNumber);

      if (!toNumber.isPresent()) {
        built.set(true);
      }

      return true;
    }
  }

  public Pair<ByteBuffer, Long> getAddressList() {
    DirectoryHashSet directory = directories.getDirectory();
    return new ImmutablePair<>(directory.getDirectByteBuffer(), directory.capacity());
  }

  @Override
  public void start() throws Exception {
    this.jedisPool        = redisFactory.getRedisClientPool();
    this.pubSubConnection = redisFactory.connect();
    this.pubSubConsumer   = new PubSubConsumer();
    this.keepAliveSender  = new KeepAliveSender();

    this.pubSubConnection.subscribe(CHANNEL);
    this.pubSubConsumer.start();
    this.keepAliveSender.start();

    rebuildLocalData();
  }

  @Override
  public void stop() throws Exception {
    keepAliveSender.shutdown();
    pubSubConsumer.shutdown();
    pubSubConnection.close();
  }

  private void addAddress(Jedis jedis, String address) throws InvalidAddressException {
    long directoryAddress = parseAddress(address);

    if (directoryCache.addAddress(jedis, address)) {
      jedis.publish(CHANNEL.getBytes(),
                    PubSubMessage.newBuilder()
                                 .setContent(ByteString.copyFrom(address.getBytes()))
                                 .setType(PubSubMessage.Type.ADDED)
                                 .build()
                                 .toByteArray());
    }

    directories.getDirectories().forEach(directory -> directory.add(directoryAddress));
  }

  private void removeAddress(Jedis jedis, String address) throws InvalidAddressException {
    long directoryAddress = parseAddress(address);

    if (directoryCache.removeAddress(jedis, address)) {
      jedis.publish(CHANNEL.getBytes(),
                    PubSubMessage.newBuilder()
                                 .setContent(ByteString.copyFrom(address.getBytes()))
                                 .setType(PubSubMessage.Type.REMOVED)
                                 .build()
                                 .toByteArray());
    }

    directories.getDirectories().forEach(directory -> directory.remove(directoryAddress));
  }

  private void rebuildLocalData() {
    try (Jedis         jedis = jedisPool.getResource();
         Timer.Context timer = rebuildLocalDataTimer.time()) {
      built.set(directoryCache.isDirectoryBuilt(jedis));

      logger.warn("starting directory cache rebuild, built=" + built.get());

      String cursor = "0";
      do {
        ScanResult<Tuple> result;
        try (Timer.Context getAllAddressesTimer = this.getAllAddressesTimer.time()) {
          result = directoryCache.getAllAddresses(jedis, cursor, SCAN_CHUNK_SIZE);
        }
        cursor = result.getStringCursor();

        for (Tuple tuple : result.getResult()) {
          String address = tuple.getElement();
          try {
            long directoryAddress = parseAddress(address);
            directories.getDirectories().forEach(directory -> directory.add(directoryAddress));
          } catch (InvalidAddressException e) {
            logger.warn("Invalid address: " + address, e);
          }
        }
      } while (!cursor.equals("0"));

      logger.info("finished directory cache rebuild");
    }
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
        connected.set(true);
        try {
          PubSubReply reply = pubSubConnection.read();

          switch (reply.getType()) {
            case SUBSCRIBE:   break;
            case UNSUBSCRIBE: break;
            case MESSAGE:     processMessage(reply);
          }
        } catch (IOException e) {
          connected.set(false);
          logger.warn("PubSub error", e);
          pubSubConnection.close();

          connect();
        }
      }
    }

    private void connect() {
      while (running.get()) {
        pubSubConnection = redisFactory.connect();

        try {
          directories.createNewDirectory();
          rebuildLocalData();
          directories.setDirectory();
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

    private void processMessage(PubSubReply message) {
      try {
        if (message.getContent().isPresent()) {
          PubSubMessage update = PubSubMessage.parseFrom(message.getContent().get());

          if (update.getType() == PubSubMessage.Type.ADDED) {
            directories.getDirectory().add(parseAddress(new String(update.getContent().toByteArray())));
          } else if (update.getType() == PubSubMessage.Type.REMOVED) {
            directories.getDirectory().remove(parseAddress(new String(update.getContent().toByteArray())));
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

  private static class DirectoryHashSets {

    private DirectoryHashSet           currentDirectory;
    private Optional<DirectoryHashSet> newDirectory;

    public DirectoryHashSets(DirectoryHashSet directory) {
      this.currentDirectory = directory;
      this.newDirectory = Optional.empty();
    }

    public synchronized void createNewDirectory() {
      newDirectory = Optional.of(new DirectoryHashSet(currentDirectory.capacity(), currentDirectory.getLoadFactor()));
    }

    public synchronized DirectoryHashSet getDirectory() {
      return currentDirectory;
    }

    public synchronized Stream<DirectoryHashSet> getDirectories() {
      return Stream.concat(Stream.of(currentDirectory), newDirectory.map(Stream::of).orElse(Stream.empty()));
    }

    public synchronized void setDirectory() {
      if (newDirectory.isPresent()) {
        currentDirectory = newDirectory.get();
        newDirectory = Optional.empty();
      }
    }

  }

}
