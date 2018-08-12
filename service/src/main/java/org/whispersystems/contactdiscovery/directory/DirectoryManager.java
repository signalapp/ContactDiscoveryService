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
import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.directory.DirectoryProtos.PubSubMessage;
import org.whispersystems.contactdiscovery.providers.RedisClientFactory;
import org.whispersystems.contactdiscovery.redis.LuaScript;
import org.whispersystems.contactdiscovery.util.Constants;
import org.whispersystems.dispatch.redis.PubSubConnection;
import org.whispersystems.dispatch.redis.PubSubReply;
import org.whispersystems.dispatch.util.Util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import io.dropwizard.lifecycle.Managed;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.ScanResult;
import redis.clients.jedis.Tuple;
import redis.clients.util.Pool;

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

  private static final String CHANNEL     = "signal_address_update";
  private static final String ADDRESS_SET = "signal_addresses_sorted::1";

  private final ExecutorService rebuildExecutor = Executors.newSingleThreadExecutor();

  private final RedisClientFactory redisFactory;
  private final DirectoryHashSet   directory;

  private Pool<Jedis>      jedisPool;
  private PubSubConnection pubSubConnection;
  private PubSubConsumer   pubSubConsumer;
  private KeepAliveSender  keepAliveSender;

  public DirectoryManager(RedisClientFactory redisFactory, long initialCapacity, float loadFactor) {
    this.redisFactory = redisFactory;
    this.directory    = new DirectoryHashSet(initialCapacity, loadFactor);
  }

  @VisibleForTesting
  public DirectoryManager(RedisClientFactory redisFactory, DirectoryHashSet directory) {
    this.redisFactory = redisFactory;
    this.directory    = directory;
  }

  public void addAddress(String address) throws InvalidAddressException {
    long directoryAddress = parseAddress(address);

    try (Jedis jedis = jedisPool.getResource()) {
      if (1L == jedis.zadd(ADDRESS_SET, 0, address)) {
        jedis.publish(CHANNEL.getBytes(),
                      PubSubMessage.newBuilder()
                                   .setContent(ByteString.copyFrom(address.getBytes()))
                                   .setType(PubSubMessage.Type.ADDED)
                                   .build()
                                   .toByteArray());
      }
    }

    directory.add(directoryAddress);
  }

  public void removeAddress(String address) throws InvalidAddressException {
    long directoryAddress = parseAddress(address);

    try (Jedis jedis = jedisPool.getResource()) {
      if (1L == jedis.zrem(ADDRESS_SET, address)) {
        jedis.publish(CHANNEL.getBytes(),
                      PubSubMessage.newBuilder()
                                   .setContent(ByteString.copyFrom(address.getBytes()))
                                   .setType(PubSubMessage.Type.REMOVED)
                                   .build()
                                   .toByteArray());
      }
    }

    directory.remove(directoryAddress);
  }

  public void reconcile(Optional<String> fromNumber, Optional<String> toNumber, List<String> addresses)
      throws InvalidAddressException
  {
    List<String> newAddresses = Optional.ofNullable(addresses).orElse(Collections.emptyList());
    Set<String>  oldAddresses = getAddressesInRange(fromNumber, toNumber);

    oldAddresses.removeAll(newAddresses);

    for (String oldAddress : oldAddresses) {
      try {
        removeAddress(oldAddress);
      } catch (InvalidAddressException ex) {
        logger.error("invalid address: ", oldAddress);
      }
    }

    for (String newAddress : newAddresses) {
      addAddress(newAddress);
    }
  }

  private Set<String> getAddressesInRange(Optional<String> fromNumber, Optional<String> toNumber) {
    try (Jedis jedis = jedisPool.getResource()) {
      String lowerBound = fromNumber.map(number -> "(" + number).orElse("-");
      String upperBound = toNumber.map(number -> "[" + number).orElse("+");
      return jedis.zrangeByLex(ADDRESS_SET, lowerBound, upperBound);
    }
  }

  public Pair<ByteBuffer, Long> getAddressList() {
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

  private void rebuildLocalData() {
    try (Jedis jedis = jedisPool.getResource()) {
      String cursor = "0";
      do {
        ScanResult<Tuple> result = jedis.zscan(ADDRESS_SET, cursor);
        cursor = result.getStringCursor();

        for (Tuple tuple : result.getResult()) {
          String address = tuple.getElement();
          try {
            this.directory.add(parseAddress(address));
          } catch (InvalidAddressException e) {
            logger.warn("Invalid address: " + address, e);
          }
        }
      } while (!cursor.equals("0"));
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
        try {
          PubSubReply reply = pubSubConnection.read();

          switch (reply.getType()) {
            case SUBSCRIBE:   break;
            case UNSUBSCRIBE: break;
            case MESSAGE:     processMessage(reply);
          }
        } catch (IOException e) {
          logger.warn("PubSub error", e);
          pubSubConnection.close();

          if (running.get()) {
            pubSubConnection = redisFactory.connect();
            rebuildExecutor.submit(DirectoryManager.this::rebuildLocalData);
          }
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
            directory.add(parseAddress(new String(update.getContent().toByteArray())));
          } else if (update.getType() == PubSubMessage.Type.REMOVED) {
            directory.remove(parseAddress(new String(update.getContent().toByteArray())));
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
