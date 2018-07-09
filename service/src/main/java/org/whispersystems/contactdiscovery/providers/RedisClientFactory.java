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
package org.whispersystems.contactdiscovery.providers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.configuration.RedisConfiguration;
import org.whispersystems.dispatch.io.RedisPubSubConnectionFactory;
import org.whispersystems.dispatch.redis.PubSubConnection;
import org.whispersystems.dispatch.util.Util;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashSet;
import java.util.Set;

import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.JedisSentinelPool;
import redis.clients.jedis.Protocol;
import redis.clients.util.Pool;

public class RedisClientFactory implements RedisPubSubConnectionFactory {

  private final Logger logger = LoggerFactory.getLogger(RedisClientFactory.class);

  private final JedisSentinelPool jedisPool;

  public RedisClientFactory(RedisConfiguration redisConfig) throws URISyntaxException {
    JedisPoolConfig poolConfig = new JedisPoolConfig();
    poolConfig.setTestOnBorrow(true);

    String      masterName = redisConfig.getMasterName();
    Set<String> sentinels  = new LinkedHashSet(redisConfig.getSentinelUrls());

    this.jedisPool = new JedisSentinelPool(masterName, sentinels, poolConfig,
                                           Protocol.DEFAULT_TIMEOUT, null);
  }

  public Pool<Jedis> getRedisClientPool() {
    return jedisPool;
  }

  @Override
  public PubSubConnection connect() {
    while (true) {
      try {
        HostAndPort hostAndPort = jedisPool.getCurrentHostMaster();
        Socket socket = new Socket(hostAndPort.getHost(), hostAndPort.getPort());
        return new PubSubConnection(socket);
      } catch (IOException e) {
        logger.warn("Error connecting", e);
        Util.sleep(200);
      }
    }
  }
}
