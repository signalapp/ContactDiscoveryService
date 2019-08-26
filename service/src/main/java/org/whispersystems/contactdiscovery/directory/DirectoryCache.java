/*
 * Copyright (C) 2018 Open Whisper Systems
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

import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.ScanParams;
import redis.clients.jedis.ScanResult;
import redis.clients.jedis.Tuple;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public class DirectoryCache {

  private final Logger logger = LoggerFactory.getLogger(DirectoryCache.class);

  private static final String ADDRESS_SET             = "signal_addresses_sorted::1";
  private static final String ADDRESS_SET_BUILT       = "signal_addresses_built";
  private static final String USER_SET                = "signal_users_sorted::1";
  private static final String USER_SET_BUILT          = "signal_users_built";
  private static final String USER_LAST_RECONCILED    = "signal_users_last_reconciled";

  private static final char USER_SEPARATOR          = ':';
  private static final char USER_SEPARATOR_PLUS_ONE = USER_SEPARATOR + 1;


  public boolean isAddressSetBuilt(Jedis jedis) {
    return jedis.exists(ADDRESS_SET_BUILT);
  }

  public boolean isUserSetBuilt(Jedis jedis) {
    return jedis.exists(USER_SET_BUILT);
  }

  public ScanResult<Tuple> getAllAddresses(Jedis jedis, String cursor, int count) {
    ScanParams scanParams = new ScanParams().count(count);
    return jedis.zscan(ADDRESS_SET, cursor, scanParams);
  }

  public ScanResult<Pair<UUID, String>> getAllUsers(Jedis jedis, String cursor, int count) {
    ScanParams        scanParams = new ScanParams().count(count);
    ScanResult<Tuple> scanResult = jedis.zscan(USER_SET, cursor, scanParams);

    List<Pair<UUID, String>> users = new ArrayList<>(scanResult.getResult().size());
    for (Tuple tuple : scanResult.getResult()) {
      try {
        users.add(decodeUser(tuple.getElement()));
      } catch (Exception ex) {
        logger.error("invalid user: " + tuple.getElement(), ex);
      }
    }
    return new ScanResult<>(scanResult.getCursorAsBytes(), users);
  }

  public List<Pair<UUID, String>> getUsersInRange(Jedis jedis, Optional<UUID> fromUuid, Optional<UUID> toUuid) {
    String lowerBound = fromUuid.map(uuid -> "(" + uuidBoundAfter(uuid)).orElse("-");
    String upperBound = toUuid.map(uuid -> "(" + uuidBoundAfter(uuid)).orElse("+");

    Set<String> encodedUsers = jedis.zrangeByLex(USER_SET, lowerBound, upperBound);

    List<Pair<UUID, String>> users = new ArrayList<>(encodedUsers.size());

    for (String encodedUser : encodedUsers) {
      try {
        users.add(decodeUser(encodedUser));
      } catch (Exception ex) {
        logger.error("invalid user: " + encodedUser, ex);
      }
    }

    return users;
  }

  public boolean addAddress(Jedis jedis, String address) {
    return 1L == jedis.zadd(ADDRESS_SET, 0, address);
  }

  public boolean addUser(Jedis jedis, UUID uuid, String address) {
    boolean userAdded    = (1L == jedis.zadd(USER_SET, 0, encodeUser(uuid, address)));
    boolean addressAdded = addAddress(jedis, address);
    return userAdded || addressAdded;
  }

  public boolean removeAddress(Jedis jedis, String address) {
    return 1L == jedis.zrem(ADDRESS_SET, address);
  }

  public boolean removeUser(Jedis jedis, UUID uuid, String address) {
    boolean userRemoved    = (1L == jedis.zrem(USER_SET, encodeUser(uuid, address)));
    boolean addressRemoved = removeAddress(jedis, address);
    return userRemoved || addressRemoved;
  }

  public Optional<UUID> getUuidLastReconciled(Jedis jedis) {
    try {
      return Optional.ofNullable(jedis.get(USER_LAST_RECONCILED)).map(UUID::fromString);
    } catch (IllegalArgumentException ex) {
      logger.error("invalid uuid for last reconciled user: ", ex);
      return Optional.empty();
    }
  }

  public void setUuidLastReconciled(Jedis jedis, Optional<UUID> uuid) {
    if (uuid.isPresent()) {
      jedis.set(USER_LAST_RECONCILED, uuid.get().toString());
    } else {
      jedis.del(USER_LAST_RECONCILED);
      jedis.set(USER_SET_BUILT, "1");
    }
  }

  public long getAddressCount(Jedis jedis) {
    return jedis.zcard(ADDRESS_SET);
  }

  public long getUserCount(Jedis jedis) {
    return jedis.zcard(USER_SET);
  }

  public static Pair<UUID, String> decodeUser(String encodedUser) {
    int separatorIndex = encodedUser.indexOf(USER_SEPARATOR);

    int uuidEndIndex;
    int addressStartIndex;
    if (separatorIndex == -1) {
      uuidEndIndex      = encodedUser.length();
      addressStartIndex = encodedUser.length();
    } else {
      uuidEndIndex      = separatorIndex;
      addressStartIndex = separatorIndex + 1;
    }
    UUID   uuid    = UUID.fromString(encodedUser.substring(0, uuidEndIndex));
    String address = encodedUser.substring(addressStartIndex);
    return Pair.of(uuid, address);
  }

  public static String encodeUser(UUID uuid, String address) {
    return uuid.toString() + USER_SEPARATOR + address;
  }

  private static String uuidBoundAfter(UUID uuid) {
    return uuid.toString() + USER_SEPARATOR_PLUS_ONE;
  }
}
