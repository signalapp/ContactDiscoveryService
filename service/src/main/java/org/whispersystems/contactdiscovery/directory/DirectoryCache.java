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

import redis.clients.jedis.Jedis;
import redis.clients.jedis.ScanParams;
import redis.clients.jedis.ScanResult;
import redis.clients.jedis.Tuple;

import java.util.Optional;
import java.util.Set;

public class DirectoryCache {

  private static final String ADDRESS_SET             = "signal_addresses_sorted::1";
  private static final String ADDRESS_SET_BUILT       = "signal_addresses_built";
  private static final String ADDRESS_LAST_RECONCILED = "signal_address_last_reconciled";

  public boolean isDirectoryBuilt(Jedis jedis) {
    return jedis.exists(ADDRESS_SET_BUILT);
  }

  public ScanResult<Tuple> getAllAddresses(Jedis jedis, String cursor, int count) {
    ScanParams scanParams = new ScanParams().count(count);
    return jedis.zscan(ADDRESS_SET, cursor, scanParams);
  }

  public Set<String> getAddressesInRange(Jedis jedis, Optional<String> fromNumber, Optional<String> toNumber) {
    String lowerBound = fromNumber.map(number -> "(" + number).orElse("-");
    String upperBound = toNumber.map(number -> "[" + number).orElse("+");
    return jedis.zrangeByLex(ADDRESS_SET, lowerBound, upperBound);
  }

  public boolean addAddress(Jedis jedis, String address) {
    return 1L == jedis.zadd(ADDRESS_SET, 0, address);
  }

  public boolean removeAddress(Jedis jedis, String address) {
    return 1L == jedis.zrem(ADDRESS_SET, address);
  }

  public Optional<String> getAddressLastReconciled(Jedis jedis) {
    return Optional.ofNullable(jedis.get(ADDRESS_LAST_RECONCILED));
  }

  public void setAddressLastReconciled(Jedis jedis, Optional<String> address) {
    if (address.isPresent()) {
      jedis.set(ADDRESS_LAST_RECONCILED, address.get());
    } else {
      jedis.del(ADDRESS_LAST_RECONCILED);
      jedis.set(ADDRESS_SET_BUILT, "1");
    }
  }

  public long getAddressCount(Jedis jedis) {
    return jedis.zcard(ADDRESS_SET);
  }
}
