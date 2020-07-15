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
package org.whispersystems.contactdiscovery.limits;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Clock;

public class LeakyBucket {

  private final int    bucketSize;
  private final double leakRatePerMillis;

  private int  spaceRemaining;
  private long lastUpdateTimeMillis;

  private final Clock clock;

  public LeakyBucket(int bucketSize, double leakRatePerMillis, Clock clock) {
    this(bucketSize, leakRatePerMillis, bucketSize, clock.millis(), clock);
  }

  private LeakyBucket(int bucketSize, double leakRatePerMillis, int spaceRemaining, long lastUpdateTimeMillis, Clock clock) {
    this.bucketSize           = bucketSize;
    this.leakRatePerMillis    = leakRatePerMillis;
    this.spaceRemaining       = spaceRemaining;
    this.lastUpdateTimeMillis = lastUpdateTimeMillis;
    this.clock                = clock;
  }

  public boolean add(int amount) {
    final long currentTimeMillis = clock.millis();

    this.spaceRemaining       = getUpdatedSpaceRemaining(currentTimeMillis);
    this.lastUpdateTimeMillis = currentTimeMillis;

    if (this.spaceRemaining >= amount) {
      this.spaceRemaining -= amount;
      return true;
    } else {
      return false;
    }
  }

  private int getUpdatedSpaceRemaining(long currentTimeMillis) {
    long elapsedTime = currentTimeMillis - this.lastUpdateTimeMillis;

    return Math.min(this.bucketSize,
                    (int)Math.floor(this.spaceRemaining + (elapsedTime * this.leakRatePerMillis)));
  }

  public String serialize(ObjectMapper mapper) throws JsonProcessingException {
    return mapper.writeValueAsString(new LeakyBucketEntity(bucketSize, leakRatePerMillis, spaceRemaining, lastUpdateTimeMillis));
  }

  public static LeakyBucket fromSerialized(ObjectMapper mapper, String serialized, Clock clock) throws IOException {
    LeakyBucketEntity entity = mapper.readValue(serialized, LeakyBucketEntity.class);

    return new LeakyBucket(entity.bucketSize, entity.leakRatePerMillis,
                           entity.spaceRemaining, entity.lastUpdateTimeMillis, clock);
  }

  private static class LeakyBucketEntity {
    @JsonProperty
    private final int    bucketSize;

    @JsonProperty
    private final double leakRatePerMillis;

    @JsonProperty
    private final int    spaceRemaining;

    @JsonProperty
    private final long   lastUpdateTimeMillis;

    @JsonCreator
    private LeakyBucketEntity(@JsonProperty("bucketSize")           int bucketSize,
                              @JsonProperty("leakRatePerMillis")    double leakRatePerMillis,
                              @JsonProperty("spaceRemaining")       int spaceRemaining,
                              @JsonProperty("lastUpdateTimeMillis") long lastUpdateTimeMillis)
    {
      this.bucketSize           = bucketSize;
      this.leakRatePerMillis    = leakRatePerMillis;
      this.spaceRemaining       = spaceRemaining;
      this.lastUpdateTimeMillis = lastUpdateTimeMillis;
    }
  }
}
