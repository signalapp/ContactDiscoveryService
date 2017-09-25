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
package org.whispersystems.contactdiscovery.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Configuration for service rate limits
 *
 * @author Moxie Marlinspike
 */
public class RateLimitsConfiguration {

  @JsonProperty
  private RateLimitConfiguration contactQueries = new RateLimitConfiguration(50000, 50000);

  @JsonProperty
  private RateLimitConfiguration remoteAttestations = new RateLimitConfiguration(10, 10);

  public RateLimitConfiguration getContactQueries() {
    return contactQueries;
  }

  public RateLimitConfiguration getRemoteAttestations() {
    return remoteAttestations;
  }

  public static class RateLimitConfiguration {
    @JsonProperty
    private int bucketSize;

    @JsonProperty
    private double leakRatePerMinute;

    public RateLimitConfiguration(int bucketSize, double leakRatePerMinute) {
      this.bucketSize        = bucketSize;
      this.leakRatePerMinute = leakRatePerMinute;
    }

    public RateLimitConfiguration() {}

    public int getBucketSize() {
      return bucketSize;
    }

    public double getLeakRatePerMinute() {
      return leakRatePerMinute;
    }
  }
}
