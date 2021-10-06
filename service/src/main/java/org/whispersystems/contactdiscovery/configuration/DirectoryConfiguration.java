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

import javax.validation.constraints.NotNull;

/**
 * Configuration for directory hash table
 *
 * @author Moxie Marlinspike
 */
public class DirectoryConfiguration {

  @JsonProperty
  @NotNull
  private long initialCapacity;

  @JsonProperty
  @NotNull
  private float minLoadFactor;

  @JsonProperty
  @NotNull
  private float maxLoadFactor;

  @JsonProperty
  @NotNull
  private DirectorySqsConfiguration sqs;

  @JsonProperty
  @NotNull
  private String peerAuthenticationToken;

  @JsonProperty
  private String mapBuilderDns;

  @JsonProperty
  private int mapBuilderPort;

  @JsonProperty
  private String mapBuilderLoadBalancer;

  @JsonProperty
  private boolean peerReadEligible = false;

  @JsonProperty
  private boolean enableReconciliation = true;

  public long getInitialCapacity() {
    return initialCapacity;
  }

  public float getMinLoadFactor() {
    return minLoadFactor;
  }

  public float getMaxLoadFactor() {
    return maxLoadFactor;
  }

  public DirectorySqsConfiguration getSqsConfiguration() {
    return sqs;
  }

  public String getPeerAuthenticationToken() {
    return peerAuthenticationToken;
  }

  public String getMapBuilderLoadBalancer() { return mapBuilderLoadBalancer; }

  public boolean isReconciliationEnabled() { return enableReconciliation; }

  public boolean isPeerReadEligible() { return peerReadEligible; }

  public String getMapBuilderDns() {
    return mapBuilderDns;
  }

  public int getMapBuilderPort() {
    return mapBuilderPort;
  }
}
