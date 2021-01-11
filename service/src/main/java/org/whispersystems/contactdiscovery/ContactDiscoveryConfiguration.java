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
package org.whispersystems.contactdiscovery;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;
import org.whispersystems.contactdiscovery.configuration.DirectoryConfiguration;
import org.whispersystems.contactdiscovery.configuration.EnclaveConfiguration;
import org.whispersystems.contactdiscovery.configuration.RateLimitsConfiguration;
import org.whispersystems.contactdiscovery.configuration.RedisConfiguration;
import org.whispersystems.contactdiscovery.configuration.SignalServiceConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * Service configuration
 *
 * @author Moxie Marlinspike
 */
public class ContactDiscoveryConfiguration extends Configuration {

  @JsonProperty
  @NotNull
  @Valid
  private EnclaveConfiguration enclave;

  @JsonProperty
  @NotNull
  @Valid
  private SignalServiceConfiguration signal;

  @JsonProperty
  @NotNull
  @Valid
  private RedisConfiguration redis;

  @JsonProperty
  @NotNull
  @Valid
  private DirectoryConfiguration directory;

  @JsonProperty
  private RateLimitServiceConfiguration rateLimitSvc = null;

  @JsonProperty
  @NotNull
  @Valid
  private RateLimitsConfiguration limits = new RateLimitsConfiguration();


  public EnclaveConfiguration getEnclaveConfiguration() {
    return enclave;
  }

  public SignalServiceConfiguration getSignalServiceConfiguration() {
    return signal;
  }

  public RedisConfiguration getRedisConfiguration() {
    return redis;
  }

  public DirectoryConfiguration getDirectoryConfiguration() {
    return directory;
  }

  public RateLimitServiceConfiguration getRateLimitSvc() {
    return rateLimitSvc;
  }

  public RateLimitsConfiguration getLimitsConfiguration() {
    return limits;
  }
}
