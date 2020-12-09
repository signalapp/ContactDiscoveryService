/*
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
package org.whispersystems.contactdiscovery.resources;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import com.codahale.metrics.annotation.ResponseMetered;
import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.limits.RateLimitExceededException;
import org.whispersystems.contactdiscovery.limits.RateLimiter;
import org.whispersystems.contactdiscovery.phonelimiter.PhoneRateLimiter;
import org.whispersystems.contactdiscovery.requests.RequestManager;
import org.whispersystems.contactdiscovery.requests.RequestManagerFullException;
import org.whispersystems.contactdiscovery.util.Constants;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.CompletionCallback;
import javax.ws.rs.container.Suspended;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * API endpoint for submitting encrypted contact discovery requests
 *
 * @author Moxie Marlinspike
 */
@Path("/v1/discovery")
public class ContactDiscoveryResource {

  private static final MetricRegistry REGISTRY = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Timer GET_CONTACTS_TIMER = REGISTRY.timer(name(ContactDiscoveryResource.class, "getRegisteredContacts"));
  private static final Meter HOST_ID_MISMATCH_METER = REGISTRY.meter(name(ContactDiscoveryResource.class, "hostIdMismatch"));
  private static final ConcurrentMap<String, Timer> PER_ENCLAVE_TIMERS = new ConcurrentHashMap<>();
  private static final Logger LOGGER = LoggerFactory.getLogger(ContactDiscoveryResource.class);

  private final RateLimiter rateLimiter;
  private final RequestManager requestManager;
  private final PhoneRateLimiter phoneLimiter;
  private final Set<String> enclaves;

  public ContactDiscoveryResource(RateLimiter rateLimiter, RequestManager requestManager, PhoneRateLimiter phoneLimiter, Set<String> enclaves) {
    this.rateLimiter = rateLimiter;
    this.requestManager = requestManager;
    this.phoneLimiter = phoneLimiter;
    this.enclaves = enclaves;
  }

  @PUT
  @Path("/{enclaveId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Consumes(MediaType.APPLICATION_JSON)
  public void getRegisteredContacts(@Auth User user,
                                    @PathParam("enclaveId") String enclaveId,
                                    @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader,
                                    @HeaderParam(HttpHeaders.USER_AGENT) String userAgent,
                                    @Valid DiscoveryRequest request,
                                    @Suspended AsyncResponse asyncResponse)
          throws RateLimitExceededException {
    final var ctx = GET_CONTACTS_TIMER.time();
    asyncResponse.register((CompletionCallback) throwable -> { ctx.close(); });

    if (!enclaves.contains(enclaveId)) {
      asyncResponse.resume(new NoSuchEnclaveException(enclaveId));
      return;
    }

    var perEnclaveTimer = PER_ENCLAVE_TIMERS.computeIfAbsent(enclaveId, key -> REGISTRY.timer(name(ContactDiscoveryResource.class, "getRegisteredContacts", "perEnclave", key)));
    final var perEnclaveCtx = perEnclaveTimer.time();
    asyncResponse.register((CompletionCallback) throwable -> { perEnclaveCtx.close(); });

    rateLimiter.validate(user.getNumber(), request.getAddressCount());
    if (!request.getEnvelopes().containsKey(RequestManager.LOCAL_ENCLAVE_HOST_ID)) {
      LOGGER.error("HostId not found in request envelopeMap. Found keys: {}, User-Agent {}",
              request.getEnvelopes().keySet(),
              userAgent
      );
      HOST_ID_MISMATCH_METER.mark();
      asyncResponse.resume(Response.status(400).build());
      return;
    }

    phoneLimiter.discoveryAllowed(user, authHeader, enclaveId, request)
                .thenAccept((allowed) -> {
                  if (!allowed) {
                    asyncResponse.resume(Response.status(429).build());
                    return;
                  }
                  try {
                    requestManager.submit(enclaveId, request)
                                  .thenAccept(asyncResponse::resume)
                                  .exceptionally(throwable -> {
                                    asyncResponse.resume(throwable.getCause());
                                    return null;
                                  });
                  } catch (NoSuchEnclaveException | RequestManagerFullException e) {
                    asyncResponse.resume(e);
                  }
                });
  }

  @Timed
  @PUT
  @Path("/test/{testName}/{enclaveId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Consumes(MediaType.APPLICATION_JSON)
  public void testGetRegisteredContacts(@Auth User user,
                                        @PathParam("testName") String testName,
                                        @PathParam("enclaveId") String enclaveId,
                                        @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader,
                                        @Valid DiscoveryRequest request,
                                        @Suspended AsyncResponse asyncResponse)
          throws NoSuchEnclaveException, RateLimitExceededException, RequestManagerFullException {
    if (!enclaves.contains(enclaveId)) {
      asyncResponse.resume(new NoSuchEnclaveException(enclaveId));
      return;
    }

    rateLimiter.validate(user.getNumber(), request.getAddressCount());

    Function<DiscoveryResponse, DiscoveryResponse> testFun;
    if ("bad-mac".equals(testName)) {
      testFun = discoveryResponse -> {
        discoveryResponse.getMac()[0] ^= 0xFF;
        return discoveryResponse;
      };
    } else {
      asyncResponse.resume(new WebApplicationException(404));
      return;
    }

    requestManager.submit(enclaveId, request)
                  .thenApply(testFun)
                  .thenAccept(asyncResponse::resume)
                  .exceptionally(throwable -> {
                    asyncResponse.resume(throwable.getCause());
                    return null;
                  });
  }

}
