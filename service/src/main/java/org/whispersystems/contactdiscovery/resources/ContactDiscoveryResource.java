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

import com.codahale.metrics.annotation.Timed;
import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.directory.DirectoryUnavailableException;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.limits.RateLimitExceededException;
import org.whispersystems.contactdiscovery.limits.RateLimiter;
import org.whispersystems.contactdiscovery.requests.RequestManager;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.Suspended;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;

import ch.qos.logback.core.status.Status;
import io.dropwizard.auth.Auth;

/**
 * API endpoint for submitting encrypted contact discovery requests
 *
 * @author Moxie Marlinspike
 */
@Path("/v1/discovery")
public class ContactDiscoveryResource {

  private final RateLimiter    rateLimiter;
  private final RequestManager requestManager;

  public ContactDiscoveryResource(RateLimiter rateLimiter, RequestManager requestManager) {
    this.rateLimiter    = rateLimiter;
    this.requestManager = requestManager;
  }

  @Timed
  @PUT
  @Path("/{enclaveId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Consumes(MediaType.APPLICATION_JSON)
  public void getRegisteredContacts(@Auth User user,
                                    @PathParam("enclaveId") String enclaveId,
                                    @Valid DiscoveryRequest request,
                                    @Suspended AsyncResponse asyncResponse)
      throws NoSuchEnclaveException, RateLimitExceededException, DirectoryUnavailableException
  {
    rateLimiter.validate(user.getNumber(), request.getAddressCount());

    requestManager.submit(enclaveId, request)
                  .thenAccept(asyncResponse::resume)
                  .exceptionally(throwable -> {
                    asyncResponse.resume(throwable.getCause());
                    return null;
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
                                        @Valid DiscoveryRequest request,
                                        @Suspended AsyncResponse asyncResponse)
          throws NoSuchEnclaveException, RateLimitExceededException, DirectoryUnavailableException
  {
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
