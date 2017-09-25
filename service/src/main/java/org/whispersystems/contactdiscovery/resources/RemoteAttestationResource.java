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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.auth.User;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.enclave.SgxException;
import org.whispersystems.contactdiscovery.enclave.SgxHandshakeManager;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationRequest;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;
import org.whispersystems.contactdiscovery.limits.RateLimitExceededException;
import org.whispersystems.contactdiscovery.limits.RateLimiter;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import io.dropwizard.auth.Auth;

/**
 * API endpoint for doing remote attestation of and simultaneously establishing a secure
 * connection to an SGX enclave
 *
 * @author Moxie Marlinspike
 */

@Path("/v1/attestation/")
public class RemoteAttestationResource {

  private final Logger logger = LoggerFactory.getLogger(RemoteAttestationResource.class);

  private final SgxHandshakeManager sgxHandshakeManager;
  private final RateLimiter         rateLimiter;

  public RemoteAttestationResource(SgxHandshakeManager sgxHandshakeManager, RateLimiter rateLimiter) {
    this.sgxHandshakeManager = sgxHandshakeManager;
    this.rateLimiter         = rateLimiter;
  }

  @PUT
  @Path("/{enclaveId}")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public RemoteAttestationResponse getAttestationHandshake(@Auth User user,
                                                           @PathParam("enclaveId") String enclaveId,
                                                           @Valid RemoteAttestationRequest request)
      throws NoSuchEnclaveException, SgxException, RateLimitExceededException
  {
    rateLimiter.validate(user.getNumber());
    return sgxHandshakeManager.getHandshake(enclaveId, request.getClientPublic());
  }
}
