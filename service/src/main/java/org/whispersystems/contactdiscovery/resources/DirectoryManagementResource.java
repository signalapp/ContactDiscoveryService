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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.auth.SignalService;
import org.whispersystems.contactdiscovery.directory.DirectoryManager;
import org.whispersystems.contactdiscovery.directory.InvalidAddressException;

import javax.ws.rs.DELETE;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import io.dropwizard.auth.Auth;

/**
 * API endpoint that the Signal service uses to update this micro-services view of
 * registered users.
 *
 * @author Moxie Marlinspike
 */
@Path("/v1/directory")
public class DirectoryManagementResource {

  private final Logger logger = LoggerFactory.getLogger(RemoteAttestationResource.class);

  private final DirectoryManager directoryManager;

  public DirectoryManagementResource(DirectoryManager directoryManager) {
    this.directoryManager = directoryManager;
  }

  @Timed
  @PUT
  @Path("/{address}")
  public void addAddress(@Auth SignalService signalService,
                         @PathParam("address") String address)
  {
    try {
      directoryManager.addAddress(address);
    } catch (InvalidAddressException e) {
      logger.warn("Bad address", e);
      throw new WebApplicationException(Response.Status.BAD_REQUEST);
    }
  }

  @Timed
  @DELETE
  @Path("/{address}")
  public void removeAddress(@Auth SignalService signalService,
                            @PathParam("address") String address)
  {
    try {
      directoryManager.removeAddress(address);
    } catch (InvalidAddressException e) {
      logger.warn("Bad address", e);
      throw new WebApplicationException(Response.Status.BAD_REQUEST);
    }
  }

}
