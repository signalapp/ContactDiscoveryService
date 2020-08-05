/*
 * Copyright (C) 2019 Open Whisper Systems
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

import com.codahale.metrics.annotation.ResponseMetered;
import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import org.whispersystems.contactdiscovery.auth.SignalService;
import org.whispersystems.contactdiscovery.entities.DirectoryReconciliationRequest;
import org.whispersystems.contactdiscovery.entities.DirectoryReconciliationResponse;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("/v1/directory")
@ResponseMetered
public class LegacyDirectoryManagementResource {

  @Timed
  @PUT
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/reconcile")
  public DirectoryReconciliationResponse reconcile(@Auth SignalService signalService,
                                                   @Valid DirectoryReconciliationRequest request)
  {
    return new DirectoryReconciliationResponse(DirectoryReconciliationResponse.Status.OK);
  }
}
