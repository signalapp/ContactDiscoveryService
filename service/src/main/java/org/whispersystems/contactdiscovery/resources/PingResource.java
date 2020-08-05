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

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.concurrent.atomic.AtomicBoolean;

@Path("/v1/ping")
@ResponseMetered
public class PingResource {

  private final AtomicBoolean healthOverride;

  public PingResource(AtomicBoolean healthOverride) {
    this.healthOverride = healthOverride;
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  public Response ping() {
    if (healthOverride.get()) {
      return Response.status(Status.OK).entity("{}").build();
    }
    return Response.status(Status.INTERNAL_SERVER_ERROR).entity("{\"healthcheck\":\"failed\"}").build();
  }
}
