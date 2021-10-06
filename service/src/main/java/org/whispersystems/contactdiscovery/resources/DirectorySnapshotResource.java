/*
 * Copyright (C) 2021 Open Whisper Systems
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.auth.PeerService;
import org.whispersystems.contactdiscovery.directory.DirectoryManager;
import org.whispersystems.contactdiscovery.directory.DirectoryUnavailableException;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;
import java.io.IOException;
import java.io.OutputStream;

/**
 * API endpoint that another, traffic-serving instance of the service uses to bootstrap its directory map
 * from a prebuilt snapshot.
 */
@Path("/v1/snapshot")
@ResponseMetered
public class DirectorySnapshotResource {

    private final Logger logger = LoggerFactory.getLogger(DirectorySnapshotResource.class);

    private final DirectoryManager directoryManager;

    public DirectorySnapshotResource(DirectoryManager directoryManager) {
        this.directoryManager = directoryManager;
    }

    @Timed
    @GET
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Path("/")
    public Response streamDirectorySnapshot(@Auth PeerService peerService)
    {
        if (directoryManager.isBootstrapping() || !directoryManager.isConnected()) {
            return Response.status(503).build();
        }

        return Response.ok(new StreamingOutput() {
            @Override
            public void write(OutputStream outputStream) throws IOException, WebApplicationException {
                try {
                    directoryManager.generateSnapshot(outputStream);
                } catch (DirectoryUnavailableException e) {
                    throw new WebApplicationException(e);
                }
            }
        }).build();
    }

}
