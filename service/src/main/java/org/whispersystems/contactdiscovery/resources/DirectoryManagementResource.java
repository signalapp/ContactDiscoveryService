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

import com.codahale.metrics.annotation.ResponseMetered;
import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.auth.SignalService;
import org.whispersystems.contactdiscovery.directory.DirectoryManager;
import org.whispersystems.contactdiscovery.directory.DirectoryUnavailableException;
import org.whispersystems.contactdiscovery.directory.InvalidAddressException;
import org.whispersystems.contactdiscovery.entities.DirectoryReconciliationRequest;
import org.whispersystems.contactdiscovery.entities.DirectoryReconciliationResponse;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * API endpoint that the Signal service uses to update this micro-services view of
 * registered users.
 *
 * @author Moxie Marlinspike
 */
@Path("/v2/directory")
@ResponseMetered
public class DirectoryManagementResource {

  private final Logger logger = LoggerFactory.getLogger(RemoteAttestationResource.class);

  private final DirectoryManager directoryManager;

  public DirectoryManagementResource(DirectoryManager directoryManager) {
    this.directoryManager = directoryManager;
  }

  @Timed
  @PUT
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/reconcile")
  public DirectoryReconciliationResponse reconcile(@Auth SignalService signalService,
                                                   @Valid DirectoryReconciliationRequest request)
      throws InvalidAddressException, DirectoryUnavailableException
  {
    List<DirectoryReconciliationRequest.User> users     = Optional.ofNullable(request.getUsers()).orElse(Collections.emptyList());
    List<Pair<UUID, String>>                  userPairs = users.stream()
                                                               .map(user -> Pair.of(user.getUuid(), user.getNumber()))
                                                               .collect(Collectors.toList());
    boolean found = directoryManager.reconcile(Optional.ofNullable(request.getFromUuid()),
                                               Optional.ofNullable(request.getToUuid()),
                                               userPairs);
    if (found) {
      return new DirectoryReconciliationResponse(DirectoryReconciliationResponse.Status.OK);
    } else {
      return new DirectoryReconciliationResponse(DirectoryReconciliationResponse.Status.MISSING);
    }
  }

}
