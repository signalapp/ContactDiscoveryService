/**
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
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
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.*;
import java.util.stream.Collectors;

@Path("/v3/directory")
@ResponseMetered
public class DirectoryManagementV3Resource {

  private final Logger logger = LoggerFactory.getLogger(DirectoryManagementV3Resource.class);

  private final DirectoryManager directoryManager;

  public DirectoryManagementV3Resource(DirectoryManager directoryManager) {
    this.directoryManager = directoryManager;
  }

  @Timed
  @PUT
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/exists")
  public DirectoryReconciliationResponse exists(@Auth SignalService signalService, @Valid DirectoryReconciliationRequest request)
      throws InvalidAddressException, DirectoryUnavailableException
  {
    directoryManager.existsReconcile(buildUserPairs(request));
    return new DirectoryReconciliationResponse(DirectoryReconciliationResponse.Status.OK);
  }

  @Timed
  @PUT
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/deletes")
  public DirectoryReconciliationResponse deletes(@Auth SignalService signalService, @Valid DirectoryReconciliationRequest request)
     throws InvalidAddressException, DirectoryUnavailableException
  {
    directoryManager.deletesReconcile(buildUserPairs(request));
    return new DirectoryReconciliationResponse(DirectoryReconciliationResponse.Status.OK);
  }

  @Timed
  @POST
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/complete")
  public DirectoryReconciliationResponse complete(@Auth SignalService signalService) {
    directoryManager.markReconcileComplete();
    return new DirectoryReconciliationResponse(DirectoryReconciliationResponse.Status.OK);
  }



  private List<Pair<UUID,String>> buildUserPairs(DirectoryReconciliationRequest request) {
    List<DirectoryReconciliationRequest.User> users = Optional.ofNullable(request.getUsers()).orElse(Collections.emptyList());
    return users.stream()
            .map(user -> Pair.of(user.getUuid(), user.getNumber()))
            .collect(Collectors.toList());
  }

}
