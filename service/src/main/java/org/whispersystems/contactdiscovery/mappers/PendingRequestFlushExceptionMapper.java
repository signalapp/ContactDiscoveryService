package org.whispersystems.contactdiscovery.mappers;

import org.whispersystems.contactdiscovery.requests.PendingRequestFlushException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class PendingRequestFlushExceptionMapper implements ExceptionMapper<PendingRequestFlushException> {
  @Override
  public Response toResponse(PendingRequestFlushException exception) {
    return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
  }
}
