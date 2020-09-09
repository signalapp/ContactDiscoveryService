package org.whispersystems.contactdiscovery.mappers;

import org.whispersystems.contactdiscovery.requests.RequestManagerFullException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class RequestManagerFullExceptionMapper implements ExceptionMapper<RequestManagerFullException> {
  @Override
  public Response toResponse(RequestManagerFullException exception) {
    return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
  }
}
