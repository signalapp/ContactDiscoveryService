package org.whispersystems.contactdiscovery.mappers;

import io.dropwizard.jersey.errors.ErrorMessage;
import org.whispersystems.contactdiscovery.resources.RequestLimiterTaskException;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class RequestLimiterTaskExceptionMapper implements ExceptionMapper<RequestLimiterTaskException> {
  @Override
  public Response toResponse(RequestLimiterTaskException ex) {
    return Response.status(Response.Status.BAD_REQUEST)
            .type(MediaType.APPLICATION_JSON_TYPE)
            .entity(new ErrorMessage(Response.Status.BAD_REQUEST.getStatusCode(), ex.toString()))
            .build();
  }
}
