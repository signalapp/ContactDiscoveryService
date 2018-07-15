package org.whispersystems.contactdiscovery.mappers;

import io.dropwizard.jersey.errors.ErrorMessage;

import javax.crypto.AEADBadTagException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class AEADBadTagExceptionMapper implements ExceptionMapper<AEADBadTagException> {
  @Override
  public Response toResponse(AEADBadTagException ex) {
    return Response.status(400)
                   .type(MediaType.APPLICATION_JSON_TYPE)
                   .entity(new ErrorMessage(400, ex.toString()))
                   .build();
  }
}
