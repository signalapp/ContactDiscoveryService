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
package org.whispersystems.contactdiscovery.mappers;

import org.glassfish.jersey.spi.ExtendedExceptionMapper;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;
import javax.ws.rs.ext.Providers;
import java.util.concurrent.CompletionException;

@Provider
public class CompletionExceptionMapper implements ExceptionMapper<CompletionException>, ExtendedExceptionMapper<CompletionException> {

  @Context
  private Providers providers;

  @Override
  @SuppressWarnings("unchecked")
  public Response toResponse(CompletionException completionException) {
    Throwable cause = completionException.getCause();
    if (cause == null) {
      throw new AssertionError("exception has no cause", completionException);
    }
    if (cause instanceof CompletionException) {
      throw new AssertionError("cause is another CompletionException", cause);
    }
    ExceptionMapper mapper = providers.getExceptionMapper(cause.getClass());
    if (mapper == null) {
      throw new AssertionError("cause exception mapper not found", cause);
    }
    return mapper.toResponse(cause);
  }

  @Override
  public boolean isMappable(CompletionException exception) {
    return exception.getCause() != null &&
           !(exception.getCause() instanceof CompletionException) &&
           providers.getExceptionMapper(exception.getCause().getClass()) != null;
  }

}
