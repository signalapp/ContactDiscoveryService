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
package org.whispersystems.contactdiscovery.validation;

import org.hibernate.validator.internal.util.logging.Log;
import org.hibernate.validator.internal.util.logging.LoggerFactory;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.lang.invoke.MethodHandles;

public class ByteLengthValidator implements ConstraintValidator<ByteLength, byte[]> {

  private static final Log log = LoggerFactory.make(MethodHandles.lookup());

  private int min;
  private int max;

  @Override
  public void initialize(ByteLength parameters) {
    min = parameters.min();
    max = parameters.max();
    validateParameters();
  }

  @Override
  public boolean isValid(byte[] value, ConstraintValidatorContext constraintValidatorContext) {
    if (value == null) {
      return true;
    }

    int length = value.length;
    return length >= min && length <= max;
  }

  private void validateParameters() {
    if ( min < 0 ) {
      throw log.getMinCannotBeNegativeException();
    }
    if ( max < 0 ) {
      throw log.getMaxCannotBeNegativeException();
    }
    if ( max < min ) {
      throw log.getLengthCannotBeNegativeException();
    }
  }
}
