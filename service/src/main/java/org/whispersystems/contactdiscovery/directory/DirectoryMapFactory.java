/*
 * Copyright (C) 2018 Open Whisper Systems
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
package org.whispersystems.contactdiscovery.directory;

public class DirectoryMapFactory {

  private final long initialCapacity;
  private final float minLoadFactor;
  private final float maxLoadFactor;

  public DirectoryMapFactory(long initialCapacity, float minLoadFactor, float maxLoadFactor) {
    this.initialCapacity = initialCapacity;
    this.minLoadFactor = minLoadFactor;
    this.maxLoadFactor = maxLoadFactor;
  }

  public DirectoryMapNative create(long minimumCapacity) {
    long capacity = Math.max(initialCapacity, (long) (minimumCapacity / minLoadFactor));
    return new DirectoryMapNative(capacity, minLoadFactor, maxLoadFactor);
  }

}
