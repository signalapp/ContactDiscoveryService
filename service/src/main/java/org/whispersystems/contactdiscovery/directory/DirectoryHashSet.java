/**
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
package org.whispersystems.contactdiscovery.directory;

import org.whispersystems.contactdiscovery.util.Util;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Hash table that contains the directory of all registered users
 *
 * @author Jeff Griffin
 */
public class DirectoryHashSet {

  private final float minLoadFactor;
  private final float maxLoadFactor;
  private final Object writeLock  = new Object();

  private ByteBuffer           curBuffer;
  private Optional<ByteBuffer> newBuffer;

  private long elementCount;
  private long usedSlotCount;
  private long newBufferUsedSlotCount;

  public DirectoryHashSet(long initialCapacity, float minLoadFactor, float maxLoadFactor) {
    if (minLoadFactor >= 1.0f || minLoadFactor <= 0.0f) {
      throw new IllegalArgumentException("bad minimum load factor: " + minLoadFactor);
    }
    if (maxLoadFactor >= 1.0f || maxLoadFactor <= 0.0f || maxLoadFactor <= minLoadFactor) {
      throw new IllegalArgumentException("bad maximum load factor: " + maxLoadFactor);
    }
    this.minLoadFactor          = minLoadFactor;
    this.maxLoadFactor          = maxLoadFactor;
    this.curBuffer              = allocateBuffer(initialCapacity);
    this.newBuffer              = Optional.empty();
    this.elementCount           = 0;
    this.usedSlotCount          = 0;
    this.newBufferUsedSlotCount = 0;
  }

  public ByteBuffer getDirectByteBuffer() {
    return curBuffer;
  }

  public long capacity() {
    return curBuffer.capacity() / 8;
  }

  public long size() {
    return elementCount;
  }

  public boolean add(long element) {
    if (element <= 0) {
      throw new IllegalArgumentException("bad number: " + element);
    }
    boolean added;
    boolean needsRehash;
    synchronized (writeLock) {
      if (elementCount >= capacity()) {
        rehash();
      }

      long oldSlotValue = addToBuffer(curBuffer, element);
      added = oldSlotValue != element;
      if (oldSlotValue == 0) {
        usedSlotCount++;
      }
      if (added) {
        elementCount++;
        if (newBuffer.isPresent()) {
          long newBufferOldSlotValue = addToBuffer(newBuffer.get(), element);
          if (newBufferOldSlotValue == 0) {
            newBufferUsedSlotCount++;
          }
        }
      }
      needsRehash = needsRehash();
    }
    if (needsRehash) {
      rehash();
    }
    return added;
  }

  public boolean remove(long element) {
    if (element <= 0) {
      throw new IllegalArgumentException("bad number: " + element);
    }
    synchronized (writeLock) {
      boolean removed = removeFromBuffer(curBuffer, element);
      if (removed) {
        elementCount--;
        if (newBuffer.isPresent()) {
          removeFromBuffer(newBuffer.get(), element);
        }
      }
      return removed;
    }
  }

  private boolean needsRehash() {
    long threshold = (long) (capacity() * maxLoadFactor);
    return usedSlotCount >= threshold;
  }

  public boolean rehash() {
    synchronized (writeLock) {
      while (newBuffer.isPresent()) {
        Util.wait(writeLock, 5000);
      }

      if (!needsRehash()) {
        return false;
      }

      long newSlotCount = (long) (elementCount / minLoadFactor);
      if (newSlotCount > Integer.MAX_VALUE / 8) {
        newSlotCount = Integer.MAX_VALUE / 8;
      }
      if (newSlotCount < capacity()) {
        newSlotCount = capacity();
      }

      newBuffer              = Optional.of(allocateBuffer(newSlotCount));
      newBufferUsedSlotCount = 0;
    }

    boolean success = false;
    try {
      long curBufferCapacity = curBuffer.capacity();
      for (long curBufferIdx = 0; curBufferIdx < curBufferCapacity; curBufferIdx += 8) {
        synchronized (writeLock) {
          long element = curBuffer.getLong((int) curBufferIdx);
          if (element > 0) {
            long newBufferOldSlotValue = addToBuffer(newBuffer.get(), element);
            if (newBufferOldSlotValue == 0) {
              newBufferUsedSlotCount++;
            }
          }
        }
      }
      success = true;
      return true;
    } finally {
      synchronized (writeLock) {
        if (success) {
          curBuffer     = newBuffer.get();
          usedSlotCount = newBufferUsedSlotCount;
        }
        newBuffer = Optional.empty();
        writeLock.notifyAll();
      }
    }
  }

  private static ByteBuffer allocateBuffer(long slotCount) {
    if (slotCount > Integer.MAX_VALUE / 8) {
      throw new IllegalArgumentException("hash_table_too_large");
    }
    return ByteBuffer.allocateDirect((int) (slotCount * 8));
  }

  private static int hashElement(int slotCount, long element) {
    return (int) (element % slotCount);
  }

  private static long addToBuffer(ByteBuffer buffer, long element) {
    int  slotCount    = buffer.capacity() / 8;
    int  slotIdx      = hashElement(slotCount, element);
    int  startSlotIdx = slotIdx;
    long slotValue    = buffer.getLong(slotIdx * 8);
    while (slotValue > 0) {
      if (slotValue == element) {
        return slotValue;
      }
      if (++slotIdx == slotCount) {
        slotIdx = 0;
      }
      if (slotIdx == startSlotIdx) {
        throw new AssertionError("DirectoryHashSet full");
      }
      slotValue = buffer.getLong(slotIdx * 8);
    }
    int freeSlotIdx = slotIdx;
    long freeSlotValue = slotValue;
    while (slotValue != 0) {
      if (slotValue == element) {
        return slotValue;
      }
      if (++slotIdx == slotCount) {
        slotIdx = 0;
      }
      if (slotIdx == freeSlotIdx) {
        break;
      }
      slotValue = buffer.getLong(slotIdx * 8);
    }
    buffer.putLong(freeSlotIdx * 8, element);
    return freeSlotValue;
  }

  private static boolean removeFromBuffer(ByteBuffer buffer, long element) {
    int slotCount = buffer.capacity() / 8;
    int slotIdx = hashElement(slotCount, element);
    long slotValue = buffer.getLong(slotIdx * 8);
    while (slotValue != 0) {
      if (slotValue == element) {
        buffer.putLong(slotIdx * 8, -1);
        return true;
      }
      if (++slotIdx == slotCount) {
        slotIdx = 0;
      }
      slotValue = buffer.getLong(slotIdx * 8);
    }
    return false;
  }

}
