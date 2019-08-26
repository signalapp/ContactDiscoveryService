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

import org.apache.commons.lang3.tuple.Pair;
import org.whispersystems.contactdiscovery.util.Util;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.UUID;

/**
 * Hash table that contains the directory of all registered users
 *
 * @author Jeff Griffin
 */
public class DirectoryHashSet {

  public static final int VALUE_SIZE = 16;

  private static final int KEY_SIZE = 8;

  private final float minLoadFactor;
  private final float maxLoadFactor;
  private final Object writeLock  = new Object();

  private ByteBuffer           curBuffer;
  private Optional<ByteBuffer> newBuffer;

  private ByteBuffer           curValueBuffer;
  private Optional<ByteBuffer> newValueBuffer;

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
    this.curBuffer              = allocateBuffer(initialCapacity, KEY_SIZE);
    this.curValueBuffer         = allocateBuffer(initialCapacity, VALUE_SIZE);
    this.newBuffer              = Optional.empty();
    this.newValueBuffer         = Optional.empty();
    this.elementCount           = 0;
    this.usedSlotCount          = 0;
    this.newBufferUsedSlotCount = 0;
  }

  public Pair<ByteBuffer, ByteBuffer> getDirectByteBuffers() {
    return Pair.of(curBuffer, curValueBuffer);
  }

  public long capacity() {
    return curBuffer.capacity() / KEY_SIZE;
  }

  public long size() {
    return elementCount;
  }

  public boolean insert(long element, UUID value) {
    if (element <= 0) {
      throw new IllegalArgumentException("bad number: " + element);
    }
    boolean added;
    boolean needsRehash;
    synchronized (writeLock) {
      if (elementCount >= capacity()) {
        rehash();
      }

      long oldSlotValue = addToBuffer(curBuffer, curValueBuffer, element, value);
      added = oldSlotValue != element;
      if (oldSlotValue == 0) {
        usedSlotCount++;
      }
      if (added) {
        elementCount++;
        if (newBuffer.isPresent()) {
          long newBufferOldSlotValue = addToBuffer(newBuffer.get(), newValueBuffer.get(), element, value);
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
      boolean removed = removeFromBuffer(curBuffer, curValueBuffer, element);
      if (removed) {
        elementCount--;
        if (newBuffer.isPresent()) {
          removeFromBuffer(newBuffer.get(), newValueBuffer.get(), element);
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
      if (newSlotCount > Integer.MAX_VALUE / KEY_SIZE) {
        newSlotCount = Integer.MAX_VALUE / KEY_SIZE;
      }
      if (newSlotCount < capacity()) {
        newSlotCount = capacity();
      }

      newBuffer              = Optional.of(allocateBuffer(newSlotCount, KEY_SIZE));
      newValueBuffer         = Optional.of(allocateBuffer(newSlotCount, VALUE_SIZE));
      newBufferUsedSlotCount = 0;
    }

    boolean success = false;
    try {
      long curBufferCapacity      = curBuffer.capacity();
      long curValueBufferCapacity = curValueBuffer.capacity();
      for (long curBufferIdx = 0, curValueBufferIdx = 0;
           curBufferIdx < curBufferCapacity && curValueBufferIdx < curValueBufferCapacity;
           curBufferIdx += KEY_SIZE, curValueBufferIdx += VALUE_SIZE) {
        synchronized (writeLock) {
          long element = curBuffer.getLong((int) curBufferIdx);
          if (element > 0) {
            UUID value = new UUID(curValueBuffer.getLong((int) curValueBufferIdx + 0),
                                  curValueBuffer.getLong((int) curValueBufferIdx + 8));
            long newBufferOldSlotValue = addToBuffer(newBuffer.get(), newValueBuffer.get(), element, value);
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
          curBuffer      = newBuffer.get();
          curValueBuffer = newValueBuffer.get();
          usedSlotCount  = newBufferUsedSlotCount;
        }
        newBuffer      = Optional.empty();
        newValueBuffer = Optional.empty();
        writeLock.notifyAll();
      }
    }
  }

  private static ByteBuffer allocateBuffer(long slotCount, int slotSize) {
    if (slotCount > Integer.MAX_VALUE / slotSize) {
      throw new IllegalArgumentException("hash_table_too_large");
    }
    return ByteBuffer.allocateDirect((int) (slotCount * slotSize));
  }

  private static int hashElement(int slotCount, long element) {
    return (int) (element % slotCount);
  }

  private static long addToBuffer(ByteBuffer buffer, ByteBuffer valueBuffer, long element, UUID value) {
    int  slotCount    = buffer.capacity() / KEY_SIZE;
    int  slotIdx      = hashElement(slotCount, element);
    int  startSlotIdx = slotIdx;
    long slotValue    = buffer.getLong(slotIdx * KEY_SIZE);
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
      slotValue = buffer.getLong(slotIdx * KEY_SIZE);
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
      slotValue = buffer.getLong(slotIdx * KEY_SIZE);
    }
    buffer.putLong(freeSlotIdx * KEY_SIZE, element);
    if (value != null) {
      valueBuffer.putLong(freeSlotIdx * VALUE_SIZE + 0, value.getMostSignificantBits());
      valueBuffer.putLong(freeSlotIdx * VALUE_SIZE + 8, value.getLeastSignificantBits());
    } else {
      valueBuffer.putLong(freeSlotIdx * VALUE_SIZE + 0, 0);
      valueBuffer.putLong(freeSlotIdx * VALUE_SIZE + 8, 0);
    }
    return freeSlotValue;
  }

  private static boolean removeFromBuffer(ByteBuffer buffer, ByteBuffer valueBuffer, long element) {
    int slotCount = buffer.capacity() / KEY_SIZE;
    int slotIdx = hashElement(slotCount, element);
    long slotValue = buffer.getLong(slotIdx * KEY_SIZE);
    while (slotValue != 0) {
      if (slotValue == element) {
        buffer.putLong(slotIdx * KEY_SIZE, -1);
        valueBuffer.putLong(slotIdx * VALUE_SIZE + 0, 0);
        valueBuffer.putLong(slotIdx * VALUE_SIZE + 8, 0);
        return true;
      }
      if (++slotIdx == slotCount) {
        slotIdx = 0;
      }
      slotValue = buffer.getLong(slotIdx * KEY_SIZE);
    }
    return false;
  }

}
