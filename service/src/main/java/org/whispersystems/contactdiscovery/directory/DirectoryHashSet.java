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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Hash table that contains the directory of all registered users
 *
 * @author Jeff Griffin
 */
public class DirectoryHashSet {

  private final float loadFactor;
  private final Object writeLock  = new Object();

  private ByteBuffer curBuffer;
  private ByteBuffer newBuffer;
  private long       elementCount;
  private long       usedSlotCount;
  private long       newBufferUsedSlotCount;
  private long       threshold;

  public DirectoryHashSet(long initialCapacity, float loadFactor) {
    if (loadFactor >= 1.0f || loadFactor <= 0.0f) {
      throw new IllegalArgumentException("bad load factor: " + loadFactor);
    }
    this.loadFactor             = loadFactor;
    this.curBuffer              = allocateBuffer(initialCapacity);
    this.newBuffer              = null;
    this.elementCount           = 0;
    this.usedSlotCount          = 0;
    this.newBufferUsedSlotCount = 0;
    this.threshold              = (long) (initialCapacity * loadFactor);
  }

  public ByteBuffer getDirectByteBuffer() {
    return curBuffer;
  }

  public long capacity() {
    return curBuffer.capacity() / 8;
  }

  public float currentLoadFactor() {
    return (float) (((double) usedSlotCount) / ((double) capacity()));
  }

  public float getLoadFactor() {
    return loadFactor;
  }

  public boolean add(long element) {
    if (element <= 0) {
      throw new IllegalArgumentException("bad number: " + element);
    }
    boolean added;
    boolean needsRehash = false;
    synchronized (writeLock) {
      if (usedSlotCount >= threshold) {
        needsRehash = true;
        if (usedSlotCount == capacity()) {
          throw new IllegalStateException("hash_table_full");
        }
      }

      long oldSlotValue = addToBuffer(curBuffer, element);
      added = oldSlotValue != element;
      if (oldSlotValue == 0) {
        usedSlotCount++;
      }
      if (added) {
        elementCount++;
        if (newBuffer != null) {
          long newBufferOldSlotValue = addToBuffer(newBuffer, element);
          if (newBufferOldSlotValue == 0) {
            newBufferUsedSlotCount++;
          }
        }
      }
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
        if (newBuffer != null) {
          removeFromBuffer(newBuffer, element);
        }
      }
      return removed;
    }
  }

  public boolean rehash() {
    long curBufferCapacity = curBuffer.capacity();
    long slotCount = curBufferCapacity / 8;
    long newSlotCount = slotCount <= Integer.MAX_VALUE / 8 / 2? slotCount * 2 : Integer.MAX_VALUE / 8;
    if (newSlotCount == slotCount) {
      return false;
    }

    synchronized (writeLock) {
      if (newBuffer != null) {
        return false;
      }
      newBuffer = allocateBuffer(newSlotCount);
      newBufferUsedSlotCount = 0;
    }
    boolean success = false;
    try {
      for (long curBufferIdx = 0; curBufferIdx < curBufferCapacity; curBufferIdx += 8) {
        synchronized (writeLock) {
          long element = curBuffer.getLong((int) curBufferIdx);
          if (element > 0) {
            addToBuffer(newBuffer, element);
          }
        }
      }
      success = true;
      return true;
    } finally {
      synchronized (writeLock) {
        if (success) {
          curBuffer = newBuffer;
          threshold = (long) (newSlotCount * loadFactor);
          usedSlotCount = newBufferUsedSlotCount;
        }
        newBuffer = null;
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
    int slotCount = buffer.capacity() / 8;
    int slotIdx = hashElement(slotCount, element);
    long slotValue = buffer.getLong(slotIdx * 8);
    while (slotValue > 0) {
      if (slotValue == element) {
        return slotValue;
      }
      if (++slotIdx == slotCount) {
        slotIdx = 0;
      }
      slotValue = buffer.getLong(slotIdx * 8);
    }
    int freeSlotIdx = slotIdx;
    while (slotValue != 0) {
      if (slotValue == element) {
        return slotValue;
      }
      if (++slotIdx == slotCount) {
        slotIdx = 0;
      }
      slotValue = buffer.getLong(slotIdx * 8);
    }
    buffer.putLong(freeSlotIdx * 8, element);
    return slotValue;
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
