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

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import com.google.common.annotations.VisibleForTesting;
import org.whispersystems.contactdiscovery.enclave.SgxException;
import org.whispersystems.contactdiscovery.util.Constants;

import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * A double buffered open hash table that contains the directory of all registered users' phone numbers and UUIDs.
 *
 * @author Jeff Griffin
 */
public class DirectoryMap {

  private static final int VALUE_SIZE = 16;
  private static final int KEY_SIZE = 8;

  private final Object writeBufLock = new Object();
  private final ReadWriteLock readBufferRWLock = new ReentrantReadWriteLock();
  private boolean modified = false;
  private InternalBuffers workingBuffers;
  private InternalBuffers publishedBuffers;

  private static final MetricRegistry METRIC_REGISTRY = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Timer COMMIT_TIMER = METRIC_REGISTRY.timer(name(DirectoryMap.class, "commit"));

  public DirectoryMap(long initialCapacity, float minLoadFactor, float maxLoadFactor) {
    this.workingBuffers = new InternalBuffers(initialCapacity, minLoadFactor, maxLoadFactor);
    this.publishedBuffers = new InternalBuffers(initialCapacity, minLoadFactor, maxLoadFactor);
  }

  public boolean insert(long element, UUID value) {
    if (value == null) {
      throw new IllegalArgumentException("no users without UUIDs allowed in the directory map");
    }
    var success = false;
    synchronized (writeBufLock) {
      success = workingBuffers.insert(element, value);
      if (success) {
        this.modified = true;
      }
    }
    return success;
  }

  public boolean remove(long element) {
    var success = false;
    synchronized (writeBufLock) {
      success = workingBuffers.remove(element);
      if (success) {
        this.modified = true;
      }
    }
    return success;
  }

  @FunctionalInterface
  public interface BorrowFunc {
    void consume(ByteBuffer phonesBuffer, ByteBuffer uuidsBuffer, long capacity) throws SgxException;
  }

  /**
   * borrowBuffers passes the currently readable buffers to the given BorrowFunc under a read lock.
   */
  public void borrowBuffers(BorrowFunc func) throws SgxException {
    readBufferRWLock.readLock().lock();
    try {
      func.consume(publishedBuffers.phonesBuffer, publishedBuffers.uuidsBuffer, publishedBuffers.capacity());
    } finally {
      readBufferRWLock.readLock().unlock();
    }
  }

  /**
   * commit swaps the write buffer with the read buffer if there have been changes to the write buffer.
   * @return whether the write and read buffers were swapped
   */
  public boolean commit() {
    try (final Timer.Context ignored = COMMIT_TIMER.time()) {
      synchronized (writeBufLock) {
        if (!modified) {
          return false;
        }
        readBufferRWLock.writeLock().lock();
        try {
          var oldReadBuffers = publishedBuffers;
          this.publishedBuffers = workingBuffers;
          this.workingBuffers = oldReadBuffers;
        } finally {
          readBufferRWLock.writeLock().unlock();
        }

        readBufferRWLock.readLock().lock();
        try {
          workingBuffers.copyFrom(publishedBuffers);
        } finally {
          readBufferRWLock.readLock().unlock();
        }
        this.modified = false;
      }
      return true;
    }
  }

  private static ByteBuffer allocateBuffer(long slotCount, int slotSize) {
    if (slotCount > Integer.MAX_VALUE / slotSize) {
      throw new IllegalArgumentException("hash_table_too_large");
    }
    return ByteBuffer.allocateDirect((int) (slotCount * slotSize));
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
        throw new AssertionError("DirectoryMap full");
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

  private static int hashElement(int slotCount, long element) {
    return (int) (element % slotCount);
  }

  // Annoying that this exists, but used in unit tests prior to the borrowBuffers refactor.
  @VisibleForTesting
  protected long size() {
    readBufferRWLock.readLock().lock();
    try {
      return publishedBuffers.size();
    } finally {
      readBufferRWLock.readLock().unlock();
    }
  }

  private static class InternalBuffers {

    private float minLoadFactor;
    private float maxLoadFactor;
    private long elementCount;
    private long usedSlotCount;
    protected ByteBuffer phonesBuffer;
    protected ByteBuffer uuidsBuffer;

    public InternalBuffers(long initialCapacity, float minLoadFactor, float maxLoadFactor) {
      if (minLoadFactor >= 1.0f || minLoadFactor <= 0.0f) {
        throw new IllegalArgumentException("bad minimum load factor: " + minLoadFactor);
      }
      if (maxLoadFactor >= 1.0f || maxLoadFactor <= 0.0f || maxLoadFactor <= minLoadFactor) {
        throw new IllegalArgumentException("bad maximum load factor: " + maxLoadFactor);
      }
      this.minLoadFactor = minLoadFactor;
      this.maxLoadFactor = maxLoadFactor;
      this.phonesBuffer = allocateBuffer(initialCapacity, KEY_SIZE);
      this.uuidsBuffer = allocateBuffer(initialCapacity, VALUE_SIZE);

      this.elementCount = 0;
      this.usedSlotCount = 0;
    }

    @VisibleForTesting
    public long size() {
      return this.elementCount;
    }

    private long capacity() {
      return phonesBuffer.capacity() / KEY_SIZE;
    }

    public boolean insert(long element, UUID value) {
      if (element <= 0) {
        throw new IllegalArgumentException("bad number: " + element);
      }
      if (elementCount == capacity()) {
        rehash();
      }
      if (elementCount > capacity()) {
        throw new IllegalStateException(String.format("elementCount %d is somehow larger than capacity %d in DirectoryHashMap", elementCount, capacity()));
      }
      long oldSlotValue = addToBuffer(phonesBuffer, uuidsBuffer, element, value);
      var added = oldSlotValue != element;
      if (oldSlotValue == 0) {
        usedSlotCount++;
      }
      if (added) {
        elementCount++;
        if (needsRehash()) {
          rehash();
        }
      }
      return added;
    }


    public boolean remove(long element) {
      if (element <= 0) {
        throw new IllegalArgumentException("bad number: " + element);
      }
      boolean removed = removeFromBuffer(phonesBuffer, uuidsBuffer, element);
      if (removed) {
        elementCount--;
      }
      return removed;
    }

    private boolean needsRehash() {
      long threshold = (long) (capacity() * maxLoadFactor);
      return usedSlotCount >= threshold;
    }

    public void rehash() {
      long newSlotCount = (long) (elementCount / minLoadFactor);
      if (newSlotCount > Integer.MAX_VALUE / KEY_SIZE) {
        newSlotCount = Integer.MAX_VALUE / KEY_SIZE;
      }
      if (newSlotCount < capacity()) {
        newSlotCount = capacity();
      }

      var newBuffer = allocateBuffer(newSlotCount, KEY_SIZE);
      var newValueBuffer = allocateBuffer(newSlotCount, VALUE_SIZE);
      var newBufferUsedSlotCount = 0;


      long curBufferCapacity = phonesBuffer.capacity();
      long curValueBufferCapacity = uuidsBuffer.capacity();
      for (long curBufferIdx = 0, curValueBufferIdx = 0;
           curBufferIdx < curBufferCapacity && curValueBufferIdx < curValueBufferCapacity;
           curBufferIdx += KEY_SIZE, curValueBufferIdx += VALUE_SIZE) {
        long element = phonesBuffer.getLong((int) curBufferIdx);
        if (element > 0) {
          UUID value = new UUID(uuidsBuffer.getLong((int) curValueBufferIdx + 0),
                                uuidsBuffer.getLong((int) curValueBufferIdx + 8));
          long newBufferOldSlotValue = addToBuffer(newBuffer, newValueBuffer, element, value);
          if (newBufferOldSlotValue == 0) {
            newBufferUsedSlotCount++;
          }
        }
      }
      phonesBuffer = newBuffer;
      uuidsBuffer = newValueBuffer;
      usedSlotCount = newBufferUsedSlotCount;
    }

    public void copyFrom(InternalBuffers src) {
      this.minLoadFactor = src.minLoadFactor;
      this.maxLoadFactor = src.maxLoadFactor;
      this.elementCount = src.elementCount;
      this.usedSlotCount = src.usedSlotCount;
      this.phonesBuffer = copy(this.phonesBuffer, src.phonesBuffer);
      this.uuidsBuffer = copy(this.uuidsBuffer, src.uuidsBuffer);
    }

    private static ByteBuffer copy(ByteBuffer dest, ByteBuffer src) {
      if (src.capacity() > dest.capacity()) {
        dest = ByteBuffer.allocateDirect(src.capacity());
      }
      src.rewind();
      dest.put(src);
      src.rewind();
      dest.flip();
      return dest;
    }
  }
}
