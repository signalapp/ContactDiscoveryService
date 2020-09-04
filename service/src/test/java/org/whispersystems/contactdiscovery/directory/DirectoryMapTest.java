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
package org.whispersystems.contactdiscovery.directory;

import org.junit.Before;
import org.junit.Test;
import org.whispersystems.contactdiscovery.enclave.SgxException;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;

public class DirectoryMapTest {

  private final SecureRandom random = new SecureRandom();

  private long randomElement() {
    return Math.abs(random.nextLong());
  }

  private Set<Long> randomElements(long size) {
    HashSet<Long> elements = new HashSet<>();
    while (elements.size() < size) {
      elements.add(randomElement());
    }
    return elements;
  }

  private List<Long> shuffle(Set<Long> elementsSet) {
    List<Long> elementsList = new ArrayList<>(elementsSet);
    for (int elementIndex = 0; elementIndex < elementsList.size() - 1; elementIndex++) {
      long element          = elementsList.get(elementIndex);
      int  swapElementIndex = random.nextInt(elementsList.size() - (elementIndex + 1)) + (elementIndex + 1);
      long swapElement      = elementsList.get(swapElementIndex);
      elementsList.set(elementIndex,     swapElement);
      elementsList.set(swapElementIndex, element);
    }
    return elementsList;
  }

  private static void joinThreads(Collection<Thread> threads) {
    threads.stream().forEach(Thread::start);
    threads.stream().forEach(thread -> {
      try {
        thread.join();
      } catch (InterruptedException ex) {
        throw new AssertionError(ex);
      }
    });
  }

  @Before
  public void setup() {
    random.setSeed(0);
  }

  @Test
  public void testFactory() throws SgxException {
    long  initialCapacity = 1000;
    float minLoadFactor   = 0.75f;
    float maxLoadFactor   = 0.85f;

    var factory = new DirectoryMapFactory(initialCapacity, minLoadFactor, maxLoadFactor);
    var set = factory.create(0);
    set.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      assertThat(capacity).isEqualTo(initialCapacity);
    });
    set = factory.create(1000);
    set.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      assertThat(capacity).isEqualTo((long) (1000 / minLoadFactor));
    });
  }

  @Test
  public void testLoadFactor() throws SgxException {
    final AtomicLong capacity = new AtomicLong(1000);
    float minLoadFactor = 0.75f;
    float maxLoadFactor = 0.85f;

    DirectoryMap directoryMap = new DirectoryMap(capacity.get(), minLoadFactor, maxLoadFactor);
    directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, bufCapacity) -> {
      assertThat(bufCapacity).isEqualTo(capacity.get());
    });

    long addedCount = 0;
    while (addedCount < 10000) {
      long rehashThreshold = (long) (capacity.get() * maxLoadFactor);
      while (addedCount < rehashThreshold - 1) {
        addedCount += 1;
        assertThat(directoryMap.insert(addedCount, UUID.randomUUID())).isTrue();
        assertThat(directoryMap.insert(addedCount, UUID.randomUUID())).isFalse();
      }

      directoryMap.commit();
      assertThat(directoryMap.size()).isEqualTo(addedCount);
      directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, bufCapacity) -> {
        assertThat(bufCapacity).isEqualTo(capacity.get());
      });

      addedCount += 1;
      assertThat(directoryMap.insert(addedCount, UUID.randomUUID())).isTrue();
      assertThat(directoryMap.insert(addedCount, UUID.randomUUID())).isFalse();

      directoryMap.commit();
      assertThat(directoryMap.size()).isEqualTo(addedCount);
      final var added = addedCount;
      directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, bufCapacity) -> {
        assertThat(bufCapacity).isEqualTo((long) (added / minLoadFactor));
        capacity.set(bufCapacity);
      });
    }

    LongStream.rangeClosed(1, addedCount)
              .forEach(removeElement -> {
                assertThat(directoryMap.remove(removeElement)).isTrue();
                assertThat(directoryMap.remove(removeElement)).isFalse();
              });

    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(0);
    directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, bufCapacity) -> {
      assertThat(bufCapacity).isEqualTo(capacity.get());
    });

    LongStream.rangeClosed(1, addedCount)
              .forEach(readdElement -> {
                assertThat(directoryMap.insert(readdElement, UUID.randomUUID())).isTrue();
                assertThat(directoryMap.insert(readdElement, UUID.randomUUID())).isFalse();
              });

    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(addedCount);
    directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, bufCapacity) -> {
      assertThat(bufCapacity).isEqualTo(capacity.get());
    });
  }

  @Test
  public void testDuplicateAdds() {
    DirectoryMap directoryMap = new DirectoryMap(1000, 0.75f, 0.85f);

    Set<Long> randomElements = randomElements(1000);

    randomElements.stream().forEach(addElement -> {
      assertThat(directoryMap.insert(addElement, UUID.randomUUID())).isTrue();
      assertThat(directoryMap.insert(addElement, UUID.randomUUID())).isFalse();
    });
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(1000);
    randomElements.stream().forEach(addElement -> assertThat(directoryMap.insert(addElement, UUID.randomUUID())).isFalse());
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(1000);
  }

  @Test
  public void testRandomAddRemove() {
    DirectoryMap directoryMap = new DirectoryMap(1000, 0.75f, 0.85f);

    Set<Long> randomElements = randomElements(10000);

    randomElements.stream().forEach(addElement -> {
      assertThat(directoryMap.insert(addElement, UUID.randomUUID())).isTrue();
      assertThat(directoryMap.remove(addElement)).isTrue();
      assertThat(directoryMap.remove(addElement)).isFalse();
      assertThat(directoryMap.insert(addElement, UUID.randomUUID())).isTrue();
      assertThat(directoryMap.insert(addElement, UUID.randomUUID())).isFalse();
    });
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(randomElements.size());

    randomElements.stream().forEach(addElement -> assertThat(directoryMap.insert(addElement, UUID.randomUUID())).isFalse());
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(randomElements.size());

    shuffle(randomElements).stream().forEach(removeElement -> assertThat(directoryMap.remove(removeElement)).isTrue());
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(0);

    randomElements.stream().forEach(removeElement -> assertThat(directoryMap.remove(removeElement)).isFalse());
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(0);

    shuffle(randomElements).stream().forEach(addElement -> assertThat(directoryMap.insert(addElement, UUID.randomUUID())).isTrue());
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(randomElements.size());

    Set<Long> moreRandomElements = randomElements(1000);
    Set<Long> allRandomElements  = new HashSet<>(randomElements);
    allRandomElements.addAll(moreRandomElements);

    shuffle(moreRandomElements).stream().forEach(addElement -> assertThat(directoryMap.insert(addElement, UUID.randomUUID())).isTrue());
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(allRandomElements.size());

    shuffle(randomElements).stream().forEach(removeElement -> assertThat(directoryMap.remove(removeElement)).isTrue());
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(moreRandomElements.size());

    shuffle(moreRandomElements).stream().forEach(removeElement -> assertThat(directoryMap.remove(removeElement)).isTrue());
    directoryMap.commit();
    assertThat(directoryMap.size()).isEqualTo(0);

    allRandomElements.stream().forEach(removeElement -> assertThat(directoryMap.remove(removeElement)).isFalse());
  }

  @Test
  public void testRandomParallelAddRemove() {
    var start = System.currentTimeMillis();
    DirectoryMap directoryMap = new DirectoryMap(1000, 0.75f, 0.85f);

    Set<Long> randomElements = randomElements(100000);
    assertThat(directoryMap.size()).isEqualTo(0);
    assertThat(directoryMap.commit()).isFalse();

    List<List<Long>> shuffledRandomElementLists =
        IntStream.range(0, 10)
                 .mapToObj(threadIndex -> shuffle(randomElements))
                 .collect(Collectors.toList());
    joinThreads(
        shuffledRandomElementLists
            .stream()
            .map(shuffledRandomElements -> new Thread(() -> {
                  shuffledRandomElements.stream().forEach(addElement -> directoryMap.insert(addElement, UUID.randomUUID()));
            }, "SetInsertThread"))
            .collect(Collectors.toList())
    );

    assertThat(directoryMap.size()).isEqualTo(0);
    assertThat(directoryMap.commit()).isTrue();
    assertThat(directoryMap.size()).isEqualTo(randomElements.size());

    shuffledRandomElementLists =
        IntStream.range(0, 10)
                 .mapToObj(threadIndex -> shuffle(randomElements))
                 .collect(Collectors.toList());

    joinThreads(
        shuffledRandomElementLists
            .stream()
            .map(shuffledRandomElements -> new Thread(() -> {
              shuffledRandomElements.stream().forEach(addElement -> directoryMap.remove(addElement));
            }, "SetRemoveThread"))
            .collect(Collectors.toList())
    );

    assertThat(directoryMap.size()).isEqualTo(randomElements.size());
    assertThat(directoryMap.commit()).isTrue();
    assertThat(directoryMap.size()).isEqualTo(0);
  }

  @Test
  public void testBuffers() throws SgxException {
    DirectoryMap directoryMap = new DirectoryMap(1000, 0.75f, 0.85f);

    directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      assertThat(phonesBuffer.capacity()).isEqualTo(8000);
      assertThat(uuidsBuffer.capacity()).isEqualTo(16000);
      assertThat(capacity).isEqualTo(1000);
    });

    directoryMap.insert(5, new UUID(6, 1));
    directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      assertThat(phonesBuffer.capacity()).isEqualTo(8000);
      assertThat(uuidsBuffer.capacity()).isEqualTo(16000);
      assertThat(capacity).isEqualTo(1000);
      long[] phoneLongs = getLongsFromByteBuffer(phonesBuffer);
      assertThat(phoneLongs[5]).isEqualTo(0);
      var uuidsLongs = getLongsFromByteBuffer(uuidsBuffer);
      assertThat(uuidsLongs[10]).isEqualTo(0);
      assertThat(uuidsLongs[11]).isEqualTo(0);
    });

    directoryMap.commit();

    directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      assertThat(phonesBuffer.capacity()).isEqualTo(8000);
      long[] phoneLongs = getLongsFromByteBuffer(phonesBuffer);
      assertThat(phoneLongs[5]).isEqualTo(5);

      assertThat(uuidsBuffer.capacity()).isEqualTo(16000);
      var uuidsLongs = getLongsFromByteBuffer(uuidsBuffer);
      assertThat(uuidsLongs[10]).isEqualTo(6);
      assertThat(uuidsLongs[11]).isEqualTo(1);
      assertThat(capacity).isEqualTo(1000);
    });

    directoryMap.insert(7, new UUID(8, 2));
    directoryMap.commit();
    directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      assertThat(phonesBuffer.capacity()).isEqualTo(8000);
      long[] phoneLongs = getLongsFromByteBuffer(phonesBuffer);
      assertThat(phoneLongs[5]).isEqualTo(5);
      assertThat(phoneLongs[7]).isEqualTo(7);

      assertThat(uuidsBuffer.capacity()).isEqualTo(16000);
      var uuidsLongs = getLongsFromByteBuffer(uuidsBuffer);
      assertThat(uuidsLongs[10]).isEqualTo(6);
      assertThat(uuidsLongs[11]).isEqualTo(1);
      assertThat(uuidsLongs[14]).isEqualTo(8);
      assertThat(uuidsLongs[15]).isEqualTo(2);
      assertThat(capacity).isEqualTo(1000);
    });

    directoryMap.remove(5);

    directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      long[] phoneLongs = getLongsFromByteBuffer(phonesBuffer);
      assertThat(phoneLongs[5]).isEqualTo(5);
    });

    directoryMap.commit();
    directoryMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      long[] phoneLongs = getLongsFromByteBuffer(phonesBuffer);
      assertThat(phoneLongs[5]).isEqualTo(-1);
      assertThat(phoneLongs[7]).isEqualTo(7);
      var uuidsLongs = getLongsFromByteBuffer(uuidsBuffer);
      assertThat(uuidsLongs[10]).isEqualTo(0);
      assertThat(uuidsLongs[11]).isEqualTo(0);
      assertThat(uuidsLongs[14]).isEqualTo(8);
      assertThat(uuidsLongs[15]).isEqualTo(2);
    });
  }

  @Test(expected = IllegalArgumentException.class)
  public void testUuidRequired() {
    var directoryMap = new DirectoryMap(1000, 0.75f, 0.85f);
    directoryMap.insert(1, null);
  }
  private long[] getLongsFromByteBuffer(ByteBuffer buffer) {
    var longBuf = buffer.asLongBuffer();
    var longs = new long[longBuf.capacity()];
    longBuf.get(longs);
    return longs;
  }
}
