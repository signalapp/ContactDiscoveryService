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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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
    final int initialCapacity = 1000;

    var factory = new DirectoryMapFactory(initialCapacity);
    var set = factory.create();
    set.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> assertThat(capacity).isEqualTo(initialCapacity));
  }

  @Test
  public void testDuplicateAdds() {
    DirectoryMap directoryMap = new DirectoryMap(2_000);

    Set<Long> randomElements = randomElements(1_000);

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
    DirectoryMap directoryMap = new DirectoryMap(20_000);

    Set<Long> randomElements = randomElements(10_000);

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
    DirectoryMap directoryMap = new DirectoryMap(110_000);

    Set<Long> randomElements = randomElements(100_000);
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
    DirectoryMap directoryMap = new DirectoryMap(1000);

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

  @Test
  public void serializeEmptyBuffers() throws IOException, SgxException {
    var originalMap = new DirectoryMap(1000);
    var outputStream = new ByteArrayOutputStream();
    originalMap.write(outputStream);
    var inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    var deserializedMap = DirectoryMap.read(inputStream);

    deserializedMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      assertThat(phonesBuffer.capacity()).isEqualTo(8000);
      assertThat(uuidsBuffer.capacity()).isEqualTo(16000);
      assertThat(capacity).isEqualTo(1000);

      long[] phoneLongs = getLongsFromByteBuffer(phonesBuffer);
      assertThat(phoneLongs[0]).isEqualTo(0);
      assertThat(phoneLongs[1]).isEqualTo(0);
      var uuidsLongs = getLongsFromByteBuffer(uuidsBuffer);
      assertThat(uuidsLongs[0]).isEqualTo(0);
      assertThat(uuidsLongs[1]).isEqualTo(0);
    });

    // Confirm that the deserialized map can still add numbers and read them back
    deserializedMap.insert(5, new UUID(6, 1));
    deserializedMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      long[] phoneLongs = getLongsFromByteBuffer(phonesBuffer);
      assertThat(phoneLongs[5]).isEqualTo(0);
      var uuidsLongs = getLongsFromByteBuffer(uuidsBuffer);
      assertThat(uuidsLongs[10]).isEqualTo(0);
      assertThat(uuidsLongs[11]).isEqualTo(0);
    });

    deserializedMap.commit();
    deserializedMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      assertThat(phonesBuffer.capacity()).isEqualTo(8000);
      long[] phoneLongs = getLongsFromByteBuffer(phonesBuffer);
      assertThat(phoneLongs[5]).isEqualTo(5);

      assertThat(uuidsBuffer.capacity()).isEqualTo(16000);
      var uuidsLongs = getLongsFromByteBuffer(uuidsBuffer);
      assertThat(uuidsLongs[10]).isEqualTo(6);
      assertThat(uuidsLongs[11]).isEqualTo(1);
      assertThat(capacity).isEqualTo(1000);
    });
  }

  @Test
  public void serializeBuffersWithData() throws IOException, SgxException {
    var originalMap = new DirectoryMap(1000);
    originalMap.insert(5, new UUID(6, 1));
    originalMap.commit();

    var outputStream = new ByteArrayOutputStream();
    originalMap.write(outputStream);
    var inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    var deserializedMap = DirectoryMap.read(inputStream);
    deserializedMap.borrowBuffers((phonesBuffer, uuidsBuffer, capacity) -> {
      assertThat(phonesBuffer.capacity()).isEqualTo(8000);
      long[] phoneLongs = getLongsFromByteBuffer(phonesBuffer);
      assertThat(phoneLongs[5]).isEqualTo(5);

      assertThat(uuidsBuffer.capacity()).isEqualTo(16000);
      var uuidsLongs = getLongsFromByteBuffer(uuidsBuffer);
      assertThat(uuidsLongs[10]).isEqualTo(6);
      assertThat(uuidsLongs[11]).isEqualTo(1);
      assertThat(capacity).isEqualTo(1000);
    });
  }

  @Test(expected = EOFException.class)
  public void deserializeEmptyBuffers() throws IOException {
    DirectoryMap.read(new ByteArrayInputStream(new byte[0]));
  }

  @Test(expected = EOFException.class)
  public void deserializeTruncatedBuffers() throws IOException {
    var originalMap = new DirectoryMap(1000);
    originalMap.insert(5, new UUID(6, 1));

    var outputStream = new ByteArrayOutputStream();
    originalMap.write(outputStream);
    var serializedData = outputStream.toByteArray();
    var inputStream = new ByteArrayInputStream(serializedData, 0, serializedData.length - 1);
    var deserializedMap = DirectoryMap.read(inputStream);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testUuidRequired() {
    var directoryMap = new DirectoryMap(1000);
    directoryMap.insert(1, null);
  }
  private long[] getLongsFromByteBuffer(ByteBuffer buffer) {
    var longBuf = buffer.asLongBuffer();
    var longs = new long[longBuf.capacity()];
    longBuf.get(longs);
    return longs;
  }
}
