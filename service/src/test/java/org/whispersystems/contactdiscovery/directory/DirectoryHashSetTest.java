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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;

public class DirectoryHashSetTest {

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
  public void testFactory() {
    long  initialCapacity = 1000;
    float minLoadFactor   = 0.75f;
    float maxLoadFactor   = 0.85f;

    DirectoryHashSetFactory factory = new DirectoryHashSetFactory(initialCapacity, minLoadFactor, maxLoadFactor);
    assertThat(factory.createDirectoryHashSet(0).capacity()).isEqualTo(initialCapacity);
    assertThat(factory.createDirectoryHashSet(1000).capacity()).isEqualTo((long) (1000 / minLoadFactor));
  }

  @Test
  public void testLoadFactor() {
    long  capacity      = 1000;
    float minLoadFactor = 0.75f;
    float maxLoadFactor = 0.85f;

    DirectoryHashSet directoryHashSet = new DirectoryHashSet(capacity, minLoadFactor, maxLoadFactor);
    assertThat(directoryHashSet.capacity()).isEqualTo(capacity);

    long addedCount = 0;
    while (addedCount < 10000) {
      long rehashThreshold = (long) (capacity * maxLoadFactor);
      while (addedCount < rehashThreshold - 1) {
        addedCount += 1;
        assertThat(directoryHashSet.add(addedCount)).isTrue();
        assertThat(directoryHashSet.add(addedCount)).isFalse();
      }

      assertThat(directoryHashSet.size()).isEqualTo(addedCount);
      assertThat(directoryHashSet.capacity()).isEqualTo(capacity);

      addedCount += 1;
      assertThat(directoryHashSet.add(addedCount)).isTrue();
      assertThat(directoryHashSet.add(addedCount)).isFalse();

      assertThat(directoryHashSet.size()).isEqualTo(addedCount);
      assertThat(directoryHashSet.capacity()).isEqualTo((long) (addedCount / minLoadFactor));
      capacity = directoryHashSet.capacity();
    }

    LongStream.rangeClosed(1, addedCount)
              .forEach(removeElement -> {
                assertThat(directoryHashSet.remove(removeElement)).isTrue();
                assertThat(directoryHashSet.remove(removeElement)).isFalse();
              });

    assertThat(directoryHashSet.size()).isEqualTo(0);
    assertThat(directoryHashSet.capacity()).isEqualTo(capacity);

    LongStream.rangeClosed(1, addedCount)
              .forEach(readdElement -> {
                assertThat(directoryHashSet.add(readdElement)).isTrue();
                assertThat(directoryHashSet.add(readdElement)).isFalse();
              });

    assertThat(directoryHashSet.size()).isEqualTo(addedCount);
    assertThat(directoryHashSet.capacity()).isEqualTo(capacity);
  }

  @Test
  public void testDuplicateAdds() {
    DirectoryHashSet directoryHashSet = new DirectoryHashSet(1000, 0.75f, 0.85f);

    Set<Long> randomElements = randomElements(1000);

    randomElements.stream().forEach(addElement -> {
      assertThat(directoryHashSet.add(addElement)).isTrue();
      assertThat(directoryHashSet.add(addElement)).isFalse();
    });
    randomElements.stream().forEach(addElement -> assertThat(directoryHashSet.add(addElement)).isFalse());
  }

  @Test
  public void testRandomAddRemove() {
    DirectoryHashSet directoryHashSet = new DirectoryHashSet(1000, 0.75f, 0.85f);

    Set<Long> randomElements = randomElements(10000);

    randomElements.stream().forEach(addElement -> {
      assertThat(directoryHashSet.add(addElement)).isTrue();
      assertThat(directoryHashSet.remove(addElement)).isTrue();
      assertThat(directoryHashSet.remove(addElement)).isFalse();
      assertThat(directoryHashSet.add(addElement)).isTrue();
      assertThat(directoryHashSet.add(addElement)).isFalse();
    });
    assertThat(directoryHashSet.size()).isEqualTo(randomElements.size());

    randomElements.stream().forEach(addElement -> assertThat(directoryHashSet.add(addElement)).isFalse());
    assertThat(directoryHashSet.size()).isEqualTo(randomElements.size());

    shuffle(randomElements).stream().forEach(removeElement -> assertThat(directoryHashSet.remove(removeElement)).isTrue());
    assertThat(directoryHashSet.size()).isEqualTo(0);

    randomElements.stream().forEach(removeElement -> assertThat(directoryHashSet.remove(removeElement)).isFalse());
    assertThat(directoryHashSet.size()).isEqualTo(0);

    shuffle(randomElements).stream().forEach(addElement -> assertThat(directoryHashSet.add(addElement)).isTrue());
    assertThat(directoryHashSet.size()).isEqualTo(randomElements.size());

    Set<Long> moreRandomElements = randomElements(1000);
    Set<Long> allRandomElements  = new HashSet<>(randomElements);
    allRandomElements.addAll(moreRandomElements);

    shuffle(moreRandomElements).stream().forEach(addElement -> assertThat(directoryHashSet.add(addElement)).isTrue());
    assertThat(directoryHashSet.size()).isEqualTo(allRandomElements.size());

    shuffle(randomElements).stream().forEach(removeElement -> assertThat(directoryHashSet.remove(removeElement)).isTrue());
    assertThat(directoryHashSet.size()).isEqualTo(moreRandomElements.size());

    shuffle(moreRandomElements).stream().forEach(removeElement -> assertThat(directoryHashSet.remove(removeElement)).isTrue());
    assertThat(directoryHashSet.size()).isEqualTo(0);

    allRandomElements.stream().forEach(removeElement -> assertThat(directoryHashSet.remove(removeElement)).isFalse());
  }

  @Test
  public void testRandomParallelAddRemove() {
    DirectoryHashSet directoryHashSet = new DirectoryHashSet(1000, 0.75f, 0.85f);

    Set<Long> randomElements = randomElements(100000);

    List<List<Long>> shuffledRandomElementLists =
        IntStream.range(0, 10)
                 .mapToObj(threadIndex -> shuffle(randomElements))
                 .collect(Collectors.toList());
    joinThreads(
        shuffledRandomElementLists
            .stream()
            .map(shuffledRandomElements -> new Thread(() -> {
              shuffledRandomElements.stream().forEach(addElement -> directoryHashSet.add(addElement));
            }))
            .collect(Collectors.toList())
    );

    assertThat(directoryHashSet.size()).isEqualTo(randomElements.size());

    shuffledRandomElementLists =
        IntStream.range(0, 10)
                 .mapToObj(threadIndex -> shuffle(randomElements))
                 .collect(Collectors.toList());

    joinThreads(
        shuffledRandomElementLists
            .stream()
            .map(shuffledRandomElements -> new Thread(() -> {
              shuffledRandomElements.stream().forEach(addElement -> directoryHashSet.remove(addElement));
            }))
            .collect(Collectors.toList())
    );

    assertThat(directoryHashSet.size()).isEqualTo(0);
  }

}
