package org.whispersystems.contactdiscovery.phonelimiter;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.whispersystems.contactdiscovery.RateLimitServiceConfiguration.HostRangeConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

public class RateLimitServicePartitionerTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testGoldenPath() {
    var hashes = List.of(
        List.of("00000000000000000000000000000000", "11111111111111111111111111111110"),
        List.of("11111111111111111111111111111111", "33333333333333333333333333333332"),
        List.of("33333333333333333333333333333333", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        List.of("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeef", "ffffffffffffffffffffffffffffffff")
    );

    var configs = hashes.stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    var hostRanges = PhoneLimiterPartitioner.configToHostRanges(configs);
    assertEquals(4, hostRanges.size());
  }

  @Test
  public void testGoldenPathMultiple() {
    var configs = List.of(List.of("00000000000000000000000000000000", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), List.of("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeef", "ffffffffffffffffffffffffffffffff")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    var hostRanges = PhoneLimiterPartitioner.configToHostRanges(configs);
    assertEquals(2, hostRanges.size());
  }

  @Test
  public void testWrongStart() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("first rate limit service host range starts at 00000000000000000000000000000001, not 00000000000000000000000000000000");
    var configs = List.of(List.of("00000000000000000000000000000001", "ffffffffffffffffffffffffffffffff")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    PhoneLimiterPartitioner.configToHostRanges(configs);
  }

  @Test
  public void testWrongEnd() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("last rate limit service host range ends at fffffffffffffffffffffffffffffff1, not ffffffffffffffffffffffffffffffff");
    var configs = List.of(List.of("00000000000000000000000000000000", "fffffffffffffffffffffffffffffff1")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    PhoneLimiterPartitioner.configToHostRanges(configs);
  }

  @Test
  public void testNotHex() {
    thrown.expect(RuntimeException.class);
    thrown.expectMessage("invalid hex string \"0000000000000000000000000000000g\" in host range config");
    var configs = List.of(List.of("0000000000000000000000000000000g", "ffffffffffffffffffffffffffffffff")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    PhoneLimiterPartitioner.configToHostRanges(configs);
  }

  @Test
  public void testOverlap() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("Rate limit service host range at index 0 (00000000000000000000000000000000, bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) is not right up against the host range of index 1 (bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, ffffffffffffffffffffffffffffffff)");
    var configs = List.of(List.of("00000000000000000000000000000000", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), List.of("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ffffffffffffffffffffffffffffffff")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    PhoneLimiterPartitioner.configToHostRanges(configs);
  }

  @Test
  public void testGapped() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("Rate limit service host range at index 0 (00000000000000000000000000000000, bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) is not right up against the host range of index 1 (bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbd, ffffffffffffffffffffffffffffffff)");
    var configs = List.of(List.of("00000000000000000000000000000000", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), List.of("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbd", "ffffffffffffffffffffffffffffffff")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    PhoneLimiterPartitioner.configToHostRanges(configs);
  }

  @Test
  public void testLookupGoldenPath() {
    var hashes = List.of(
        List.of("00000000000000000000000000000000", "11111111111111111111111111111110"),
        List.of("11111111111111111111111111111111", "33333333333333333333333333333332"),
        List.of("33333333333333333333333333333333", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        List.of("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeef", "ffffffffffffffffffffffffffffffff")
    );
    var configs = new ArrayList<HostRangeConfig>();
    for (var i = 0; i < hashes.size(); i++) {
      var conf = hashes.get(i);
      configs.add(new HostRangeConfig(List.of(String.format("host-%d", i)), conf.get(0), conf.get(1)));
    }
    var ranges = PhoneLimiterPartitioner.configToHostRanges(configs);
    var parter = new RateLimitServicePartitioner(ranges);
    var hosts = parter.lookup("0123456789");
    assertEquals(ranges.get(1).hostIdToAddrs, hosts);
  }
}