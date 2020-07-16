package org.whispersystems.contactdiscovery.phonelimiter;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.whispersystems.contactdiscovery.RateLimitServiceConfiguration.HostRangeConfig;
import org.whispersystems.contactdiscovery.phonelimiter.PhoneLimiterPartitioner.HostRange;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

@RunWith(JUnitParamsRunner.class)
public class RateLimitServicePartitionerTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testGoldenPathConfigToRange() {
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
  public void testGoldenPathMultipleConfigToRange() {
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
  public void testWrongEndConfigToRange() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("last rate limit service host range ends at fffffffffffffffffffffffffffffff1, not ffffffffffffffffffffffffffffffff");
    var configs = List.of(List.of("00000000000000000000000000000000", "fffffffffffffffffffffffffffffff1")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    PhoneLimiterPartitioner.configToHostRanges(configs);
  }

  @Test
  public void testNotHexConfigToRange() {
    thrown.expect(RuntimeException.class);
    thrown.expectMessage("invalid hex string \"0000000000000000000000000000000g\" in host range config");
    var configs = List.of(List.of("0000000000000000000000000000000g", "ffffffffffffffffffffffffffffffff")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    PhoneLimiterPartitioner.configToHostRanges(configs);
  }

  @Test
  public void testOverlapConfigToRange() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("Rate limit service host range at index 0 (00000000000000000000000000000000, bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) is not right up against the host range of index 1 (bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, ffffffffffffffffffffffffffffffff)");
    var configs = List.of(List.of("00000000000000000000000000000000", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), List.of("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ffffffffffffffffffffffffffffffff")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    PhoneLimiterPartitioner.configToHostRanges(configs);
  }

  @Test
  public void testGappedToRange() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("Rate limit service host range at index 0 (00000000000000000000000000000000, bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) is not right up against the host range of index 1 (bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbd, ffffffffffffffffffffffffffffffff)");
    var configs = List.of(List.of("00000000000000000000000000000000", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), List.of("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbd", "ffffffffffffffffffffffffffffffff")).stream().map((list) -> {
      return new HostRangeConfig(List.of("fakehost"), list.get(0), list.get(1));
    }).collect(Collectors.toUnmodifiableList());
    PhoneLimiterPartitioner.configToHostRanges(configs);
  }

  @Test
  @Parameters(method = "parametersToTestLookupGoldenPath")
  public void testLookupGoldenPath(List<HostRange> ranges, String userNumber, Integer rangeIndex) {
    var parter = new RateLimitServicePartitioner(ranges);
    var hosts = parter.lookup(userNumber);
    assertEquals(String.format("userNumber: %s; rangeIndex: %d", userNumber, rangeIndex), ranges.get(rangeIndex).hostIdToAddrs, hosts);
  }

  private Object[] parametersToTestLookupGoldenPath() {
    var hashes = List.of(
        List.of("00000000000000000000000000000000", "33333333333333333333333333333332"),
        List.of("33333333333333333333333333333333", "88888888888888888888888888888888"),
        List.of("88888888888888888888888888888889", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        List.of("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeef", "ffffffffffffffffffffffffffffffff")
    );
    var configs = new ArrayList<HostRangeConfig>();
    for (var i = 0; i < hashes.size(); i++) {
      var conf = hashes.get(i);
      configs.add(new HostRangeConfig(List.of(String.format("host-%d", i)), conf.get(0), conf.get(1)));
    }
    var ranges = PhoneLimiterPartitioner.configToHostRanges(configs);
    return new Object[]{
        new Object[]{ranges, "0123456789", 2},
        new Object[]{ranges,"afa", 2},
        new Object[]{ranges,"ad", 3},
        new Object[]{ranges,"adfasdfas", 0},
        new Object[]{ranges,"akaaaacdae", 1}
    };
  }

  @Test
  public void testLookupSingleConfigGoldenPath() {
    var configs = List.of(new HostRangeConfig(List.of("host-0"), "00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff"));
    var ranges = PhoneLimiterPartitioner.configToHostRanges(configs);
    var parter = new RateLimitServicePartitioner(ranges);
    var inputs = List.of("asdfsa", "qq", "badf");
    for (var input : inputs) {
      // No throws should be seen here.
      var hosts = parter.lookup(input);
      assertEquals(ranges.get(0).hostIdToAddrs, hosts);
    }
  }
}