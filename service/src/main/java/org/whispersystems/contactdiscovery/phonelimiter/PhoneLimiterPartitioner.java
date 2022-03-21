package org.whispersystems.contactdiscovery.phonelimiter;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.whispersystems.contactdiscovery.RateLimitServiceConfiguration.HostRangeConfig;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public interface PhoneLimiterPartitioner {

  Map<String, URI> lookup(String userNumber);

  static List<HostRange> configToHostRanges(List<HostRangeConfig> immutableConfigs) {
    var configs = new ArrayList<HostRangeConfig>(immutableConfigs);
    configs.sort(HostRangeConfig::compareTo);
    if (configs.size() < 1) {
      throw new IllegalArgumentException("empty range list is not allowed");
    }
    var ranges = configs.stream().map((config) -> {
      var start = config.start;
      validateHex(start);
      var end = config.end;
      validateHex(end);
      if (start.compareTo(end) >= 0) {
        throw new IllegalArgumentException(String.format("range (%s, %s) ends before it begins (%s, %s)", start, end, start, end));
      }
      return new HostRange(config.addrs, start.toLowerCase(Locale.ENGLISH), end.toLowerCase(Locale.ENGLISH));
    }).collect(Collectors.toUnmodifiableList());

    var zero = "00000000000000000000000000000000";
    var max = "ffffffffffffffffffffffffffffffff";
    if (!ranges.get(0).start.equals(zero)) {
      throw new IllegalArgumentException(String.format("first rate limit service host range starts at %s, not %s", configs.get(0).start, zero));
    }
    if (!ranges.get(ranges.size() - 1).end.equals(max)) {
      throw new IllegalArgumentException(String.format("last rate limit service host range ends at %s, not %s", configs.get(configs.size() - 1).end, max));
    }
    var it = ranges.iterator();
    var prev = it.next();
    if (prev.start.compareTo(prev.end) >= 0) {
      throw new IllegalArgumentException(String.format("Rate limit service host range at index %d ends before it begins", 0));
    }
    var i = 1;
    while (it.hasNext()) {
      var curr = it.next();
      if (curr.start.compareTo(curr.end) >= 0) {
        throw new IllegalArgumentException(String.format("Rate limit service host range at index %d ends before it begins", i));
      }
      var prevEnd = new BigInteger(prev.end, 16);
      var currStart = new BigInteger(curr.start, 16);
      if (!prevEnd.add(BigInteger.valueOf(1L)).equals(currStart)) {
        throw new IllegalArgumentException(String.format("Rate limit service host range at index %d (%s, %s) is not right up against the host range of index %d (%s, %s)", i - 1, prev.start, prev.end, i, curr.start, curr.end));
      }
      prev = curr;
      i++;
    }
    return ranges;
  }

  static void validateHex(String str) {
    try {
      Hex.decodeHex(str);
    } catch (DecoderException e) {
      throw new RuntimeException(String.format("invalid hex string \"%s\" in host range config", str), e);
    }
  }

  class HostRange {

    public final Map<String, URI> hostIdToAddrs;
    public final String start;
    public final String end;

    public HostRange(List<String> addrs, String start, String end) {
      this.hostIdToAddrs = new HashMap<>();
      MessageDigest hasher;
      try {
        hasher = MessageDigest.getInstance("SHA-256");
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
      for (var addr : addrs) {
        var uri = URI.create(addr);
        var hostId = Hex.encodeHex(hasher.digest(addr.getBytes(StandardCharsets.UTF_8)));
        hostIdToAddrs.put(new String(hostId), uri);
      }
      this.start = start;
      this.end = end;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      HostRange hostRange = (HostRange) o;
      return hostIdToAddrs.equals(hostRange.hostIdToAddrs) &&
             start.equals(hostRange.start) &&
             end.equals(hostRange.end);
    }

    @Override
    public int hashCode() {
      return Objects.hash(hostIdToAddrs, start, end);
    }
  }
}
