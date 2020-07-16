package org.whispersystems.contactdiscovery.phonelimiter;

import com.google.common.base.Preconditions;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class RateLimitServicePartitioner implements PhoneLimiterPartitioner {

  private static final HashFunction MURMUR32 = Hashing.murmur3_128(-376142896);

  private final TreeMap<String, HostRange> ranges;
  private final HashFunction hashFunc;

  public RateLimitServicePartitioner(List<HostRange> rangeList) {
    this(rangeList, MURMUR32);
  }

  public RateLimitServicePartitioner(List<HostRange> rangeList, HashFunction hashFunc) {
    Preconditions.checkArgument(rangeList.size() > 0,
                                "RateLimitServicePartitioner needs at least one range to talk to");
    this.ranges = new TreeMap<>();
    for (var i = 0; i < rangeList.size(); i++) {
      var range = rangeList.get(i);
      Preconditions.checkArgument(range.hostIdToAddrs.size() > 0,
                                  String.format("RateLimitServicePartitioner needs at least one host to talk to in each range but range at index %d doesn't", i));
      ranges.put(range.end, range);
    }
    this.hashFunc = hashFunc;
  }

  @Override
  public Map<String, URI> lookup(String userNumber) {
    var hashed = hashFunc.newHasher().putString(userNumber, StandardCharsets.UTF_8).hash().toString();
    var rangeEntry = ranges.ceilingEntry(hashed);
    if (rangeEntry == null) {
      throw new RuntimeException("Hash function didn't work correctly. A code bug.");
    }
    return rangeEntry.getValue().hostIdToAddrs;
  }

}
