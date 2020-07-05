package org.whispersystems.contactdiscovery;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ComparisonChain;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.ArrayList;
import java.util.List;

public class RateLimitServiceConfiguration {

  @JsonProperty
  @NotEmpty
  public List<HostRangeConfig> hostRanges = new ArrayList<>();

  @JsonProperty
  private int connectTimeoutMs = 50;

  @JsonProperty
  private int requestTimeoutMs = 500;

  public List<HostRangeConfig> getHostRanges() {
    return hostRanges;
  }

  public int getConnectTimeoutMs() {
    return connectTimeoutMs;
  }

  public int getRequestTimeoutMs() {
    return requestTimeoutMs;
  }

  public static class HostRangeConfig {

    @JsonProperty
    @NotEmpty
    public List<String> addrs;

    @JsonProperty
    @NotNull
    @Size(min = 32, max = 32)
    public String start;

    @JsonProperty
    @NotNull
    @Size(min = 32, max = 32)
    public String end;

    public HostRangeConfig(List<String> addrs, String start, String end) {
      this.addrs = addrs;
      this.start = start;
      this.end = end;
    }

    public HostRangeConfig() {
    }

    public int compareTo(HostRangeConfig other) {
      return ComparisonChain.start().compare(this.start, other.start).compare(this.end, other.end).result();
    }
  }
}
