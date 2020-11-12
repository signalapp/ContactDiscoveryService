package org.whispersystems.contactdiscovery.metrics;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.ScheduledReporter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;

import javax.annotation.Nullable;
import java.net.UnknownHostException;

import io.dropwizard.metrics.BaseReporterFactory;
import org.whispersystems.contactdiscovery.configuration.ConfigParameters;

@JsonTypeName("json")
public class JsonMetricsReporterFactory extends BaseReporterFactory {

  @JsonProperty
  @Nullable
  private String hostname;

  @JsonProperty
  @Nullable
  private Integer port;

  private String getHostname() {
    return ConfigParameters.getString("metrics.hostname").orElse(hostname);
  }

  private Integer getPort() {
    return ConfigParameters.getInteger("metrics.port").orElse(port);
  }

  @Override
  public ScheduledReporter build(MetricRegistry metricRegistry) {
    try {
      return JsonMetricsReporter.forRegistry(metricRegistry)
                                .withHostname(getHostname())
                                .withPort(getPort())
                                .convertRatesTo(getRateUnit())
                                .convertDurationsTo(getDurationUnit())
                                .filter(getFilter())
                                .build();
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(e);
    }
  }
}
