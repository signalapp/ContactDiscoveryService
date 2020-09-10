package org.whispersystems.contactdiscovery.resources;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import org.whispersystems.contactdiscovery.util.Constants;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static com.codahale.metrics.MetricRegistry.name;

public class RequestLimiterFilter implements ContainerRequestFilter {
  private static final MetricRegistry REGISTRY     = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Meter REQUEST_LIMITER_METER = REGISTRY.meter(name(ContactDiscoveryResource.class, "requestLimiter"));

  private final AtomicInteger dropPercent  = new AtomicInteger(0);
  private final AtomicLong    requestCount = new AtomicLong(0);

  public int getAndSet(int newValue) {
    return dropPercent.getAndSet(newValue);
  }

  @Override
  public void filter(ContainerRequestContext containerRequestContext) throws WebApplicationException {
    if (requestCount.getAndIncrement() % 100 < dropPercent.get()) {
      REQUEST_LIMITER_METER.mark();
      throw new WebApplicationException(Response.status(Response.Status.SERVICE_UNAVAILABLE).build());
    }
  }
}
