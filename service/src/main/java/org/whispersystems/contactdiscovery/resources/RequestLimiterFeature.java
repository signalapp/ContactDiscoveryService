package org.whispersystems.contactdiscovery.resources;

import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;

@Provider
public class RequestLimiterFeature implements DynamicFeature {

  private final RequestLimiterFilter requestLimiterFilter;

  public RequestLimiterFeature(RequestLimiterFilter requestLimiterFilter) {
    this.requestLimiterFilter = requestLimiterFilter;
  }

  @Override
  public void configure(ResourceInfo resourceInfo, FeatureContext featureContext) {
    if (resourceInfo.getResourceMethod().getAnnotation(RequestLimiter.class) != null) {
      featureContext.register(requestLimiterFilter);
    }
  }
}
