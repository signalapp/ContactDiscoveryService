package org.whispersystems.contactdiscovery.phonelimiter;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class AlwaysSuccessfulPhoneRateLimiterTest {

  @Test
  public void testGoldenPath() {
    var limiter = new AlwaysSuccessfulPhoneRateLimiter();
    var mapFut  = limiter.attest(null, null, null, null);
    var map     = mapFut.join();
    assertNotNull(map);
    assertThat(map.size(), is(0));
    map.put("foo", null); // Testing that the map is mutable

    var allowed = limiter.discoveryAllowed(null, null, null, null).join();
    assertTrue(allowed);
  }
}