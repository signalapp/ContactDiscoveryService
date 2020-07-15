package org.whispersystems.contactdiscovery.limits;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LeakyBucketTest {

  private static final Clock CLOCK = Clock.fixed(Instant.now(), ZoneId.systemDefault());

  @Test
  public void testFull() {
    LeakyBucket leakyBucket = new LeakyBucket(2, 1.0 / 2.0, CLOCK);

    assertTrue(leakyBucket.add(1));
    assertTrue(leakyBucket.add(1));
    assertFalse(leakyBucket.add(1));

    leakyBucket = new LeakyBucket(2, 1.0 / 2.0, CLOCK);

    assertTrue(leakyBucket.add(2));
    assertFalse(leakyBucket.add(1));
    assertFalse(leakyBucket.add(2));
  }

  @Test
  public void testLapseRate() throws IOException {
    ObjectMapper mapper     = new ObjectMapper();
    String       serialized = "{\"bucketSize\":2,\"leakRatePerMillis\":8.333333333333334E-6,\"spaceRemaining\":0,\"lastUpdateTimeMillis\":" + (CLOCK.millis() - TimeUnit.MINUTES.toMillis(2)) + "}";

    LeakyBucket leakyBucket = LeakyBucket.fromSerialized(mapper, serialized, CLOCK);
    assertTrue(leakyBucket.add(1));

    String      serializedAgain  = leakyBucket.serialize(mapper);
    LeakyBucket leakyBucketAgain = LeakyBucket.fromSerialized(mapper, serializedAgain, CLOCK);

    assertFalse(leakyBucketAgain.add(1));
  }

  @Test
  public void testLapseShort() throws Exception {
    ObjectMapper mapper     = new ObjectMapper();
    String       serialized = "{\"bucketSize\":2,\"leakRatePerMillis\":8.333333333333334E-6,\"spaceRemaining\":0,\"lastUpdateTimeMillis\":" + (CLOCK.millis() - TimeUnit.MINUTES.toMillis(1)) + "}";

    LeakyBucket leakyBucket = LeakyBucket.fromSerialized(mapper, serialized, CLOCK);
    assertFalse(leakyBucket.add(1));
  }

  @Test
  public void testDrain() throws Exception {
    ObjectMapper mapper     = new ObjectMapper();
    String       serialized = "{\"bucketSize\":2,\"leakRatePerMillis\":8.333333333333334E-6,\"spaceRemaining\":0,\"lastUpdateTimeMillis\":" + (CLOCK.millis() - TimeUnit.MINUTES.toMillis(1)) + "}";

    assertFalse(LeakyBucket.fromSerialized(mapper, serialized, CLOCK).add(1));
    assertTrue(LeakyBucket.fromSerialized(mapper, serialized, Clock.offset(CLOCK, Duration.ofHours(1))).add(1));
  }
}
