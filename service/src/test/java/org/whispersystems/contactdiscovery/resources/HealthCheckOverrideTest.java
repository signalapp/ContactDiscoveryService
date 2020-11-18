package org.whispersystems.contactdiscovery.resources;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.*;

public class HealthCheckOverrideTest {

  @Test
  public void testGoldenPath() throws Exception {
    var override = new AtomicBoolean(true);
    var on = new HealthCheckOverride.HealthCheckOn(override);
    var off = new HealthCheckOverride.HealthCheckOff(override);
    Map<String, List<String>> map = Map.of();

    var out = new ByteArrayOutputStream();
    on.execute(map, new PrintWriter(out));
    assertEquals("Health check was \"on\", set to \"on\"\n", new String(out.toByteArray(),StandardCharsets.UTF_8));
    assertTrue("AtomicBoolean for health check should be still set to true", override.get());

    out = new ByteArrayOutputStream();
    off.execute(map, new PrintWriter(out));
    assertEquals("Health check was \"on\", set to \"off\"\n", new String(out.toByteArray(),StandardCharsets.UTF_8));
    assertFalse("AtomicBoolean for health check should be set to false", override.get());

    out = new ByteArrayOutputStream();
    on.execute(map, new PrintWriter(out));
    assertEquals("Health check was \"off\", set to \"on\"\n", new String(out.toByteArray(),StandardCharsets.UTF_8));
    assertTrue("AtomicBoolean for health check should be set to true", override.get());
  }
}