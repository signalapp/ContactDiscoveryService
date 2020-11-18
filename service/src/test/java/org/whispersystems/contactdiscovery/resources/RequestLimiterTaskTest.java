package org.whispersystems.contactdiscovery.resources;

import org.junit.Test;

import javax.ws.rs.WebApplicationException;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class RequestLimiterTaskTest {

  @Test
  public void testGoldenPath() throws Exception {
    RequestLimiterFilter requestLimiterFilter = new RequestLimiterFilter();
    RequestLimiterTask requestLimiterTask     = new RequestLimiterTask(requestLimiterFilter);

    var map100 = Map.of("percent", List.of("100"));
    var map50 = Map.of("percent", List.of("50"));
    var map0 = Map.of("percent", List.of("0"));

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    requestLimiterTask.execute(map100, new PrintWriter(output));
    assertEquals("Request Drop Percent was \"0\", set to \"100\"\n", new String(output.toByteArray(),StandardCharsets.UTF_8));
    assertEquals(100, requestLimiterFilter.getAndSet(0));

    output = new ByteArrayOutputStream();
    requestLimiterTask.execute(map50, new PrintWriter(output));
    assertEquals("Request Drop Percent was \"0\", set to \"50\"\n", new String(output.toByteArray(),StandardCharsets.UTF_8));
    assertEquals(50, requestLimiterFilter.getAndSet(0));

    output = new ByteArrayOutputStream();
    requestLimiterTask.execute(map0, new PrintWriter(output));
    assertEquals("Request Drop Percent was \"0\", set to \"0\"\n", new String(output.toByteArray(),StandardCharsets.UTF_8));
    assertEquals(0, requestLimiterFilter.getAndSet(0));

  }

  @Test
  public void testInvalidInput() throws Exception {
    RequestLimiterFilter requestLimiterFilter = new RequestLimiterFilter();
    RequestLimiterTask requestLimiterTask     = new RequestLimiterTask(requestLimiterFilter);

    try {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      // Empty map
      Map<String, List<String>> mapParameterMissing = Map.of();
      requestLimiterTask.execute(mapParameterMissing, new PrintWriter(output));
      fail("Missing exception for missing 'percent' parameter");
    } catch (RequestLimiterTaskException e) {
      assertEquals("missing 'percent' parameter", e.getMessage());
    }

    try {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      // Non-empty map, but without valid key
      var mapParameterMissing = Map.of("uninteresting-key", List.of("not-an-integer"));
      requestLimiterTask.execute(mapParameterMissing, new PrintWriter(output));
      fail("Missing exception for missing 'percent' parameter");
    } catch (RequestLimiterTaskException e) {
      assertEquals("missing 'percent' parameter", e.getMessage());
    }

    try {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      // Non-empty map, valid key, but invalid integer value
      var mapParameterMissing = Map.of("percent", List.of("not-an-integer"));
      requestLimiterTask.execute(mapParameterMissing, new PrintWriter(output));
      fail("Missing exception for unable to parse integer string parameter");
    } catch (RequestLimiterTaskException e) {
      assertEquals("unable to parse 'percent' parameter as integer: For input string: \"not-an-integer\"", e.getMessage());
    }

    try {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      // Non-empty map, valid key, but with out of bounds integer value
      var mapParameterMissing = Map.of("percent", List.of("-1"));
      requestLimiterTask.execute(mapParameterMissing, new PrintWriter(output));
      fail("Missing exception for percent parameter out of bounds");
    } catch (RequestLimiterTaskException e) {
      assertEquals("percent parameter out of bounds: -1", e.getMessage());
    }

    try {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      // Non-empty map, valid key, but with out of bounds integer value
      var mapParameterMissing = Map.of("percent", List.of("101"));
      requestLimiterTask.execute(mapParameterMissing, new PrintWriter(output));
      fail("Missing exception for percent parameter out of bounds");
    } catch (RequestLimiterTaskException e) {
      assertEquals("percent parameter out of bounds: 101", e.getMessage());
    }
  }

  private int tryRequestLimit(int dropPercent, int iterations) {
    RequestLimiterFilter requestLimiterFilter = new RequestLimiterFilter();
    int dropCount = 0;

    requestLimiterFilter.getAndSet(dropPercent);
    for (int i = 0; i < iterations; i++) {
      try {
        requestLimiterFilter.filter(null);
      } catch (WebApplicationException e) {
        dropCount++;
      }
    }
    return dropCount;
  }

  @Test
  public void testRequestLimiterRandom() {
    int iterations = 1973;
    assertEquals(0, tryRequestLimit(0, 1000));
    assertEquals(iterations, tryRequestLimit(100, iterations));

    int dropPercent = 25;
    int dropCount = tryRequestLimit(dropPercent, iterations);
    assertEquals(dropPercent * (iterations / 100) + Math.min(dropPercent, Integer.remainderUnsigned(iterations, 100)), dropCount);
  }
}