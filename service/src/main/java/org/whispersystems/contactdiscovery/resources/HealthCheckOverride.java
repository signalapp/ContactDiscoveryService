package org.whispersystems.contactdiscovery.resources;

import com.codahale.metrics.annotation.Metered;
import io.dropwizard.servlets.tasks.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class HealthCheckOverride {

  private static final Logger LOGGER = LoggerFactory.getLogger(HealthCheckOverride.class);

  static void changeHealthCheck(AtomicBoolean healthOverride, boolean newSetting, PrintWriter output) {
    var old = healthOverride.getAndSet(newSetting);
    String line = String.format("Health check was \"%s\", set to \"%s\"",  boolToOnOff(old), boolToOnOff(newSetting));
    LOGGER.info(line);
    output.println(line);
    output.flush();
  }

  private static String boolToOnOff(boolean onoff) {
    if (onoff) {
      return "on";
    }
    return "off";
  }

  private HealthCheckOverride() {
  }

  public static class HealthCheckOn extends Task {

    private final AtomicBoolean healthOverride;

    public HealthCheckOn(AtomicBoolean healthOverride) {
      super("healthcheck/on");
      this.healthOverride = healthOverride;
    }

    @Override @Metered(name = "healthcheck.on")
    public void execute(Map<String, List<String>> parameters, PrintWriter output) throws Exception {
      HealthCheckOverride.changeHealthCheck(healthOverride, true, output);
    }
  }

  public static class HealthCheckOff extends Task {

    private final AtomicBoolean healthOverride;

    public HealthCheckOff(AtomicBoolean healthOverride) {
      super("healthcheck/off");
      this.healthOverride = healthOverride;
    }

    @Override @Metered(name = "healthcheck.off")
    public void execute(Map<String, List<String>> parameters, PrintWriter output) throws Exception {
      HealthCheckOverride.changeHealthCheck(healthOverride, false, output);
    }
  }
}
