package org.whispersystems.contactdiscovery.resources;

import com.codahale.metrics.annotation.Metered;
import io.dropwizard.servlets.tasks.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintWriter;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class RequestLimiterTask extends Task {

  private static final Logger LOGGER = LoggerFactory.getLogger(RequestLimiterTask.class);
  private final RequestLimiterFilter requestLimiterFilter;

  public RequestLimiterTask(RequestLimiterFilter requestLimiterFiler) {
    super("drop-requests");
    this.requestLimiterFilter = requestLimiterFiler;
  }

  @Override
  @Metered(name = "drop-requests")
  public void execute(Map<String, List<String>> parameters, PrintWriter output) throws Exception {
    int newDropPercent = getDropPercent(parameters);
    int oldDropPercent = requestLimiterFilter.getAndSet(newDropPercent);
    String line = String.format("Request Drop Percent was \"%d\", set to \"%d\"", oldDropPercent, newDropPercent);
    LOGGER.info(line);
    output.println(line);
    output.flush();
  }

  private int getDropPercent(Map<String, List<String>> parameters) throws RequestLimiterTaskException {
    try {
      final int dropPercentValue = parameters.getOrDefault("percent", Collections.emptyList())
          .stream()
          .findFirst()
          .map(Integer::parseInt)
          .orElseThrow(() -> new RequestLimiterTaskException("missing 'percent' parameter"));

      if ((dropPercentValue < 0) || (dropPercentValue > 100)) {
        throw new RequestLimiterTaskException(("percent parameter out of bounds: " + dropPercentValue));
      }
      return dropPercentValue;
    } catch (NumberFormatException e) {
      throw new RequestLimiterTaskException(("unable to parse 'percent' parameter as integer: " + e.getMessage()));
    }
  }
}
