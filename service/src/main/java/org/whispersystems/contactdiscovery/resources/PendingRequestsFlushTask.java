package org.whispersystems.contactdiscovery.resources;

import com.codahale.metrics.annotation.Metered;
import com.google.common.collect.ImmutableMultimap;
import io.dropwizard.servlets.tasks.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.requests.RequestManager;

import java.io.PrintWriter;

public class PendingRequestsFlushTask extends Task {

  private static final Logger LOGGER = LoggerFactory.getLogger(PendingRequestsFlushTask.class);
  private final RequestManager requestManager;

  public PendingRequestsFlushTask(RequestManager requestManager) {
    super("flush-pending-requests");
    this.requestManager = requestManager;
  }

  @Override
  @Metered(name = "flush-pending-requests")
  public void execute(ImmutableMultimap<String, String> parameters, PrintWriter output) {
    int requestCount = requestManager.flushPendingQueues();
    String line = String.format("Flushed \"%d\" pending requests", requestCount);
    LOGGER.info(line);
    output.println(line);
    output.flush();
  }
}
