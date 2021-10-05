/*
 * Copyright (C) 2018 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.contactdiscovery.directory;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.MessageAttributeValue;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import io.dropwizard.lifecycle.Managed;
import org.assertj.core.util.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.util.Constants;
import org.whispersystems.contactdiscovery.util.Util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.codahale.metrics.MetricRegistry.name;

public class DirectoryQueueManager implements Managed, Runnable {

  private final Logger logger = LoggerFactory.getLogger(DirectoryQueueManager.class);

  private static final MetricRegistry metricRegistry       = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Meter          invalidMessagesMeter = metricRegistry.meter(name(DirectoryQueueManager.class, "invalidMessages"));

  private static final long RETRY_DELAY_MS = 10_000L;

  private final DirectoryQueue   directoryQueue;
  private final DirectoryManager directoryManager;
  private final AtomicBoolean    running;
  private final Set<String>      messageReceipts;
  private boolean processingEnabled;

  public DirectoryQueueManager(DirectoryQueue directoryQueue, DirectoryManager directoryManager, boolean processingEnabled) {
    this.directoryQueue   = directoryQueue;
    this.directoryManager = directoryManager;
    this.running          = new AtomicBoolean(false);
    this.messageReceipts  = new HashSet<>();
    this.processingEnabled = processingEnabled;
  }

  @Override
  public synchronized void start() {
    if (!processingEnabled) {
      return;
    }
    running.set(true);
    new Thread(this).start();
  }

  @Override
  public void stop() {
    if (!processingEnabled) {
      return;
    }
    running.set(false);
  }

  @Override
  public void run() {
    while (running.get()) {
      try {
        if (!processQueue()) {
          Util.sleep(RETRY_DELAY_MS);
        }
      } catch (Throwable t) {
        logger.warn("error receiving from directory queue: ", t);
        Util.sleep(RETRY_DELAY_MS);
      }
    }
  }

  @VisibleForTesting
  public boolean processQueue() throws DirectoryUnavailableException {
    deleteMessages();

    if (!directoryManager.isConnected()) {
      return false;
    }

    List<Message> messages = directoryQueue.waitForMessages();

    for (Message message : messages) {
      try {
        processMessage(message);
      } catch (InvalidQueueMessageException | InvalidAddressException ex) {
        logger.error("dropping invalid message: ", ex);
        invalidMessagesMeter.mark();
      }

      messageReceipts.add(message.getReceiptHandle());
    }

    return true;
  }

  private void deleteMessages() {
    List<String> deleteMessageReceipts = new ArrayList<>(messageReceipts);
    for (String messageReceipt : deleteMessageReceipts) {
      try {
        directoryQueue.deleteMessage(messageReceipt);
        messageReceipts.remove(messageReceipt);
      } catch (AmazonServiceException ex) {
        if (AmazonServiceException.ErrorType.Client.equals(ex.getErrorType())) {
          logger.error("error deleting from directory queue; skipping: ", ex);
          messageReceipts.remove(messageReceipt);
        } else {
          logger.warn("error deleting from directory queue: ", ex);
        }
      }
    }
  }

  private void processMessage(Message message)
      throws InvalidQueueMessageException, InvalidAddressException, DirectoryUnavailableException
  {
    Map<String, MessageAttributeValue> messageAttributes = message.getMessageAttributes();

    Optional<String> number     = Optional.ofNullable(messageAttributes.get("id"))
                                          .map(MessageAttributeValue::getStringValue)
                                          .filter(numberValue -> !numberValue.isEmpty());
    Optional<String> optUuidString = Optional.ofNullable(messageAttributes.get("uuid"))
                                          .map(MessageAttributeValue::getStringValue)
                                          .filter(uuidValue -> !uuidValue.isEmpty());
    Optional<String> action     = Optional.ofNullable(messageAttributes.get("action"))
                                          .map(MessageAttributeValue::getStringValue);

    if (!number.isPresent()) {
      throw new InvalidQueueMessageException("missing number");
    }

    UUID uuid;
    try {
      uuid = optUuidString.map(UUID::fromString)
                          .orElseThrow(() -> new InvalidQueueMessageException("missing UUID for user"));
    } catch (Exception ex) {
      var uuidString = optUuidString.orElse(null);
      logger.error("invalid uuid: " + uuidString);
      throw new InvalidQueueMessageException("invalid uuid: " + uuidString);
    }

    if (Optional.of("add").equals(action)) {
      directoryManager.addUser(uuid, number.get());
    } else if (Optional.of("delete").equals(action)) {
      directoryManager.removeUser(uuid, number.get());
    } else {
      throw new InvalidQueueMessageException("bad action " + action);
    }
  }

}
