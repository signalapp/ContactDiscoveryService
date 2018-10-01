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

import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.MessageAttributeValue;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class DirectoryQueueManagerTest {

  private final DirectoryQueue   directoryQueue   = mock(DirectoryQueue.class);
  private final DirectoryManager directoryManager = mock(DirectoryManager.class);
  private final Message          validMessageOne  = mock(Message.class);
  private final Message          validMessageTwo  = mock(Message.class);
  private final Message          badMessageOne    = mock(Message.class);
  private final Message          badMessageTwo    = mock(Message.class);

  @Before
  public void setup() {
    when(validMessageOne.getMessageAttributes()).thenReturn(createMessageAttributes("+14085550001", "add"));
    when(validMessageOne.getReceiptHandle()).thenReturn("validMessageOne");
    when(validMessageTwo.getMessageAttributes()).thenReturn(createMessageAttributes("+14085550002", "delete"));
    when(validMessageTwo.getReceiptHandle()).thenReturn("validMessageTwo");
    when(badMessageOne.getMessageAttributes()).thenReturn(createMessageAttributes("+14085550003", ""));
    when(badMessageOne.getReceiptHandle()).thenReturn("badMessageOne");
    when(badMessageTwo.getMessageAttributes()).thenReturn(createMessageAttributes("", "add"));
    when(badMessageTwo.getReceiptHandle()).thenReturn("badMessageTwo");

    when(directoryQueue.waitForMessages()).thenReturn(Arrays.asList(validMessageOne, validMessageTwo, badMessageOne, badMessageTwo));

    when(directoryManager.isConnected()).thenReturn(true);
  }

  @Test
  public void testProcessQueue() throws Exception {
    DirectoryQueueManager queueManager = new DirectoryQueueManager(directoryQueue, directoryManager);

    boolean processedQueueOne = queueManager.processQueue();

    when(directoryQueue.waitForMessages()).thenReturn(Collections.emptyList());

    boolean processedQueueTwo   = queueManager.processQueue();
    boolean processedQueueThree = queueManager.processQueue();

    assertThat(processedQueueOne).isEqualTo(true);
    assertThat(processedQueueTwo).isEqualTo(true);
    assertThat(processedQueueThree).isEqualTo(true);

    verify(directoryQueue).deleteMessage(eq("validMessageOne"));
    verify(directoryQueue).deleteMessage(eq("validMessageTwo"));
    verify(directoryQueue).deleteMessage(eq("badMessageOne"));
    verify(directoryQueue).deleteMessage(eq("badMessageTwo"));

    verify(directoryQueue, times(3)).waitForMessages();

    verify(directoryManager, times(3)).isConnected();
    verify(directoryManager).addAddress(eq(validMessageOne.getMessageAttributes().get("id").getStringValue()));
    verify(directoryManager).removeAddress(eq(validMessageTwo.getMessageAttributes().get("id").getStringValue()));

    verifyNoMoreInteractions(directoryQueue);
    verifyNoMoreInteractions(directoryManager);
  }

  @Test
  public void testDirectoryManagerDisconnected() throws Exception {
    when(directoryManager.isConnected()).thenReturn(false);

    DirectoryQueueManager queueManager = new DirectoryQueueManager(directoryQueue, directoryManager);

    boolean processedQueue = queueManager.processQueue();

    assertThat(processedQueue).isEqualTo(false);

    verify(directoryManager).isConnected();

    verifyNoMoreInteractions(directoryQueue);
    verifyNoMoreInteractions(directoryManager);
  }

  private static Map<String, MessageAttributeValue> createMessageAttributes(String id, String action) {
    Map<String, MessageAttributeValue> attributes = new HashMap<>();
    attributes.put("id", new MessageAttributeValue().withStringValue(id));
    attributes.put("action", new MessageAttributeValue().withStringValue(action));
    return attributes;
  }
}
