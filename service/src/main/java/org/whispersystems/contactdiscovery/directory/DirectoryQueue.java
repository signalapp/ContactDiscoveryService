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

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.ReceiveMessageRequest;
import com.amazonaws.services.sqs.model.ReceiveMessageResult;
import org.whispersystems.contactdiscovery.configuration.DirectorySqsConfiguration;

import java.util.List;

public class DirectoryQueue {

  private static final int VISIBILITY_TIMEOUT = 30;
  private static final int WAIT_TIME          = 20;

  private static final int RECEIVE_BATCH_SIZE = 10;

  private final AmazonSQS sqs;
  private final String    queueUrl;

  public DirectoryQueue(DirectorySqsConfiguration sqsConfig) {
    AWSCredentials               credentials         = new BasicAWSCredentials(sqsConfig.getAccessKey(), sqsConfig.getAccessSecret());
    AWSStaticCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(credentials);

    this.sqs      = AmazonSQSClientBuilder.standard()
                                          .withRegion(sqsConfig.getQueueRegion())
                                          .withCredentials(credentialsProvider).build();
    this.queueUrl = sqsConfig.getQueueUrl();
  }

  public List<Message> waitForMessages() {
    ReceiveMessageRequest receiveMessageRequest =
        new ReceiveMessageRequest().withQueueUrl(queueUrl)
                                   .withMaxNumberOfMessages(RECEIVE_BATCH_SIZE)
                                   .withVisibilityTimeout(VISIBILITY_TIMEOUT)
                                   .withMessageAttributeNames("All")
                                   .withWaitTimeSeconds(WAIT_TIME);

    ReceiveMessageResult receiveMessageResult = sqs.receiveMessage(receiveMessageRequest);

    return receiveMessageResult.getMessages();
  }

  public void deleteMessage(String messageReceipt) {
    sqs.deleteMessage(queueUrl, messageReceipt);
  }

}
