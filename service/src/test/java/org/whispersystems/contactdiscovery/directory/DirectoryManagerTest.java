package org.whispersystems.contactdiscovery.directory;

import com.google.common.base.Optional;
import com.google.protobuf.ByteString;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.whispersystems.contactdiscovery.providers.RedisClientFactory;
import org.whispersystems.dispatch.redis.PubSubConnection;
import org.whispersystems.dispatch.redis.PubSubReply;

import java.io.IOException;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.ScanResult;

public class DirectoryManagerTest {

  private RedisClientFactory redisClientFactory;
  private PubSubConnection   pubSubConnection;
  private JedisPool          jedisPool;
  private Jedis              jedis;
  private DirectoryHashSet   directoryHashSet;

  private LinkedBlockingQueue<PubSubReply> queue = new LinkedBlockingQueue<>();

  @Before
  public void setup() throws IOException {
    redisClientFactory = mock(RedisClientFactory.class);
    pubSubConnection   = mock(PubSubConnection.class);
    jedisPool          = mock(JedisPool.class);
    directoryHashSet   = mock(DirectoryHashSet.class);
    jedis              = mock(Jedis.class);

    when(redisClientFactory.getRedisClientPool()).thenReturn(jedisPool);
    when(jedisPool.getResource()).thenReturn(jedis);
    when(jedis.scriptLoad(anyString())).thenReturn("fakesha");
    when(redisClientFactory.connect()).thenReturn(pubSubConnection);

    when(pubSubConnection.read()).thenAnswer(new Answer<PubSubReply>() {
      @Override
      public PubSubReply answer(InvocationOnMock invocationOnMock) throws Throwable {
        return queue.take();
      }
    });
  }


  @Test
  public void testAdd() throws Exception {
    ScanResult<String> scanResult = new ScanResult<>("0".getBytes(),
                                                     new LinkedList<String>() {{
                                                       add("+14152222222");
                                                       add("+14151111111");
                                                     }});

    when(jedis.sscan(anyString(), anyString())).thenReturn(scanResult);

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryHashSet);
    directoryManager.start();

    verify(directoryHashSet).add(eq(Long.parseLong("14152222222")));
    verify(directoryHashSet).add(eq(Long.parseLong("14151111111")));
    verifyNoMoreInteractions(directoryHashSet);

    verify(pubSubConnection).subscribe(eq("signal_address_update"));

    queue.add(new PubSubReply(PubSubReply.Type.MESSAGE,
                              "signal_address_update",
                              Optional.of(DirectoryProtos.PubSubMessage.newBuilder()
                                                                       .setType(DirectoryProtos.PubSubMessage.Type.ADDED)
                                                                       .setContent(ByteString.copyFrom("+14153333333".getBytes()))
                                                                       .build().toByteArray())));

    Thread.sleep(200);

    verify(directoryHashSet).add(eq(Long.parseLong("14153333333")));

    directoryManager.addAddress("+14154444444");

    verify(directoryHashSet).add(eq(Long.parseLong("14154444444")));
    verify(jedis).sadd(eq("signal_addresses::1"), eq("+14154444444"));
//    verify(jedis).publish(eq("signal_address_update".getBytes()), any());

  }

}
