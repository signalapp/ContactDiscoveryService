package org.whispersystems.contactdiscovery.directory;

import com.google.protobuf.ByteString;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.whispersystems.contactdiscovery.providers.RedisClientFactory;
import org.whispersystems.dispatch.redis.PubSubConnection;
import org.whispersystems.dispatch.redis.PubSubReply;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.ScanResult;
import redis.clients.jedis.Tuple;

public class DirectoryManagerTest {

  private RedisClientFactory redisClientFactory;
  private PubSubConnection   pubSubConnection;
  private JedisPool          jedisPool;
  private Jedis              jedis;
  private DirectoryHashSet   directoryHashSet;
  private ScanResult<Tuple>  scanResult;

  private LinkedBlockingQueue<PubSubReply> queue = new LinkedBlockingQueue<>();

  @Before
  public void setup() throws IOException {
    redisClientFactory = mock(RedisClientFactory.class);
    pubSubConnection   = mock(PubSubConnection.class);
    jedisPool          = mock(JedisPool.class);
    directoryHashSet   = mock(DirectoryHashSet.class);
    jedis              = mock(Jedis.class);
    scanResult         = new ScanResult<>("0".getBytes(), Arrays.asList(mockTuple("+14152222222"), mockTuple("+14151111111")));

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

  private static Tuple mockTuple(String address) {
    Tuple tuple = mock(Tuple.class);
    when(tuple.getElement()).thenReturn(address);
    return tuple;
  }


  @Test
  public void testAdd() throws Exception {
    when(jedis.zscan(anyString(), anyString())).thenReturn(scanResult);

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryHashSet);
    directoryManager.start();

    verify(directoryHashSet).add(eq(Long.parseLong("14152222222")));
    verify(directoryHashSet).add(eq(Long.parseLong("14151111111")));
    verifyNoMoreInteractions(directoryHashSet);

    verify(pubSubConnection).subscribe(eq("signal_address_update"));

    byte[] pubSubMessage = DirectoryProtos.PubSubMessage.newBuilder()
                                                        .setType(DirectoryProtos.PubSubMessage.Type.ADDED)
                                                        .setContent(ByteString.copyFrom("+14153333333".getBytes()))
                                                        .build()
                                                        .toByteArray();
    queue.add(new PubSubReply(PubSubReply.Type.MESSAGE,
                              "signal_address_update",
                              com.google.common.base.Optional.of(pubSubMessage)));

    Thread.sleep(200);

    verify(directoryHashSet).add(eq(Long.parseLong("14153333333")));

    directoryManager.addAddress("+14154444444");

    verify(directoryHashSet).add(eq(Long.parseLong("14154444444")));
    verify(jedis).zadd(eq("signal_addresses_sorted::1"), eq(0.0), eq("+14154444444"));
//    verify(jedis).publish(eq("signal_address_update".getBytes()), any());

  }

  @Test
  public void testReconcileAll() throws Exception {
    when(jedis.zscan(anyString(), anyString())).thenReturn(scanResult);

    Set<String> addressSet = new HashSet<>(Arrays.asList("+14151111111", "+14152222222"));
    when(jedis.zrangeByLex(eq("signal_addresses_sorted::1"), eq("-"), eq("+"))).thenReturn(addressSet);

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryHashSet);
    directoryManager.start();
    directoryManager.reconcile(Optional.empty(), Optional.empty(), Arrays.asList("+14151111111"));

    verify(jedis).zscan(eq("signal_addresses_sorted::1"), any());
    verify(jedis).zrangeByLex(eq("signal_addresses_sorted::1"), eq("-"), eq("+"));
    verify(jedis).zadd(eq("signal_addresses_sorted::1"), eq(0.0), eq("+14151111111"));
    verify(jedis).zrem(eq("signal_addresses_sorted::1"), eq("+14152222222"));
    verify(jedis, atLeastOnce()).publish((byte[]) any(), (byte[]) any());
    verify(jedis, atLeastOnce()).close();
    verifyNoMoreInteractions(jedis);
  }

  @Test
  public void testReconcileRange() throws Exception {
    when(jedis.zscan(anyString(), anyString())).thenReturn(scanResult);

    Set<String> addressSetOne = new HashSet<>(Arrays.asList("+14151111111"));
    Set<String> addressSetTwo = new HashSet<>(Arrays.asList("+14152222222"));
    when(jedis.zrangeByLex(eq("signal_addresses_sorted::1"), eq("-"), eq("[+14151111111"))).thenReturn(addressSetOne);
    when(jedis.zrangeByLex(eq("signal_addresses_sorted::1"), eq("(+14151111111"), eq("+"))).thenReturn(addressSetTwo);

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryHashSet);
    directoryManager.start();
    directoryManager.reconcile(Optional.empty(), Optional.of("+14151111111"), Arrays.asList("+14151111111"));
    directoryManager.reconcile(Optional.of("+14151111111"), Optional.empty(), Arrays.asList("+14152222222"));

    verify(jedis).zscan(eq("signal_addresses_sorted::1"), any());
    verify(jedis).zrangeByLex(eq("signal_addresses_sorted::1"), eq("-"), eq("[+14151111111"));
    verify(jedis).zrangeByLex(eq("signal_addresses_sorted::1"), eq("(+14151111111"), eq("+"));
    verify(jedis).zadd(eq("signal_addresses_sorted::1"), eq(0.0), eq("+14151111111"));
    verify(jedis).zadd(eq("signal_addresses_sorted::1"), eq(0.0), eq("+14152222222"));
    verify(jedis, atLeastOnce()).publish((byte[]) any(), (byte[]) any());
    verify(jedis, atLeastOnce()).close();
    verifyNoMoreInteractions(jedis);
  }

}
