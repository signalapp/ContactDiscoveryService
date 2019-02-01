package org.whispersystems.contactdiscovery.directory;

import com.google.protobuf.ByteString;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.whispersystems.contactdiscovery.providers.RedisClientFactory;
import org.whispersystems.dispatch.redis.PubSubConnection;
import org.whispersystems.dispatch.redis.PubSubReply;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.ScanResult;
import redis.clients.jedis.Tuple;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class DirectoryManagerTest {

  private final RedisClientFactory      redisClientFactory      = mock(RedisClientFactory.class);
  private final PubSubConnection        pubSubConnection        = mock(PubSubConnection.class);
  private final JedisPool               jedisPool               = mock(JedisPool.class);
  private final Jedis                   jedis                   = mock(Jedis.class);
  private final DirectoryCache          directoryCache          = mock(DirectoryCache.class);
  private final DirectoryHashSet        directoryHashSet        = mock(DirectoryHashSet.class);
  private final DirectoryHashSetFactory directoryHashSetFactory = mock(DirectoryHashSetFactory.class);

  private ScanResult<Tuple>  scanResult;

  private LinkedBlockingQueue<PubSubReply> queue = new LinkedBlockingQueue<>();

  @Before
  public void setup() throws IOException {
    scanResult = new ScanResult<>("0".getBytes(), Arrays.asList(mockTuple("+14152222222"), mockTuple("+14151111111")));

    when(redisClientFactory.getRedisClientPool()).thenReturn(jedisPool);
    when(jedisPool.getResource()).thenReturn(jedis);
    when(jedis.scriptLoad(anyString())).thenReturn("fakesha");
    when(redisClientFactory.connect()).thenReturn(pubSubConnection);

    when(directoryHashSetFactory.createDirectoryHashSet(anyLong())).thenReturn(directoryHashSet);

    when(directoryCache.isDirectoryBuilt(any())).thenReturn(true);
    when(directoryCache.getAllAddresses(any(), any(), anyInt())).thenReturn(new ScanResult<>("0", Collections.emptyList()));

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

  @Test(expected = DirectoryUnavailableException.class)
  public void testGetAddressListDirectoryUnavailable() throws Exception {
    when(directoryCache.isDirectoryBuilt(any())).thenReturn(false);
    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryHashSetFactory);
    directoryManager.start();
    directoryManager.getAddressList();
  }

  @Test
  public void testGetAddressList() throws Exception {
    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryHashSetFactory);
    directoryManager.start();
    directoryManager.getAddressList();
  }

  @Test
  public void testAdd() throws Exception {
    when(directoryCache.getAllAddresses(any(), any(), anyInt())).thenReturn(scanResult);
    when(directoryCache.addAddress(any(), eq("+14154444444"))).thenReturn(true);

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryHashSetFactory);
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
    verify(directoryCache).addAddress(any(), eq("+14154444444"));
//    verify(jedis).publish(eq("signal_address_update".getBytes()), any());

  }

  @Test
  public void testReconcileAll() throws Exception {
    when(directoryCache.getAllAddresses(any(), any(), anyInt())).thenReturn(scanResult);
    when(directoryCache.removeAddress(any(), eq("+14152222222"))).thenReturn(true);

    Set<String> addressSet = new HashSet<>(Arrays.asList("+14151111111", "+14152222222"));
    when(directoryCache.getAddressesInRange(any(), eq(Optional.empty()), eq(Optional.empty()))).thenReturn(addressSet);

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryHashSetFactory);
    directoryManager.start();
    boolean reconciled = directoryManager.reconcile(Optional.empty(), Optional.empty(), Arrays.asList("+14151111111"));

    assertThat(reconciled).isEqualTo(false);

    verify(directoryCache).isDirectoryBuilt(any());

    verify(directoryCache, atLeast(0)).getAddressCount(any());
    verify(directoryCache).getAllAddresses(any(), any(), anyInt());
    verify(jedis, atLeast(0)).publish((byte[]) any(), (byte[]) any());
    verify(jedis, atLeastOnce()).close();

    verifyNoMoreInteractions(directoryCache);
    verifyNoMoreInteractions(jedis);
  }

  @Test
  public void testReconcileRange() throws Exception {
    when(directoryCache.getAllAddresses(any(), any(), anyInt())).thenReturn(scanResult);
    when(directoryCache.addAddress(any(), eq("+14153333333"))).thenReturn(true);

    Set<String> addressSetOne = new HashSet<>(Arrays.asList("+14151111111"));
    Set<String> addressSetTwo = new HashSet<>(Arrays.asList("+14152222222"));
    when(directoryCache.getAddressesInRange(any(), eq(Optional.empty()), eq(Optional.of("+14151111111")))).thenReturn(addressSetOne);
    when(directoryCache.getAddressesInRange(any(), eq(Optional.of("+14151111111")), eq(Optional.empty()))).thenReturn(addressSetTwo);

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryHashSetFactory);
    directoryManager.start();
    boolean reconciledOne = directoryManager.reconcile(Optional.empty(), Optional.of("+14151111111"), Arrays.asList("+14151111111"));

    assertThat(reconciledOne).isEqualTo(true);

    when(directoryCache.getAddressLastReconciled(any())).thenReturn(Optional.of("+14151111111"));
    boolean reconciledTwo = directoryManager.reconcile(Optional.of("+14151111111"), Optional.empty(), Arrays.asList("+14152222222", "+14153333333"));

    assertThat(reconciledTwo).isEqualTo(true);

    verify(directoryCache).isDirectoryBuilt(any());
    verify(directoryCache).getAddressesInRange(any(), eq(Optional.empty()), eq(Optional.of("+14151111111")));
    verify(directoryCache).setAddressLastReconciled(any(), eq(Optional.of("+14151111111")));

    verify(directoryCache).getAddressLastReconciled(any());
    verify(directoryCache).getAddressesInRange(any(), eq(Optional.of("+14151111111")), eq(Optional.empty()));
    verify(directoryCache).addAddress(any(), eq("+14153333333"));
    verify(directoryCache).setAddressLastReconciled(any(), eq(Optional.empty()));

    verify(directoryCache, atLeast(0)).getAddressCount(any());
    verify(directoryCache).getAllAddresses(any(), any(), anyInt());
    verify(jedis, atLeastOnce()).publish((byte[]) any(), (byte[]) any());
    verify(jedis, atLeastOnce()).close();

    verifyNoMoreInteractions(directoryCache);
    verifyNoMoreInteractions(jedis);
  }

}
