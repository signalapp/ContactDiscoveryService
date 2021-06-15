package org.whispersystems.contactdiscovery.directory;

import com.google.protobuf.ByteString;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.whispersystems.contactdiscovery.providers.RedisClientFactory;
import org.whispersystems.contactdiscovery.util.NativeUtils;
import org.whispersystems.dispatch.redis.PubSubConnection;
import org.whispersystems.dispatch.redis.PubSubReply;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.ScanResult;
import redis.clients.jedis.Tuple;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
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

public class DirectoryManagerIntegrationTest {
  @BeforeClass
  public static void setupClass() throws Exception {
    NativeUtils.loadNativeResource("/enclave-jni.so");
  }

  private final RedisClientFactory      redisClientFactory      = mock(RedisClientFactory.class);
  private final PubSubConnection        pubSubConnection        = mock(PubSubConnection.class);
  private final JedisPool               jedisPool               = mock(JedisPool.class);
  private final Jedis                   jedis                   = mock(Jedis.class);
  private final DirectoryCache          directoryCache          = mock(DirectoryCache.class);
  private final DirectoryMapNative directoryMap = mock(DirectoryMapNative.class);
  private final DirectoryMapFactory directoryMapFactory = mock(DirectoryMapFactory.class);
  private final DirectoryPeerManager directoryPeerManager = mock(DirectoryPeerManager.class);

  private final Pair<UUID, String> validUserOne   = Pair.of(UUID.fromString("1447ea61-f636-42b2-b6d2-97aa73760a60"), "+14151111111");
  private final Pair<UUID, String> validUserTwo   = Pair.of(UUID.fromString("37ef986f-ee35-454c-97a3-9d16855d4ebc"), "+14152222222");
  private final Pair<UUID, String> validUserThree = Pair.of(UUID.fromString("e29272d9-4146-45bf-b58f-f8fbf4597fc5"), "+14153333333");

  private ScanResult<Tuple>              addressesScanResult;
  private ScanResult<Pair<UUID, String>> usersScanResult;

  private LinkedBlockingQueue<PubSubReply> queue = new LinkedBlockingQueue<>();

  @Before
  public void setup() throws IOException {
    addressesScanResult = new ScanResult<>("0".getBytes(), Arrays.asList(mockTuple("+14152222222"), mockTuple("+14151111111")));
    usersScanResult     = new ScanResult<>("0".getBytes(), Arrays.asList(validUserTwo, validUserOne));

    when(redisClientFactory.getRedisClientPool()).thenReturn(jedisPool);
    when(jedisPool.getResource()).thenReturn(jedis);
    when(jedis.scriptLoad(anyString())).thenReturn("fakesha");
    when(redisClientFactory.connect()).thenReturn(pubSubConnection);

    when(directoryMapFactory.create(anyLong())).thenReturn(directoryMap);

    when(directoryCache.isUserSetBuilt(any())).thenReturn(true);
    when(directoryCache.getAllUsers(any(), any(), anyInt())).thenReturn(new ScanResult<>("0", Collections.emptyList()));

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
    when(directoryCache.isUserSetBuilt(any())).thenReturn(false);
    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryMapFactory, directoryPeerManager, true);
    directoryManager.start();
    directoryManager.borrow((map) -> {
      // Never called.
    });
  }

  @Test
  public void testAdd() throws Exception {
    when(directoryCache.getAllUsers(any(), any(), anyInt())).thenReturn(usersScanResult);

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryMapFactory, directoryPeerManager , true);
    assertThat(directoryManager).isNotNull();
    directoryManager.start();

    verify(directoryMap).insert(eq(Long.parseLong("14152222222")), eq(validUserTwo.getLeft()));
    verify(directoryMap).insert(eq(Long.parseLong("14151111111")), eq(validUserOne.getLeft()));
    verify(directoryMap).commit();

    verifyNoMoreInteractions(directoryMap);

    verify(pubSubConnection).subscribe(eq("signal_address_update"));

    byte[] pubSubMessageOne = DirectoryProtos.PubSubMessage.newBuilder()
                                                           .setType(DirectoryProtos.PubSubMessage.Type.ADDED_USER)
                                                           .setContent(ByteString.copyFrom("e29272d9-4146-45bf-b58f-f8fbf4597fc5:+14153333333".getBytes()))
                                                           .build()
                                                           .toByteArray();
    byte[] pubSubMessageTwo = DirectoryProtos.PubSubMessage.newBuilder()
                                                           .setType(DirectoryProtos.PubSubMessage.Type.ADDED)
                                                           .setContent(ByteString.copyFrom("+14154444444".getBytes()))
                                                           .build()
                                                           .toByteArray();

    queue.add(new PubSubReply(PubSubReply.Type.MESSAGE,
                              "signal_address_update",
                              com.google.common.base.Optional.of(pubSubMessageOne)));
    queue.add(new PubSubReply(PubSubReply.Type.MESSAGE,
                              "signal_address_update",
                              com.google.common.base.Optional.of(pubSubMessageTwo)));

    Thread.sleep(200);

    verify(directoryMap).insert(eq(Long.parseLong("14153333333")), eq(UUID.fromString("e29272d9-4146-45bf-b58f-f8fbf4597fc5")));

    directoryManager.addUser(UUID.fromString("37ef986f-ee35-454c-97a3-9d16855d4ebc"), "+14155555555");

    verify(directoryMap).insert(eq(Long.parseLong("14155555555")), eq(UUID.fromString("37ef986f-ee35-454c-97a3-9d16855d4ebc")));
    verify(directoryCache).addUser(any(), eq(UUID.fromString("37ef986f-ee35-454c-97a3-9d16855d4ebc")), eq("+14155555555"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testAddNullUUID() throws Exception {
    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryMapFactory, directoryPeerManager, true);
    directoryManager.start();
    directoryManager.addUser(null, "+14155555555");
  }

  private void reconcileAll(boolean enableReconciliation) throws Exception {
    when(directoryCache.getAllUsers(any(), any(), anyInt())).thenReturn(usersScanResult);

    List<Pair<UUID, String>> addressList = Arrays.asList(validUserOne, validUserTwo);
    when(directoryCache.getUsersInRange(any(), eq(Optional.empty()), eq(Optional.empty()))).thenReturn(addressList);

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryMapFactory, directoryPeerManager, enableReconciliation);
    directoryManager.start();
    boolean reconciled = directoryManager.reconcile(Optional.empty(), Optional.empty(), Arrays.asList(validUserOne));

    assertThat(reconciled).isEqualTo(!enableReconciliation);

    verify(directoryCache).isUserSetBuilt(any());

    verify(directoryCache, atLeast(0)).getUserCount(any());
    verify(directoryCache).getAllUsers(any(), any(), anyInt());
    verify(jedis, atLeast(0)).publish((byte[]) any(), (byte[]) any());
    verify(jedis, atLeastOnce()).close();

    verifyNoMoreInteractions(directoryCache);
    verifyNoMoreInteractions(jedis);
  }

  @Test
  public void testReconcileAll() throws Exception {
    reconcileAll(true);
  }

  @Test
  public void testReconcileDisable() throws Exception {
    reconcileAll(false);
  }

  @Test
  public void testReconcileRange() throws Exception {
    when(directoryCache.getAllUsers(any(), any(), anyInt())).thenReturn(usersScanResult);

    when(directoryCache.getUsersInRange(any(), eq(Optional.empty()), eq(Optional.of(validUserOne.getLeft())))).thenReturn(Arrays.asList(validUserOne));
    when(directoryCache.getUsersInRange(any(), eq(Optional.of(validUserOne.getLeft())), eq(Optional.empty()))).thenReturn(Arrays.asList(validUserTwo));

    DirectoryManager directoryManager = new DirectoryManager(redisClientFactory, directoryCache, directoryMapFactory, directoryPeerManager, true);
    directoryManager.start();
    boolean reconciledOne = directoryManager.reconcile(Optional.empty(), Optional.of(validUserOne.getLeft()), Arrays.asList(validUserOne));

    assertThat(reconciledOne).isEqualTo(true);

    when(directoryCache.getUuidLastReconciled(any())).thenReturn(Optional.of(validUserOne.getLeft()));
    when(directoryCache.addUser(eq(jedis), eq(validUserThree.getLeft()), eq(validUserThree.getRight()))).thenReturn(true);
    boolean reconciledTwo = directoryManager.reconcile(Optional.of(validUserOne.getLeft()), Optional.empty(), Arrays.asList(validUserTwo, validUserThree));

    assertThat(reconciledTwo).isEqualTo(true);

    verify(directoryCache).isUserSetBuilt(any());
    verify(directoryCache).getUsersInRange(any(), eq(Optional.empty()), eq(Optional.of(validUserOne.getLeft())));
    verify(directoryCache).setUuidLastReconciled(any(), eq(Optional.of(validUserOne.getLeft())));

    verify(directoryCache).getUuidLastReconciled(any());
    verify(directoryCache).getUsersInRange(any(), eq(Optional.of(validUserOne.getLeft())), eq(Optional.empty()));
    verify(directoryCache).addUser(any(), eq(validUserThree.getLeft()), eq("+14153333333"));
    verify(directoryCache).setUuidLastReconciled(any(), eq(Optional.empty()));

    verify(directoryCache, atLeast(0)).getUserCount(any());
    verify(directoryCache).getAllUsers(any(), any(), anyInt());
    verify(jedis, atLeastOnce()).publish((byte[]) any(), (byte[]) any());
    verify(jedis, atLeastOnce()).close();

    verifyNoMoreInteractions(directoryCache);
    verifyNoMoreInteractions(jedis);
  }

}
