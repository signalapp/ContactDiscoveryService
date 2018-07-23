package org.whispersystems.contactdiscovery.resources;

import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.Rule;
import org.junit.Test;
import org.whispersystems.contactdiscovery.directory.DirectoryManager;
import org.whispersystems.contactdiscovery.directory.InvalidAddressException;
import org.whispersystems.contactdiscovery.entities.DirectoryReconciliationRequest;
import org.whispersystems.contactdiscovery.mappers.NoSuchEnclaveExceptionMapper;
import org.whispersystems.contactdiscovery.util.AuthHelper;
import org.whispersystems.contactdiscovery.util.SystemMapper;
import org.whispersystems.dropwizard.simpleauth.AuthValueFactoryProvider;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.dropwizard.testing.junit.ResourceTestRule;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

public class DirectoryManagementResourceTest {

  private final DirectoryManager directoryManager = mock(DirectoryManager.class);

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addProvider(AuthHelper.getAuthFilter())
                                                            .addProvider(new AuthValueFactoryProvider.Binder())
                                                            .setMapper(SystemMapper.getMapper())
                                                            .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
                                                            .addProvider(new NoSuchEnclaveExceptionMapper())
                                                            .addResource(new DirectoryManagementResource(directoryManager))
                                                            .build();

  @Test
  public void testDirectoryAdd() throws InvalidAddressException {
    Response response = resources.getJerseyTest()
                                 .target("/v1/directory/+14152222222")
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader("foo", AuthHelper.VALID_SERVER_TOKEN))
                                 .put(Entity.json(""));

    assertEquals(204, response.getStatus());
    verify(directoryManager, times(1)).addAddress("+14152222222");
  }

  @Test
  public void testDirectoryRemove() throws InvalidAddressException {
    Response response = resources.getJerseyTest()
                                 .target("/v1/directory/+14151111111")
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .delete();

    assertEquals(204, response.getStatus());
    verify(directoryManager, times(1)).removeAddress("+14151111111");
  }

  @Test
  public void testDirectoryReconcile() throws InvalidAddressException {
    List<String> addresses = new ArrayList<>();
    addresses.add("+14151111111");

    DirectoryReconciliationRequest reconciliationRequest = new DirectoryReconciliationRequest(addresses);

    Response response = resources.getJerseyTest()
                                 .target("/v1/directory/reconcile/1/1")
                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_TOKEN))
                                 .put(Entity.json(reconciliationRequest));

    assertEquals(204, response.getStatus());
    verify(directoryManager, times(1)).reconcileBucket(1L, 1L, addresses);
  }

}
