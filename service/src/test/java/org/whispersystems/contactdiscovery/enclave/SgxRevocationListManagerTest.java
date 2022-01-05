package org.whispersystems.contactdiscovery.enclave;

import org.junit.Test;
import org.whispersystems.contactdiscovery.client.IasVersion;
import org.whispersystems.contactdiscovery.client.IntelClient;

import java.io.IOException;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SgxRevocationListManagerTest {

    @Test
    public void getRevocationList() throws Exception {
        final IntelClient intelClient = mock(IntelClient.class);
        final SgxRevocationListManager sgxRevocationListManager = new SgxRevocationListManager(intelClient);

        {
            final long groupId = 17;
            final byte[] revocationList = new byte[32];

            new Random().nextBytes(revocationList);
            when(intelClient.getSignatureRevocationList(groupId)).thenReturn(revocationList);

            assertThat(sgxRevocationListManager.getRevocationList(groupId)).isEqualTo(revocationList);
        }

        {
            final long groupId = 19;

            when(intelClient.getSignatureRevocationList(groupId)).thenThrow(IOException.class);

            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> sgxRevocationListManager.getRevocationList(groupId));
        }

        {
            final long groupId = 23;

            when(intelClient.getSignatureRevocationList(groupId)).thenThrow(InterruptedException.class);

            assertThatExceptionOfType(InterruptedException.class)
                    .isThrownBy(() -> sgxRevocationListManager.getRevocationList(groupId));
        }
    }
}