package org.whispersystems.contactdiscovery.client;

import org.junit.Test;

import static org.junit.Assert.*;

public class IasVersionTest {

    @Test
    public void fromVersionNumber() {
        assertEquals(IasVersion.IAS_V3, IasVersion.fromVersionNumber(3));
        assertEquals(IasVersion.IAS_V4, IasVersion.fromVersionNumber(4));
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromVersionNumberUnrecognized() {
        IasVersion.fromVersionNumber(-74);
    }

    @Test
    public void testGetVersionNumber() {
        assertEquals(3, IasVersion.IAS_V3.getVersionNumber());
        assertEquals(4, IasVersion.IAS_V4.getVersionNumber());
    }
}
