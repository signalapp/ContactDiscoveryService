package org.whispersystems.contactdiscovery.enclave;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.whispersystems.contactdiscovery.util.NativeUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

public class SgxEnclaveIntegrationTest {

  @Test
  public void testGoldenPath() throws SgxException, DecoderException, IOException {
    var mrenclave = "c98e00a4e3ff977a56afefe7362a27e4961e4f19e211febfbb19b897e6b80b15";
    var debugBuild = false;
    var stream = SgxEnclaveIntegrationTest.class.getResourceAsStream("/enclave/current.mrenclave");
    if (stream != null) {
      mrenclave = new String(stream.readAllBytes(), StandardCharsets.UTF_8).trim();
      debugBuild = true;
    }

    NativeUtils.loadNativeResource("/enclave-jni.so");
    File enclaveLibrary = NativeUtils.extractNativeResource("/enclave/" + mrenclave + ".so");
    byte[] spid = Hex.decodeHex("00000000000000000000000000000000");
    SgxEnclave enclave = new SgxEnclave(enclaveLibrary.getAbsolutePath(), mrenclave, debugBuild, spid);
    enclave.start();
    enclave.setCurrentQuote();
    byte[] nextQuote = enclave.getNextQuote(new byte[0]);
    enclave.stop();
    assertEquals("With mrenclave "+mrenclave, nextQuote.length, 1116);
    enclave.stop();
  }
}
