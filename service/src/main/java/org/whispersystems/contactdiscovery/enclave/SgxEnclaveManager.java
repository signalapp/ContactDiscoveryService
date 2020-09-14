/*
 * Copyright (C) 2017 Open Whisper Systems
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
package org.whispersystems.contactdiscovery.enclave;

import io.dropwizard.lifecycle.Managed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.configuration.EnclaveConfiguration;
import org.whispersystems.contactdiscovery.configuration.EnclaveInstanceConfiguration;
import org.whispersystems.contactdiscovery.util.NativeUtils;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Collection of all enclaves, indexed by MRENCLAVE value
 *
 * @author Moxie Marlinspike
 */
public class SgxEnclaveManager implements Managed {

  private final Logger logger = LoggerFactory.getLogger(SgxEnclaveManager.class);

  private final Map<String, SgxEnclave> enclaves = new HashMap<>();

  public SgxEnclaveManager(EnclaveConfiguration configuration) throws IOException {
    for (EnclaveInstanceConfiguration instance : configuration.getInstances()) {
      File enclaveLibrary = NativeUtils.extractNativeResource("/enclave/" + instance.getMrenclave() + ".so");
      enclaves.put(instance.getMrenclave(), new SgxEnclave(enclaveLibrary.getAbsolutePath(),
                                                           instance.getMrenclave(),
                                                           instance.isDebug(),
                                                           configuration.getSpid()));
    }
  }

  SgxEnclave getEnclave(String mrenclave) throws NoSuchEnclaveException {
    SgxEnclave enclave = enclaves.get(mrenclave);

    if (enclave == null) throw new NoSuchEnclaveException(mrenclave);
    else                 return enclave;
  }

  public Map<String, SgxEnclave> getEnclaves() {
    return enclaves;
  }

  public void start() throws Exception {
    for (SgxEnclave enclave : enclaves.values()) {
      enclave.start();
    }
  }

  public void stop() throws Exception {
    for (SgxEnclave enclave : enclaves.values()) {
      enclave.stop();
    }
  }
}
