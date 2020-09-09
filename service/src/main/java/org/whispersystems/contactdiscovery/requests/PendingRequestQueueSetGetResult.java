package org.whispersystems.contactdiscovery.requests;

import org.whispersystems.contactdiscovery.enclave.SgxEnclave;

import java.util.List;

public final class PendingRequestQueueSetGetResult {
  private final String               enclaveId;
  private final SgxEnclave           enclave;
  private final List<PendingRequest> requests;

  public PendingRequestQueueSetGetResult(String enclaveId, SgxEnclave enclave, List<PendingRequest> requests) {
    this.enclaveId = enclaveId;
    this.enclave = enclave;
    this.requests = requests;
  }

  public String getEnclaveId() {
    return enclaveId;
  }

  public SgxEnclave getEnclave() {
    return enclave;
  }

  public List<PendingRequest> getRequests() {
    return requests;
  }
}
