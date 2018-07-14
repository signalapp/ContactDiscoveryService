package org.whispersystems.contactdiscovery;

import javax.ws.rs.core.Cookie;
import java.util.Set;

public class RemoteAttestation {

  private final byte[]                requestId;
  private final RemoteAttestationKeys keys;
  private final Set<Cookie>           cookies;

  public RemoteAttestation(byte[] requestId, RemoteAttestationKeys keys, Set<Cookie> cookies) {
    this.requestId = requestId;
    this.keys      = keys;
    this.cookies   = cookies;
  }

  public byte[] getRequestId() {
    return requestId;
  }

  public RemoteAttestationKeys getKeys() {
    return keys;
  }

  public Set<Cookie> getCookies() {
    return cookies;
  }
}
