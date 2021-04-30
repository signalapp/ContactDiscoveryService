/**
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.contactdiscovery.auth;


import javax.security.auth.Subject;
import java.security.Principal;

/**
 * Placeholder representation for an authenticated peer CDS server
 */
public class PeerService implements Principal {
  @Override
  public String getName() {
    return null;
  }

  @Override
  public boolean implies(Subject subject) {
    return false;
  }
}
