/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.contactdiscovery;

public class ContactDiscoveryServerVersion {

  private static final String VERSION = "${project.version}";

  public static String getServerVersion() {
    return VERSION;
  }
}
