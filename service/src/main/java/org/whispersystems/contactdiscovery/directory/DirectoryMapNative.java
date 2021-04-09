/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.contactdiscovery.directory;

import java.util.UUID;

public class DirectoryMapNative implements AutoCloseable {
  private long nativeHandle;

  public DirectoryMapNative(long startingCapacity, float minLoadFactor, float maxLoadFactor) {
    nativeHandle = nativeInit(startingCapacity, minLoadFactor, maxLoadFactor);
  }

  @Override
  protected void finalize() throws Throwable {
    try {
      close();
    } finally {
      super.finalize();
    }
  }

  @Override
  public void close() {
    if (nativeHandle != 0) {
      nativeFree(nativeHandle);
      nativeHandle = 0;
    }
  }

  public long getNativeHandle() {
    return nativeHandle;
  }

  public boolean insert(long e164, UUID uuid) {
    if (uuid == null) {
      throw new IllegalArgumentException("no users without UUIDs allowed in the directory map");
    }
    return nativeInsert(nativeHandle, e164, uuid);
  }

  public boolean remove(long e164) {
    return nativeRemove(nativeHandle, e164);
  }

  public boolean commit() {
    return nativeCommit(nativeHandle);
  }

  public long size() {
    return nativeSize(nativeHandle);
  }

  private static native long nativeInit(long startingCapacity, float minLoadFactor, float maxLoadFactor);
  private static native void nativeFree(long nativeHandle);
  private static native boolean nativeInsert(long nativeHandle, long e164, UUID uuid);
  private static native boolean nativeRemove(long nativeHandle, long e164);
  private static native boolean nativeCommit(long nativeHandle);
  private static native long nativeSize(long nativeHandle);
}
