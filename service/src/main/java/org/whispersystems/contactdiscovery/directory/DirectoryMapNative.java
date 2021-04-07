/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.contactdiscovery.directory;

import org.whispersystems.contactdiscovery.enclave.SgxException;

import java.util.UUID;

public class DirectoryMapNative implements AutoCloseable {
  @FunctionalInterface
  public interface BorrowFunction {
    void consume(long e164sHandle, long e164sCapacityBytes, long uuidsHandle, long uuidsCapacityBytes) throws SgxException;
  }

  private long nativeHandle;

  public DirectoryMapNative(long capacity) {
    nativeHandle = nativeInit(capacity);
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

  public boolean insert(long e164, UUID uuid) {
    if (uuid == null) {
      throw new IllegalArgumentException("no users without UUIDs allowed in the directory map");
    }
    return nativeInsert(nativeHandle, e164, uuid);
  }

  public boolean remove(long e164) {
    return nativeRemove(nativeHandle, e164);
  }

  public void borrow(BorrowFunction borrowFunction) {
    if (borrowFunction == null) {
      throw new NullPointerException("null borrow function");
    }
    nativeBorrow(nativeHandle, borrowFunction);
  }

  public boolean commit() {
    return nativeCommit(nativeHandle);
  }

  public long size() {
    return nativeSize(nativeHandle);
  }

  private static native long nativeInit(long capacity);
  private static native void nativeFree(long nativeHandle);
  private static native boolean nativeInsert(long nativeHandle, long e164, UUID uuid);
  private static native boolean nativeRemove(long nativeHandle, long e164);
  private static native void nativeBorrow(long nativeHandle, BorrowFunction borrowFunction);
  private static native boolean nativeCommit(long nativeHandle);
  private static native long nativeSize(long nativeHandle);
}
