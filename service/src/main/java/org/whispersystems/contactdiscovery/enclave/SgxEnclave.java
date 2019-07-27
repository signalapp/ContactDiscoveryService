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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.AEADBadTagException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CompletableFuture;
import java.util.EnumSet;
import java.util.Set;

/**
 * Java interface for interacting with an SGX enclave
 *
 * @author Jeff Griffin
 */
public class SgxEnclave implements Runnable {

  private static final byte PENDING_REQUESTS_TABLE_ORDER = 16; // 2^16 = 65536 pending requests buffer size

  private final Logger logger = LoggerFactory.getLogger(SgxEnclave.class);

  private final String  enclavePath;
  private final boolean debug;
  private final byte[]  spid;

  private Thread       thread          = null;
  private EnclaveState enclaveState    = null;
  private byte[]       lastLaunchToken = null;
  private Long         lastGid         = null;
  private boolean      stopped         = false;
  private SgxException lastError       = null;

  private static class EnclaveState {
    private final long id;
    private EnclaveState(long id) {
            this.id = id;
        }
  }

  public SgxEnclave(String enclavePath, boolean debug, byte[] launchToken, byte[] spid) {
    if (enclavePath == null || (launchToken != null && launchToken.length != 1024) || spid == null || spid.length != 16) {
      throw new IllegalArgumentException("Bad SgxEnclave arguments");
    }

    this.enclavePath = enclavePath;
    this.debug       = debug;
    lastLaunchToken  = launchToken;
    this.spid        = spid;
  }

  synchronized void start() throws SgxException {
    if (thread == null) {
      thread = new Thread(this);
      thread.start();

      while (enclaveState == null && !isStopped()) {
        try {
          wait();
        } catch (InterruptedException e) {
          logger.warn("Interrupt", e);
        }
      }

      if (lastError != null) {
        throw lastError;
      }
    } else {
      throw new IllegalStateException("Already started!");
    }
  }

  void stop() {
    stop(null);
  }

  private synchronized void stop(SgxException lastError) {
    if (!stopped) {
      stopped = true;
      killEnclave(lastError);
    }
  }

  private synchronized boolean isStopped() {
    return stopped;
  }

  private synchronized void killEnclave(SgxException lastError) {
    this.lastError = lastError;
    enclaveState = null;
    notifyAll();
  }

  @Override
  public void run() {
    while (!isStopped()) {
      try {
        // native will call back into runEnclave
        nativeEnclaveStart(enclavePath, debug, lastLaunchToken, PENDING_REQUESTS_TABLE_ORDER,
                           (enclaveId, gid, launchToken) -> {
                             synchronized(SgxEnclave.this) {
                               EnclaveState enclaveState = new EnclaveState(enclaveId);

                               SgxEnclave.this.enclaveState    = enclaveState;
                               SgxEnclave.this.lastLaunchToken = launchToken;
                               SgxEnclave.this.lastGid         = gid;
                               SgxEnclave.this.notifyAll();

                               while (enclaveState == this.enclaveState) {
                                 try {
                                   SgxEnclave.this.wait();
                                 } catch (InterruptedException ex) {
                                   logger.warn("Interrupt", ex);
                                 }
                               }
                             }
                           });
      } catch (SgxException ex) {
        stop(ex);
      }
      // XXX fail if restart intensity too high
    }
  }

  private synchronized EnclaveState getEnclaveState() throws SgxException {
    if (enclaveState == null) {
      throw new SgxException("enclave_dead");
    }

    return enclaveState;
  }

  private void handleSgxException(SgxException ex) {
    if (ex.getCode() <= Integer.MAX_VALUE) {
      switch ((int) ex.getCode()) {
        case SgxException.SGX_ERROR_INVALID_PARAMETER: throw new IllegalArgumentException(ex.getName());
        case SgxException.SGX_ERROR_INVALID_STATE:     throw new IllegalStateException(ex.getName());
        case SgxException.SGX_ERROR_ENCLAVE_LOST:
        case SgxException.SGX_ERROR_ENCLAVE_CRASHED:
        case SgxException.SGX_ERROR_INVALID_ENCLAVE:
        case SgxException.SGX_ERROR_INVALID_ENCLAVE_ID: {
          killEnclave(ex);
        }
      }
    }
  }
  private Exception convertSgxException(SgxException ex) {
    if (ex.getCode() <= Integer.MAX_VALUE) {
      switch ((int) ex.getCode()) {
        case SgxException.SGXSD_ERROR_PENDING_REQUEST_NOT_FOUND: return new NoSuchPendingRequestException();
        case SgxException.SGX_ERROR_MAC_MISMATCH:                return new AEADBadTagException();
        case SgxException.SGX_ERROR_INVALID_PARAMETER:           return new IllegalArgumentException(ex.getName());
        case SgxException.SGX_ERROR_INVALID_STATE:               return new IllegalStateException(ex.getName());
      }
    }
    return ex;
  }

  long getGid() {
    if (lastGid == null) {
      throw new IllegalStateException("enclave_never_started");
    }
    return lastGid;
  }

  public static Set<SgxNeedsUpdateFlag> reportPlatformAttestationStatus(byte[] platformInfoBlob, boolean attestationSuccessful) throws SgxException {
    int updateFlags = nativeReportPlatformAttestationStatus(platformInfoBlob, attestationSuccessful);
    EnumSet<SgxNeedsUpdateFlag> updateFlagSet = EnumSet.noneOf(SgxNeedsUpdateFlag.class);
    if ((updateFlags & (1 << 0)) != 0) {
      updateFlagSet.add(SgxNeedsUpdateFlag.UCODE_UPDATE);
    }
    if ((updateFlags & (1 << 1)) != 0) {
      updateFlagSet.add(SgxNeedsUpdateFlag.CSME_FW_UPDATE);
    }
    if ((updateFlags & (1 << 2)) != 0) {
      updateFlagSet.add(SgxNeedsUpdateFlag.PSW_UPDATE);
    }
    return updateFlagSet;
  }

  byte[] getNextQuote(byte[] sig_rl) throws SgxException {
    try {
      return nativeGetNextQuote(getEnclaveState().id, spid, sig_rl);
    } catch (SgxException ex) {
      handleSgxException(ex);
      throw ex;
    }
  }

  void setCurrentQuote() throws SgxException {
    try {
      nativeSetCurrentQuote(getEnclaveState().id);
    } catch (SgxException ex) {
      handleSgxException(ex);
      throw ex;
    }
  }

  SgxRequestNegotiationResponse negotiateRequest(byte[] clientPublicKey) throws SgxException {
    try {
      return nativeNegotiateRequest(getEnclaveState().id, clientPublicKey);
    } catch (SgxException ex) {
      handleSgxException(ex);
      throw ex;
    }
  }

  public SgxsdBatch newBatch(long threadNo, int maxBatchSize) throws SgxException {
    return new SgxsdBatch(threadNo, maxBatchSize);
  }

  public class SgxsdBatch implements AutoCloseable {

    private final long                            stateHandle;
    private final int                             maxJidCount;
    private final CompletableFuture<SgxsdMessage> batchFuture;
    private       int                             jidCount;
    private       boolean                         processed;

    private SgxsdBatch(long stateHandle, int maxJidCount) throws SgxException {
      this.stateHandle = stateHandle;
      this.maxJidCount = maxJidCount;
      this.batchFuture = new CompletableFuture<>();
      this.jidCount    = 0;
      this.processed   = false;

      try {
        nativeServerStart(getEnclaveState().id, this.stateHandle, this.maxJidCount);
      } catch (SgxException ex) {
        handleSgxException(ex);
        throw ex;
      }
    }

    public synchronized CompletableFuture<SgxsdMessage> add(SgxsdMessage request, int requestJidCount) {
      if (processed) {
        throw new IllegalStateException("batch_already_processed");
      }

      if (requestJidCount > maxJidCount - jidCount) {
        throw new IllegalArgumentException("batch_full");
      }

      final CompletableFuture<SgxsdMessage> future        = new CompletableFuture<>();
      final byte[]                          requestTicket = request.getTicket();

      try {
        nativeServerCall(getEnclaveState().id, stateHandle, requestJidCount,
                         request.getData(), request.getIv(), request.getMac(), request.getTicket(),
                         (replyData, replyIv, replyMac) -> {
                           future.complete(new SgxsdMessage(replyData, replyIv, replyMac, requestTicket));
                         });
      } catch (SgxException ex) {
        future.completeExceptionally(convertSgxException(ex));
        handleSgxException(ex);
      }

      jidCount += requestJidCount;
      return batchFuture.applyToEither(future, reply -> reply);
    }

    public synchronized void close() throws SgxException {
      if (!processed) {
        batchFuture.completeExceptionally(new SgxException("batch_closed"));
        process(ByteBuffer.allocateDirect(8), 0);
      }
    }

    public synchronized void process(ByteBuffer inJidsBuf, long inJidCount) throws SgxException {
      if (processed) {
        throw new IllegalStateException("batch_already_processed");
      }

      processed = true;

      try {
        nativeServerStop(getEnclaveState().id, stateHandle, inJidsBuf, inJidCount);
      } catch (SgxException ex) {
        batchFuture.completeExceptionally(convertSgxException(ex));
        handleSgxException(ex);
        throw ex;
      }

      // trigger an exception for any messages that didn't get a reply (shouldn't happen unless enclave is buggy)
      batchFuture.completeExceptionally(new SgxException("reply_missing"));
    }
  }

  //

  private interface EnclaveStartCallback {
    void runEnclave(long enclaveId, long gid, byte[] launchToken) throws SgxException;
  }

  private interface NativeServerReplyCallback {
    void receiveServerReply(byte[] data, byte[] iv, byte[] mac);
  }

  private static native void nativeEnclaveStart(String enclavePath, boolean debug, byte[] launchToken, byte pendingRequestsTableOrder, EnclaveStartCallback callback) throws SgxException;

  private static native byte[] nativeGetNextQuote(long enclaveId, byte[] spid, byte[] sig_rl) throws SgxException;
  private static native void nativeSetCurrentQuote(long enclaveId) throws SgxException;
  private static native SgxRequestNegotiationResponse nativeNegotiateRequest(long enclaveId, byte[] client_pubkey_le) throws SgxException;

  private static native void nativeServerStart(long enclaveId, long stateHandle, int maxAbJids) throws SgxException;
  private static native void nativeServerCall(long enclaveId, long stateHandle, int abJidCount, byte[] msg_data, byte[] msg_iv, byte[] msg_mac, byte[] msg_ticket, NativeServerReplyCallback callback) throws SgxException;
  private static native void nativeServerStop(long enclaveId, long stateHandle, ByteBuffer inJidsBuf, long inJidCount) throws SgxException;
  private static native int nativeReportPlatformAttestationStatus(byte[] platformInfoBlob, boolean attestationSuccessful);
}
