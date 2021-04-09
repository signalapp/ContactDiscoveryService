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

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.directory.DirectoryMapNative;
import org.whispersystems.contactdiscovery.util.Constants;

import javax.crypto.AEADBadTagException;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Java interface for interacting with an SGX enclave
 *
 * @author Jeff Griffin
 */
public class SgxEnclave implements Runnable {
  private static final MetricRegistry METRIC_REGISTRY = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Timer NATIVE_LOOKUP_TIMER = METRIC_REGISTRY.timer(name(SgxEnclave.class, "nativeLookup"));
  private static final ConcurrentMap<String, Timer> PER_ENCLAVE_TIMERS = new ConcurrentHashMap<>();
  private static final Meter NATIVE_LOOKUP_ERROR_METER = METRIC_REGISTRY.meter(name(SgxEnclave.class, "nativeLookup", "errors"));
  private static final byte PENDING_REQUESTS_TABLE_ORDER = 16; // 2^16 = 65536 pending requests buffer size

  private final Logger logger = LoggerFactory.getLogger(SgxEnclave.class);

  private final String  enclavePath;
  private final String  enclaveId;
  private final boolean debug;
  private final byte[]  spid;
  private final Timer perEnclaveTimer;

  private Thread       thread          = null;
  private EnclaveState enclaveState    = null;
  private Long         lastGid         = null;
  private boolean      stopped         = false;
  private SgxException lastError       = null;

  private static class EnclaveState {
    private final long id;
    private EnclaveState(long id) {
            this.id = id;
        }
  }

  public SgxEnclave(String enclavePath, String enclaveId, boolean debug, byte[] spid) {
    if (enclavePath == null || spid == null || spid.length != 16) {
      throw new IllegalArgumentException("Bad SgxEnclave arguments");
    }

    this.enclavePath = enclavePath;
    this.enclaveId   = enclaveId;
    this.debug       = debug;
    this.spid        = spid;
    this.perEnclaveTimer = PER_ENCLAVE_TIMERS.computeIfAbsent(enclaveId, key -> METRIC_REGISTRY.timer(name(SgxEnclave.class, "nativeLookup", "perEnclave", key)));
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
        // TODO(CDS-136): turn this callback into return values now that we've moved to rust and return values are
        // easier to pass back up the stack.
        // native will call back into runEnclave
        nativeEnclaveStart(enclavePath, debug, PENDING_REQUESTS_TABLE_ORDER,
                           (enclaveId, gid) -> {
                             synchronized(SgxEnclave.this) {
                               EnclaveState enclaveState = new EnclaveState(enclaveId);

                               SgxEnclave.this.enclaveState    = enclaveState;
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
        case SgxException.SGX_ERROR_INVALID_PARAMETER: throw new IllegalArgumentException(ex.getName(), ex);
        case SgxException.SGX_ERROR_INVALID_STATE:     throw new IllegalStateException(ex.getName(), ex);
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
        case SgxException.SABD_ERROR_INVALID_REQUEST_SIZE:       return new InvalidRequestSizeException();
        case SgxException.SGX_ERROR_MAC_MISMATCH:                return new AEADBadTagException();
        case SgxException.SGX_ERROR_INVALID_PARAMETER:           return new IllegalArgumentException(ex.getName(), ex);
        case SgxException.SGX_ERROR_INVALID_STATE:               return new IllegalStateException(ex.getName(), ex);
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
    private final int                             maxPhoneCount;
    private final CompletableFuture<SgxsdMessage> batchFuture;
    private       int                             phoneCount;
    private       boolean                         processed;

    private SgxsdBatch(long stateHandle, int maxPhoneCount) throws SgxException {
      this.stateHandle   = stateHandle;
      this.maxPhoneCount = maxPhoneCount;
      this.batchFuture   = new CompletableFuture<>();
      this.phoneCount    = 0;
      this.processed     = false;

      try {
        nativeServerStart(getEnclaveState().id, this.stateHandle, this.maxPhoneCount);
      } catch (SgxException ex) {
        handleSgxException(ex);
        throw ex;
      }
    }

    public synchronized CompletableFuture<SgxsdMessage> add(SgxsdMessage envelope,
                                                            byte[] requestId,
                                                            SgxsdMessage query,
                                                            int queryPhoneCount,
                                                            byte[] queryCommitment)
    {
      if (processed) {
        throw new IllegalStateException("batch_already_processed");
      }

      if (queryPhoneCount > maxPhoneCount - phoneCount) {
        throw new IllegalArgumentException("batch_full");
      }

      CompletableFuture<SgxsdMessage> future   = new CompletableFuture<>();
      NativeServerCallArgs            callArgs = new NativeServerCallArgs();

      callArgs.msg_data           = envelope.getData();
      callArgs.msg_iv             = envelope.getIv();
      callArgs.msg_mac            = envelope.getMac();
      callArgs.pending_request_id = requestId;
      callArgs.query_data         = query.getData();
      callArgs.query_iv           = query.getIv();
      callArgs.query_mac          = query.getMac();
      callArgs.query_phone_count  = queryPhoneCount;
      callArgs.query_commitment   = queryCommitment;

      try {
        nativeServerCall(getEnclaveState().id, stateHandle, callArgs, future);
      } catch (SgxException ex) {
        future.completeExceptionally(ex);
        handleSgxException(ex);
      }

      phoneCount += queryPhoneCount;
      return batchFuture.applyToEither(future.exceptionally(throwable -> {
        Throwable t = throwable;
        if (t instanceof CompletionException) {
          t = t.getCause();
        }
        if (t instanceof SgxException) {
          SgxException sgxException = (SgxException) t;
          Exception    exception    = convertSgxException(sgxException);
          if (sgxException != exception) {
            throw new CompletionException(exception);
          }
        }
        if (throwable instanceof CompletionException) {
          throw (CompletionException) throwable;
        } else {
          throw new CompletionException(throwable);
        }
      }), reply -> reply);
    }

    public synchronized void close() throws SgxException {
      if (!processed) {
        batchFuture.completeExceptionally(new SgxException("batch_closed"));
        process(null);
      }
    }

    public synchronized void process(DirectoryMapNative directoryMapNative) throws SgxException {
      if (processed) {
        throw new IllegalStateException("batch_already_processed");
      }

      processed = true;

      try (Timer.Context ctx = NATIVE_LOOKUP_TIMER.time(); Timer.Context perEnclaveCtx = perEnclaveTimer.time()) {
        try {
          nativeServerStop(getEnclaveState().id, stateHandle, directoryMapNative != null ? directoryMapNative.getNativeHandle() : 0);
        } catch (SgxException ex) {
          batchFuture.completeExceptionally(convertSgxException(ex));
          NATIVE_LOOKUP_ERROR_METER.mark();
          handleSgxException(ex);
          throw ex;
        }
      }

      // trigger an exception for any messages that didn't get a reply (shouldn't happen unless enclave is buggy)
      batchFuture.completeExceptionally(new SgxException("reply_missing"));
    }
  }

  //

  private interface EnclaveStartCallback {

    void runEnclave(long enclaveId, long gid) throws SgxException;
  }

  private static class NativeServerCallArgs {
    int    query_phone_count;
    byte[] query_data;
    byte[] query_iv;
    byte[] query_mac;
    byte[] query_commitment;
    byte[] msg_data;
    byte[] msg_iv;
    byte[] msg_mac;
    byte[] pending_request_id;
  }

  private static native void nativeEnclaveStart(String enclavePath, boolean debug, byte pendingRequestsTableOrder, EnclaveStartCallback callback) throws SgxException;

  private static native byte[] nativeGetNextQuote(long enclaveId, byte[] spid, byte[] sig_rl) throws SgxException;
  private static native void nativeSetCurrentQuote(long enclaveId) throws SgxException;
  private static native SgxRequestNegotiationResponse nativeNegotiateRequest(long enclaveId, byte[] client_pubkey_le) throws SgxException;

  private static native void nativeServerStart(long enclaveId, long stateHandle, int maxQueryPhones) throws SgxException;
  private static native void nativeServerCall(long enclaveId, long stateHandle, NativeServerCallArgs args, CompletableFuture<SgxsdMessage> callbackFut) throws SgxException;
  private static native void nativeServerStop(long enclaveId, long stateHandle, long directoryMapHandle) throws SgxException;
  private static native int nativeReportPlatformAttestationStatus(byte[] platformInfoBlob, boolean attestationSuccessful);
}
