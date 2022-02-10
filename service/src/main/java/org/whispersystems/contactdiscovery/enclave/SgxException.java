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

/**
 * @author Jeff Griffin
 */
public class SgxException extends Exception {

  private final String name;
  private final long   code;

  SgxException(String name) {
    this(name, 0);
  }

  SgxException(String name, long code) {
    super(code != 0? name + ": 0x" + Long.toHexString(code) : name);
    this.name = name;
    this.code = code;
  }

  public String getName() {
    return name;
  }

  public long getCode() {
    return code;
  }

  // from sgxsd.h:
  public static final int
    SGXSD_ERROR_PENDING_REQUEST_NOT_FOUND = (0x10001);

  // from sabd.h:
  public static final int
      SABD_ERROR_INVALID_REQUEST_SIZE = (0x20001);

  // from sgx_error.h:
  public static final int
    SGX_ERROR_UNEXPECTED         = (0x0001),      /* Unexpected error */
    SGX_ERROR_INVALID_PARAMETER  = (0x0002),      /* The parameter is incorrect */
    SGX_ERROR_OUT_OF_MEMORY      = (0x0003),      /* Not enough memory is available to complete this operation */
    SGX_ERROR_ENCLAVE_LOST       = (0x0004),      /* Enclave lost after power transition or used in child process created by linux:fork() */
    SGX_ERROR_INVALID_STATE      = (0x0005),      /* SGX API is invoked in incorrect order or state */

    SGX_ERROR_INVALID_FUNCTION   = (0x1001),      /* The ecall/ocall index is invalid */
    SGX_ERROR_OUT_OF_TCS         = (0x1003),      /* The enclave is out of TCS */
    SGX_ERROR_ENCLAVE_CRASHED    = (0x1006),      /* The enclave is crashed */
    SGX_ERROR_ECALL_NOT_ALLOWED  = (0x1007),      /* The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization */
    SGX_ERROR_OCALL_NOT_ALLOWED  = (0x1008),      /* The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling */
    SGX_ERROR_STACK_OVERRUN      = (0x1009),      /* The enclave is running out of stack */

    SGX_ERROR_UNDEFINED_SYMBOL   = (0x2000),      /* The enclave image has undefined symbol. */
    SGX_ERROR_INVALID_ENCLAVE    = (0x2001),      /* The enclave image is not correct. */
    SGX_ERROR_INVALID_ENCLAVE_ID = (0x2002),      /* The enclave id is invalid */
    SGX_ERROR_INVALID_SIGNATURE  = (0x2003),      /* The signature is invalid */
    SGX_ERROR_NDEBUG_ENCLAVE     = (0x2004),      /* The enclave is signed as product enclave, and can not be created as debuggable enclave. */
    SGX_ERROR_OUT_OF_EPC         = (0x2005),      /* Not enough EPC is available to load the enclave */
    SGX_ERROR_NO_DEVICE          = (0x2006),      /* Can't open SGX device */
    SGX_ERROR_MEMORY_MAP_CONFLICT= (0x2007),      /* Page mapping failed in driver */
    SGX_ERROR_INVALID_METADATA   = (0x2009),      /* The metadata is incorrect. */
    SGX_ERROR_DEVICE_BUSY        = (0x200c),      /* Device is busy, mostly EINIT failed. */
    SGX_ERROR_INVALID_VERSION    = (0x200d),      /* Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform. */
    SGX_ERROR_MODE_INCOMPATIBLE  = (0x200e),      /* The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS. */
    SGX_ERROR_ENCLAVE_FILE_ACCESS = (0x200f),     /* Can't open enclave file. */
    SGX_ERROR_INVALID_MISC        = (0x2010),     /* The MiscSelct/MiscMask settings are not correct.*/

    SGX_ERROR_MAC_MISMATCH       = (0x3001),      /* Indicates verification error for reports, sealed datas, etc */
    SGX_ERROR_INVALID_ATTRIBUTE  = (0x3002),      /* The enclave is not authorized */
    SGX_ERROR_INVALID_CPUSVN     = (0x3003),      /* The cpu svn is beyond platform's cpu svn value */
    SGX_ERROR_INVALID_ISVSVN     = (0x3004),      /* The isv svn is greater than the enclave's isv svn */
    SGX_ERROR_INVALID_KEYNAME    = (0x3005),      /* The key name is an unsupported value */

    SGX_ERROR_SERVICE_UNAVAILABLE       = (0x4001),   /* Indicates aesm didn't response or the requested service is not supported */
    SGX_ERROR_SERVICE_TIMEOUT           = (0x4002),   /* The request to aesm time out */
    SGX_ERROR_AE_INVALID_EPIDBLOB       = (0x4003),   /* Indicates epid blob verification error */
    SGX_ERROR_SERVICE_INVALID_PRIVILEGE = (0x4004),   /* Enclave has no privilege to get launch token */
    SGX_ERROR_EPID_MEMBER_REVOKED       = (0x4005),   /* The EPID group membership is revoked. */
    SGX_ERROR_UPDATE_NEEDED             = (0x4006),   /* SGX needs to be updated */
    SGX_ERROR_NETWORK_FAILURE           = (0x4007),   /* Network connecting or proxy setting issue is encountered */
    SGX_ERROR_AE_SESSION_INVALID        = (0x4008),   /* Session is invalid or ended by server */
    SGX_ERROR_BUSY                      = (0x400a),   /* The requested service is temporarily not available */
    SGX_ERROR_MC_NOT_FOUND              = (0x400c),   /* The Monotonic Counter doesn't exist or has been invalided */
    SGX_ERROR_MC_NO_ACCESS_RIGHT        = (0x400d),   /* Caller doesn't have the access right to specified VMC */
    SGX_ERROR_MC_USED_UP                = (0x400e),   /* Monotonic counters are used out */
    SGX_ERROR_MC_OVER_QUOTA             = (0x400f),   /* Monotonic counters exceeds quota limitation */
    SGX_ERROR_KDF_MISMATCH              = (0x4011),   /* Key derivation function doesn't match during key exchange */
    SGX_ERROR_UNRECOGNIZED_PLATFORM     = (0x4012),   /* EPID Provisioning failed due to platform not recognized by backend server*/
    
    /* SGX errors are only used in the file API when there is no appropriate EXXX (EINVAL, EIO etc.) error code */
    SGX_ERROR_FILE_BAD_STATUS               = (0x7001),	/* The file is in bad status, run sgx_clearerr to try and fix it */
    SGX_ERROR_FILE_NO_KEY_ID                = (0x7002),	/* The Key ID field is all zeros, can't re-generate the encryption key */
    SGX_ERROR_FILE_NAME_MISMATCH            = (0x7003),	/* The current file name is different then the original file name (not allowed, substitution attack) */
    SGX_ERROR_FILE_NOT_SGX_FILE             = (0x7004), /* The file is not an SGX file */
    SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE  = (0x7005),	/* A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)  */
    SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE = (0x7006), /* A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)  */
    SGX_ERROR_FILE_RECOVERY_NEEDED          = (0x7007),	/* When opening the file, recovery is needed, but the recovery process failed */
    SGX_ERROR_FILE_FLUSH_FAILED             = (0x7008),	/* fflush operation (to disk) failed (only used when no EXXX is returned) */
    SGX_ERROR_FILE_CLOSE_FAILED             = (0x7009);	/* fclose operation (to disk) failed (only used when no EXXX is returned) */
}
