package org.whispersystems.contactdiscovery.enclave;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

public class SgxsdClient {
    public static final int SGX_AESGCM_KEY_SIZE = 16;
    public static final int SGX_AESGCM_IV_SIZE = 12;
    public static final int SGX_AESGCM_MAC_SIZE = 16;

    public final byte[] spid;
    public final byte[] mrEnclave;

    private SecretKey _sendKey;
    private SecretKey _recvKey;
    private byte[] _ticket;
    private boolean _raFinished = false;
    private final byte[] _raPrivateKey;
    private final byte[] _raPublicKey;
    private final SecureRandom _ivRand;

    public SgxsdClient(byte[] spid, byte[] mrEnclave) {
        this.spid = spid;
        this.mrEnclave = mrEnclave;
        SecureRandom rand = new SecureRandom();

        // generate our key pair B
        Curve25519KeyPair raKeyPair = Curve25519.getInstance(Curve25519.BEST).generateKeyPair();
        _raPrivateKey = raKeyPair.getPrivateKey();
        _raPublicKey = raKeyPair.getPublicKey();

        _ivRand = rand;
    }

    public byte[] getRAPublicKey() {
        return _raPublicKey;
    }

    public void finishRA(byte[] serverPublicKey, byte[] quote, byte[] ticket, byte[] mac,
                         byte[] iasReport, byte[] iasReportSignature, byte[] iasReportSigningCertificate)
        throws DigestException, NoSuchAlgorithmException {
        finishRA(serverPublicKey, quote, ticket, mac, iasReport, iasReportSignature, iasReportSigningCertificate, true);
    }
    public void finishRANoVerify(byte[] serverPublicKey, byte[] quote, byte[] ticket, byte[] mac)
        throws DigestException, NoSuchAlgorithmException {
        finishRA(serverPublicKey, quote, ticket, mac, null, null, null, false);
    }
    private void finishRA(byte[] serverPublicKey, byte[] quote, byte[] ticket, byte[] mac,
                          byte[] iasReport, byte[] iasReportSignature, byte[] iasReportSigningCertificate,
                          boolean verify)
        throws DigestException, NoSuchAlgorithmException {
        // derive ECDH shared secret
        byte[] sharedSecret = Curve25519.getInstance(Curve25519.BEST).calculateAgreement(serverPublicKey, _raPrivateKey);

        // generate subkeys using HKDF(salt=sha256(server pubkey || client pubkey), IKM=(shared secret))
        Mac hkdf = Mac.getInstance("HmacSHA256");
        byte[] publicKeys = new byte[serverPublicKey.length + _raPublicKey.length];
        System.arraycopy(serverPublicKey, 0, publicKeys, 0, serverPublicKey.length);
        System.arraycopy(_raPublicKey, 0, publicKeys, serverPublicKey.length, _raPublicKey.length);
        try {
            hkdf.init(new SecretKeySpec(publicKeys, hkdf.getAlgorithm()));
            hkdf.init(new SecretKeySpec(hkdf.doFinal(sharedSecret), hkdf.getAlgorithm()));
        } catch (InvalidKeyException ex) {
            // shouldn't happen if it worked in testing
            throw new RuntimeException(ex);
        }
        byte hkdfCtr = 0;
        byte[] hkdfResult = new byte[0];

        // HKDF T(1) = handshake hmac key
        hkdf.update(hkdfResult = hkdf.doFinal(new byte[] { ++hkdfCtr }));
        byte[] responseHmacKey = hkdfResult;

        // HKDF T(2) = report data hmac key
        hkdf.update(hkdfResult = hkdf.doFinal(new byte[] { ++hkdfCtr }));
        byte[] reportDataHmacKey = hkdfResult;

        // HKDF T(3) = client sending, client receiving AES-GCM keys
        hkdf.update(hkdfResult = hkdf.doFinal(new byte[] { ++hkdfCtr }));
        _sendKey = new SecretKeySpec(hkdfResult, 0, SGX_AESGCM_KEY_SIZE, "AES");
        _recvKey = new SecretKeySpec(hkdfResult, SGX_AESGCM_KEY_SIZE, SGX_AESGCM_KEY_SIZE, "AES");

        // verify response hmac
        Mac responseHmac = Mac.getInstance("HmacSHA256");
        try {
            responseHmac.init(new SecretKeySpec(responseHmacKey, responseHmac.getAlgorithm()));
        } catch (InvalidKeyException ex) {
            // shouldn't happen if it worked in testing
            throw new RuntimeException(ex);
        }
        responseHmac.update(serverPublicKey);
        responseHmac.update(quote);
        responseHmac.update(ticket);
        if (!MessageDigest.isEqual(mac, responseHmac.doFinal())) {
            throw new DigestException("response_mac_mismatch");
        }

        if (verify) {
            RAQuote parsedQuote = new RAQuote(quote);

            // verify report data hmac
            Mac reportDataHmac = Mac.getInstance("HmacSHA256");
            try {
                reportDataHmac.init(new SecretKeySpec(reportDataHmacKey, reportDataHmac.getAlgorithm()));
            } catch (InvalidKeyException ex) {
                // shouldn't happen if it worked in testing
                throw new RuntimeException(ex);
            }
            reportDataHmac.update(serverPublicKey);
            reportDataHmac.update(_raPublicKey);
            byte[] reportData = new byte[64];
            try {
                reportDataHmac.doFinal(reportData, 0);
            } catch (ShortBufferException ex) {
                // can't happen with HMAC-SHA256
                throw new RuntimeException(ex);
            }
            if (!MessageDigest.isEqual(parsedQuote.report_data, reportData)) {
                throw new DigestException("report_data_mismatch");
            }

            // verify mrenclave
            if (MessageDigest.isEqual(parsedQuote.mr_enclave, mrEnclave) && mrEnclave != null) {
                throw new DigestException("mr_enclave_mismatch");
            }
        }

        _ticket = ticket;
        _raFinished = true;
    }

    private byte[] getTicket() {
        if (!_raFinished) {
            throw new IllegalStateException("ra_not_finished");
        }
        return _ticket;
    }

    public SgxsdMessage serverCall(byte[] msgData) {
        byte[] msgTicket = getTicket();

        // generate random iv
        byte[] msgIv = new byte[SGX_AESGCM_IV_SIZE];
        _ivRand.nextBytes(msgIv);

        try {
            // encrypt message
            Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] msgMac = new byte[SGX_AESGCM_MAC_SIZE];
            aesGcm.init(Cipher.ENCRYPT_MODE, _sendKey, new GCMParameterSpec(msgMac.length * 8, msgIv));
            int msgDataOff = aesGcm.update(msgData, 0, msgData.length, msgData, 0);
            int msgDataLeft = msgData.length - msgDataOff;

            // calculate message mac
            byte[] lastBlock = aesGcm.doFinal();
            System.arraycopy(lastBlock, 0, msgData, msgDataOff, msgDataLeft);
            System.arraycopy(lastBlock, msgDataLeft, msgMac, 0, msgMac.length);
            return new SgxsdMessage(msgData, msgIv, msgMac, msgTicket);
        } catch (NoSuchAlgorithmException ex) {
            // shouldn't happen if it worked in constructor
            throw new RuntimeException(ex);
        } catch (NoSuchPaddingException ex) {
            // can't happen with no padding
            throw new RuntimeException(ex);
        } catch (InvalidKeyException ex) {
            // shouldn't happen if it worked in testing
            throw new RuntimeException(ex);
        } catch (InvalidAlgorithmParameterException ex) {
            // shouldn't happen if it worked in testing
            throw new RuntimeException(ex);
        } catch (ShortBufferException ex) {
            // shouldn't happen with AES-GCM
            throw new RuntimeException(ex);
        } catch (IllegalBlockSizeException ex) {
            // can't happen with AES-GCM
            throw new RuntimeException(ex);
        } catch (BadPaddingException ex) {
            // can't happen with decryption
            throw new RuntimeException(ex);
        }
    }

    public byte[] serverCallReply(SgxsdMessage msg) throws AEADBadTagException {
        byte[] msgData = msg.getData();
        byte[] msgMac = msg.getMac();

        try {
            Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
            aesGcm.init(Cipher.DECRYPT_MODE, _recvKey, new GCMParameterSpec(msgMac.length * 8, msg.getIv()));
            int msgDataOff = aesGcm.update(msgData, 0, msgData.length, msgData, 0);
            aesGcm.doFinal(msgMac, 0, msgMac.length, msgData, msgDataOff);
            return msgData;
        } catch (NoSuchAlgorithmException ex) {
            // shouldn't happen if it worked in constructor
            throw new RuntimeException(ex);
        } catch (NoSuchPaddingException ex) {
            // can't happen with no padding
            throw new RuntimeException(ex);
        } catch (InvalidKeyException ex) {
            // shouldn't happen if it worked in testing
            throw new RuntimeException(ex);
        } catch (InvalidAlgorithmParameterException ex) {
            // shouldn't happen if it worked in testing
            throw new RuntimeException(ex);
        } catch (ShortBufferException ex) {
            // shouldn't happen with AES-GCM
            throw new RuntimeException(ex);
        } catch (IllegalBlockSizeException ex) {
            // can't happen with AES-GCM
            throw new RuntimeException(ex);
        } catch (AEADBadTagException ex) {
            // pass this exception on so it's not caught in BadPaddingException below
            throw ex;
        } catch (BadPaddingException ex) {
            // can't happen with AES-GCM (must be an AEADBadTagException caught above)
            throw new RuntimeException(ex);
        }
    }

    public static class RAQuote {
        public static final long SGX_FLAGS_INITTED        = 0x0000_0000_0000_0001L;
        public static final long SGX_FLAGS_DEBUG          = 0x0000_0000_0000_0002L;
        public static final long SGX_FLAGS_MODE64BIT      = 0x0000_0000_0000_0004L;
        public static final long SGX_FLAGS_PROVISION_KEY  = 0x0000_0000_0000_0004L;
        public static final long SGX_FLAGS_EINITTOKEN_KEY = 0x0000_0000_0000_0004L;
        public static final long SGX_FLAGS_RESERVED       = 0xFFFF_FFFF_FFFF_FFC8L;
        public static final long SGX_XFRM_LEGACY          = 0x0000_0000_0000_0003L;
        public static final long SGX_XFRM_AVX             = 0x0000_0000_0000_0006L;

        public final int version;
        public final boolean sig_linkable;
        public final long gid;
        public final int qe_svn;
        public final int pce_svn;
        public final byte[] basename = new byte[32];
        public final byte[] cpu_svn = new byte[16];
        public final long flags;
        public final long xfrm;
        public final byte[] mr_enclave = new byte[32];
        public final byte[] mr_signer = new byte[32];
        public final int isv_prod_id;
        public final int isv_svn;
        public final byte[] report_data = new byte[64];
        public final byte[] signature;

        public RAQuote(byte[] quoteBytes) {
            ByteBuffer quoteBuf = ByteBuffer.wrap(quoteBytes);
            quoteBuf.order(ByteOrder.LITTLE_ENDIAN);

            version = quoteBuf.getShort(0) & 0xFFFF;
            if (!(version >= 1 && version <= 2)) {
                throw new IllegalArgumentException("unknown_quote_version "+version);
            }

            int sign_type = quoteBuf.getShort(2) & 0xFFFF;
            if ((sign_type & ~1) != 0) {
                throw new IllegalArgumentException("unknown_quote_sign_type "+sign_type);
            }
            sig_linkable = sign_type == 1;

            gid = quoteBuf.getInt(4) & 0xFFFF_FFFF;
            qe_svn = quoteBuf.getShort(8) & 0xFFFF;

            if (version > 1) {
                pce_svn = quoteBuf.getShort(10) & 0xFFFF;
            } else {
                readZero(quoteBuf, 10, 2);
                pce_svn = 0;
            }

            readZero(quoteBuf, 12, 4); // xeid (reserved)
            read(quoteBuf, 16, basename);

            //
            // report_body
            //

            read(quoteBuf, 48, cpu_svn);
            readZero(quoteBuf, 64, 4); // misc_select (reserved)
            readZero(quoteBuf, 68, 28); // reserved1
            flags = quoteBuf.getLong(96);
            if ((flags & SGX_FLAGS_RESERVED) != 0 || (flags & SGX_FLAGS_INITTED) == 0) {
                throw new IllegalArgumentException("bad_quote_flags "+flags);
            }
            xfrm = quoteBuf.getLong(104);
            read(quoteBuf, 112, mr_enclave);
            readZero(quoteBuf, 144, 32); // reserved2
            read(quoteBuf, 176, mr_signer);
            readZero(quoteBuf, 208, 96); // reserved3
            isv_prod_id = quoteBuf.getShort(304) & 0xFFFF;
            isv_svn = quoteBuf.getShort(306) & 0xFFFF;
            readZero(quoteBuf, 308, 60); // reserved4
            read(quoteBuf, 368, report_data);

            // quote signature
            int sig_len = quoteBuf.getInt(432) & 0xFFFF_FFFF;
            if (sig_len != quoteBytes.length - 436) {
                throw new IllegalArgumentException("bad_quote_sig_len "+sig_len);
            }
            signature = new byte[sig_len];
            read(quoteBuf, 436, signature);
        }
        private static void read(ByteBuffer quoteBuf, int pos, byte[] buf) {
            quoteBuf.position(pos);
            quoteBuf.get(buf);
        }
        private static void readZero(ByteBuffer quoteBuf, int pos, int count) {
            byte[] zeroBuf = new byte[count];
            read(quoteBuf, pos, zeroBuf);
            for (int zeroBufIdx = 0; zeroBufIdx < count; zeroBufIdx++) {
                if (zeroBuf[zeroBufIdx] != 0) {
                    throw new IllegalArgumentException("quote_reserved_mismatch "+pos);
                }
            }
        }
    }
}
