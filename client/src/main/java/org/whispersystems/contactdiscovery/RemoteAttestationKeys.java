package org.whispersystems.contactdiscovery;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.whispersystems.contactdiscovery.util.ByteUtils;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

class RemoteAttestationKeys {

  private final byte[] clientKey = new byte[32];
  private final byte[] serverKey = new byte[32];

  public RemoteAttestationKeys(Curve25519KeyPair keyPair, byte[] serverPublicEphemeral, byte[] serverPublicStatic) {
    byte[] ephemeralToEphemeral = Curve25519.getInstance(Curve25519.BEST).calculateAgreement(serverPublicEphemeral, keyPair.getPrivateKey());
    byte[] ephemeralToStatic    = Curve25519.getInstance(Curve25519.BEST).calculateAgreement(serverPublicStatic, keyPair.getPrivateKey());

    byte[] masterSecret = ByteUtils.combine(ephemeralToEphemeral, ephemeralToStatic                          );
    byte[] publicKeys   = ByteUtils.combine(keyPair.getPublicKey(), serverPublicEphemeral, serverPublicStatic);

    HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
    generator.init(new HKDFParameters(masterSecret, publicKeys, null));
    generator.generateBytes(clientKey, 0, clientKey.length);
    generator.generateBytes(serverKey, 0, serverKey.length);
  }

  public byte[] getClientKey() {
    return clientKey;
  }

  public byte[] getServerKey() {
    return serverKey;
  }
}
