package org.whispersystems.contactdiscovery.client;

import com.google.common.annotations.VisibleForTesting;

import java.util.Arrays;

public enum IasVersion {
    IAS_V3(3),
    IAS_V4(4);

    private final int versionNumber;

    IasVersion(final int versionNumber) {
        this.versionNumber = versionNumber;
    }

    public static IasVersion fromVersionNumber(final int versionNumber) {
        return Arrays.stream(IasVersion.values())
                .filter(iasVersion -> iasVersion.versionNumber == versionNumber)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unrecognized IAS version: " + versionNumber));
    }

    public int getVersionNumber() {
        return versionNumber;
    }
}
