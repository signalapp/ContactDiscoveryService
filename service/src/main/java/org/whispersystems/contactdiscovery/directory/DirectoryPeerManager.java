/**
 * Copyright (C) 2021 Signal LLC
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

package org.whispersystems.contactdiscovery.directory;

import io.dropwizard.logback.shaded.guava.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.providers.RedisClientFactory;
import org.whispersystems.contactdiscovery.util.TextUtils;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Random;

public class DirectoryPeerManager {
    private final Logger logger = LoggerFactory.getLogger(RedisClientFactory.class);

    private static final Random RANDOM = new SecureRandom();

    private final String mapBuilderUrl;
    private final String mapBuilderDns;
    private final String peerAuthToken;
    private boolean peerLoadEligible;

    private int peerBuildAttempts = 0;

    public DirectoryPeerManager(String mapBuilderUrl, String mapBuilderDns, String peerAuthToken, boolean peerLoadEligible) {
        this.mapBuilderUrl = mapBuilderUrl;
        this.mapBuilderDns = mapBuilderDns;
        this.peerAuthToken = peerAuthToken;
        this.peerLoadEligible = peerLoadEligible;
    }

    public boolean loadFromPeer() {
        logger.info(String.format("determining peer eligibility. url=%s; token=%s; elligible=%s; attempts=%s",
                mapBuilderUrl, peerAuthToken, peerLoadEligible, peerBuildAttempts));
        if (!peerLoadEligible) {
            return false;
        }
        return !TextUtils.isEmpty(mapBuilderUrl) && !TextUtils.isEmpty(peerAuthToken);
    }

    public String getPeerBuildRequestUrl() {
        try {
            final InetAddress[] addresses = InetAddress.getAllByName(mapBuilderDns);

            if (addresses.length > 0) {
                final InetAddress address = addresses[RANDOM.nextInt(addresses.length)];
                return String.format("http://%s", address.getHostAddress());
            }

        } catch (final Exception e) {
            logger.warn("Failed to resolve mapBuilderDns", e);
        }

        return this.mapBuilderUrl;
    }

    public void setPeerLoadEligible(boolean isEligible) {
        logger.info("setting peer loading eligibility to: " + peerLoadEligible);
        peerLoadEligible = isEligible;
    }

    public void startPeerLoadAttempt() {
        peerBuildAttempts++;
    }

    public void markPeerLoadSuccessful() {
        peerBuildAttempts = 0;
    }

    public String getAuthHeader() {
        return generateAuthHeader(this.peerAuthToken);
    }

    public Duration getBackoffTime() {
        return Duration.ofSeconds(
                Math.min((long) (5 * Math.pow(2,this.peerBuildAttempts)),
                60));
    }

    @VisibleForTesting
    public static String generateAuthHeader(String password) {
        if (password == null) {
            return "";
        }
        return String.format("Basic %s", Base64.getEncoder().encodeToString(String.format("Service:%s", password).getBytes(StandardCharsets.US_ASCII)));
    }
}
