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
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

public class DirectoryPeerManager {
    private final Logger logger = LoggerFactory.getLogger(DirectoryPeerManager.class);

    private static final Random RANDOM = new SecureRandom();

    private final String mapBuilderLoadBalancer;
    private final String mapBuilderDns;
    private final int mapBuilderPort;
    private final String peerAuthToken;
    private boolean peerLoadEligible;

    private int peerBuildAttempts = 0;

    public DirectoryPeerManager(String mapBuilderLoadBalancer, String mapBuilderDns, int mapBuilderPort, String peerAuthToken, boolean peerLoadEligible) {
        this.mapBuilderLoadBalancer = mapBuilderLoadBalancer;
        this.mapBuilderDns = mapBuilderDns;
        this.mapBuilderPort = mapBuilderPort;
        this.peerAuthToken = peerAuthToken;
        this.peerLoadEligible = peerLoadEligible;
    }

    public boolean loadFromPeer() {
        logger.info(String.format("determining peer eligibility. url=%s; token=%s; elligible=%s; attempts=%s",
                mapBuilderLoadBalancer, peerAuthToken, peerLoadEligible, peerBuildAttempts));
        if (!peerLoadEligible) {
            return false;
        }
        return !TextUtils.isEmpty(mapBuilderLoadBalancer) && !TextUtils.isEmpty(peerAuthToken);
    }

    public String getPeerBuildRequestUrl() {
        try {
            final List<InetAddress> addresses = Arrays.stream(InetAddress.getAllByName(mapBuilderDns))
                    .filter(address -> {
                        try {
                            // filter out our own IP, for two reasons:
                            //
                            // 1. If we were to try to use it at startup, the peer load request would hang, because
                            //    data is loaded after the service is bound to the port, but before startup is complete
                            //    and requests are processed
                            // 2. If we used it later, we’d be serving ourselves our own potentially stale data
                            return NetworkInterface.getByInetAddress(address) == null;
                        } catch (final Exception e) {
                            return false;
                        }
                    }).collect(Collectors.toList());

            if (addresses.size() > 0) {
                final InetAddress address = addresses.get(RANDOM.nextInt(addresses.size()));
                return String.format("http://%s:%d", address.getHostAddress(), mapBuilderPort);
            }

        } catch (final Exception e) {
            logger.warn("Failed to resolve mapBuilderDns", e);
        }

        return this.mapBuilderLoadBalancer;
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
