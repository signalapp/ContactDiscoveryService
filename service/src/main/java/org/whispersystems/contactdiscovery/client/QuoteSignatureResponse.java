/*
 * Copyright (C) 2018 Open Whisper Systems
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
package org.whispersystems.contactdiscovery.client;

public class QuoteSignatureResponse {

  private final String signature;
  private final String response;
  private final String certificates;
  private final String platformInfoBlob;

  public QuoteSignatureResponse(String signature, String response, String certificates, String platformInfoBlob) {
    this.signature        = signature;
    this.response         = response;
    this.certificates     = certificates;
    this.platformInfoBlob = platformInfoBlob;
  }

  public String getSignature() {
    return signature;
  }

  public String getResponse() {
    return response;
  }

  public String getCertificates() {
    return certificates;
  }

  public byte[] getPlatformInfoBlob() throws QuoteVerificationException {
    return IntelClient.unwrapPlatformInfoBlob(platformInfoBlob);
  }

}
