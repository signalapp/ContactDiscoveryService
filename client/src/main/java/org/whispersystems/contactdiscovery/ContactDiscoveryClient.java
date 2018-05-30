package org.whispersystems.contactdiscovery;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationRequest;
import org.whispersystems.contactdiscovery.entities.RemoteAttestationResponse;
import org.whispersystems.contactdiscovery.util.ByteUtils;
import org.whispersystems.contactdiscovery.util.IntegerUtil;
import org.whispersystems.contactdiscovery.util.StreamUtils;
import org.whispersystems.contactdiscovery.util.SystemMapper;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.dispatch.util.Util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.Period;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

public class ContactDiscoveryClient {

  private static final int MAX_REQUEST_SIZE = 2048;

  public RemoteAttestation getRemoteAttestation(String keyStorePath, String url, String mrenclave, String authorizationHeader)
      throws UnauthenticatedQuoteException, SignatureException, KeyStoreException, Quote.InvalidQuoteFormatException, UnauthenticatedResponseException
  {
    try {
      KeyStore          keyStore = loadKeyStore(keyStorePath);
      Curve25519        curve    = Curve25519.getInstance(Curve25519.BEST);
      Curve25519KeyPair keyPair  = curve.generateKeyPair();

      RemoteAttestationRequest  request  = new RemoteAttestationRequest(keyPair.getPublicKey());
      RemoteAttestationResponse response = ClientBuilder.newClient()
                                                        .target(url)
                                                        .path("/v1/attestation/" + mrenclave)
                                                        .request(MediaType.APPLICATION_JSON_TYPE)
                                                        .header("Authorization", authorizationHeader)
                                                        .put(Entity.json(request), RemoteAttestationResponse.class);


      RemoteAttestationKeys keys      = new RemoteAttestationKeys(keyPair, response.getServerEphemeralPublic(), response.getServerStaticPublic());
      Quote                 quote     = new Quote(response.getQuote());
      byte[]                requestId = getPlaintext(keys.getServerKey(), response.getIv(), response.getCiphertext(), response.getTag());

      verifyServerQuote(quote, response.getServerStaticPublic(), mrenclave);
      verifyIasSignature(keyStore, response.getCertificates(), response.getSignatureBody(), response.getSignature(), quote);

      return new RemoteAttestation(requestId, keys);
    } catch (BadPaddingException e) {
      throw new UnauthenticatedResponseException(e);
    }
  }

  public Stream<String> getRegisteredUsers(List<String> addressBook, RemoteAttestation remoteAttestation, String url, String mrenclave, String authorizationHeader)
      throws IOException
  {
    DiscoveryRequest  request     = createDiscoveryRequest(addressBook, remoteAttestation);

    DiscoveryResponse response    = ClientBuilder.newClient()
                                                 .target(url)
                                                 .path("/v1/discovery/" + mrenclave)
                                                 .request(MediaType.APPLICATION_JSON_TYPE)
                                                 .header("Authorization", authorizationHeader)
                                                 .put(Entity.json(request), DiscoveryResponse.class);

    List<Byte> responseData = Arrays.asList(ArrayUtils.toObject(getDiscoveryResponseData(response, remoteAttestation)));

    return StreamUtils.zip(addressBook.stream(), responseData.stream(), ImmutablePair::new)
                      .filter(pair -> pair.getRight() != 0)
                      .map(Pair::getLeft);
  }

  public void setRegisteredUser(String url, String authorizationHeader, String user) {
    Response response = ClientBuilder.newClient()
                                     .target(url)
                                     .path("/v1/directory/" + user)
                                     .request()
                                     .header("Authorization", authorizationHeader)
                                     .put(Entity.json(""));

    System.out.println(response.getStatusInfo());
  }

  public void removeRegisteredUser(String url, String authorizationHeader, String user) {
    Response response = ClientBuilder.newClient()
                                     .target(url)
                                     .path("/v1/directory/" + user)
                                     .request()
                                     .header("Authorization", authorizationHeader)
                                     .delete();

    System.out.println(response.getStatusInfo());
  }


  private void verifyServerQuote(Quote quote, byte[] serverPublicStatic, String mrenclave)
      throws UnauthenticatedQuoteException
  {
    try {
      byte[] theirServerPublicStatic = new byte[serverPublicStatic.length];
      System.arraycopy(quote.getReportData(), 0, theirServerPublicStatic, 0, theirServerPublicStatic.length);

      if (!MessageDigest.isEqual(theirServerPublicStatic, serverPublicStatic)) {
        throw new UnauthenticatedQuoteException("Response quote has unauthenticated report data!");
      }

      if (!MessageDigest.isEqual(Hex.decodeHex(mrenclave.toCharArray()), quote.getMrenclave())) {
        throw new UnauthenticatedQuoteException("The response quote has the wrong mrenclave value in it: " + Hex.encodeHexString(quote.getMrenclave()));
      }

      if (!quote.isDebugQuote()) { // Invert in production
        throw new UnauthenticatedQuoteException("Expecting debug quote!");
      }
    } catch (DecoderException e) {
      throw new AssertionError(e);
    }
  }

  private void verifyIasSignature(KeyStore trustStore, String certificates, String signatureBody, String signature, Quote quote)
      throws SignatureException
  {
    try {
      SigningCertificate signingCertificate = new SigningCertificate(certificates, trustStore);
      signingCertificate.verifySignature(signatureBody, signature);

      SignatureBodyEntity signatureBodyEntity = SystemMapper.getMapper().readValue(signatureBody, SignatureBodyEntity.class);

      if (!MessageDigest.isEqual(ByteUtils.truncate(signatureBodyEntity.getIsvEnclaveQuoteBody(), 432), ByteUtils.truncate(quote.getQuoteBytes(), 432))) {
        throw new SignatureException("Signed quote is not the same as RA quote: " + Hex.encodeHexString(signatureBodyEntity.getIsvEnclaveQuoteBody()) + " vs " + Hex.encodeHexString(quote.getQuoteBytes()));
      }

      if (!"OK".equals(signatureBodyEntity.getIsvEnclaveQuoteStatus())) {
        throw new SignatureException("Quote status is: " + signatureBodyEntity.getIsvEnclaveQuoteStatus());
      }

      if (Instant.from(ZonedDateTime.of(LocalDateTime.from(DateTimeFormatter.ofPattern("yyy-MM-dd'T'HH:mm:ss.SSSSSS").parse(signatureBodyEntity.getTimestamp())), ZoneId.of("UTC")))
                 .plus(Period.ofDays(1))
                 .isBefore(Instant.now()))
      {
        throw new SignatureException("Signature is expired");
      }
      
    } catch (CertificateException | CertPathValidatorException | IOException e) {
      throw new SignatureException(e);
    }
  }

  private KeyStore loadKeyStore(String path) throws KeyStoreException{
    try {
      KeyStore keyStore = KeyStore.getInstance("JKS");
      keyStore.load(new FileInputStream(path), "insecure".toCharArray());

      return keyStore;
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    } catch (CertificateException | IOException e) {
      throw new KeyStoreException(e);
    }
  }

  private static List<String> loadAddressBook(String path) throws IOException {
    List<String>   results = new LinkedList<>();
    BufferedReader reader  = new BufferedReader(new FileReader(new File(path)));

    String line;

    while ((line = reader.readLine()) != null) {
      results.add(line);
    }

    return results;
  }

  private DiscoveryRequest createDiscoveryRequest(List<String> addressBook, RemoteAttestation remoteAttestation) {
    try {
      ByteArrayOutputStream requestDataStream = new ByteArrayOutputStream();
      addressBook.forEach(address -> requestDataStream.write(IntegerUtil.longToByteArray(Long.parseLong(address)), 0, 8));

      byte[]           requestData      = requestDataStream.toByteArray();
      byte[]           iv               = ByteUtils.getRandomBytes(12);
      Cipher           cipher           = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec cipherParamaters = new GCMParameterSpec(16 * 8, iv);

      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(remoteAttestation.getKeys().getClientKey(), "AES"), cipherParamaters);

      cipher.updateAAD(remoteAttestation.getRequestId());

      byte[] combinedCiphertext = cipher.doFinal(requestData);
      byte[] ciphertext         = ByteUtils.truncate(combinedCiphertext, combinedCiphertext.length - 16);
      byte[] mac                = ByteUtils.reverseTruncate(combinedCiphertext, 16);

      return new DiscoveryRequest(addressBook.size(), remoteAttestation.getRequestId(), iv, ciphertext, mac);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] getDiscoveryResponseData(DiscoveryResponse response, RemoteAttestation remoteAttestation) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec cipherParameters = new GCMParameterSpec(16 * 8, response.getIv());

      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(remoteAttestation.getKeys().getServerKey(), "AES"), cipherParameters);

      byte[] ciphertext = Util.combine(response.getData(), response.getMac());

      return cipher.doFinal(ciphertext);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] getPlaintext(byte[] serverKey, byte[] iv, byte[] ciphertext, byte[] tag) throws BadPaddingException {
    try {
      Cipher           cipher           = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec cipherParameters = new GCMParameterSpec(16 * 8, iv);

      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(serverKey, "AES"), cipherParameters);

      byte[] combinedCipherText = Util.combine(ciphertext, tag);

      return cipher.doFinal(combinedCipherText);
    } catch (NoSuchAlgorithmException | IllegalBlockSizeException | InvalidAlgorithmParameterException | NoSuchPaddingException | InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  private static void printUsageAndExit(Options options) {
    HelpFormatter formatter = new HelpFormatter();
    formatter.printHelp("ContactDiscoveryClient", options);
    System.exit(0);
  }

  private static CommandLine getCommandLine(String[] argv) throws ParseException {
    Options options = new Options();
    options.addOption("c", true, "[register|discover]");
    options.addOption("h", true, "Contact discovery service URL");
    options.addOption("u", true, "Username");
    options.addOption("p", true, "Password");
    options.addOption("s", true, "Address to set as registered");
    options.addOption("d", true, "Address to delete from registered");
    options.addOption("a", true, "File containing addresses to lookup");
    options.addOption("S", true, String.format("Size of discovery requests, in addresses (%d default)", MAX_REQUEST_SIZE));
    options.addOption("m", true, "MRENCLAVE value");
    options.addOption("t", true, "Path to trust store");
    options.addOption("T", true, "Number of threads used for sending discovery requests");

    CommandLineParser parser      = new DefaultParser();
    CommandLine       commandLine = parser.parse(options, argv);

    if (!commandLine.hasOption("c") ||
        !commandLine.hasOption("h") ||
        !commandLine.hasOption("u") ||
        !commandLine.hasOption("p"))
    {
      HelpFormatter formatter = new HelpFormatter();
      formatter.printHelp("ContactDiscoveryClient", options);
      System.exit(1);
    }

    String commandType = commandLine.getOptionValue("c");

    if (!commandType.equals("register") && !commandType.equals("discover")) {
      printUsageAndExit(options);
    }

    if (commandType.equals("register")  && !commandLine.hasOption("s") && !commandLine.hasOption("d")) {
      printUsageAndExit(options);
    }

    if (commandType.equals("discover")  && !commandLine.hasOption("a")) {
      printUsageAndExit(options);
    }

    return commandLine;
  }

  private static void handleDiscoverCommand(CommandLine commandLine) throws Throwable {
    String       authorizationHeader = "Basic " + Base64.encodeBase64String((commandLine.getOptionValue("u") + ":" + commandLine.getOptionValue("p")).getBytes());
    List<String> addressBook         = loadAddressBook(commandLine.getOptionValue("a"));
    String       keyStorePath        = commandLine.getOptionValue("t");
    String       url                 = commandLine.getOptionValue("h");
    String       mrenclave           = commandLine.getOptionValue("m");
    int          threadCount         = Integer.parseInt(commandLine.getOptionValue("T", "1"));
    int          maxRequestSize      = Integer.parseInt(commandLine.getOptionValue("S", String.valueOf(MAX_REQUEST_SIZE)));
    ForkJoinPool attestationPool     = new ForkJoinPool(threadCount);
    ForkJoinPool requestPool         = new ForkJoinPool(threadCount);

    List<CompletableFuture<Stream<String>>> futures = new ArrayList<>();
    for (int addressBookIdx = 0; addressBookIdx < addressBook.size(); addressBookIdx += maxRequestSize) {
      ContactDiscoveryClient client            = new ContactDiscoveryClient();
      int                    addressBookEndIdx = Math.min(addressBookIdx + maxRequestSize, addressBook.size());
      List<String>           addressBookChunk  = addressBook.subList(addressBookIdx, addressBookEndIdx);
      CompletableFuture<Stream<String>> future =
        CompletableFuture
        .supplyAsync(() -> {
            try {
              return client.getRemoteAttestation(keyStorePath, url, mrenclave, authorizationHeader);
            } catch (Exception ex) {
              throw new CompletionException(ex);
            }
          }, attestationPool)
        .thenApplyAsync(remoteAttestation -> {
            try {
              return client.getRegisteredUsers(addressBookChunk, remoteAttestation, url, mrenclave, authorizationHeader);
            } catch (Exception ex) {
              throw new CompletionException(ex);
            }
          }, requestPool);
      futures.add(future);
    }

    System.out.println("Registered users:");
    futures.stream()
           .flatMap(future -> future.join())
           .forEach(System.out::println);
  }

  private static void handleRegisterCommand(CommandLine commandLine) throws Throwable {
    String                 authorizationHeader = "Basic " + Base64.encodeBase64String((commandLine.getOptionValue("u") + ":" + commandLine.getOptionValue("p")).getBytes());
    ContactDiscoveryClient client              = new ContactDiscoveryClient();

    if (commandLine.hasOption("s")) {
      client.setRegisteredUser(commandLine.getOptionValue("h"), authorizationHeader, commandLine.getOptionValue("s"));
    } else {
      client.removeRegisteredUser(commandLine.getOptionValue("h"), authorizationHeader, commandLine.getOptionValue("d"));
    }
  }

  public static void main(String[] argv) throws Throwable {
    CommandLine commandLine = getCommandLine(argv);

    if (commandLine.getOptionValue("c").equals("discover")) {
      handleDiscoverCommand(commandLine);
    } else {
      handleRegisterCommand(commandLine);
    }

  }

}
