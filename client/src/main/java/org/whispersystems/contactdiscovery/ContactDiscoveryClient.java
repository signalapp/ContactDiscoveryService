package org.whispersystems.contactdiscovery;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.push.TrustStore;
import org.whispersystems.signalservice.internal.configuration.SignalCdnUrl;
import org.whispersystems.signalservice.internal.configuration.SignalContactDiscoveryUrl;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.configuration.SignalServiceUrl;
import org.whispersystems.signalservice.internal.util.Base64;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class ContactDiscoveryClient {

  private static final int    MAX_REQUEST_SIZE     = 2048;
  private static final String TRUST_STORE_PASSWORD = "insecure";
  private static final String USER_AGENT           = "ContactDiscoveryClient";

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

  private static KeyStore loadKeyStore(String path) throws KeyStoreException {
    try {
      KeyStore keyStore = KeyStore.getInstance("BKS");
      keyStore.load(new FileInputStream(path), TRUST_STORE_PASSWORD.toCharArray());

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

  private static void printUsageAndExit(Options options) {
    HelpFormatter formatter = new HelpFormatter();
    formatter.printHelp("ContactDiscoveryClient", options);
    System.exit(0);
  }

  private static CommandLine getCommandLine(String[] argv) throws ParseException {
    Options options = new Options();
    options.addOption("c",  "command",     true, "[register|discover]");
    options.addOption("u",  "username",    true, "Username");
    options.addOption("p",  "password",    true, "Password");
    options.addOption("h",  "host",        true, "Directory service URL");
    options.addOption("s",  "set",         true, "Address to set as registered");
    options.addOption("d",  "delete",      true, "Address to delete from registered");
    options.addOption("a",  "address-file",true, "File containing addresses to lookup");
    options.addOption("S",  "request-size",true, String.format("Maximum number of addresses per discovery request (default %d)", MAX_REQUEST_SIZE));
    options.addOption("m",  "mrenclave",   true, "MRENCLAVE value");
    options.addOption("T",  "threads",     true, "Number of threads used for sending discovery requests");

    options.addOption(null, "signal-host",        true, "Signal service URL");
    options.addOption(null, "signal-trust-store", true, "Path to signal service trust store");
    options.addOption(null, "intel-trust-store",  true, "Path to intel attestation signature trust store");

    CommandLineParser parser      = new DefaultParser();
    CommandLine       commandLine = parser.parse(options, argv);

    if (!commandLine.hasOption("command") ||
        !commandLine.hasOption("host") ||
        !commandLine.hasOption("username") ||
        !commandLine.hasOption("password")) {
      HelpFormatter formatter = new HelpFormatter();
      formatter.printHelp("ContactDiscoveryClient", options);
      System.exit(1);
    }

    String commandType = commandLine.getOptionValue("command");

    if (commandType.equals("register")) {
      if (!commandLine.hasOption("set") &&
          !commandLine.hasOption("delete")) {
        printUsageAndExit(options);
      }
    } else if (commandType.equals("discover")) {
      if (!commandLine.hasOption("address-file") ||
          !commandLine.hasOption("signal-host") ||
          !commandLine.hasOption("signal-trust-store") ||
          !commandLine.hasOption("intel-trust-store") ||
          !commandLine.hasOption("mrenclave")) {
        printUsageAndExit(options);
      }
    } else {
      printUsageAndExit(options);
    }

    return commandLine;
  }

  private static void handleDiscoverCommand(CommandLine commandLine) throws Throwable {
    String                      username         = commandLine.getOptionValue("username");
    String                      password         = commandLine.getOptionValue("password");
    List<String>                addressBook      = loadAddressBook(commandLine.getOptionValue("address-file"));
    KeyStore                    intelTrustStore  = loadKeyStore(commandLine.getOptionValue("intel-trust-store"));
    TrustStore                  signalTrustStore = SignalTrustStore.fromFile(commandLine.getOptionValue("signal-trust-store"));
    SignalServiceUrl[]          serviceUrls      = {new SignalServiceUrl(commandLine.getOptionValue("signal-host"), signalTrustStore)};
    SignalContactDiscoveryUrl[] directoryUrls    = {new SignalContactDiscoveryUrl(commandLine.getOptionValue("host"), signalTrustStore)};
    String                      mrenclave        = commandLine.getOptionValue("mrenclave");
    int                         threadCount      = Integer.parseInt(commandLine.getOptionValue("threads", "1"));
    int                         maxRequestSize   = Integer.parseInt(commandLine.getOptionValue("request-size", String.valueOf(MAX_REQUEST_SIZE)));
    SignalServiceConfiguration  serviceConfig    = new SignalServiceConfiguration(serviceUrls, new SignalCdnUrl[0], directoryUrls);

    ForkJoinPool                            requestPool = new ForkJoinPool(threadCount);
    List<CompletableFuture<Stream<String>>> futures     = new ArrayList<>();

    BlockingQueue<SignalServiceAccountManager> serviceManagers =
        IntStream.range(0, threadCount)
                 .mapToObj(threadIndex -> new SignalServiceAccountManager(serviceConfig, username, password, USER_AGENT))
                 .collect(Collectors.toCollection(() -> new ArrayBlockingQueue<>(threadCount)));

    for (int addressBookIdx = 0; addressBookIdx < addressBook.size(); addressBookIdx += maxRequestSize) {
      int         addressBookEndIdx = Math.min(addressBookIdx + maxRequestSize, addressBook.size());
      Set<String> addressBookChunk  = new HashSet<>(addressBook.subList(addressBookIdx, addressBookEndIdx));
      CompletableFuture<Stream<String>> future =
          CompletableFuture
              .supplyAsync(() -> {
                try {
                  SignalServiceAccountManager serviceManager = serviceManagers.take();
                  try {
                    return serviceManager.getRegisteredUsers(intelTrustStore, addressBookChunk, mrenclave).stream();
                  } finally {
                    serviceManagers.add(serviceManager);
                  }
                } catch (Throwable t) {
                  t.printStackTrace();
                  throw new CompletionException(t);
                }
              }, requestPool);
      futures.add(future);
    }

    System.out.println("Registered users:");
    futures.stream()
           .flatMap(future -> {
             try {
               return future.join();
             } catch (Throwable t) {
               return Stream.empty();
             }
           })
           .forEach(System.out::println);
  }

  private static void handleRegisterCommand(CommandLine commandLine) throws Throwable {
    String                 username            = commandLine.getOptionValue("username");
    String                 password            = commandLine.getOptionValue("password");
    String                 authorizationHeader = "Basic " + Base64.encodeBytes((username + ":" + password).getBytes());
    ContactDiscoveryClient client              = new ContactDiscoveryClient();

    if (commandLine.hasOption("set")) {
      client.setRegisteredUser(commandLine.getOptionValue("host"), authorizationHeader, commandLine.getOptionValue("set"));
    } else {
      client.removeRegisteredUser(commandLine.getOptionValue("host"), authorizationHeader, commandLine.getOptionValue("delete"));
    }
  }

  public static void main(String[] argv) throws Throwable {
    Security.addProvider(new BouncyCastleProvider());

    CommandLine commandLine = getCommandLine(argv);

    if (commandLine.getOptionValue("command").equals("discover")) {
      handleDiscoverCommand(commandLine);
    } else {
      handleRegisterCommand(commandLine);
    }

  }

  private static class SignalTrustStore implements TrustStore {

    private final byte[] trustStore;

    private SignalTrustStore(byte[] trustStore) {
      this.trustStore = trustStore;
    }

    public static SignalTrustStore fromFile(String trustStorePath) throws IOException {
      return new SignalTrustStore(Files.readAllBytes(Paths.get(trustStorePath)));
    }

    @Override
    public InputStream getKeyStoreInputStream() {
      return new ByteArrayInputStream(trustStore);
    }

    @Override
    public String getKeyStorePassword() {
      return TRUST_STORE_PASSWORD;
    }

  }

}
