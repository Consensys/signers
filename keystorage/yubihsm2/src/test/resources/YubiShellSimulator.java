/*
 * Copyright 2020 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.signers.yubihsm2;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.Console;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Scanner;
import java.util.concurrent.Callable;

import com.google.common.base.Objects;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Option;

/** YubiHsm Shell Simulator Simulates a subset of yubishell options Example supported commands. */
@SuppressWarnings("UnusedVariable")
@Command(name = "yubihsm-shell", mixinStandardHelpOptions = true, version = "1.0")
public class YubiShellSimulator implements Callable<Integer> {
  private static final String YUBI_SHELL_DATA_DIR =
      Optional.ofNullable(System.getenv("YUBI_SIM_DATA_DIR")).orElse(".");
  private static final String YUBI_SHELL_DATA = "yubi_shell_simulator.data";
  private static final Path YUBI_DATA_PATH = Path.of(YUBI_SHELL_DATA_DIR, YUBI_SHELL_DATA);

  enum Action {
    put_authentication_key,
    put_opaque,
    get_opaque;
  }

  static class ActionTypeConverter implements ITypeConverter<Action> {
    @Override
    public Action convert(final String value) throws Exception {
      return Action.valueOf(value.replace('-', '_'));
    }
  }

  @Option(
      names = {"-C", "--connector"},
      paramLabel = "STRING",
      description = "List of connectors to use",
      required = true)
  private String connector;

  @Option(
      names = {"-a", "--action"},
      paramLabel = "ENUM",
      description = "Action to perform.",
      required = true,
      converter = ActionTypeConverter.class)
  private Action action;

  @Option(names = "--password")
  private String password;

  @Option(
      names = "--authkey",
      paramLabel = "INT",
      description = "Authentication key (default: ${DEFAULT-VALUE}))")
  private short authKey = (short) 1;

  @Option(
      names = {"-i", "--object-id"},
      paramLabel = "SHORT",
      description = "Object ID  (default: ${DEFAULT-VALUE})")
  private short objectId = (short) 0;

  @Option(
      names = {"-l", "--label"},
      paramLabel = "STRING",
      description = "Object label (default: ${DEFAULT-VALUE})")
  private String label = "";

  @Option(
      names = {"-d", "--domains"},
      paramLabel = "STRING",
      description = "Object domains (default: ${DEFAULT-VALUE})")
  private String domains = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16";

  @Option(
      names = {"-c", "--capabilities"},
      paramLabel = "STRING",
      description = "Capabilities for an object (default: ${DEFAULT-VALUE})")
  private String capabilities = "0";

  @Option(
      names = {"--delegated"},
      paramLabel = "STRING",
      description = "Delegated capabilities (default: ${DEFAULT-VALUE})")
  private String delegated = "0";

  @Option(
      names = {"--new-password"},
      paramLabel = "STRING",
      description = "New authentication password")
  private String newPassword;

  @Option(
      names = {"-A", "--algorithm"},
      paramLabel = "STRING",
      description = "Operation Algorithm")
  private String algorithm;

  @Option(
      names = {"--in"},
      paramLabel = "STRING",
      description = "Input Data")
  private String inputData;

  @Option(
      names = {"--informat"},
      paramLabel = "STRING",
      description = "Input format (default, hex)")
  private String informat = "default";

  @Option(
      names = {"--outformat"},
      paramLabel = "STRING",
      description = "Output format (default, hex)")
  private String outformat = "default";

  @Option(
      names = {"--verbose"},
      paramLabel = "INT",
      description = "Verbose output. Default: 0")
  private int verbose = 0;

  @Option(
      names = {"--Xreset"},
      paramLabel = "BOOLEAN",
      description = "Resets data file if exists")
  private boolean reset;

  static class YubiHsmDataException extends RuntimeException {
    public YubiHsmDataException(final String message) {
      super(message);
    }
  }

  static class YubiHsmData implements Serializable {
    private final Map<Short, String> authCreds = new HashMap<>();
    private final Map<Short, String> opaqueData = new HashMap<>();

    public int createSession(final Short authId, final String password) {
      if (!authCreds.containsKey(authId)) {
        throw new YubiHsmDataException("Object Not Found");
      }

      if (!Objects.equal(authCreds.get(authId), password)) {
        throw new YubiHsmDataException("Unable to verify cryptogram");
      }

      return 0;
    }

    public void initDefaultAuth() {
      authCreds.put((short) 1, "password");
    }

    public void addAuthKey(final Short authId, final char[] password) {
      if (authCreds.containsKey(authId)) {
        throw new YubiHsmDataException("An Object with that ID already exists");
      }

      authCreds.put(authId, new String(password));
    }

    public void addOpaqueData(final Short objId, final String data) {
      if (opaqueData.containsKey(objId)) {
        throw new YubiHsmDataException("An Object with that ID already exists");
      }

      opaqueData.put(objId, data);
    }

    public String getOpaqueData(final Short objId) {
      if (!opaqueData.containsKey(objId)) {
        throw new YubiHsmDataException("Object not found");
      }

      return opaqueData.get(objId);
    }
  }

  public static void main(String[] args) {
    int returnCode = new CommandLine(new YubiShellSimulator()).execute(args);
    System.exit(returnCode);
  }

  @Override
  public Integer call() {
    if (reset) {
      resetDataFile();
    }

    askPassword();

    final YubiHsmData yubiHsmData;
    try {
      yubiHsmData = loadYubiHsmData();
    } catch (final IOException | ClassNotFoundException e) {
      System.err.println("Error loading data file: " + e.getMessage());
      return 1;
    }

    // simulate session creation
    try {
      final int session = yubiHsmData.createSession(authKey, password);
      System.out.printf("Created session %s%n", session);
    } catch (final YubiHsmDataException e) {
      System.err.println("Failed to create session: " + e.getMessage());
      System.err.println("Failed to open Session");
      return 1;
    }

    // perform actions
    switch (action) {
      case put_authentication_key:
        try {
          yubiHsmData.addAuthKey(objectId, newPassword.toCharArray());
          persistYubiHsmData(yubiHsmData);
          System.out.printf("Stored Authentication key 0x%04X%n", objectId);
        } catch (final YubiHsmDataException | IOException e) {
          System.err.println("Failed to store auth key: " + e.getMessage());
          System.err.println("Unable to store authentication key");
          return 1;
        }
        break;
      case put_opaque:
        if (algorithm == null) {
          System.err.println("Missing argument algorithm");
          return -1;
        }

        try {
          yubiHsmData.addOpaqueData(objectId, inputData);
          persistYubiHsmData(yubiHsmData);
          System.out.printf("Stored Opaque object 0x%04X%n", objectId);
        } catch (final YubiHsmDataException | IOException e) {
          System.err.println("Failed to store opaque object: " + e.getMessage());
          System.err.println("Unable to store opaque object");
          return 1;
        }
        break;

      case get_opaque:
        try {
          final String opaqueData = yubiHsmData.getOpaqueData(objectId);
          System.out.println(opaqueData);
        } catch (final YubiHsmDataException e) {
          System.err.println("Failed to get opaque object: " + e.getMessage());
          System.err.println("Unable to get opaque object");
          return 1;
        }
        break;
      default:
        System.err.println("Action not implemented");
        return 1;
    }

    return 0;
  }

  private void askPassword() {
    if (password == null) {
      final Console console = System.console();
      if (console != null) {
        final char[] passwordFromConsole = console.readPassword("Enter Password:");
        password = passwordFromConsole == null ? null : new String(passwordFromConsole);
      } else {
        Scanner scanner = new Scanner(System.in, UTF_8.name());
        password = scanner.nextLine();
      }

      if (password == null) {
        System.err.println("Password is required");
        System.exit(1);
      }
    }
  }

  private YubiHsmData loadYubiHsmData() throws IOException, ClassNotFoundException {
    final YubiHsmData yubiHsmData;
    if (!YUBI_DATA_PATH.toFile().exists()) {
      yubiHsmData = new YubiHsmData();
      yubiHsmData.initDefaultAuth();

      // attempts to persist default data file
      verboseLog("Creating " + YUBI_DATA_PATH);
      persistYubiHsmData(yubiHsmData);
    } else {
      verboseLog("Loading " + YUBI_DATA_PATH);
      try (final FileInputStream fs = new FileInputStream(YUBI_DATA_PATH.toFile());
          final ObjectInputStream os = new ObjectInputStream(fs)) {
        yubiHsmData = (YubiHsmData) os.readObject();
      }
    }
    return yubiHsmData;
  }

  private void persistYubiHsmData(final YubiHsmData yubiHsmData) throws IOException {
    try (final FileOutputStream fs = new FileOutputStream(YUBI_DATA_PATH.toFile());
        final ObjectOutputStream os = new ObjectOutputStream(fs)) {
      os.writeObject(yubiHsmData);
    }
  }

  private void resetDataFile() {
    if (YUBI_DATA_PATH.toFile().exists()) {
      verboseLog("Deleting " + YUBI_DATA_PATH);
      final boolean deleted = YUBI_DATA_PATH.toFile().delete();
      if (!deleted) {
        System.err.println("Unable to delete " + YUBI_DATA_PATH);
      }
    } else {
      verboseLog(YUBI_DATA_PATH + " does not exist, bypassing reset");
    }
  }

  private void verboseLog(final String msg) {
    if (verbose > 0) {
      System.out.println(msg);
    }
  }
}
