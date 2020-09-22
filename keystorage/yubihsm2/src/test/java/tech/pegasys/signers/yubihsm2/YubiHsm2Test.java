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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static tech.pegasys.signers.yubihsm2.ProcessUtil.executeProcess;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

import com.google.common.io.Resources;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class YubiHsm2Test {
  @TempDir static Path hsmDataDir;
  private static final short DEFAULT_AUTH_KEY = (short) 1;
  private static final String DEFAULT_PASSWORD = "password";
  private static final short SECONDARY_AUTH_KEY = (short) 2;
  private static final String SECONDARY_PASSWORD = "password2";
  private static List<String> expectedKeys = new ArrayList<>(10);

  @BeforeAll
  static void initYubiHsmSimulator() throws IOException, TimeoutException, InterruptedException {
    addSecondaryAuthKey();
    addOpaqueData();
  }

  @Test
  public void validKeysAreFetchedSuccessfully() {
    final YubiHsm2 yubiHsm2 =
        new YubiHsm2(
            yubiHsmSimulatorBinArgs(),
            Optional.of(envVar()),
            "http://localhost:12345",
            SECONDARY_AUTH_KEY,
            SECONDARY_PASSWORD,
            Optional.empty(),
            Optional.empty());

    for (int i = 1; i <= 10; i++) {
      final String key = yubiHsm2.fetchOpaqueData((short) i, Optional.of(OutputFormat.ASCII));
      assertThat(key).isEqualTo(expectedKeys.get(i - 1));
    }
  }

  @Test
  public void errorIsReportedIfOpaqueObjectIdDoesNotExist() {
    final YubiHsm2 yubiHsm2 =
        new YubiHsm2(
            yubiHsmSimulatorBinArgs(),
            Optional.of(envVar()),
            "http://localhost:12345",
            SECONDARY_AUTH_KEY,
            SECONDARY_PASSWORD,
            Optional.empty(),
            Optional.empty());

    assertThatExceptionOfType(YubiHsmException.class)
        .isThrownBy(() -> yubiHsm2.fetchOpaqueData((short) 11, Optional.of(OutputFormat.ASCII)))
        .withMessageContaining("Unable to get opaque object");
  }

  @Test
  public void errorIsReportedIfInvalidAuthKeyIsUsed() {
    final YubiHsm2 yubiHsm2 =
        new YubiHsm2(
            yubiHsmSimulatorBinArgs(),
            Optional.of(envVar()),
            "http://localhost:12345",
            (short) 4,
            SECONDARY_PASSWORD,
            Optional.empty(),
            Optional.empty());

    assertThatExceptionOfType(YubiHsmException.class)
        .isThrownBy(() -> yubiHsm2.fetchOpaqueData((short) 11, Optional.of(OutputFormat.ASCII)))
        .withMessage("Unable to fetch data from YubiHSM: Failed to open Session");
  }

  @Test
  public void errorIsReportedIfInvalidAuthPasswordIsUsed() {
    final YubiHsm2 yubiHsm2 =
        new YubiHsm2(
            yubiHsmSimulatorBinArgs(),
            Optional.of(envVar()),
            "http://localhost:12345",
            SECONDARY_AUTH_KEY,
            DEFAULT_PASSWORD,
            Optional.empty(),
            Optional.empty());

    assertThatExceptionOfType(YubiHsmException.class)
        .isThrownBy(() -> yubiHsm2.fetchOpaqueData((short) 11, Optional.of(OutputFormat.ASCII)))
        .withMessage("Unable to fetch data from YubiHSM: Failed to open Session");
  }

  private static void addOpaqueData() throws IOException, TimeoutException, InterruptedException {
    for (int i = 1; i <= 10; i++) {
      final String privateKeyStr = "key" + i;
      expectedKeys.add(privateKeyStr);
      final List<String> args = addOpaqueArgs((short) i, privateKeyStr);
      final String output = executeProcess(args, envVar(), SECONDARY_PASSWORD);
      assertThat(output).contains(String.format("Stored Opaque object 0x%04X", i));
    }
  }

  private static void addSecondaryAuthKey()
      throws IOException, InterruptedException, TimeoutException {
    final List<String> args = addAuthKeyArgs(SECONDARY_AUTH_KEY, SECONDARY_PASSWORD);
    final String output = executeProcess(args, envVar(), DEFAULT_PASSWORD);
    assertThat(output).contains("Stored Authentication key 0x0002");
  }

  private static List<String> addAuthKeyArgs(final short newAuthKeyId, final String newPassword) {
    ArrayList<String> args = new ArrayList<>(yubiHsmSimulatorBinArgs());
    args.addAll(
        List.of(
            "--connector=http://localhost:12345",
            "--authkey=" + DEFAULT_AUTH_KEY,
            "--action=put-authentication-key",
            "--new-password=" + newPassword,
            "--object-id=" + newAuthKeyId,
            "--domains=1,2,3",
            "--capabilities=get-opaque,put-opaque,delete-opaque,export-wrapped,get-pseudo-random,put-wrap-key,import-wrapped",
            "--delegated=exportable-under-wrap,export-wrapped,import-wrapped"));
    return args;
  }

  private static List<String> addOpaqueArgs(short objId, String hexData) {
    ArrayList<String> args = new ArrayList<>(yubiHsmSimulatorBinArgs());
    args.addAll(
        List.of(
            "--connector=http://localhost:12345",
            "--authkey=" + SECONDARY_AUTH_KEY,
            "--action=put-opaque",
            "--object-id=" + objId,
            "--domains=1,2,3",
            "--algorithm=opaque-data",
            "--capabilities=none",
            "--informat=hex",
            "--in=" + hexData));
    return args;
  }

  private static Map<String, String> envVar() {
    return Map.of("YUBI_SIM_DATA_DIR", hsmDataDir.toString());
  }

  private static List<String> yubiHsmSimulatorBinArgs() {
    final URL simulatorSource = Resources.getResource("YubiShellSimulator.java");
    return List.of(
        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "-cp",
        System.getProperty("java.class.path"),
        simulatorSource.getPath());
  }
}
