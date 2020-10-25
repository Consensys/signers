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
package tech.pegasys.signers.yubihsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.Disabled;
import tech.pegasys.signers.yubihsm.pkcs11.Configuration;

import java.nio.file.Path;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

@Disabled("Require physical YubiHSM device")
public class ManualYubiHsmPKCS11Test {

  private static final short AUTH_KEY = (short) 1;
  private static final String PASSWORD = "password";
  private static final Bytes expected =
      Bytes.fromHexString("0x5e8d5667ce78982a07242739ab03dc63c91e830c80a5b6adca777e3f216a405d");
  private static final Path PKCS_11_MODULE_PATH =
      Path.of("/Users/user/yubihsm2-sdk/lib/pkcs11/yubihsm_pkcs11.dylib");
  private static final String CONNECTOR_URL = "http://localhost:12345";

  @Test
  public void validKeysAreFetchedSuccessfully() {
    Configuration configuration =
        new Configuration(
            PKCS_11_MODULE_PATH, CONNECTOR_URL, Optional.of("debug libdebug"), AUTH_KEY, PASSWORD);

    try (final YubiHsmSession session = YubiHsmSessionFactory.createYubiHsmSession(configuration)) {
      final Bytes key1 = session.fetchOpaqueData((short) 30, OpaqueDataFormat.HEX);
      final Bytes key2 = session.fetchOpaqueData((short) 31, OpaqueDataFormat.ASCII);

      assertThat(key1).isEqualTo(expected);
      assertThat(key2).isEqualTo(expected);
    }
  }

  @Test
  public void errorIsReportedIfOpaqueObjectIdDoesNotExist() {
    Configuration configuration =
        new Configuration(PKCS_11_MODULE_PATH, CONNECTOR_URL, Optional.empty(), AUTH_KEY, PASSWORD);

    try (final YubiHsmSession session = YubiHsmSessionFactory.createYubiHsmSession(configuration)) {
      assertThatExceptionOfType(YubiHsmException.class)
          .isThrownBy(() -> session.fetchOpaqueData((short) 40, OpaqueDataFormat.HEX))
          .withMessage("Opaque data not found");
    }
  }

  @Test
  public void errorIsReportedIfInvalidAuthKeyIsUsed() {
    final Configuration configuration =
        new Configuration(
            PKCS_11_MODULE_PATH, CONNECTOR_URL, Optional.empty(), (short) 30, PASSWORD);

    assertThatExceptionOfType(YubiHsmException.class)
        .isThrownBy(() -> YubiHsmSessionFactory.createYubiHsmSession(configuration))
        .withMessage("Login Failed");
  }

  @Test
  public void errorIsReportedIfInvalidPasswordIsUsed() {
    final Configuration configuration =
        new Configuration(
            PKCS_11_MODULE_PATH, CONNECTOR_URL, Optional.empty(), AUTH_KEY, "invalidpassword");

    assertThatExceptionOfType(YubiHsmException.class)
        .isThrownBy(() -> YubiHsmSessionFactory.createYubiHsmSession(configuration))
        .withMessage("Login Failed");
  }

  @Test
  public void errorIsReportedIfInvalidModulePathIsUsed() {
    final Configuration configuration =
        new Configuration(
            Path.of("/invalid"), CONNECTOR_URL, Optional.empty(), AUTH_KEY, "invalidpassword");

    assertThatExceptionOfType(YubiHsmException.class)
        .isThrownBy(() -> YubiHsmSessionFactory.createYubiHsmSession(configuration))
        .withMessage("File /invalid does not exist");
  }

  @Test
  public void errorIsReportedIfInvalidConnectorUrlIsUsed() {
    final Configuration configuration =
        new Configuration(
            PKCS_11_MODULE_PATH, "http://localhost:11111", Optional.empty(), AUTH_KEY, PASSWORD);

    assertThatExceptionOfType(YubiHsmException.class)
        .isThrownBy(() -> YubiHsmSessionFactory.createYubiHsmSession(configuration))
        .withMessage("Unable to obtain slot");
  }
}
