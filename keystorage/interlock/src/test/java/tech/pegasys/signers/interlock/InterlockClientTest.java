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
package tech.pegasys.signers.interlock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import tech.pegasys.signers.interlock.model.ApiAuth;

import java.nio.file.Path;
import java.util.Collections;

import io.vertx.core.Vertx;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@Disabled("Required access to actual Usb Armory with Interlock")
public class InterlockClientTest {
  private static final String EXPECTED =
      "3ee2224386c82ffea477e2adf28a2929f5c349165a4196158c7f3a2ecca40f35";
  private static Vertx vertx;
  @TempDir Path tempDir;

  @BeforeAll
  static void beforeAll() {
    vertx = Vertx.vertx();
  }

  @AfterAll
  static void afterAll() {
    vertx.close();
  }

  @Test
  void successfullyDecryptAndFetchKey() {
    final Path whitelistFile = tempDir.resolve("whitelist.txt");
    final InterlockClient interlockClient =
        InterlockClientFactory.create(vertx, "10.0.0.1", 443, whitelistFile);
    final ApiAuth apiAuth = interlockClient.login("armory", "usbarmory");

    final String blsKey = interlockClient.fetchKey(apiAuth, Path.of("/bls/key1.txt"));
    assertThat(blsKey).isEqualTo(EXPECTED);

    interlockClient.logout(apiAuth);
  }

  @Test
  void errorRaisedForInvalidLoginCredentials() {
    final Path whitelistFile = tempDir.resolve("whitelist.txt");
    final InterlockClient interlockClient =
        InterlockClientFactory.create(vertx, "10.0.0.1", 443, whitelistFile);

    assertThatExceptionOfType(InterlockClientException.class)
        .isThrownBy(() -> interlockClient.login("test", "test"))
        .withMessage(
            "Login failed. Status: INVALID_SESSION, Response: [\"Device /dev/lvmvolume/test doesn't exist or access denied.\\n\"]");
  }

  @Test
  void errorRaisedForInvalidKeyPath() {
    final Path whitelistFile = tempDir.resolve("whitelist.txt");
    final InterlockClient interlockClient =
        InterlockClientFactory.create(vertx, "10.0.0.1", 443, whitelistFile);

    final ApiAuth apiAuth = interlockClient.login("armory", "usbarmory");

    assertThatExceptionOfType(InterlockClientException.class)
        .isThrownBy(() -> interlockClient.fetchKey(apiAuth, Path.of("/test/test.txt")))
        .withMessage(
            "Download File Id failed. Status: KO, Response: [\"stat /home/interlock/.interlock-mnt/test/test.txt: no such file or directory\"]");

    interlockClient.logout(apiAuth);
  }

  @Test
  void errorRaisedForInvalidAuthLogout() {
    final Path whitelistFile = tempDir.resolve("whitelist.txt");
    final InterlockClient interlockClient =
        InterlockClientFactory.create(vertx, "10.0.0.1", 443, whitelistFile);

    final ApiAuth apiAuth = new ApiAuth("test", Collections.emptyList());
    assertThatExceptionOfType(InterlockClientException.class)
        .isThrownBy(() -> interlockClient.logout(apiAuth))
        .withMessage("Logout failed. Status: INVALID_SESSION, Response: null");
  }
}
