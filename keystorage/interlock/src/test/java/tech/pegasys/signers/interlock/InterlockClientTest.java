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

import tech.pegasys.signers.interlock.model.ApiAuth;

import java.nio.file.Path;

import io.vertx.core.Vertx;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@Disabled("Required access to actual Usb Armory")
public class InterlockClientTest {
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
  void successfullyFetchKey() {
    final Path whitelistFile = tempDir.resolve("whitelist.txt");
    final VertxHttpClientFactory vertxHttpClientFactory =
        new VertxHttpClientFactory(vertx, "10.0.0.1", 443, whitelistFile);
    final InterlockClient interlockClient = new InterlockClient(vertxHttpClientFactory);
    final ApiAuth apiAuth = interlockClient.login("armory", "usbarmory");

    try {
      final String blsKey = interlockClient.fetchKey(apiAuth, "/bls/key1.txt");
      assertThat(blsKey)
          .isEqualTo("3ee2224386c82ffea477e2adf28a2929f5c349165a4196158c7f3a2ecca40f35")
          .as("BLS Key");
    } finally {
      interlockClient.logout(apiAuth);
    }
  }
}
