/*
 * Copyright 2019 ConsenSys AG.
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
package tech.pegasys.signers.secp256k1.tests.multikey;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.pegasys.signers.secp256k1.MultiKeyTomlFileUtil.createAzureTomlFileAt;

import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;

import java.nio.file.Path;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class AzureBasedTomlLoadingAcceptanceTest extends MultiKeyAcceptanceTestBase {

  static final String clientId = System.getenv("AZURE_CLIENT_ID");
  static final String clientSecret = System.getenv("AZURE_CLIENT_SECRET");
  static final String keyVaultName = System.getenv("AZURE_KEY_VAULT_NAME");
  static final String tenantId = System.getenv("AZURE_TENANT_ID");
  public static final String PUBLIC_KEY_HEX_STRING =
      "09b02f8a5fddd222ade4ea4528faefc399623af3f736be3c44f03e2df22fb792f3931a4d9573d333ca74343305762a753388c3422a86d98b713fc91c1ea04842";

  @BeforeAll
  static void preChecks() {
    Assumptions.assumeTrue(
        clientId != null && clientSecret != null && keyVaultName != null && tenantId != null,
        "Ensure Azure env variables are set");
  }

  @Test
  void azureSignersAreCreatedAndExpectedAddressIsReported(@TempDir Path tomlDirectory) {
    createAzureTomlFileAt(
        tomlDirectory.resolve(PUBLIC_KEY_HEX_STRING + ".toml"),
        clientId,
        clientSecret,
        keyVaultName,
        tenantId);

    setup(tomlDirectory, Path.of(""));

    assertThat(signerProvider.availablePublicKeys().stream().map(EthPublicKeyUtils::toHexString))
        .containsOnly("0x" + PUBLIC_KEY_HEX_STRING);
  }
}
