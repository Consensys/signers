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
  // TestKey2
  public static final String PUBLIC_KEY_HEX_STRING =
      "964f00253459f1f43c7a7720a0db09a328d4ee6f18838015023135d7fc921f1448de34d05de7a1f72a7b5c9f6c76931d7ab33d0f0846ccce5452063bd20f5809";

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

    setup(tomlDirectory);

    assertThat(signerProvider.availablePublicKeys().stream().map(EthPublicKeyUtils::toHexString))
        .containsOnly("0x" + PUBLIC_KEY_HEX_STRING);
  }
}
