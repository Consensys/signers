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
package tech.pegasys.signers.secp256k1.tests.multikey.signing;

import static tech.pegasys.signers.secp256k1.MultiKeyTomlFileUtil.createAzureTomlFileAt;

import java.nio.file.Path;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class MultiKeyAzureTransactionSignerAcceptanceTest
    extends MultiKeyTransactionSigningAcceptanceTestBase {

  static final String clientId = System.getenv("AZURE_CLIENT_ID");
  static final String clientSecret = System.getenv("AZURE_CLIENT_SECRET");
  static final String keyVaultName = System.getenv("AZURE_KEY_VAULT_NAME");
  static final String tenantId = System.getenv("AZURE_TENANT_ID");

  @BeforeAll
  public static void checkAzureCredentials() {
    Assumptions.assumeTrue(
        clientId != null && clientSecret != null,
        "Ensure Azure client id and client secret env variables are set");
  }

  @Test
  public void azureLoadedFromMultiKeyCanSign(@TempDir Path tomlDirectory) {
    createAzureTomlFileAt(
        tomlDirectory.resolve(PUBLIC_KEY_HEX_STRING + ".toml"),
        clientId,
        clientSecret,
        keyVaultName,
        tenantId);
    setup(tomlDirectory);
    verifySignature();
  }
}
