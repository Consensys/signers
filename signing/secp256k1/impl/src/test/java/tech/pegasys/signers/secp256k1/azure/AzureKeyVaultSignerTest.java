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
package tech.pegasys.signers.secp256k1.azure;

import static java.nio.charset.StandardCharsets.UTF_8;

import tech.pegasys.signers.secp256k1.api.Signer;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class AzureKeyVaultSignerTest {

  private static final String clientId = System.getenv("AZURE_CLIENT_ID");
  private static final String clientSecret = System.getenv("AZURE_CLIENT_SECRET");
  private static final String keyVaultName = System.getenv("AZURE_KEY_VAULT_NAME");
  private static final String tenantId = System.getenv("AZURE_TENANT_ID");

  @BeforeAll
  static void preChecks() {
    Assumptions.assumeTrue(
        clientId != null && clientSecret != null && keyVaultName != null && tenantId != null,
        "Ensure Azure env variables are set");
  }

  @Test
  public void azureSignerCanSignTwice() {
    final AzureConfig config =
        new AzureConfig(keyVaultName, "TestKey", "", clientId, clientSecret, tenantId);

    final AzureKeyVaultSignerFactory factory = new AzureKeyVaultSignerFactory();
    final Signer signer = factory.createSigner(config);
    signer.sign("Hello World".getBytes(UTF_8));
    signer.sign("Hello World".getBytes(UTF_8));
  }
}
