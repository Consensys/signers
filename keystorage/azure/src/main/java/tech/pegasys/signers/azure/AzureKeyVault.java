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
package tech.pegasys.signers.azure;

import java.util.Optional;

import com.azure.core.exception.ResourceNotFoundException;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;

public class AzureKeyVault {

  private final ClientSecretCredential clientSecretCredential;
  private final SecretClient secretClient;
  private final KeyClient keyClient;

  private static final String AZURE_URL_PATTERN = "https://%s.vault.azure.net";

  public AzureKeyVault(
      final String clientId,
      final String clientSecret,
      final String tenantId,
      final String vaultName) {
    clientSecretCredential =
        new ClientSecretCredentialBuilder()
            .clientId(clientId)
            .clientSecret(clientSecret)
            .tenantId(tenantId)
            .build();

    final String vaultUrl = constructAzureKeyVaultUrl(vaultName);

    secretClient =
        new SecretClientBuilder()
            .vaultUrl(vaultUrl)
            .credential(clientSecretCredential)
            .buildClient();

    keyClient =
        new KeyClientBuilder().vaultUrl(vaultUrl).credential(clientSecretCredential).buildClient();
  }

  public Optional<String> fetchSecret(final String secretName) {
    try {
      return Optional.of(secretClient.getSecret(secretName).getValue());
    } catch (final ResourceNotFoundException e) {
      return Optional.empty();
    }
  }

  public CryptographyClient fetchKey(final String keyName, final String keyVersion) {
    final KeyVaultKey key = keyClient.getKey(keyName, keyVersion);
    final String keyId = key.getId();

    return new CryptographyClientBuilder()
        .credential(clientSecretCredential)
        .keyIdentifier(keyId)
        .buildClient();
  }

  public KeyClient getKeyClient() {
    return keyClient;
  }

  public static String constructAzureKeyVaultUrl(final String keyVaultName) {
    return String.format(AZURE_URL_PATTERN, keyVaultName);
  }
}
