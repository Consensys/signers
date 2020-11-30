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

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.core.http.rest.PagedIterable;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AzureKeyVault {

  private static final Logger LOG = LogManager.getLogger();

  private final TokenCredential tokenCredential;
  private final SecretClient secretClient;
  private final KeyClient keyClient;

  private static final String AZURE_URL_PATTERN = "https://%s.vault.azure.net";

  public static AzureKeyVault createUsingClientSecretCredentials(
      final String clientId,
      final String clientSecret,
      final String tenantId,
      final String vaultName) {
    final TokenCredential tokenCredential =
        new ClientSecretCredentialBuilder()
            .clientId(clientId)
            .clientSecret(clientSecret)
            .tenantId(tenantId)
            .build();

    return new AzureKeyVault(tokenCredential, vaultName);
  }

  public static AzureKeyVault createUsingManagedIdentity(
      final Optional<String> clientId, final String vaultName) {
    final ManagedIdentityCredentialBuilder managedIdentityCredentialBuilder =
        new ManagedIdentityCredentialBuilder();
    clientId.ifPresent(managedIdentityCredentialBuilder::clientId);
    return new AzureKeyVault(managedIdentityCredentialBuilder.build(), vaultName);
  }

  private AzureKeyVault(final TokenCredential tokenCredential, final String vaultName) {
    this.tokenCredential = tokenCredential;
    final String vaultUrl = constructAzureKeyVaultUrl(vaultName);

    secretClient =
        new SecretClientBuilder().vaultUrl(vaultUrl).credential(tokenCredential).buildClient();

    keyClient = new KeyClientBuilder().vaultUrl(vaultUrl).credential(tokenCredential).buildClient();
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
        .credential(tokenCredential)
        .keyIdentifier(keyId)
        .buildClient();
  }

  public static String constructAzureKeyVaultUrl(final String keyVaultName) {
    return String.format(AZURE_URL_PATTERN, keyVaultName);
  }

  public List<String> getAvailableSecrets() {
    return secretClient.listPropertiesOfSecrets().stream()
        .map(SecretProperties::getName)
        .collect(Collectors.toList());
  }

  public <R> Collection<R> mapSecrets(final BiFunction<String, String, R> mapper) {
    final PagedIterable<SecretProperties> secretsPagedIterable;
    try {
      secretsPagedIterable = secretClient.listPropertiesOfSecrets();
    } catch (final Exception e) {
      throw new RuntimeException(
          "Failed to connect to an Azure Keyvault with provided configuration.", e);
    }

    final Set<R> result = ConcurrentHashMap.newKeySet();
    secretsPagedIterable
        .streamByPage()
        .forEach(
            keyPage ->
                keyPage
                    .getValue()
                    .parallelStream()
                    .forEach(
                        sp -> {
                          try {
                            final KeyVaultSecret secret = secretClient.getSecret(sp.getName());
                            final R obj = mapper.apply(sp.getName(), secret.getValue());
                            if (obj != null) {
                              result.add(obj);
                            } else {
                              LOG.warn(
                                  "Mapped '{}' to a null object, and was discarded", sp.getName());
                            }
                          } catch (final Exception e) {
                            LOG.warn(
                                "Failed to map secret '{}' to requested object type.",
                                sp.getName());
                          }
                        }));

    return result;
  }
}
