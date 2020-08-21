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
package tech.pegasys.signers.secp256k1.azure;

import static com.google.common.base.Preconditions.checkNotNull;

import tech.pegasys.signers.azure.AzureKeyVault;
import tech.pegasys.signers.secp256k1.api.Signer;
import tech.pegasys.signers.secp256k1.common.SignerInitializationException;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class AzureKeyVaultSignerFactory {

  public static final String INACCESSIBLE_KEY_ERROR = "Failed to authenticate to vault.";
  public static final String INVALID_KEY_PARAMETERS_ERROR =
      "Keyvault does not contain key with specified parameters";
  private static final Logger LOG = LogManager.getLogger();

  private final boolean needsToHash;

  public AzureKeyVaultSignerFactory() {
    this(true);
  }

  public AzureKeyVaultSignerFactory(final boolean needsToHash) {
    this.needsToHash = needsToHash;
  }

  public Signer createSigner(final AzureConfig config) {
    checkNotNull(config, "Config must be specified");

    final AzureKeyVault vault;
    try {
      vault =
          new AzureKeyVault(
              config.getClientId(),
              config.getClientSecret(),
              config.getTenantId(),
              config.getKeyVaultName());
    } catch (final Exception e) {
      LOG.error("Failed to connect to vault", e);
      throw new SignerInitializationException(INACCESSIBLE_KEY_ERROR, e);
    }

    final CryptographyClient cryptoClient;
    try {
      cryptoClient = vault.fetchKey(config.getKeyName(), config.getKeyVersion());
    } catch (final Exception e) {
      LOG.error("Unable to load key {}", e.getMessage());
      throw new SignerInitializationException(INVALID_KEY_PARAMETERS_ERROR, e);
    }
    final JsonWebKey jsonWebKey = cryptoClient.getKey().getKey();
    final Bytes rawPublicKey =
        Bytes.concatenate(Bytes.wrap(jsonWebKey.getX()), Bytes.wrap(jsonWebKey.getY()));
    return new AzureKeyVaultSigner(config, rawPublicKey, needsToHash);
  }
}
