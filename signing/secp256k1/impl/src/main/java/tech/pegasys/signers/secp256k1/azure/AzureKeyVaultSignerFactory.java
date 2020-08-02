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
  public static final String INVALID_VAULT_PARAMETERS_ERROR_PATTERN =
      "Specified key vault (%s) does not exist.";
  public static final String UNKNOWN_VAULT_ACCESS_ERROR = "Failed to access the Azure key vault";

  private static final Logger LOG = LogManager.getLogger();
  private final AzureKeyVault vault;

  public AzureKeyVaultSignerFactory(final AzureKeyVault vault) {
    this.vault = vault;
  }

  public Signer createSigner(final String keyName, final String keyVersion) {
    checkNotNull(keyName, "Config must be specified");

    final CryptographyClient cryptoClient;
    try {
      cryptoClient = vault.fetchKey(keyName, keyVersion);
    } catch (final Exception e) {
      LOG.error("Unable to load key");
      throw new SignerInitializationException(INACCESSIBLE_KEY_ERROR, e);
    }
    final JsonWebKey jsonWebKey = cryptoClient.getKey().getKey();
    final Bytes rawPublicKey =
        Bytes.concatenate(Bytes.wrap(jsonWebKey.getX()), Bytes.wrap(jsonWebKey.getY()));
    return new AzureKeyVaultSigner(cryptoClient, rawPublicKey);
    //
    //    try {
    //    } catch (final KeyVaultErrorException ex) {
    //      if (ex.response().raw().code() == 401) {
    //        LOG.debug(INACCESSIBLE_KEY_ERROR);
    //        LOG.trace(ex);
    //        throw new SignerInitializationException(INACCESSIBLE_KEY_ERROR, ex);
    //      } else {
    //        LOG.debug(INVALID_KEY_PARAMETERS_ERROR);
    //        LOG.trace(ex);
    //        throw new SignerInitializationException(INVALID_KEY_PARAMETERS_ERROR, ex);
    //      }
    //    } catch (final RuntimeException ex) {
    //      final String errorMsg;
    //      if (ex.getCause() instanceof UnknownHostException) {
    //        errorMsg = String.format(INVALID_VAULT_PARAMETERS_ERROR_PATTERN, vaultUrl);
    //      } else {
    //        errorMsg = UNKNOWN_VAULT_ACCESS_ERROR;
    //      }
    //      LOG.debug(errorMsg);
    //      LOG.trace(ex);
    //      throw new SignerInitializationException(errorMsg, ex);
    //    }

  }
}
