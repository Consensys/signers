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
package tech.pegasys.signers.secp256k1.multikey;

import tech.pegasys.signers.secp256k1.DefaultTransactionSigner;
import tech.pegasys.signers.secp256k1.api.TransactionSigner;
import tech.pegasys.signers.secp256k1.api.TransactionSignerProvider;
import tech.pegasys.signers.secp256k1.azure.AzureKeyVaultAuthenticator;
import tech.pegasys.signers.secp256k1.azure.AzureKeyVaultSignerFactory;
import tech.pegasys.signers.secp256k1.common.TransactionSignerInitializationException;
import tech.pegasys.signers.secp256k1.filebased.FileBasedSignerFactory;
import tech.pegasys.signers.secp256k1.hashicorp.HashicorpSignerFactory;
import tech.pegasys.signers.secp256k1.multikey.metadata.AzureSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.FileBasedSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.HashicorpSigningMetadataFile;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import io.vertx.core.Vertx;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MultiKeyTransactionSignerProvider
    implements TransactionSignerProvider, MultiSignerFactory {

  private static final Logger LOG = LogManager.getLogger();

  private final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader;
  private final AzureKeyVaultSignerFactory azureFactory;
  private final HashicorpSignerFactory hashicorpSignerFactory;

  public static MultiKeyTransactionSignerProvider create(final Path rootDir) {
    final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader =
        new SigningMetadataTomlConfigLoader(rootDir);

    final AzureKeyVaultSignerFactory azureFactory =
        new AzureKeyVaultSignerFactory(new AzureKeyVaultAuthenticator());

    final HashicorpSignerFactory hashicorpSignerFactory = new HashicorpSignerFactory(Vertx.vertx());

    return new MultiKeyTransactionSignerProvider(
        signingMetadataTomlConfigLoader, azureFactory, hashicorpSignerFactory);
  }

  public MultiKeyTransactionSignerProvider(
      final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader,
      final AzureKeyVaultSignerFactory azureFactory,
      final HashicorpSignerFactory hashicorpSignerFactory) {
    this.signingMetadataTomlConfigLoader = signingMetadataTomlConfigLoader;
    this.azureFactory = azureFactory;
    this.hashicorpSignerFactory = hashicorpSignerFactory;
  }

  @Override
  public Optional<TransactionSigner> getSigner(final String address) {
    return signingMetadataTomlConfigLoader
        .loadMetadataForAddress(address)
        .map(metadataFile -> metadataFile.createSigner(this));
  }

  @Override
  public Set<String> availableAddresses() {
    return signingMetadataTomlConfigLoader.loadAvailableSigningMetadataTomlConfigs().stream()
        .map(metadataFile -> metadataFile.createSigner(this))
        .filter(Objects::nonNull)
        .map(TransactionSigner::getAddress)
        .collect(Collectors.toSet());
  }

  @Override
  public TransactionSigner createSigner(final AzureSigningMetadataFile metadataFile) {
    try {
      return new DefaultTransactionSigner(azureFactory.createSigner(metadataFile.getConfig()));
    } catch (final TransactionSignerInitializationException e) {
      LOG.error("Failed to construct Azure signer from " + metadataFile.getBaseFilename());
      return null;
    }
  }

  @Override
  public TransactionSigner createSigner(final HashicorpSigningMetadataFile metadataFile) {
    try {
      return new DefaultTransactionSigner(hashicorpSignerFactory.create(metadataFile.getConfig()));
    } catch (final TransactionSignerInitializationException e) {
      LOG.error("Failed to construct Hashicorp signer from " + metadataFile.getBaseFilename());
      return null;
    }
  }

  @Override
  public TransactionSigner createSigner(final FileBasedSigningMetadataFile metadataFile) {
    try {
      return new DefaultTransactionSigner(
          FileBasedSignerFactory.createSigner(
              metadataFile.getKeyPath(), metadataFile.getPasswordPath()));

    } catch (final TransactionSignerInitializationException e) {
      LOG.error("Unable to load signer with key " + metadataFile.getKeyPath().getFileName(), e);
      return null;
    }
  }

  @Override
  public void shutdown() {
    hashicorpSignerFactory.shutdown(); // required to clean up its Vertx instance.
  }
}
