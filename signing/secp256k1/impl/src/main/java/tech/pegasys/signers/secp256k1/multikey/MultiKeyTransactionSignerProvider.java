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

import tech.pegasys.signers.cavium.CaviumKeyStoreProvider;
import tech.pegasys.signers.secp256k1.api.TransactionSigner;
import tech.pegasys.signers.secp256k1.api.TransactionSignerProvider;
import tech.pegasys.signers.secp256k1.azure.AzureKeyVaultAuthenticator;
import tech.pegasys.signers.secp256k1.azure.AzureKeyVaultTransactionSignerFactory;
import tech.pegasys.signers.secp256k1.cavium.CaviumKeyStoreSignerFactory;
import tech.pegasys.signers.secp256k1.common.TransactionSignerInitializationException;
import tech.pegasys.signers.secp256k1.filebased.FileBasedSignerFactory;
import tech.pegasys.signers.secp256k1.hashicorp.HashicorpSignerFactory;
import tech.pegasys.signers.secp256k1.hsm.HSMTransactionSignerFactory;
import tech.pegasys.signers.secp256k1.multikey.metadata.AzureSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.CaviumSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.FileBasedSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.HSMSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.HashicorpSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.SigningMetadataFile;

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
  private final AzureKeyVaultTransactionSignerFactory azureFactory;
  private final HashicorpSignerFactory hashicorpSignerFactory;
  private final HSMTransactionSignerFactory hsmFactory;
  private final CaviumKeyStoreSignerFactory caviumFactory;

  public static MultiKeyTransactionSignerProvider create(
      final Path rootDir, final String... subArgs) {
    final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader =
        new SigningMetadataTomlConfigLoader(rootDir);

    final AzureKeyVaultTransactionSignerFactory azureFactory =
        new AzureKeyVaultTransactionSignerFactory(new AzureKeyVaultAuthenticator());

    final HashicorpSignerFactory hashicorpSignerFactory = new HashicorpSignerFactory(Vertx.vertx());

    String library = null;
    String label = null;
    String pin = null;
    if (subArgs != null && subArgs.length > 2) {
      library = subArgs[0];
      label = subArgs[1];
      pin = subArgs[2];
    }

    final HSMTransactionSignerFactory hsmFactory =
        new HSMTransactionSignerFactory(library, label, pin);

    final CaviumKeyStoreSignerFactory caviumFactory =
        new CaviumKeyStoreSignerFactory(new CaviumKeyStoreProvider(library, pin));

    return new MultiKeyTransactionSignerProvider(
        signingMetadataTomlConfigLoader,
        azureFactory,
        hashicorpSignerFactory,
        hsmFactory,
        caviumFactory);
  }

  public MultiKeyTransactionSignerProvider(
      final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader,
      final AzureKeyVaultTransactionSignerFactory azureFactory,
      final HashicorpSignerFactory hashicorpSignerFactory,
      final HSMTransactionSignerFactory hsmFactory,
      final CaviumKeyStoreSignerFactory caviumFactory) {
    this.signingMetadataTomlConfigLoader = signingMetadataTomlConfigLoader;
    this.azureFactory = azureFactory;
    this.hashicorpSignerFactory = hashicorpSignerFactory;
    this.hsmFactory = hsmFactory;
    this.caviumFactory = caviumFactory;
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
    final TransactionSigner signer;
    try {
      signer = azureFactory.createSigner(metadataFile.getConfig());
    } catch (final TransactionSignerInitializationException e) {
      LOG.error("Failed to construct Azure signer from " + metadataFile.getBaseFilename());
      return null;
    }

    if (filenameMatchesSigningAddress(signer, metadataFile)) {
      LOG.info("Loaded signer for address {}", signer.getAddress());
      return signer;
    }

    return null;
  }

  @Override
  public TransactionSigner createSigner(final HashicorpSigningMetadataFile metadataFile) {
    final TransactionSigner signer;
    try {
      signer = hashicorpSignerFactory.create(metadataFile.getConfig());
    } catch (final TransactionSignerInitializationException e) {
      LOG.error("Failed to construct Hashicorp signer from " + metadataFile.getBaseFilename());
      return null;
    }

    if (filenameMatchesSigningAddress(signer, metadataFile)) {
      LOG.info("Loaded signer for address {}", signer.getAddress());
      return signer;
    }

    return null;
  }

  @Override
  public TransactionSigner createSigner(final FileBasedSigningMetadataFile metadataFile) {
    try {
      final TransactionSigner signer =
          FileBasedSignerFactory.createSigner(
              metadataFile.getKeyPath(), metadataFile.getPasswordPath());
      if (filenameMatchesSigningAddress(signer, metadataFile)) {
        LOG.info("Loaded signer for address {}", signer.getAddress());
        return signer;
      }

      return null;

    } catch (final TransactionSignerInitializationException e) {
      LOG.error("Unable to load signer with key " + metadataFile.getKeyPath().getFileName(), e);
      return null;
    }
  }

  private boolean filenameMatchesSigningAddress(
      final TransactionSigner signer, final SigningMetadataFile metadataFile) {

    // strip leading 0x from the address.
    final String signerAddress = signer.getAddress().substring(2).toLowerCase();
    if (!metadataFile.getBaseFilename().toLowerCase().endsWith(signerAddress)) {
      LOG.error(
          String.format(
              "Signer's Ethereum Address (%s) does not align with metadata filename (%s)",
              signerAddress, metadataFile.getBaseFilename()));
      return false;
    }
    return true;
  }

  @Override
  public TransactionSigner createSigner(final HSMSigningMetadataFile metadataFile) {
    final TransactionSigner signer;
    if (!metadataFile.getConfig().getSlot().equals(hsmFactory.getSlotLabel())) {
      LOG.error("Failed to construct HSM signer for slot " + metadataFile.getConfig().getSlot());
      return null;
    }
    try {
      signer = hsmFactory.createSigner(metadataFile.getConfig().getAddress());
    } catch (final TransactionSignerInitializationException e) {
      LOG.error("Failed to construct HSM signer from " + metadataFile.getBaseFilename());
      return null;
    }

    if (filenameMatchesSigningAddress(signer, metadataFile)) {
      LOG.info("Loaded signer for address {}", signer.getAddress());
      return signer;
    }

    return null;
  }

  @Override
  public TransactionSigner createSigner(final CaviumSigningMetadataFile metadataFile) {
    final TransactionSigner signer;
    try {
      signer = caviumFactory.createSigner(metadataFile.getConfig().getAddress());
    } catch (final TransactionSignerInitializationException e) {
      LOG.error("Failed to construct Cavium signer from " + metadataFile.getBaseFilename());
      return null;
    }

    if (filenameMatchesSigningAddress(signer, metadataFile)) {
      LOG.info("Loaded signer for address {}", signer.getAddress());
      return signer;
    }

    return null;
  }

  @Override
  public void shutdown() {
    hashicorpSignerFactory.shutdown(); // required to clean up its Vertx instance.
    hsmFactory.shutdown();
    caviumFactory.shutdown();
  }
}
