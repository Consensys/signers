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

import tech.pegasys.signers.secp256k1.api.FileSelector;
import tech.pegasys.signers.secp256k1.api.PublicKey;
import tech.pegasys.signers.secp256k1.api.Signer;
import tech.pegasys.signers.secp256k1.api.SignerProvider;
import tech.pegasys.signers.secp256k1.azure.AzureConfig;
import tech.pegasys.signers.secp256k1.azure.AzureKeyVaultSignerFactory;
import tech.pegasys.signers.secp256k1.common.SignerInitializationException;
import tech.pegasys.signers.secp256k1.filebased.FileBasedSignerFactory;
import tech.pegasys.signers.secp256k1.hashicorp.HashicorpSignerFactory;
import tech.pegasys.signers.secp256k1.multikey.metadata.AzureSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.FileBasedSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.HashicorpSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.SigningMetadataFile;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import io.vertx.core.Vertx;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MultiKeySignerProvider implements SignerProvider, MultiSignerFactory {

  private static final Logger LOG = LogManager.getLogger();

  private final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader;
  private final HashicorpSignerFactory hashicorpSignerFactory;
  private final FileSelector<PublicKey> configFileSelector;

  public static MultiKeySignerProvider create(
      final Path rootDir, final FileSelector<PublicKey> configFileSelector) {
    final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader =
        new SigningMetadataTomlConfigLoader(rootDir);

    final HashicorpSignerFactory hashicorpSignerFactory = new HashicorpSignerFactory(Vertx.vertx());

    return new MultiKeySignerProvider(
        signingMetadataTomlConfigLoader, hashicorpSignerFactory, configFileSelector);
  }

  public MultiKeySignerProvider(
      final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader,
      final HashicorpSignerFactory hashicorpSignerFactory,
      final FileSelector<PublicKey> configFileSelector) {
    this.signingMetadataTomlConfigLoader = signingMetadataTomlConfigLoader;
    this.hashicorpSignerFactory = hashicorpSignerFactory;
    this.configFileSelector = configFileSelector;
  }

  @Override
  public Optional<Signer> getSigner(final PublicKey publicKey) {
    final Optional<Signer> signer =
        signingMetadataTomlConfigLoader
            .loadMetadata(configFileSelector.getSpecificConfigFileFilter(publicKey))
            .map(metadataFile -> metadataFile.createSigner(this));
    if (signer.isPresent()) {
      if (signer.get().getPublicKey().getValue().equals(publicKey.getValue())) {
        return signer;
      } else {
        LOG.warn(
            "Content of file matching {}, contains a different public key ({})",
            publicKey,
            signer.get().getPublicKey());
      }
    }
    return Optional.empty();
  }

  @Override
  public Set<PublicKey> availablePublicKeys() {
    return signingMetadataTomlConfigLoader
        .loadAvailableSigningMetadataTomlConfigs(configFileSelector.getAllConfigFilesFilter())
        .stream()
        .map(this::createSigner)
        .filter(Objects::nonNull)
        .map(Signer::getPublicKey)
        .collect(Collectors.toSet());
  }

  private Signer createSigner(final SigningMetadataFile metadataFile) {
    final Signer signer = metadataFile.createSigner(this);
    try {
      if ((signer != null)
          && configFileSelector
              .getSpecificConfigFileFilter(signer.getPublicKey())
              .accept(Path.of(metadataFile.getFilename()))) {
        return signer;
      }
      return null;
    } catch (final IOException e) {
      LOG.warn("IO Exception raised while loading {}", metadataFile.getFilename());
      return null;
    }
  }

  @Override
  public Signer createSigner(final AzureSigningMetadataFile metadataFile) {
    try {
      final AzureConfig config = metadataFile.getConfig();
      final AzureKeyVaultSignerFactory azureFactory = new AzureKeyVaultSignerFactory();
      return azureFactory.createSigner(config);
    } catch (final SignerInitializationException e) {
      LOG.error("Failed to construct Azure signer from " + metadataFile.getFilename());
      return null;
    }
  }

  @Override
  public Signer createSigner(final HashicorpSigningMetadataFile metadataFile) {
    try {
      return hashicorpSignerFactory.create(metadataFile.getConfig());
    } catch (final SignerInitializationException e) {
      LOG.error("Failed to construct Hashicorp signer from " + metadataFile.getFilename());
      return null;
    }
  }

  @Override
  public Signer createSigner(final FileBasedSigningMetadataFile metadataFile) {
    try {
      return FileBasedSignerFactory.createSigner(metadataFile.getConfig());

    } catch (final SignerInitializationException e) {
      LOG.error("Unable to construct Filebased signer from " + metadataFile.getFilename());
      return null;
    }
  }

  @Override
  public void shutdown() {
    hashicorpSignerFactory.shutdown(); // required to clean up its Vertx instance.
  }
}
