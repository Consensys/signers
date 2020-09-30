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

import tech.pegasys.signers.cavium.CaviumConfig;
import tech.pegasys.signers.cavium.CaviumKeyStoreProvider;
import tech.pegasys.signers.hsm.HSMConfig;
import tech.pegasys.signers.hsm.HSMWalletProvider;
import tech.pegasys.signers.secp256k1.api.FileSelector;
import tech.pegasys.signers.secp256k1.api.Signer;
import tech.pegasys.signers.secp256k1.api.SignerProvider;
import tech.pegasys.signers.secp256k1.azure.AzureConfig;
import tech.pegasys.signers.secp256k1.azure.AzureKeyVaultSignerFactory;
import tech.pegasys.signers.secp256k1.cavium.CaviumKeyStoreSignerFactory;
import tech.pegasys.signers.secp256k1.common.SignerInitializationException;
import tech.pegasys.signers.secp256k1.filebased.CredentialSigner;
import tech.pegasys.signers.secp256k1.filebased.FileBasedSignerFactory;
import tech.pegasys.signers.secp256k1.hashicorp.HashicorpSignerFactory;
import tech.pegasys.signers.secp256k1.hsm.HSMSignerFactory;
import tech.pegasys.signers.secp256k1.multikey.metadata.AzureSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.CaviumSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.FileBasedSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.HSMSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.HashicorpSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.RawSigningMetadataFile;
import tech.pegasys.signers.secp256k1.multikey.metadata.SigningMetadataFile;

import java.io.IOException;
import java.nio.file.Path;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import io.vertx.core.Vertx;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.toml.TomlInvalidTypeException;
import org.apache.tuweni.toml.TomlParseResult;
import org.apache.tuweni.toml.TomlTable;
import org.web3j.crypto.Credentials;

public class MultiKeySignerProvider implements SignerProvider, MultiSignerFactory {

  private static final Logger LOG = LogManager.getLogger();

  private final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader;
  private final HashicorpSignerFactory hashicorpSignerFactory;
  private final HSMSignerFactory hsmFactory;
  private final CaviumKeyStoreSignerFactory caviumFactory;
  private final FileSelector<ECPublicKey> configFileSelector;

  public static MultiKeySignerProvider create(
      final Path rootDir,
      final Path configFile,
      final FileSelector<ECPublicKey> configFileSelector) {
    final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader =
        new SigningMetadataTomlConfigLoader(rootDir);

    final HashicorpSignerFactory hashicorpSignerFactory = new HashicorpSignerFactory(Vertx.vertx());

    HSMSignerFactory hsmFactory = null;
    CaviumKeyStoreSignerFactory caviumFactory = null;
    Optional<TomlParseResult> result = loadConfig(configFile);
    if (result.isPresent()) {
      try {
        final HSMConfig hsmConfig = getHSMConfigFrom(result.get());
        final HSMWalletProvider provider = new HSMWalletProvider(hsmConfig);
        provider.initialize();
        hsmFactory = new HSMSignerFactory(provider);
      } catch (final Exception e) {
        LOG.error("Unable to initialize HSM signer factory from config in " + configFile);
      }
      try {
        final CaviumConfig caviumConfig = getCaviumConfigFrom(result.get());
        CaviumKeyStoreProvider provider = new CaviumKeyStoreProvider(caviumConfig);
        provider.initialize();
        caviumFactory = new CaviumKeyStoreSignerFactory(provider);
      } catch (final Exception e) {
        LOG.error("Unable to initialize Cavium signer factory from config in " + configFile);
      }
    }

    return new MultiKeySignerProvider(
        signingMetadataTomlConfigLoader,
        hashicorpSignerFactory,
        hsmFactory,
        caviumFactory,
        configFileSelector);
  }

  public MultiKeySignerProvider(
      final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader,
      final HashicorpSignerFactory hashicorpSignerFactory,
      final HSMSignerFactory hsmFactory,
      final CaviumKeyStoreSignerFactory caviumFactory,
      final FileSelector<ECPublicKey> configFileSelector) {
    this.signingMetadataTomlConfigLoader = signingMetadataTomlConfigLoader;
    this.hashicorpSignerFactory = hashicorpSignerFactory;
    this.hsmFactory = hsmFactory;
    this.caviumFactory = caviumFactory;
    this.configFileSelector = configFileSelector;
  }

  private static Optional<TomlParseResult> loadConfig(final Path file) {
    if (file == null) return Optional.empty();
    final String filename = file.getFileName().toString();
    try {
      return Optional.of(
          TomlConfigFileParser.loadConfigurationFromFile(file.toAbsolutePath().toString()));

    } catch (final IllegalArgumentException | TomlInvalidTypeException e) {
      final String errorMsg = String.format("%s failed to decode: %s", filename, e.getMessage());
      LOG.error(errorMsg);
      return Optional.empty();
    } catch (final Exception e) {
      LOG.error("Could not load TOML file " + file, e);
      return Optional.empty();
    }
  }

  private static HSMConfig getHSMConfigFrom(final TomlParseResult result) {
    final HSMConfig.HSMConfigBuilder builder = new HSMConfig.HSMConfigBuilder();
    final TomlTable hsmSignerTable = result.getTable("hsm-signer");
    if (hsmSignerTable == null || hsmSignerTable.isEmpty()) {
      return builder.fromEnvironmentVariables().build();
    }
    final TomlTableAdapter table = new TomlTableAdapter(hsmSignerTable);
    builder.withLibrary(table.getString("library"));
    builder.withSlot(table.getString("slot"));
    builder.withPin(table.getString("pin"));
    return builder.build();
  }

  private static CaviumConfig getCaviumConfigFrom(final TomlParseResult result) {
    final CaviumConfig.CaviumConfigBuilder builder = new CaviumConfig.CaviumConfigBuilder();
    final TomlTable caviumSignerTable = result.getTable("cavium-signer");
    if (caviumSignerTable == null || caviumSignerTable.isEmpty()) {
      return builder.fromEnvironmentVariables().build();
    }
    final TomlTableAdapter table = new TomlTableAdapter(caviumSignerTable);
    builder.withLibrary(table.getString("library"));
    builder.withPin(table.getString("pin"));
    return builder.build();
  }

  @Override
  public Optional<Signer> getSigner(final ECPublicKey publicKey) {
    final Optional<Signer> signer =
        signingMetadataTomlConfigLoader
            .loadMetadata(configFileSelector.getSpecificConfigFileFilter(publicKey))
            .map(metadataFile -> metadataFile.createSigner(this));
    if (signer.isPresent()) {
      if (signer.get().getPublicKey().getW().equals(publicKey.getW())) {
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
  public Set<ECPublicKey> availablePublicKeys() {
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
  public Signer createSigner(final RawSigningMetadataFile metadataFile) {
    try {
      final Credentials credentials = Credentials.create(metadataFile.getPrivKey());
      return new CredentialSigner(credentials);
    } catch (final Exception e) {
      LOG.error("Unable to construct raw signer from " + metadataFile.getFilename());
      return null;
    }
  }

  @Override
  public Signer createSigner(HSMSigningMetadataFile metadataFile) {
    if (hsmFactory == null) {
      LOG.warn("HSM signer factory is not initialized to load " + metadataFile.getFilename());
      return null;
    }
    if (!metadataFile.getConfig().getSlot().equals(hsmFactory.getSlotLabel())) {
      LOG.warn("Failed to construct HSM signer for slot " + metadataFile.getConfig().getSlot());
      return null;
    } else {
      try {
        return hsmFactory.createSigner(metadataFile.getConfig().getAddress());
      } catch (SignerInitializationException e) {
        LOG.error("Failed to construct HSM signer from " + metadataFile.getFilename());
        return null;
      }
    }
  }

  @Override
  public Signer createSigner(CaviumSigningMetadataFile metadataFile) {
    if (caviumFactory == null) {
      LOG.warn("Cavium signer factory is not initialized to load " + metadataFile.getFilename());
      return null;
    }
    try {
      return caviumFactory.createSigner(metadataFile.getConfig().getAddress());
    } catch (SignerInitializationException e) {
      LOG.error("Failed to construct Cavium signer from " + metadataFile.getFilename());
      return null;
    }
  }

  @Override
  public void shutdown() {
    hashicorpSignerFactory.shutdown(); // required to clean up its Vertx instance.
    if (hsmFactory != null) hsmFactory.shutdown();
    if (caviumFactory != null) caviumFactory.shutdown();
  }
}
