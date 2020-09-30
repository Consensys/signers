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
package tech.pegasys.signers.secp256k1;

import static org.assertj.core.api.Assertions.fail;

import tech.pegasys.signers.hashicorp.dsl.certificates.CertificateHelpers;
import tech.pegasys.signers.hashicorp.dsl.certificates.SelfSignedCertificate;
import tech.pegasys.signers.hashicorp.util.HashicorpConfigUtil;
import tech.pegasys.signers.secp256k1.common.TomlStringBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class MultiKeyTomlFileUtil {

  public static void createAzureTomlFileAt(
      final Path tomlPath,
      final String clientId,
      final String clientSecret,
      final String keyVaultName,
      final String tenantId) {
    final String toml =
        new TomlStringBuilder("signing")
            .withQuotedString("type", "azure-signer")
            .withQuotedString("key-vault-name", keyVaultName)
            .withQuotedString("key-name", "TestKey")
            .withQuotedString("key-version", "7c01fe58d68148bba5824ce418241092")
            .withQuotedString("client-id", clientId)
            .withQuotedString("client-secret", clientSecret)
            .withQuotedString("tenant-id", tenantId)
            .build();
    createTomlFile(tomlPath, toml);
  }

  public static void createFileBasedTomlFileAt(
      final Path tomlPath, final String keyPath, final String passwordPath) {
    final String toml =
        new TomlStringBuilder("signing")
            .withQuotedString("type", "file-based-signer")
            .withQuotedString("key-file", keyPath)
            .withQuotedString("password-file", passwordPath)
            .build();

    createTomlFile(tomlPath, toml);
  }

  public static void createHashicorpTomlFileAt(
      final Path tomlPath, final HashicorpSigningParams hashicorpNode) {

    try {
      final Optional<SelfSignedCertificate> tlsCert = hashicorpNode.getServerCertificate();
      String trustStorePath = null;
      if (tlsCert.isPresent()) {
        trustStorePath =
            CertificateHelpers.createFingerprintFile(
                    tomlPath.getParent(), tlsCert.get(), Optional.of(hashicorpNode.getPort()))
                .toString();
      }

      final String hashicorpSignerToml =
          HashicorpConfigUtil.createTomlConfig(
              hashicorpNode.getHost(),
              hashicorpNode.getPort(),
              hashicorpNode.getVaultToken(),
              hashicorpNode.getSecretHttpPath(),
              hashicorpNode.getSecretName(),
              10_000,
              tlsCert.isPresent(),
              tlsCert.map(ignored -> "WHITELIST").orElse(null),
              trustStorePath,
              null);

      final TomlStringBuilder tomlBuilder = new TomlStringBuilder("signing");
      tomlBuilder.withQuotedString("type", "hashicorp-signer");
      final String toml = tomlBuilder.build() + hashicorpSignerToml;

      createTomlFile(tomlPath, toml);
    } catch (final Exception e) {
      throw new RuntimeException("Failed to construct a valid hashicorp TOML file", e);
    }
  }

  public static void createRawSignerTomlFileAt(final Path tomlPath, final String privKeyHexString) {
    final String toml =
        new TomlStringBuilder("signing")
            .withQuotedString("type", "raw-signer")
            .withQuotedString("priv-key", privKeyHexString)
            .build();
    createTomlFile(tomlPath, toml);
  }

  public static void createHSMTomlFileAt(
      final Path tomlPath, final String address, final String slot) {
    final String toml =
        new TomlStringBuilder("signing")
            .withQuotedString("type", "hsm-signer")
            .withQuotedString("address", address)
            .withQuotedString("slot", slot)
            .build();

    createTomlFile(tomlPath, toml);
  }

  public static void createCaviumTomlFileAt(final Path tomlPath, final String address) {
    final String toml =
        new TomlStringBuilder("signing")
            .withQuotedString("type", "cavium-signer")
            .withQuotedString("address", address)
            .build();

    createTomlFile(tomlPath, toml);
  }

  private static void createTomlFile(final Path tomlPath, final String toml) {
    try {
      Files.writeString(tomlPath, toml);
    } catch (final IOException e) {
      fail("Unable to create TOML file.");
    }
  }
}
