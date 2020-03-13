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
package tech.pegasys.signers.keystorage.hashicorp.tests;

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.signers.dsl.DockerClientFactory;
import tech.pegasys.signers.dsl.certificates.CertificateHelpers;
import tech.pegasys.signers.dsl.hashicorp.HashicorpNode;
import tech.pegasys.signers.dsl.hashicorp.HashicorpVaultDocker;
import tech.pegasys.signing.hashicorp.HashicorpConnection;
import tech.pegasys.signing.hashicorp.HashicorpConnectionFactory;
import tech.pegasys.signing.hashicorp.config.HashicorpKeyConfig;
import tech.pegasys.signing.hashicorp.config.loader.toml.TomlConfigLoader;
import tech.pegasys.signing.hashicorp.util.HashicorpConfigUtil;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.util.Optional;

import com.github.dockerjava.api.DockerClient;
import io.vertx.core.Vertx;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class HashicorpVaultAccessAcceptanceTest {

  private static final Logger LOG = LogManager.getLogger();

  private final Vertx vertx = Vertx.vertx();
  final DockerClient docker = new DockerClientFactory().create();
  private HashicorpNode hashicorpNode;

  @AfterEach
  void cleanup() {
    try {
      vertx.close();
    } catch (final Exception e) {
      LOG.error("Failed to close vertx.", e);
    }

    try {
      if (hashicorpNode != null) {
        hashicorpNode.shutdown();
        hashicorpNode = null;
      }
    } catch (final Exception e) {
      LOG.error("Failed to shutdown Hashicorp Node.", e);
    }

    try {
      docker.close();
    } catch (final Exception e) {
      LOG.error("Failed to close docker.", e);
    }
  }

  @Test
  void keyCanBeExtractedFromVault() throws IOException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, false);

    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getSigningKeyPath(),
            null,
            30_000,
            false,
            null,
            null,
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(HashicorpVaultDocker.SECRET_VALUE);
  }

  @Test
  void keyCanBeExtractedFromVaultOverTlsUsingWhitelist(@TempDir final Path testDir)
      throws IOException, CertificateEncodingException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, true);

    final Path fingerprintFile =
        CertificateHelpers.createFingerprintFile(
            testDir,
            hashicorpNode.getServerCertificate().get(),
            Optional.of(hashicorpNode.getPort()));

    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getSigningKeyPath(),
            null,
            30_000,
            true,
            "WHITELIST",
            fingerprintFile.toString(),
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(HashicorpVaultDocker.SECRET_VALUE);
  }

  @Test
  void canConnectToHashicorpVaultUsingPkcs12Certificate(@TempDir final Path testDir)
      throws IOException {
    final String TRUST_STORE_PASSWORD = "password";
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, true);

    final Path trustStorePath =
        CertificateHelpers.createPkcs12TrustStore(
            testDir, hashicorpNode.getServerCertificate().get(), TRUST_STORE_PASSWORD);

    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getSigningKeyPath(),
            null,
            30_000,
            true,
            "PKCS12",
            trustStorePath.toString(),
            TRUST_STORE_PASSWORD);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(HashicorpVaultDocker.SECRET_VALUE);
  }

  @Test
  void canConnectToHashicorpVaultUsingJksCertificate(@TempDir final Path testDir)
      throws IOException {
    final String TRUST_STORE_PASSWORD = "password";
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, true);

    final Path trustStorePath =
        CertificateHelpers.createJksTrustStore(
            testDir, hashicorpNode.getServerCertificate().get(), TRUST_STORE_PASSWORD);

    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getSigningKeyPath(),
            null,
            30_000,
            true,
            "JKS",
            trustStorePath.toString(),
            TRUST_STORE_PASSWORD);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(HashicorpVaultDocker.SECRET_VALUE);
  }

  @Test
  void canConnectToHashicorpVaultUsingPemCertificate(@TempDir final Path testDir)
      throws IOException, CertificateEncodingException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, true);

    final Path trustStorePath = testDir.resolve("cert.crt");
    hashicorpNode.getServerCertificate().get().writeCertificateToFile(trustStorePath);

    // create tomlfile
    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getSigningKeyPath(),
            null,
            30_000,
            true,
            "PEM",
            trustStorePath.toString(),
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(HashicorpVaultDocker.SECRET_VALUE);
  }

  private String fetchSecretFromVault(final Path configFilePath) {
    final HashicorpKeyConfig config = TomlConfigLoader.fromToml(configFilePath, null);

    final HashicorpConnectionFactory factory = new HashicorpConnectionFactory(vertx);
    final HashicorpConnection connection = factory.create(config.getConnectionParams());

    return connection.fetchKey(config.getKeyDefinition());
  }
}
