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

import tech.pegasys.signing.hashicorp.HashicorpConfigUtil;
import tech.pegasys.signing.hashicorp.HashicorpConnection;
import tech.pegasys.signing.hashicorp.HashicorpConnectionFactory;
import tech.pegasys.signing.hashicorp.config.HashicorpKeyConfig;
import tech.pegasys.signing.hashicorp.config.loader.toml.TomlConfigLoader;
import tech.pegasys.signing.hashicorp.dsl.DockerClientFactory;
import tech.pegasys.signing.hashicorp.dsl.certificates.CertificateHelpers;
import tech.pegasys.signing.hashicorp.dsl.hashicorp.HashicorpNode;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.Optional;

import com.github.dockerjava.api.DockerClient;
import io.vertx.core.Vertx;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class HashicorpVaultAccessAcceptanceTest {

  private final Vertx vertx = Vertx.vertx();
  final DockerClient docker = new DockerClientFactory().create();
  private HashicorpNode hashicorpNode;

  private final String SECRET_KEY = "storedSecetKey";
  private final String SECRET_CONTENT = "secretValue";

  @AfterEach
  void cleanup() {
    try {
      vertx.close();
    } catch (final Exception ignored) {
    }

    if (hashicorpNode != null) {
      hashicorpNode.shutdown();
      hashicorpNode = null;
    }

    try {
      docker.close();
    } catch (final Exception ignored) {
    }
  }

  @Test
  void keyCanBeExtractedFromVault() throws IOException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, false);

    final String hashicorpSecretHttpPath =
        hashicorpNode.addSecretsToVault(
            Collections.singletonMap(SECRET_KEY, SECRET_CONTENT), "acceptanceTestSecret");

    // create tomlfile
    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpSecretHttpPath,
            SECRET_KEY,
            30_000,
            false,
            null,
            null,
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_CONTENT);
  }

  @Test
  void keyCanBeExtractedFromVaultOverTlsUsingWhitelist(@TempDir final Path testDir)
      throws IOException, CertificateEncodingException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, true);

    final String hashicorpSecretHttpPath =
        hashicorpNode.addSecretsToVault(
            Collections.singletonMap(SECRET_KEY, SECRET_CONTENT), "acceptanceTestSecret");

    final Path fingerprintFile = testDir.resolve("whitelist.tmp");
    CertificateHelpers.populateFingerprintFile(
        fingerprintFile,
        hashicorpNode.getServerCertificate(),
        Optional.of(hashicorpNode.getPort()));

    // create tomlfile
    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpSecretHttpPath,
            SECRET_KEY,
            30_000,
            true,
            "WHITELIST",
            fingerprintFile.toString(),
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_CONTENT);
  }

  @Test
  void canConnectToHashicorpVaultUsingPkcs12Certificate(@TempDir final Path testDir)
      throws IOException {
    final String TRUST_STORE_PASSWORD = "password";
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, true);

    final String hashicorpSecretHttpPath =
        hashicorpNode.addSecretsToVault(
            Collections.singletonMap(SECRET_KEY, SECRET_CONTENT), "acceptanceTestSecret");

    final Path trustStorePath =
        CertificateHelpers.createPkcs12TrustStore(
            testDir, hashicorpNode.getServerCertificate(), TRUST_STORE_PASSWORD);

    // create tomlfile
    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpSecretHttpPath,
            SECRET_KEY,
            30_000,
            true,
            "PKCS12",
            trustStorePath.toString(),
            TRUST_STORE_PASSWORD);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_CONTENT);
  }

  @Test
  void canConnectToHashicorpVaultUsingJksCertificate(@TempDir final Path testDir)
      throws IOException {
    final String TRUST_STORE_PASSWORD = "password";
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, true);

    final String hashicorpSecretHttpPath =
        hashicorpNode.addSecretsToVault(
            Collections.singletonMap(SECRET_KEY, SECRET_CONTENT), "acceptanceTestSecret");

    final Path trustStorePath =
        CertificateHelpers.createJksTrustStore(
            testDir, hashicorpNode.getServerCertificate(), TRUST_STORE_PASSWORD);

    // create tomlfile
    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpSecretHttpPath,
            SECRET_KEY,
            30_000,
            true,
            "JKS",
            trustStorePath.toString(),
            TRUST_STORE_PASSWORD);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_CONTENT);
  }

  @Test
  void canConnectToHashicorpVaultUsingPemCertificate(@TempDir final Path testDir)
      throws IOException, CertificateEncodingException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, true);

    final String hashicorpSecretHttpPath =
        hashicorpNode.addSecretsToVault(
            Collections.singletonMap(SECRET_KEY, SECRET_CONTENT), "acceptanceTestSecret");

    final Path trustStorePath = testDir.resolve("cert.crt");
    hashicorpNode.getServerCertificate().writeCertificateToFile(trustStorePath);

    // create tomlfile
    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpSecretHttpPath,
            SECRET_KEY,
            30_000,
            true,
            "PEM",
            trustStorePath.toString(),
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_CONTENT);
  }

  private String fetchSecretFromVault(final Path configFilePath) {
    final HashicorpKeyConfig config = TomlConfigLoader.fromToml(configFilePath, null);

    final HashicorpConnectionFactory factory = new HashicorpConnectionFactory(vertx);
    final HashicorpConnection connection = factory.create(config.getConnectionParams());

    return connection.fetchKey(config.getKeyDefinition());
  }
}
