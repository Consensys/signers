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

import tech.pegasys.signers.hashicorp.HashicorpConnection;
import tech.pegasys.signers.hashicorp.HashicorpConnectionFactory;
import tech.pegasys.signers.hashicorp.config.HashicorpKeyConfig;
import tech.pegasys.signers.hashicorp.config.loader.toml.TomlConfigLoader;
import tech.pegasys.signers.hashicorp.dsl.HashicorpNode;
import tech.pegasys.signers.hashicorp.dsl.certificates.CertificateHelpers;
import tech.pegasys.signers.hashicorp.util.HashicorpConfigUtil;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.Optional;

import io.vertx.core.Vertx;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class HashicorpVaultAccessAcceptanceTest {

  private static final Logger LOG = LogManager.getLogger();
  private final Vertx vertx = Vertx.vertx();

  private HashicorpNode hashicorpNode;

  private final String SECRET_KEY = "storedSecetKey";
  private final String SECRET_VALUE = "secretValue";
  private final String KEY_SUBPATH = "acceptanceTestSecret";

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
  }

  @Test
  void keyCanBeExtractedFromVault() throws IOException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(false);
    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            SECRET_KEY,
            30_000,
            false,
            null,
            null,
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  @Test
  void keyCanBeExtractedFromVaultOverTlsUsingWhitelist(@TempDir final Path testDir)
      throws IOException, CertificateEncodingException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(true);

    final Path fingerprintFile =
        CertificateHelpers.createFingerprintFile(
            testDir,
            hashicorpNode.getServerCertificate().get(),
            Optional.of(hashicorpNode.getPort()));

    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            SECRET_KEY,
            30_000,
            true,
            "WHITELIST",
            fingerprintFile.toString(),
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  @Test
  void canConnectToHashicorpVaultUsingPkcs12Certificate(@TempDir final Path testDir)
      throws IOException {
    final String TRUST_STORE_PASSWORD = "password";
    hashicorpNode = HashicorpNode.createAndStartHashicorp(true);

    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final Path trustStorePath =
        CertificateHelpers.createPkcs12TrustStore(
            testDir, hashicorpNode.getServerCertificate().get(), TRUST_STORE_PASSWORD);

    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            SECRET_KEY,
            30_000,
            true,
            "PKCS12",
            trustStorePath.toString(),
            TRUST_STORE_PASSWORD);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  @Test
  void canConnectToHashicorpVaultUsingJksCertificate(@TempDir final Path testDir)
      throws IOException {
    final String TRUST_STORE_PASSWORD = "password";
    hashicorpNode = HashicorpNode.createAndStartHashicorp(true);

    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final Path trustStorePath =
        CertificateHelpers.createJksTrustStore(
            testDir, hashicorpNode.getServerCertificate().get(), TRUST_STORE_PASSWORD);

    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            SECRET_KEY,
            30_000,
            true,
            "JKS",
            trustStorePath.toString(),
            TRUST_STORE_PASSWORD);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  @Test
  void canConnectToHashicorpVaultUsingPemCertificate(@TempDir final Path testDir)
      throws IOException, CertificateEncodingException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(true);

    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final Path trustStorePath = testDir.resolve("cert.crt");
    hashicorpNode.getServerCertificate().get().writeCertificateToFile(trustStorePath);

    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            SECRET_KEY,
            30_000,
            true,
            "PEM",
            trustStorePath.toString(),
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  private String fetchSecretFromVault(final Path configFilePath) {
    final HashicorpKeyConfig config = TomlConfigLoader.fromToml(configFilePath, null);

    final HashicorpConnectionFactory factory = new HashicorpConnectionFactory(vertx);
    final HashicorpConnection connection = factory.create(config.getConnectionParams());

    return connection.fetchKey(config.getKeyDefinition());
  }
}
