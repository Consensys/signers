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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.Optional;

import com.github.dockerjava.api.DockerClient;
import io.vertx.core.Vertx;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public class HashicorpVaultAccessAcceptanceTest {

  private final Vertx vertx = Vertx.vertx();
  private HashicorpNode hashicorpNode;

  @AfterEach
  void cleanup() {
    vertx.close();
    if (hashicorpNode != null) {
      hashicorpNode.shutdown();
      hashicorpNode = null;
    }
  }

  @Test
  void keyCanBeExtractedFromVault() throws IOException {
    final DockerClient docker = new DockerClientFactory().create();

    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, false);
    final String secretKey = "storedSecetKey";
    final String secretContent = "secretValue";
    final String hashicorpSecretHttpPath =
        hashicorpNode.addSecretsToVault(
            Collections.singletonMap(secretKey, "secretValue"), "acceptanceTestSecret");

    // create tomlfile
    final Path configFilePath =
        HashicorpConfigUtil.createConfigFile(
            hashicorpNode.getHost(),
            hashicorpNode.getPort(),
            hashicorpNode.getVaultToken(),
            hashicorpSecretHttpPath,
            secretKey,
            30_000,
            false,
            null,
            null,
            null);

    final HashicorpKeyConfig config = TomlConfigLoader.fromToml(configFilePath, null);

    final HashicorpConnectionFactory factory = new HashicorpConnectionFactory(vertx);
    final HashicorpConnection connection = factory.create(config.getConnectionParams());

    final String secretData = connection.fetchKey(config.getKeyDefinition());

    assertThat(secretData).isEqualTo(secretContent);
  }

  @Test
  void keyCanBeExtractedFromVaultOverTls() throws IOException, CertificateEncodingException {
    final DockerClient docker = new DockerClientFactory().create();
    hashicorpNode = HashicorpNode.createAndStartHashicorp(docker, true);
    final String secretKey = "storedSecetKey";
    final String secretContent = "secretValue";
    final String hashicorpSecretHttpPath =
        hashicorpNode.addSecretsToVault(
            Collections.singletonMap(secretKey, secretContent), "acceptanceTestSecret");

    final Path fingerprintFile = Files.createTempFile("fingerprint", ".fingerpint");
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
            secretKey,
            30_000,
            true,
            "WHITELIST",
            fingerprintFile.toString(),
            null);

    final HashicorpKeyConfig config = TomlConfigLoader.fromToml(configFilePath, null);

    final HashicorpConnectionFactory factory = new HashicorpConnectionFactory(vertx);
    final HashicorpConnection connection = factory.create(config.getConnectionParams());

    final String secretData = connection.fetchKey(config.getKeyDefinition());

    assertThat(secretData).isEqualTo(secretContent);
  }
}
