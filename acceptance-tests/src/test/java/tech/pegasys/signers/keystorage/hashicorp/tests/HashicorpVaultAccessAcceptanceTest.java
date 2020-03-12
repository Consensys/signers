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
import tech.pegasys.signers.dsl.hashicorp.HashicorpNode;
import tech.pegasys.signing.hashicorp.HashicorpConnection;
import tech.pegasys.signing.hashicorp.HashicorpConnectionFactory;
import tech.pegasys.signing.hashicorp.config.HashicorpKeyConfig;
import tech.pegasys.signing.hashicorp.config.loader.toml.TomlConfigLoader;
import tech.pegasys.signing.hashicorp.util.HashicorpConfigUtil;

import java.io.IOException;
import java.nio.file.Path;

import com.github.dockerjava.api.DockerClient;
import io.vertx.core.Vertx;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public class HashicorpVaultAccessAcceptanceTest {

  private final Vertx vertx = Vertx.vertx();
  private HashicorpNode hashicorpNode;
  final DockerClientFactory dockerClientFactory = new DockerClientFactory();
  final DockerClient dockerClient = dockerClientFactory.create();

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
  }

  @Test
  void keyCanBeExtractedFromVault() throws IOException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(dockerClient, false);

    // create tomlfile
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

    assertThat(secretData)
        .isEqualTo("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63");
  }

  @Test
  void keyCanBeExtractedFromVaultOverTlsUsingWhitelist() throws IOException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(dockerClient, true);

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
            "WHITELIST",
            hashicorpNode.getKnownServerFilePath().get().toString(),
            null);

    final String secretData = fetchSecretFromVault(configFilePath);

    assertThat(secretData)
        .isEqualTo("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63");
  }

  private String fetchSecretFromVault(final Path configFilePath) {
    final HashicorpKeyConfig config = TomlConfigLoader.fromToml(configFilePath, null);

    final HashicorpConnectionFactory factory = new HashicorpConnectionFactory(vertx);
    final HashicorpConnection connection = factory.create(config.getConnectionParams());

    return connection.fetchKey(config.getKeyDefinition());
  }
}
