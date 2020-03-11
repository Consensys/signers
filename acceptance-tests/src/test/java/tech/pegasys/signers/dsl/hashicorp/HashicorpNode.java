/*
 * Copyright (C) 2019 ConsenSys AG.
 *
 * The source code is provided to licensees of PegaSys Plus for their convenience and internal
 * business use. These files may not be copied, translated, and/or distributed without the express
 * written permission of an authorized signatory for ConsenSys AG.
 */
package tech.pegasys.signers.dsl.hashicorp;

import tech.pegasys.plus.plugin.encryptedstorage.encryption.util.HashicorpConfigUtil;

import java.io.IOException;
import java.nio.file.Path;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.DockerCmdExecFactory;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.jaxrs.JerseyDockerCmdExecFactory;

public class HashicorpNode {

  private static final String HASHICORP_KEY_PATH = "/v1/secret/data/DBEncryptionKey";
  private static final int HASHICORP_TIMEOUT_MILLI_SECONDS = 30_000;
  private static final String HASHICORP_TLS_TYPE = "PEM";

  private HashicorpVaultDocker hashicorpVaultDocker;
  private String hashicorpRootToken;
  private final HashicorpVaultCerts hashicorpVaultCerts;

  public static HashicorpNode createAndstartupNode(final HashicorpVaultCerts hashicorpVaultCerts) {
    final HashicorpNode hashicorpNode = new HashicorpNode(hashicorpVaultCerts);
    hashicorpNode.startup();
    return hashicorpNode;
  }

  public HashicorpNode(final HashicorpVaultCerts hashicorpVaultCerts) {
    this.hashicorpVaultCerts = hashicorpVaultCerts;
  }

  public void startup() {
    final DockerClient docker = createDockerClient();
    hashicorpVaultDocker = new HashicorpVaultDocker(docker, hashicorpVaultCerts);
    Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
    hashicorpVaultDocker.start();
    hashicorpVaultDocker.awaitStartupCompletion();
    hashicorpRootToken = hashicorpVaultDocker.postStartup();
    hashicorpVaultDocker.createTestData();
  }

  public void shutdown() {
    hashicorpVaultDocker.shutdown();
  }

  public Path createConfigFile() throws IOException {
    final String certPath = hashicorpVaultCerts.getTlsCertificate().toString();
    final String hashicorpHost = hashicorpVaultDocker.getIpAddress();
    final int hashicorpPort = hashicorpVaultDocker.getPort();
    return HashicorpConfigUtil.createConfigFile(
        hashicorpHost,
        hashicorpPort,
        hashicorpRootToken,
        HASHICORP_KEY_PATH,
        null,
        HASHICORP_TIMEOUT_MILLI_SECONDS,
        true,
        HASHICORP_TLS_TYPE,
        certPath,
        null);
  }

  private DockerClient createDockerClient() {
    final DockerCmdExecFactory dockerCmdExecFactory =
        new JerseyDockerCmdExecFactory()
            .withReadTimeout(7500)
            .withConnectTimeout(7500)
            .withMaxTotalConnections(100)
            .withMaxPerRouteConnections(10);

    return DockerClientBuilder.getInstance(
            DefaultDockerClientConfig.createDefaultConfigBuilder().build())
        .withDockerCmdExecFactory(dockerCmdExecFactory)
        .build();
  }
}
