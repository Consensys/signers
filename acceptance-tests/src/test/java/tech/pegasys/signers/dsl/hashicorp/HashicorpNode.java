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
package tech.pegasys.signers.dsl.hashicorp;

import tech.pegasys.signers.dsl.certificates.SelfSignedCertificate;

import java.util.Optional;

import com.github.dockerjava.api.DockerClient;

public class HashicorpNode {

  private final Optional<SelfSignedCertificate> serverTlsCertificate;
  private final DockerClient dockerClient;
  private HashicorpVaultDocker hashicorpVaultDocker;

  private HashicorpNode(final DockerClient dockerClient) {
    this(dockerClient, null);
  }

  private HashicorpNode(
      final DockerClient dockerClient, final SelfSignedCertificate serverTlsCertificate) {
    this.dockerClient = dockerClient;
    this.serverTlsCertificate = Optional.ofNullable(serverTlsCertificate);
  }

  public static HashicorpNode createAndStartHashicorp(
      final DockerClient dockerClient, final boolean withTls) {
    try {
      final HashicorpNode hashicorpNode =
          withTls
              ? new HashicorpNode(dockerClient, SelfSignedCertificate.generate())
              : new HashicorpNode(dockerClient);
      hashicorpNode.start();
      return hashicorpNode;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to create Hashicorp Node.", e);
    }
  }

  private void start() {
    final HashicorpVaultDockerCertificate hashicorpVaultDockerCertificate =
        serverTlsCertificate.map(HashicorpVaultDockerCertificate::create).orElse(null);

    hashicorpVaultDocker =
        HashicorpVaultDocker.createVaultDocker(dockerClient, hashicorpVaultDockerCertificate);
    Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
  }

  public synchronized void shutdown() {
    if (hashicorpVaultDocker != null) {
      hashicorpVaultDocker.shutdown();
      hashicorpVaultDocker = null;
    }
  }

  public String getVaultToken() {
    return hashicorpVaultDocker.getHashicorpRootToken();
  }

  public String getHost() {
    return hashicorpVaultDocker.getIpAddress();
  }

  public String getSigningKeyPath() {
    return hashicorpVaultDocker.getVaultSigningKeyPath();
  }

  public int getPort() {
    return hashicorpVaultDocker.getPort();
  }

  public boolean isTlsEnabled() {
    return serverTlsCertificate != null;
  }

  public Optional<SelfSignedCertificate> getServerCertificate() {
    return serverTlsCertificate;
  }
}
