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
package tech.pegasys.signers.hashicorp.dsl;

import tech.pegasys.signers.hashicorp.dsl.certificates.SelfSignedCertificate;

import java.util.Map;
import java.util.Optional;

import com.github.dockerjava.api.DockerClient;

public class HashicorpDockerNode implements HashicorpNode {
  private final Optional<SelfSignedCertificate> serverTlsCertificate;
  private final DockerClient dockerClient;
  private HashicorpVaultDocker hashicorpVaultDocker;

  HashicorpDockerNode(final DockerClient dockerClient) {
    this(dockerClient, null);
  }

  HashicorpDockerNode(
      final DockerClient dockerClient, final SelfSignedCertificate serverTlsCertificate) {
    this.dockerClient = dockerClient;
    this.serverTlsCertificate = Optional.ofNullable(serverTlsCertificate);
  }

  void start() {
    final HashicorpVaultDockerCertificate hashicorpVaultDockerCertificate =
        serverTlsCertificate.map(HashicorpVaultDockerCertificate::create).orElse(null);

    hashicorpVaultDocker =
        HashicorpVaultDocker.createVaultDocker(dockerClient, hashicorpVaultDockerCertificate);
    Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
  }

  @Override
  public synchronized void shutdown() {
    if (hashicorpVaultDocker != null) {
      hashicorpVaultDocker.shutdown();
      hashicorpVaultDocker = null;
    }
  }

  @Override
  public String getVaultToken() {
    return hashicorpVaultDocker.getHashicorpRootToken();
  }

  @Override
  public String getHost() {
    return hashicorpVaultDocker.getIpAddress();
  }

  @Override
  public int getPort() {
    return hashicorpVaultDocker.getPort();
  }

  @Override
  public Optional<SelfSignedCertificate> getServerCertificate() {
    return serverTlsCertificate;
  }

  /* Note: Path should be the "subpath" of the secret - not the full HTTP path.
  The full HTTP Path will be returned.
   */
  @Override
  public void addSecretsToVault(final Map<String, String> entries, final String path) {
    hashicorpVaultDocker.addSecretsToVault(entries, path);
  }

  @Override
  public String getHttpApiPathForSecret(final String secretPath) {
    // *ALL* Hashicorp Http API endpoints are prefixed by "/v1"
    // KV-V2 insert "data" after the rootpath, and before the signing key path (so, just gotta
    // handle that)
    return hashicorpVaultDocker.getHttpApiPathForSecret(secretPath);
  }
}
