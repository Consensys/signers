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

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import com.github.dockerjava.api.DockerClient;

public interface HashicorpNode {
  String VAULT_ROOT_PATH = "secret";

  /**
   * Create a dockerized Hashicorp Vault process and start it.
   *
   * @param dockerClient Instance of com.github.dockerjava.api.DockerClient
   * @param withTls if TLS should be enabled
   * @return An instance of HashicorpNode backed by Dockerized Vault
   */
  static HashicorpNode createAndStartHashicorp(
      final DockerClient dockerClient, final boolean withTls) {
    try {
      final HashicorpDockerNode hashicorpNode =
          withTls
              ? new HashicorpDockerNode(dockerClient, SelfSignedCertificate.generate())
              : new HashicorpDockerNode(dockerClient);
      hashicorpNode.start();
      return hashicorpNode;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to create Hashicorp Node.", e);
    }
  }

  /**
   * Create a local Hashicorp Vault process and start it.
   *
   * @param vaultBinary Path to vault binary
   * @param withTls if TLS should be enabled
   * @return An instance of HashicorpNode backed by a local vault process.
   */
  static HashicorpNode createAndStartHashicorp(final Path vaultBinary, final boolean withTls) {
    try {
      final HashicorpLocalNode hashicorpNode =
          withTls
              ? new HashicorpLocalNode(vaultBinary, SelfSignedCertificate.generate())
              : new HashicorpLocalNode(vaultBinary);
      hashicorpNode.start();
      return hashicorpNode;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to create Hashicorp Node.", e);
    }
  }

  void shutdown();

  String getVaultToken();

  String getHost();

  int getPort();

  Optional<SelfSignedCertificate> getServerCertificate();

  /* Note: Path should be the "subpath" of the secret - not the full HTTP path.
  The full HTTP Path will be returned.
   */
  String addSecretsToVault(final Map<String, String> entries, final String path);

  // *ALL* Hashicorp Http API endpoints are prefixed by "/v1"
  // KV-V2 insert "data" after the rootpath, and before the signing key path (so, just gotta
  // handle that)
  default String getHttpApiPathForSecret(final String secretPath) {
    return "/v1/" + VAULT_ROOT_PATH + "/data/" + secretPath;
  }
}
