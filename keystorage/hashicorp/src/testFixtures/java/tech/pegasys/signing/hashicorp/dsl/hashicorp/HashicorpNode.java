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
package tech.pegasys.signing.hashicorp.dsl.hashicorp;

import com.github.dockerjava.api.DockerClient;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.util.Map;
import org.apache.tuweni.net.tls.TLS;
import tech.pegasys.signing.hashicorp.dsl.certificates.MySelfSignedCertificate;

public class HashicorpNode {

  private final DockerClient dockerClient;
  private HashicorpVaultDocker hashicorpVaultDocker;

  final MySelfSignedCertificate serverTlsCertificate;

  private HashicorpNode(final DockerClient dockerClient) {
    this(dockerClient, null);
  }

  private HashicorpNode(
      final DockerClient dockerClient,
      final MySelfSignedCertificate serverTlsCertificate) {
    this.dockerClient = dockerClient;
    this.serverTlsCertificate = serverTlsCertificate;
  }

  public static HashicorpNode createAndStartHashicorp(
      final DockerClient dockerClient, final boolean withTls) {
    final HashicorpNode hashicorpNode =
        withTls
            ? new HashicorpNode(dockerClient, MySelfSignedCertificate.generate())
            : new HashicorpNode(dockerClient);
    hashicorpNode.start();
    return hashicorpNode;
  }

  private void start() {
    hashicorpVaultDocker =
        HashicorpVaultDocker.createVaultDocker(dockerClient, serverTlsCertificate);
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

  public int getPort() {
    return hashicorpVaultDocker.getPort();
  }

  public boolean isTlsEnabled() {
    return serverTlsCertificate != null;
  }

  public MySelfSignedCertificate getServerCertificate() {
    return serverTlsCertificate;
  }

  /* Note: Path should be the "subpath" of the secret - not the full HTTP path.
  The full HTTP Path will be returned.
   */
  public String addSecretsToVault(final Map<String, String> entries, final String path) {
    return hashicorpVaultDocker.addSecretsToVault(entries, path);
  }

}
