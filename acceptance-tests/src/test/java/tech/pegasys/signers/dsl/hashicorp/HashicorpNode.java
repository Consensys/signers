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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Optional;

import com.github.dockerjava.api.DockerClient;
import org.apache.tuweni.net.tls.TLS;

public class HashicorpNode {

  private final Optional<SelfSignedCertificate> tlsServerCertificate;
  private final DockerClient dockerClient;
  private HashicorpVaultDocker hashicorpVaultDocker;
  private Optional<Path> knownServerFile = Optional.empty();

  private HashicorpNode(final DockerClient dockerClient) {
    this(dockerClient, null);
  }

  private HashicorpNode(
      final DockerClient dockerClient, final SelfSignedCertificate tlsServerCertificate) {
    this.dockerClient = dockerClient;
    this.tlsServerCertificate = Optional.ofNullable(tlsServerCertificate);
  }

  public static HashicorpNode createAndStartHashicorp(
      final DockerClient dockerClient, final boolean withTls) {
    try {
      final SelfSignedCertificate selfSignedCertificate = SelfSignedCertificate.generate();
      final HashicorpNode hashicorpNode =
          withTls
              ? new HashicorpNode(dockerClient, selfSignedCertificate)
              : new HashicorpNode(dockerClient);
      hashicorpNode.start();
      return hashicorpNode;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to create Hashicorp Node.", e);
    }
  }

  private void start() throws CertificateEncodingException {
    final HashicorpVaultDockerCertificate hashicorpVaultDockerCertificate =
        tlsServerCertificate.map(HashicorpVaultDockerCertificate::create).orElse(null);

    hashicorpVaultDocker =
        HashicorpVaultDocker.createVaultDocker(dockerClient, hashicorpVaultDockerCertificate);
    Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));

    if (tlsServerCertificate.isPresent()) {
      knownServerFile =
          Optional.of(createKnownServerFile(tlsServerCertificate.get().getCertificate()));
    }
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
    return tlsServerCertificate != null;
  }

  public Optional<Path> getKnownServerFilePath() {
    return knownServerFile;
  }

  private Path createKnownServerFile(final Certificate certificate)
      throws CertificateEncodingException {
    try {
      final Path tempFile = Files.createTempFile("knownServer", ".txt");
      final String hexFingerprint = TLS.certificateHexFingerprint(certificate);
      Files.writeString(tempFile, String.format("%s:%d %s", getHost(), getPort(), hexFingerprint));
      return tempFile;
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
