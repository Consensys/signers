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
package tech.pegasys.signers.hashicorp;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.signers.hashicorp.config.ConnectionParameters;
import tech.pegasys.signers.hashicorp.config.TlsOptions;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import com.google.common.io.Resources;
import io.vertx.core.Vertx;
import io.vertx.core.VertxException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public class HashicorpConnectionFactoryTest {

  final String CONFIGURED_HOST = "Host";

  final Vertx vertx = Vertx.vertx();
  final HashicorpConnectionFactory connectionFactory = new HashicorpConnectionFactory(vertx);

  @AfterEach
  void cleanup() {
    vertx.close();
  }

  @Test
  void invalidWhiteListFileCausesConnectionToThrowHashicorpException() throws IOException {
    final File invalidWhitelist = File.createTempFile("invalid", ".whitelist");
    Files.writeString(invalidWhitelist.toPath(), "Invalid Whitelist content");

    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.WHITELIST), invalidWhitelist.toPath(), null);
    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.empty(), Optional.of(tlsOptions), Optional.of(10L));

    assertThatThrownBy(() -> connectionFactory.create(params))
        .isInstanceOf(HashicorpException.class);
  }

  @Test
  void missingJksTrustStoreFileThrowsHashicorpException() throws IOException {
    final File tempFile = File.createTempFile("trustStore", ".tmp");
    tempFile.deleteOnExit();
    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.JKS), tempFile.toPath(), "anyPassword");

    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.empty(), Optional.of(tlsOptions), Optional.of(10L));

    assertThatThrownBy(() -> connectionFactory.create(params))
        .isInstanceOf(HashicorpException.class)
        .hasMessage("Unable to initialise connection to hashicorp vault.");
  }

  @Test
  void pkcs12FileWithIncorrectPasswordThrowsHashicorpException() {
    final URL sslCertificate = Resources.getResource("tls/cert1.pfx");
    final Path keystorePath = Path.of(sslCertificate.getPath());

    // valid password is "password"
    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.PKCS12), keystorePath, "wrongPassword");

    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.empty(), Optional.of(tlsOptions), Optional.of(10L));

    assertThatThrownBy(() -> connectionFactory.create(params))
        .isInstanceOf(HashicorpException.class)
        .hasMessage("Unable to initialise connection to hashicorp vault.")
        .hasCauseInstanceOf(VertxException.class);
  }

  @Test
  void missingAndUncreatableWhiteListThrowsHashicorpException() {
    final Path invalidFile = Path.of("/missingUnCreatable.whitelist");

    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.WHITELIST), invalidFile, null);
    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.empty(), Optional.of(tlsOptions), Optional.of(10L));

    assertThatThrownBy(() -> connectionFactory.create(params))
        .isInstanceOf(HashicorpException.class)
        .hasMessage("Unable to initialise connection to hashicorp vault.");
  }
}
