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
package tech.pegasys.signers.yubihsm.backend;

import tech.pegasys.signers.yubihsm.exceptions.YubiHsmConnectionException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.net.tls.TrustManagerFactories;

public class YubihsmConnectorBackend implements YubiHsmBackend {
  private static final Logger LOG = LogManager.getLogger(YubihsmConnectorBackend.class);
  private static final String CONNECTOR_URL_SUFFIX = "/connector/api";
  private static final int MAX_MESSAGE_SIZE = 2048;

  private final URI connectorUri;
  private final HttpClient httpClient;
  private final Optional<Duration> requestTimeout;

  private final AtomicLong debugHeaderCounter = new AtomicLong(0);
  private boolean enableDebugHeader = false;

  /**
   * YubiHsm Connector Backend
   *
   * @param uri YubiHSMConnector URI. For instance, http://localhost:12345
   * @param connectionTimeout Connection timeout duration. Use empty to block forever.
   * @param requestTimeout Request timeout duration. Use empty to block forever.
   * @param knownServersFile Known servers file which contains server certificate signature. If file
   *     doesn't exist, it will be created and certificate fingerprint will be recorded on first
   *     access. If null, will use defaults.
   */
  public YubihsmConnectorBackend(
      final URI uri,
      final Optional<Duration> connectionTimeout,
      final Optional<Duration> requestTimeout,
      final Path knownServersFile) {
    this.connectorUri = uri.resolve(CONNECTOR_URL_SUFFIX);
    this.requestTimeout = requestTimeout;
    LOG.debug("yubihsm-connector {}", connectorUri);

    final HttpClient.Builder builder = HttpClient.newBuilder();
    connectionTimeout.ifPresent(builder::connectTimeout);
    getSSLContext(knownServersFile).ifPresent(builder::sslContext);

    this.httpClient = builder.build();
  }

  private Optional<SSLContext> getSSLContext(final Path knownServersFile) {
    if (!isTLS() || knownServersFile == null) {
      return Optional.empty();
    }

    try {
      final TrustManagerFactory trustManagerFactory =
          TrustManagerFactories.recordServerFingerprints(knownServersFile);
      final SSLContext sc = SSLContext.getInstance("TLS");
      // no mutual authentication supported by yubihsm connector
      sc.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
      return Optional.of(sc);
    } catch (final NoSuchAlgorithmException | KeyManagementException e) {
      LOG.warn("Unable to initialize SSL Context", e);
      return Optional.empty();
    }
  }

  private boolean isTLS() {
    return "https".equalsIgnoreCase(connectorUri.getScheme());
  }

  @Override
  public Bytes send(final Bytes message) throws YubiHsmConnectionException {
    if (message.size() > MAX_MESSAGE_SIZE) {
      throw new IllegalArgumentException("Message exceed maximum size of " + MAX_MESSAGE_SIZE);
    }

    // send POST byte array
    final HttpRequest.Builder builder =
        HttpRequest.newBuilder(connectorUri)
            .header("Content-Type", "application/octet-stream")
            .POST(HttpRequest.BodyPublishers.ofByteArray(message.toArrayUnsafe()));
    requestTimeout.ifPresent(builder::timeout);

    if (enableDebugHeader) {
      builder.header("X-DEBUG", String.valueOf(debugHeaderCounter.getAndIncrement()));
    }

    final HttpRequest req = builder.build();

    try {
      final HttpResponse<byte[]> response =
          httpClient.send(req, HttpResponse.BodyHandlers.ofByteArray());
      if (response.statusCode() != 200) {
        LOG.debug("Status Code: {}", response.statusCode());
      }

      return Bytes.wrap(response.body());
    } catch (final IOException | InterruptedException e) {
      LOG.warn("Error in sending request to connector: {}", e.getMessage());
      throw new YubiHsmConnectionException(e);
    }
  }

  // visible for testing - add debug header which helps in replaying mock responses
  void enableDebugHeader() {
    this.enableDebugHeader = true;
  }
}
