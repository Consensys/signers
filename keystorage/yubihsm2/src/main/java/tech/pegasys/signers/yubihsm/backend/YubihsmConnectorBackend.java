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
import java.time.Duration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class YubihsmConnectorBackend implements YubiHsmBackend {
  private static final Logger LOG = LogManager.getLogger(YubihsmConnectorBackend.class);
  private static final String CONNECTOR_URL_SUFFIX = "/connector/api";
  private static final Duration DEFAULT_TIMEOUT = Duration.ofMillis(0);
  private static final int MAX_MESSAGE_SIZE = 2048;

  private final URI connectorUri;
  private final HttpClient httpClient;

  public YubihsmConnectorBackend(final URI uri, final Duration timeout) {
    this.connectorUri = uri.resolve(CONNECTOR_URL_SUFFIX);
    this.httpClient =
        HttpClient.newBuilder()
            .connectTimeout(timeout.isNegative() ? DEFAULT_TIMEOUT : timeout)
            .build();
  }

  @Override
  public Bytes transceive(final Bytes message) throws YubiHsmConnectionException {
    if (message.size() > MAX_MESSAGE_SIZE) {
      throw new IllegalArgumentException("Message exceed maximum size of " + MAX_MESSAGE_SIZE);
    }

    // send POST byte array
    final HttpRequest req =
        HttpRequest.newBuilder(connectorUri)
            .timeout(Duration.ofSeconds(5))
            .header("Content-Type", "application/octet-stream")
            .POST(HttpRequest.BodyPublishers.ofByteArray(message.toArrayUnsafe()))
            .build();

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
}
