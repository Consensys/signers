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

import tech.pegasys.signers.hashicorp.config.ConnectionParameters;
import tech.pegasys.signers.hashicorp.config.TlsOptions;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.net.JksOptions;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.core.net.PfxOptions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.net.tls.VertxTrustOptions;

public class HashicorpConnectionFactory {

  private static final Logger LOG = LogManager.getLogger();

  private final Vertx vertx;

  public static final Long DEFAULT_TIMEOUT_MILLISECONDS = 10_000L;
  public static final Integer DEFAULT_SERVER_PORT = 8200;

  public HashicorpConnectionFactory(final Vertx vertx) {
    this.vertx = vertx;
  }

  public HashicorpConnection create(final ConnectionParameters connectionParameters) {
    final int serverPort = connectionParameters.getServerPort().orElse(DEFAULT_SERVER_PORT);

    final HttpClientOptions httpClientOptions =
        new HttpClientOptions()
            .setDefaultHost(connectionParameters.getServerHost())
            .setDefaultPort(serverPort);

    final HttpClient httpClient;
    try {
      if (connectionParameters.getTlsOptions().isPresent()) {
        LOG.debug("Connection to hashicorp vault using TLS.");
        setTlsOptions(httpClientOptions, connectionParameters.getTlsOptions().get());
      }
      httpClient = vertx.createHttpClient(httpClientOptions);
    } catch (final Exception e) {
      throw new HashicorpException("Unable to initialise connection to hashicorp vault.", e);
    }

    return new HashicorpConnection(
        httpClient,
        connectionParameters.getTimeoutMilliseconds().orElse(DEFAULT_TIMEOUT_MILLISECONDS));
  }

  private void setTlsOptions(
      final HttpClientOptions httpClientOptions, final TlsOptions tlsOptions) {
    httpClientOptions.setSsl(true);
    setTrustOptions(httpClientOptions, tlsOptions);
  }

  private void setTrustOptions(
      final HttpClientOptions httpClientOptions, final TlsOptions tlsOptions) {

    validateTlsTrustStoreOptions(tlsOptions);

    if (tlsOptions.getTrustStoreType().isEmpty()) {
      LOG.debug("Hashicorp server to authenticate against system CA");
      return;
    }

    final TrustStoreType trustStoreType = tlsOptions.getTrustStoreType().get();
    switch (trustStoreType) {
      case JKS:
        httpClientOptions.setTrustStoreOptions(
            new JksOptions()
                .setPath(tlsOptions.getTrustStorePath().toString())
                .setPassword(tlsOptions.getTrustStorePassword()));
        break;
      case PKCS12:
        httpClientOptions.setPfxTrustOptions(
            new PfxOptions()
                .setPath(tlsOptions.getTrustStorePath().toString())
                .setPassword(tlsOptions.getTrustStorePassword()));
        break;
      case PEM:
        httpClientOptions.setPemTrustOptions(
            new PemTrustOptions().addCertPath(tlsOptions.getTrustStorePath().toString()));
        break;
      case WHITELIST:
        // Tuweni throws an NPE if the trustStorePath has no directory prefix, thus requiring
        // the use of absolutePath.
        httpClientOptions.setTrustOptions(
            VertxTrustOptions.whitelistServers(
                tlsOptions.getTrustStorePath().toAbsolutePath(), false));
        break;
    }
  }

  private void validateTlsTrustStoreOptions(final TlsOptions tlsOptions) {
    if (tlsOptions.getTrustStoreType().isEmpty()) {
      return;
    }

    final TrustStoreType trustStoreType = tlsOptions.getTrustStoreType().get();

    if (tlsOptions.getTrustStorePath() == null) {
      throw new HashicorpException(
          String.format(
              "To use a %s trust store for TLS connections, " + "the trustStore path must be set",
              trustStoreType.name()));
    }

    if (tlsOptions.getTrustStorePassword() == null && trustStoreType.isPasswordRequired()) {
      throw new HashicorpException(
          String.format(
              "To use a %s trust store for TLS connections, "
                  + "the trustStore password must be set",
              trustStoreType.name()));
    }
  }
}
