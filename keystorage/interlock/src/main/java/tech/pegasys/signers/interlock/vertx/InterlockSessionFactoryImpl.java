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
package tech.pegasys.signers.interlock.vertx;

import static org.apache.tuweni.net.tls.VertxTrustOptions.trustServerOnFirstUse;

import tech.pegasys.signers.interlock.InterlockClientException;
import tech.pegasys.signers.interlock.InterlockSession;
import tech.pegasys.signers.interlock.InterlockSessionFactory;
import tech.pegasys.signers.interlock.model.ApiAuth;
import tech.pegasys.signers.interlock.vertx.operations.LoginOperation;

import java.net.URI;
import java.nio.file.Path;
import java.util.Objects;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class InterlockSessionFactoryImpl implements InterlockSessionFactory {
  private static final Logger LOG = LogManager.getLogger();

  private static final String TIMEOUT_ENV = "INTERLOCK_CLIENT_TIMEOUT";
  private static final int DEFAULT_TIMEOUT_MS = 5000;
  private final Vertx vertx;
  private final Path serverWhitelist;

  public InterlockSessionFactoryImpl(final Vertx vertx, final Path serverWhitelist) {
    this.vertx = vertx;
    this.serverWhitelist = serverWhitelist;
  }

  @Override
  public InterlockSession newSession(
      final URI interlockURI, final String volume, final String password) {
    final HttpClient httpClient = createHttpClient(interlockURI);
    try {
      LOG.trace("Login for volume {}", volume);
      final LoginOperation loginOperation = new LoginOperation(httpClient, volume, password);
      final ApiAuth apiAuth = loginOperation.waitForResponse();
      return new InterlockSessionImpl(httpClient, apiAuth);
    } catch (final InterlockClientException e) {
      LOG.warn("Login attempt for volume {} failed: {}", volume, e.getMessage());
      throw new InterlockClientException("Login failed. " + e.getMessage());
    }
  }

  private HttpClient createHttpClient(final URI interlockURI) {
    final boolean useSsl = Objects.equals("https", interlockURI.getScheme());
    final int port;
    if (interlockURI.getPort() == -1) {
      port = useSsl ? 443 : 80;
    } else {
      port = interlockURI.getPort();
    }
    final HttpClientOptions httpClientOptions =
        new HttpClientOptions()
            .setDefaultHost(interlockURI.getHost())
            .setDefaultPort(port)
            .setTryUseCompression(true)
            .setConnectTimeout(timeoutMS())
            .setSsl(useSsl);
    if (useSsl) {
      httpClientOptions.setTrustOptions(
          trustServerOnFirstUse(serverWhitelist.toAbsolutePath(), true));
    }

    return vertx.createHttpClient(httpClientOptions);
  }

  private int timeoutMS() {
    final String timeoutEnv = System.getenv(TIMEOUT_ENV);
    try {
      final int timeout = Integer.parseInt(timeoutEnv);
      if (timeout < 0) {
        return DEFAULT_TIMEOUT_MS;
      }
      return timeout;
    } catch (final NumberFormatException | NullPointerException e) {
      return DEFAULT_TIMEOUT_MS;
    }
  }
}
