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
package tech.pegasys.signers.interlock;

import static org.apache.tuweni.net.tls.VertxTrustOptions.trustServerOnFirstUse;

import java.nio.file.Path;

import com.google.common.base.Preconditions;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;

public class VertxHttpClientFactory {
  private final Vertx vertx;
  private final String host;
  private final int port;
  private final Path serverWhitelist;

  /**
   * Constructor with parameters to create vertx HttpClient
   *
   * @param vertx An instance of Vertx which will be used to create HttpClient
   * @param host The host name of interlock. Usually 10.0.0.1
   * @param port The port of intrelock server. Usually 443
   * @param serverWhitelist The server whitelist file containing host+port
   *     server_certificate_fingerprint. If it doesn't exist or is empty, it will be created and
   *     populated with server's TLS certificate fingerprint on first use.
   */
  public VertxHttpClientFactory(
      final Vertx vertx, final String host, final int port, final Path serverWhitelist) {
    Preconditions.checkNotNull(vertx, "vertx cannot be null");
    Preconditions.checkNotNull(host, "host cannot be null");
    Preconditions.checkNotNull(serverWhitelist, "server whitelist path cannot be null");

    this.vertx = vertx;
    this.host = host;
    this.port = port;
    this.serverWhitelist = serverWhitelist;
  }

  /**
   * Create HttpClient
   *
   * @return HttpClient using Tuweni Vertx Trust Options
   */
  public HttpClient create() {
    final HttpClientOptions httpClientOptions =
        new HttpClientOptions()
            .setDefaultHost(this.host)
            .setDefaultPort(this.port)
            .setTryUseCompression(true)
            .setSsl(true)
            .setTrustOptions(trustServerOnFirstUse(serverWhitelist.toAbsolutePath(), true));

    return vertx.createHttpClient(httpClientOptions);
  }
}
