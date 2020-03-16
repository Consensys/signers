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
package tech.pegasys.signers.hashicorp.config;

import java.util.Optional;

public class ConnectionParameters {
  private String serverHost;
  private Optional<Integer> serverPort;
  private Optional<TlsOptions> tlsOptions;
  private Optional<Long> timeoutMs;

  /* Optional parameters will be set to their defaults when connecting */
  public ConnectionParameters(
      final String serverHost,
      final Optional<Integer> serverPort,
      final Optional<TlsOptions> tlsOptions,
      final Optional<Long> timeoutMs) {
    this.serverHost = serverHost;
    this.serverPort = serverPort;
    this.tlsOptions = tlsOptions;
    this.timeoutMs = timeoutMs;
  }

  public String getServerHost() {
    return serverHost;
  }

  public Optional<Integer> getServerPort() {
    return serverPort;
  }

  public Optional<TlsOptions> getTlsOptions() {
    return tlsOptions;
  }

  public Optional<Long> getTimeoutMilliseconds() {
    return timeoutMs;
  }
}
