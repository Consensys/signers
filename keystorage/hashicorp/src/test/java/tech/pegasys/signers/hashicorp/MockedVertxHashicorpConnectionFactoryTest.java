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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import tech.pegasys.signers.hashicorp.config.ConnectionParameters;
import tech.pegasys.signers.hashicorp.config.TlsOptions;

import java.io.File;
import java.io.IOException;
import java.util.Optional;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

class MockedVertxHashicorpConnectionFactoryTest {

  final Vertx mockedVertx = mock(Vertx.class);
  final HashicorpConnectionFactory connectionFactory = new HashicorpConnectionFactory(mockedVertx);

  final ArgumentCaptor<HttpClientOptions> clientOptionsArgCaptor =
      ArgumentCaptor.forClass(HttpClientOptions.class);

  final int CONFIGURED_PORT = 500;
  final String CONFIGURED_HOST = "Host";

  @Test
  void serverAndPortFromConnectionConfigAreUsedToConstructHttpClient() {

    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.of(CONFIGURED_PORT), Optional.empty(), Optional.of(10L));

    connectionFactory.create(params);

    verify(mockedVertx).createHttpClient(clientOptionsArgCaptor.capture());
    assertThat(clientOptionsArgCaptor.getValue().getDefaultPort()).isEqualTo(CONFIGURED_PORT);
    assertThat(clientOptionsArgCaptor.getValue().getDefaultHost()).isEqualTo(CONFIGURED_HOST);
    assertThat(clientOptionsArgCaptor.getValue().isSsl()).isFalse();
  }

  @Test
  void defaultPortIsUsedByHttpClientIfNonConfigured() {
    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.empty(), Optional.empty(), Optional.of(10L));

    connectionFactory.create(params);

    verify(mockedVertx).createHttpClient(clientOptionsArgCaptor.capture());
    assertThat(clientOptionsArgCaptor.getValue().getDefaultPort())
        .isEqualTo(HashicorpConnectionFactory.DEFAULT_SERVER_PORT.intValue());
  }

  @Test
  void httpClientIsInitialisedWithTlsIfTlsIsInConfiguration() {
    final TlsOptions tlsOptions = new TlsOptions(Optional.empty(), null, null);
    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.empty(), Optional.of(tlsOptions), Optional.of(10L));

    connectionFactory.create(params);

    verify(mockedVertx).createHttpClient(clientOptionsArgCaptor.capture());
    assertThat(clientOptionsArgCaptor.getValue().isSsl()).isTrue();
    // TrustOptions are null, implying fallback to system CA
    assertThat(clientOptionsArgCaptor.getValue().getTrustOptions()).isNull();
  }

  @Test
  void httpClientTlsOptionsMatchConfiguration() throws IOException {
    final File tempFile = File.createTempFile("whitlist", ".tmp");
    tempFile.deleteOnExit();

    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.WHITELIST), tempFile.toPath(), null);

    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.empty(), Optional.of(tlsOptions), Optional.of(10L));

    connectionFactory.create(params);

    verify(mockedVertx).createHttpClient(clientOptionsArgCaptor.capture());
    assertThat(clientOptionsArgCaptor.getValue().isSsl()).isTrue();
    assertThat(clientOptionsArgCaptor.getValue().getTrustOptions()).isNotNull();
  }

  @ParameterizedTest
  @ValueSource(strings = {"JKS", "PKCS12", "PEM", "WHITELIST"})
  void allCustomTlsTrustOptionsRequireANonNullPathElseThrowsHashicorpException(String trustType) {
    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.fromString(trustType).get()), null, null);

    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.empty(), Optional.of(tlsOptions), Optional.of(10L));

    assertThatThrownBy(() -> connectionFactory.create(params))
        .isInstanceOf(HashicorpException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {"JKS", "PKCS12"})
  void missingPasswordForTrustStoreThrowsHashicorpException(String trustType) throws IOException {
    final File tempFile = File.createTempFile("trustStore", ".tmp");
    tempFile.deleteOnExit();
    final TlsOptions tlsOptions =
        new TlsOptions(
            Optional.of(TrustStoreType.fromString(trustType).get()), tempFile.toPath(), null);

    final ConnectionParameters params =
        new ConnectionParameters(
            CONFIGURED_HOST, Optional.empty(), Optional.of(tlsOptions), Optional.of(10L));

    assertThatThrownBy(() -> connectionFactory.create(params))
        .isInstanceOf(HashicorpException.class);
  }
}
