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

import static io.vertx.core.http.HttpMethod.GET;

import tech.pegasys.signers.hashicorp.config.KeyDefinition;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLException;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientResponse;

public class HashicorpConnection {

  private static final String ERROR_HTTP_CLIENT_CALL =
      "Error while waiting for response from Hashicorp Vault";

  private static final String DEFAULT_HASHICORP_KEY_NAME = "value";

  private final HttpClient httpClient;
  private final long requestTimeoutMs;

  public HashicorpConnection(final HttpClient httpClient, final long requestTimeoutMs) {
    this.httpClient = httpClient;
    this.requestTimeoutMs = requestTimeoutMs;
  }

  public String fetchKey(final KeyDefinition key) {
    final Map<String, String> kvMap = fetchKeyValuesFromVault(key);
    final String keyName = key.getKeyName().orElse(DEFAULT_HASHICORP_KEY_NAME);
    return Optional.ofNullable(kvMap.get(keyName))
        .orElseThrow(() -> new HashicorpException("Requested Secret name does not exist."));
  }

  private Map<String, String> fetchKeyValuesFromVault(final KeyDefinition key) {
    final CompletableFuture<Map<String, String>> futureResponse = new CompletableFuture<>();

    httpClient
        .request(GET, key.getKeyPath(), response -> responseHandler(futureResponse, response))
        .putHeader("X-Vault-Token", key.getToken())
        .setChunked(false)
        .exceptionHandler(futureResponse::completeExceptionally)
        .setTimeout(requestTimeoutMs)
        .end();

    try {
      return futureResponse.get();
    } catch (final ExecutionException e) {
      final Throwable underlyingFailure = e.getCause();
      if (underlyingFailure instanceof HashicorpException) {
        throw (HashicorpException) e.getCause();
      } else if (underlyingFailure instanceof TimeoutException) {
        throw new HashicorpException(
            "Hashicorp Vault failed to respond within expected timeout.", underlyingFailure);
      } else if (underlyingFailure instanceof SSLException) {
        throw new HashicorpException("Failed during SSL negotiation.", underlyingFailure);
      }
      throw new HashicorpException(ERROR_HTTP_CLIENT_CALL, underlyingFailure);
    } catch (final InterruptedException e) {
      throw new HashicorpException("Waiting for Hashicorp response was terminated unexpectedly");
    }
  }

  private void responseHandler(
      final CompletableFuture<Map<String, String>> future, final HttpClientResponse response) {

    final int statusCode = response.statusCode();
    if (statusCode != HttpResponseStatus.OK.code()) {
      future.completeExceptionally(
          new HashicorpException(String.format("Invalid Http Status code %d", statusCode)));
    } else {

      response.bodyHandler(
          buffer -> {
            try {
              final Map<String, String> kvMap = HashicorpKVResponseMapper.from(buffer.toString());
              future.complete(kvMap);
            } catch (final Exception e) {
              future.completeExceptionally(e);
            }
          });
    }
  }
}
