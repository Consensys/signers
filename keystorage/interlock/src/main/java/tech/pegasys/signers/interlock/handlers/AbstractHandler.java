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
package tech.pegasys.signers.interlock.handlers;

import tech.pegasys.signers.interlock.InterlockClientException;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.json.JsonObject;

public abstract class AbstractHandler<T> {
  private final CompletableFuture<T> responseFuture = new CompletableFuture<>();
  private final String operation;

  protected AbstractHandler(final String operation) {
    this.operation = operation;
  }

  protected final CompletableFuture<T> getResponseFuture() {
    return responseFuture;
  }

  public final void handle(final HttpClientResponse response) {
    if (!isValidHttpResponseCode(response)) {
      handleException(
          new InterlockClientException(
              "Unexpected " + operation + " response status code " + response.statusCode()));
      return;
    }

    response.bodyHandler(
        buffer -> {
          try {
            handleResponseBuffer(response, buffer);
          } catch (final RuntimeException e) {
            handleException(e);
          }
        });
  }

  protected void handleResponseBuffer(final HttpClientResponse response, final Buffer buffer) {
    final JsonObject json = new JsonObject(buffer);
    if (isValidJsonResponseStatus(json)) {
      responseFuture.complete(processJsonResponse(json, response.headers()));
    } else {
      final String jsonResponse = json.getJsonArray("response").encode();
      handleException(
          new InterlockClientException("Invalid response for " + operation + ": " + jsonResponse));
    }
  }

  protected abstract T processJsonResponse(final JsonObject json, final MultiMap headers);

  public final void handleException(final Throwable ex) {
    responseFuture.completeExceptionally(ex);
  }

  public final T waitForResponse() {
    try {
      return responseFuture.get();
    } catch (final InterruptedException e) {
      throw new InterlockClientException(operation + " response handler thread interrupted.", e);
    } catch (final ExecutionException e) {
      throw convertException(e);
    }
  }

  private boolean isValidHttpResponseCode(final HttpClientResponse response) {
    return response.statusCode() == 200;
  }

  private boolean isValidJsonResponseStatus(final JsonObject json) {
    final String status = json.getString("status");
    return Objects.equals(status, "OK");
  }

  private InterlockClientException convertException(final ExecutionException e) {
    final Throwable cause = e.getCause();

    if (cause instanceof InterlockClientException) {
      return (InterlockClientException) cause;
    }

    if (cause instanceof TimeoutException) {
      return new InterlockClientException(
          "Interlock response handling timed out for operation: " + operation, cause);
    }

    return new InterlockClientException(
        "Interlock response handling failed for operation: "
            + operation
            + " due to :"
            + cause.getMessage(),
        cause);
  }
}
