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

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import io.vertx.core.http.HttpClientResponse;

public class FileDownloadHandler {
  private final CompletableFuture<String> responseFuture = new CompletableFuture<>();
  private final ExceptionConverter exceptionConverter = new ExceptionConverter();

  public void handle(final HttpClientResponse response) {
    if (response.statusCode() != 200) {
      responseFuture.completeExceptionally(
          new InterlockClientException(
              "Unexpected file download response status code " + response.statusCode()));
      return;
    }

    response.bodyHandler(
        buffer -> {
          try {
            responseFuture.complete(buffer.toString(StandardCharsets.UTF_8));

            // TODO: Failure case where file is encrypted or 0 bytes??
          } catch (final RuntimeException e) {
            handle(e);
          }
        });
  }

  public void handle(final Throwable ex) {
    responseFuture.completeExceptionally(ex);
  }

  public String waitForResponse() {
    try {
      return responseFuture.get();
    } catch (final InterruptedException e) {
      throw new InterlockClientException(getClass().getSimpleName() + " thread interrupted.", e);
    } catch (final ExecutionException e) {
      throw exceptionConverter.apply(e);
    }
  }
}
