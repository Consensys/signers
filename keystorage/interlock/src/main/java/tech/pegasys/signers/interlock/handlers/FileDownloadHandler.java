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

import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.json.JsonObject;

public class FileDownloadHandler extends AbstractHandler<String> {

  public FileDownloadHandler() {
    super("File Download");
  }

  @Override
  protected String processJsonResponse(final JsonObject json, final MultiMap headers) {
    return null;
  }

  @Override
  public String body() {
    return null;
  }

  @Override
  public void handle(final HttpClientResponse response) {
    if (response.statusCode() != 200) {
      getResponseFuture()
          .completeExceptionally(
              new InterlockClientException(
                  "Unexpected file download response status code " + response.statusCode()));
      return;
    }

    response.bodyHandler(
        buffer -> {
          try {
            getResponseFuture().complete(buffer.toString(StandardCharsets.UTF_8));
          } catch (final RuntimeException e) {
            handle(e);
          }
        });
  }
}
