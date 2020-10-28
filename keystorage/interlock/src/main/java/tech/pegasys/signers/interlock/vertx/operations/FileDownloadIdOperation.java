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
package tech.pegasys.signers.interlock.vertx.operations;

import static io.vertx.core.http.HttpHeaders.COOKIE;
import static tech.pegasys.signers.interlock.model.ApiAuth.XSRF_TOKEN_HEADER;

import tech.pegasys.signers.interlock.model.ApiAuth;

import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;

public class FileDownloadIdOperation extends AbstractOperation<String> {
  private final HttpClient httpClient;
  private final ApiAuth apiAuth;
  private final String keyPath;

  public FileDownloadIdOperation(
      final HttpClient httpClient, final ApiAuth apiAuth, final String keyPath) {
    this.httpClient = httpClient;
    this.apiAuth = apiAuth;
    this.keyPath = keyPath;
  }

  @Override
  protected void invoke() {
    final String body = new JsonObject().put("path", keyPath).encode();
    httpClient
        .post("/api/file/download", this::handle)
        .exceptionHandler(this::handleException)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end(body);
  }

  @Override
  protected String processJsonResponse(final JsonObject json, final MultiMap headers) {
    return json.getString("response");
  }
}
