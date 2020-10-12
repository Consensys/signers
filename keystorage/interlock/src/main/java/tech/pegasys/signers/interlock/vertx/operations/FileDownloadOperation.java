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

import tech.pegasys.signers.interlock.model.ApiAuth;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientResponse;

public class FileDownloadOperation extends AbstractOperation<String> {
  private final HttpClient httpClient;
  private final ApiAuth apiAuth;
  private final String downloadId;

  public FileDownloadOperation(
      final HttpClient httpClient, final ApiAuth apiAuth, final String downloadId) {
    this.httpClient = httpClient;
    this.apiAuth = apiAuth;
    this.downloadId = downloadId;
  }

  @Override
  protected void invoke() {
    httpClient
        .get("/api/file/download?" + downloadIdQueryParam(downloadId), this::handle)
        .exceptionHandler(this::handleException)
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end();
  }

  @Override
  protected void handleResponseBuffer(final HttpClientResponse response, final Buffer buffer) {
    getResponseFuture().complete(buffer.toString(StandardCharsets.UTF_8));
  }

  private String downloadIdQueryParam(final String downloadId) {
    return "id=" + URLEncoder.encode(downloadId, StandardCharsets.UTF_8);
  }
}
