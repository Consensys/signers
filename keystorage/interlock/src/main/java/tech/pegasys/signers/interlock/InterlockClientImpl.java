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

import static io.vertx.core.http.HttpHeaders.COOKIE;
import static tech.pegasys.signers.interlock.model.ApiAuth.XSRF_TOKEN_HEADER;

import tech.pegasys.signers.interlock.handlers.FileDownloadHandler;
import tech.pegasys.signers.interlock.handlers.FileDownloadIdHandler;
import tech.pegasys.signers.interlock.handlers.LoginHandler;
import tech.pegasys.signers.interlock.handlers.LogoutHandler;
import tech.pegasys.signers.interlock.model.ApiAuth;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class InterlockClientImpl implements InterlockClient {
  private static final Logger LOG = LogManager.getLogger();
  private final HttpClient httpClient;

  InterlockClientImpl(final HttpClient httpClient) {
    this.httpClient = httpClient;
  }

  @Override
  public ApiAuth login(final String volume, final String password) throws InterlockClientException {
    LOG.trace("Login for volume {}", volume);

    final LoginHandler handler = new LoginHandler();
    final String body =
        new JsonObject()
            .put("volume", volume)
            .put("password", password)
            .put("dispose", false)
            .encode();
    httpClient
        .post("/api/auth/login", handler::handle)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .exceptionHandler(handler::handleException)
        .end(body);

    return handler.waitForResponse();
  }

  @Override
  public void logout(final ApiAuth apiAuth) throws InterlockClientException {
    LOG.trace("Logout");
    final LogoutHandler handler = new LogoutHandler();

    httpClient
        .post("/api/auth/logout", handler::handle)
        .exceptionHandler(handler::handleException)
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end();

    handler.waitForResponse();
  }

  @Override
  public String fetchKey(final ApiAuth apiAuth, final Path keyPath) {
    LOG.trace("Fetching key from {}.", keyPath);

    // first fetch unique file download id
    final String downloadId = fetchDownloadId(apiAuth, keyPath);
    LOG.trace("Download ID {}", downloadId);

    // now fetch actual file contents
    final FileDownloadHandler handler = new FileDownloadHandler();
    httpClient
        .get("/api/file/download?" + downloadIdQueryParam(downloadId), handler::handle)
        .exceptionHandler(handler::handleException)
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end();

    return handler.waitForResponse();
  }

  private String fetchDownloadId(final ApiAuth apiAuth, final Path path) {
    LOG.trace("Fetching download id {}", path);
    final FileDownloadIdHandler handler = new FileDownloadIdHandler();
    final String body = new JsonObject().put("path", path.toString()).encode();
    httpClient
        .post("/api/file/download", handler::handle)
        .exceptionHandler(handler::handleException)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end(body);

    return handler.waitForResponse();
  }

  private String downloadIdQueryParam(final String downloadId) {
    return "id=" + URLEncoder.encode(downloadId, StandardCharsets.UTF_8);
  }
}
