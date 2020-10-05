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

import tech.pegasys.signers.interlock.handlers.FileDecryptHandler;
import tech.pegasys.signers.interlock.handlers.FileDeleteHandler;
import tech.pegasys.signers.interlock.handlers.FileDownloadHandler;
import tech.pegasys.signers.interlock.handlers.FileDownloadIdHandler;
import tech.pegasys.signers.interlock.handlers.FileSizeHandler;
import tech.pegasys.signers.interlock.handlers.LoginHandler;
import tech.pegasys.signers.interlock.handlers.LogoutHandler;
import tech.pegasys.signers.interlock.model.ApiAuth;
import tech.pegasys.signers.interlock.model.Cipher;
import tech.pegasys.signers.interlock.model.DecryptCredentials;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonArray;
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
  public String fetchKey(
      final ApiAuth apiAuth,
      final Path path,
      final Optional<DecryptCredentials> decryptCredentials) {
    LOG.trace("Fetching key from {}. Encrypted {}", path, decryptCredentials.isPresent());

    final Path decryptedFilePath;
    if (decryptCredentials.isEmpty()) {
      decryptedFilePath = path;
    } else {
      decryptedFilePath = decryptFile(apiAuth, path, decryptCredentials.get());

      waitForDecryption(apiAuth, decryptedFilePath);
    }

    final String contents = downloadFile(apiAuth, decryptedFilePath);

    if (decryptCredentials.isPresent()) {
      deleteFile(apiAuth, decryptedFilePath);
    }

    return contents;
  }

  private void waitForDecryption(final ApiAuth apiAuth, final Path decryptedFile) {
    /* Note: This is a hack.

    Interlock file decrypt operation takes some time to decrypt the file completely.
    if decrypt is successful, the file size changes to non-zero approximately after 200 ms.
    if decrypt fails, the file size remains 0.

    So, we schedule two runs with a delay of 200 ms to make sure file size changes from 0
    */
    ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    try {
      for (int i = 0; i < 2; i++) {
        final ScheduledFuture<Long> future =
            executor.schedule(() -> fileSize(apiAuth, decryptedFile), 200, TimeUnit.MILLISECONDS);
        final Long decryptedFileSize = future.get();
        LOG.trace("decrypted File size: {}", decryptedFileSize);
        if (decryptedFileSize > 0) {
          break;
        }
      }
    } catch (final InterruptedException | ExecutionException e) {
      LOG.warn("Waiting for file size execution failed: " + e);
    } finally {
      executor.shutdown();
    }
  }

  private String downloadFile(final ApiAuth apiAuth, final Path path) {
    LOG.trace("Downloading File {}", path);

    // first fetch unique file download id
    final String downloadId = fetchDownloadId(apiAuth, path);
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

  private Path decryptFile(
      final ApiAuth apiAuth, final Path path, final DecryptCredentials decryptCredentials) {
    LOG.trace("Decrypting file {}", path);
    final FileDecryptHandler handler = new FileDecryptHandler(path, decryptCredentials);
    httpClient
        .post("/api/file/decrypt", handler::handle)
        .exceptionHandler(handler::handleException)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end(decryptFileBody(path, decryptCredentials));

    return handler.waitForResponse();
  }

  private String decryptFileBody(final Path path, final DecryptCredentials decryptCredentials) {
    final Cipher cipher = decryptCredentials.getCipher();
    final String password = cipher.isUsePassword() ? decryptCredentials.getPassword() : "";
    final String key =
        cipher.isUsePrivateKey() ? decryptCredentials.getPrivateKeyPath().toString() : "";
    return new JsonObject()
        .put("src", path)
        .put("password", password)
        .put("verify", false)
        .put("key", key)
        .put("sig_key", "")
        .put("cipher", cipher.getCipherName())
        .encode();
  }

  private void deleteFile(final ApiAuth apiAuth, final Path decryptedFile) {
    LOG.trace("Deleting File {}", decryptedFile);
    final FileDeleteHandler handler = new FileDeleteHandler();
    final String body = new JsonObject().put("path", new JsonArray().add(decryptedFile)).encode();
    httpClient
        .post("/api/file/delete", handler::handle)
        .exceptionHandler(handler::handleException)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end(body);

    handler.waitForResponse();
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

  private Long fileSize(final ApiAuth apiAuth, final Path path) {
    LOG.trace("list path {}", path);
    final FileSizeHandler handler = new FileSizeHandler(path);
    final String body =
        new JsonObject().put("path", path.getParent().toString()).put("sha256", true).encode();
    httpClient
        .post("/api/file/list", handler::handle)
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
