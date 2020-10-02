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
import tech.pegasys.signers.interlock.handlers.FileListHandler;
import tech.pegasys.signers.interlock.handlers.LoginHandler;
import tech.pegasys.signers.interlock.handlers.LogoutHandler;
import tech.pegasys.signers.interlock.model.ApiAuth;
import tech.pegasys.signers.interlock.model.Cipher;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpHeaders;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class InterlockClient {
  private static final Logger LOG = LogManager.getLogger();
  private final HttpClient httpClient;

  /**
   * Constructor for InterlockClient
   *
   * @param vertxHttpClientFactory An instance of VertxHttpClientFactory defining connection
   *     properties.
   */
  public InterlockClient(final VertxHttpClientFactory vertxHttpClientFactory) {
    this.httpClient = vertxHttpClientFactory.create();
  }

  /**
   * Performs login to Interlock. This should be the first call.
   *
   * @param volume The LUKS volume name to use.
   * @param password The LUKS volume password
   * @return ApiAuth containing XSRF Token and list of Cookies that will be used by consecutive
   *     calls.
   * @throws InterlockClientException In case login fails.
   */
  public ApiAuth login(final String volume, final String password) throws InterlockClientException {
    LOG.debug("Login");

    final LoginHandler loginHandler = new LoginHandler();

    httpClient
        .post("/api/auth/login", loginHandler::handle)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .exceptionHandler(loginHandler::handle)
        .end(loginHandler.body(volume, password));

    return loginHandler.waitForResponse();
  }

  /**
   * Performs logout from Interlock server. This should be the last call sequence.
   *
   * @param apiAuth An instance of ApiAuth returned from login method
   * @throws InterlockClientException If logout fails.
   */
  public void logout(final ApiAuth apiAuth) throws InterlockClientException {
    LOG.debug("Logout");
    final LogoutHandler logoutHandler = new LogoutHandler();

    httpClient
        .post("/api/auth/logout", logoutHandler::handle)
        .exceptionHandler(logoutHandler::handle)
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end();

    logoutHandler.waitForResponse();
  }

  /**
   * Attempts to fetch contents from file. If Cipher is not empty, attempt to decrypt file as well.
   *
   * @param apiAuth An instance of ApiAuth from login call
   * @param path The path of file, for instance "/bls/key1.txt.pgp" or "/bls/key1.txt.aes256ofb"
   * @param cipher The cipher to use which is supported by Interlock. Use NONE for unencrypted
   *     files.
   * @param password Password for AES_256_OFB cipher. Can be empty for OpenPGP cipher.
   * @param keyPath Key path for OpenPGP. For example "/keys/pgp/private/test.armor". Can be empty
   *     for AES_256_OFB.
   * @return decrypted file contents.
   */
  public String fetchKey(
      final ApiAuth apiAuth,
      final String path,
      final Cipher cipher,
      final String password,
      final String keyPath) {
    LOG.debug("Fetching key with cipher {} and path {} ", cipher.getCipherName(), path);
    final String decryptedFilePath;
    if (cipher == Cipher.NONE) {
      decryptedFilePath = path;
    } else {
      decryptedFilePath = decryptFile(apiAuth, path, cipher, password, keyPath);

      waitForDecryption(apiAuth, decryptedFilePath);
    }

    final String contents = downloadFile(apiAuth, decryptedFilePath);
    LOG.debug("Contents downloaded [{}]", contents); // TODO: Remove debug call
    if (cipher != Cipher.NONE) {
      deleteFile(apiAuth, decryptedFilePath);
    }

    return contents;
  }

  private void waitForDecryption(final ApiAuth apiAuth, final String decryptedFilePath) {
    // wait for two rounds of list for file to be completely decrypted
    try {
      ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
      for (int i = 0; i < 2; i++) {
        final ScheduledFuture<Long> future =
            executor.schedule(() -> list(apiAuth, decryptedFilePath), 200, TimeUnit.MILLISECONDS);
        final Long decryptedFileSize = future.get();
        LOG.debug("decrypted File size: {}", decryptedFileSize);
        if (decryptedFileSize > 0) {
          break;
        }
      }
      executor.shutdown();
    } catch (final InterruptedException | ExecutionException e) {
      LOG.warn("Waiting for list execution failed: " + e);
    }
  }

  private String downloadFile(final ApiAuth apiAuth, final String path) {
    LOG.debug("Downloading File {}", path);
    final String downloadId = fetchDownloadId(apiAuth, path);
    LOG.debug("Download ID {}", downloadId);
    // fetch actual file contents
    final FileDownloadHandler fileDownloadHandler = new FileDownloadHandler();
    httpClient
        .get("/api/file/download?" + downloadIdQueryParam(downloadId), fileDownloadHandler::handle)
        .exceptionHandler(fileDownloadHandler::handle)
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end();

    return fileDownloadHandler.waitForResponse();
  }

  private String decryptFile(
      final ApiAuth apiAuth,
      final String path,
      final Cipher cipher,
      final String password,
      final String keyPath) {
    LOG.debug("Decrypting file");
    final FileDecryptHandler handler = new FileDecryptHandler();
    httpClient
        .post("/api/file/decrypt", handler::handle)
        .exceptionHandler(handler::handle)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end(handler.body(path, password, keyPath, cipher));

    handler.waitForResponse();

    // Interlock seems to rename the decrypted file by dropping its cipher specific extension
    if (StringUtils.endsWith(path, cipher.getCipherExtension())) {
      return StringUtils.removeEnd(path, cipher.getCipherExtension());
    }

    return path + ".decrypted";
  }

  private void deleteFile(final ApiAuth apiAuth, final String path) {
    // /api/file/delete
    // {"path":["/bls/key1.txt"]}
    LOG.debug("Deleting File {}", path);
    final FileDeleteHandler handler = new FileDeleteHandler();
    httpClient
        .post("/api/file/delete", handler::handle)
        .exceptionHandler(handler::handle)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end(handler.body(path));

    handler.waitForResponse();
  }

  private String fetchDownloadId(final ApiAuth apiAuth, final String path) {
    LOG.debug("Fetching download id {}", path);
    final FileDownloadIdHandler fileDownloadIdHandler = new FileDownloadIdHandler();
    httpClient
        .post("/api/file/download", fileDownloadIdHandler::handle)
        .exceptionHandler(fileDownloadIdHandler::handle)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end(fileDownloadIdHandler.body(path));

    return fileDownloadIdHandler.waitForResponse();
  }

  private Long list(final ApiAuth apiAuth, final String path) {
    LOG.debug("list path {}", path);
    final FileListHandler handler = new FileListHandler(path);
    httpClient
        .post("/api/file/list", handler::handle)
        .exceptionHandler(handler::handle)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end(handler.body());

    return handler.waitForResponse();
  }

  private String downloadIdQueryParam(final String downloadId) {
    return "id=" + URLEncoder.encode(downloadId, StandardCharsets.UTF_8);
  }
}
