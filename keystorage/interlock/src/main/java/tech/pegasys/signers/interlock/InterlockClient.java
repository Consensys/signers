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

import tech.pegasys.signers.interlock.handlers.LoginHandler;
import tech.pegasys.signers.interlock.handlers.LogoutHandler;
import tech.pegasys.signers.interlock.model.ApiAuth;

import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpHeaders;

public class InterlockClient {
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
    final LogoutHandler logoutHandler = new LogoutHandler();

    httpClient
        .post("/api/auth/logout", logoutHandler::handle)
        .exceptionHandler(logoutHandler::handle)
        .putHeader(XSRF_TOKEN_HEADER, apiAuth.getToken())
        .putHeader(COOKIE.toString(), apiAuth.getCookies())
        .end();

    logoutHandler.waitForResponse();
  }
}
