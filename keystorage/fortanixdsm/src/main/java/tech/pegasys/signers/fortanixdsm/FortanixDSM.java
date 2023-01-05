/*
 * Copyright 2022 ConsenSys AG.
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
package tech.pegasys.signers.fortanixdsm;

import java.io.Closeable;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;

import com.fortanix.sdkms.v1.ApiClient;
import com.fortanix.sdkms.v1.ApiException;
import com.fortanix.sdkms.v1.Configuration;
import com.fortanix.sdkms.v1.api.AuthenticationApi;
import com.fortanix.sdkms.v1.api.SecurityObjectsApi;
import com.fortanix.sdkms.v1.auth.ApiKeyAuth;
import com.fortanix.sdkms.v1.model.AuthResponse;
import com.fortanix.sdkms.v1.model.KeyObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class FortanixDSM implements Closeable {

  private static final Logger LOG = LogManager.getLogger();
  private String bearerToken;
  private ApiClient client;
  private SecurityObjectsApi securityObject;

  public static FortanixDSM createWithApiKeyCredential(final String server, final String apiKey) {
    try {
      return new FortanixDSM(server, apiKey);
    } catch (ApiException e) {
      throw new RuntimeException(e);
    }
  }

  private FortanixDSM(final String server, final String apiKey) throws ApiException {
    client = new ApiClient();
    client.setBasePath(server);
    Configuration.setDefaultApiClient(client);
    client.setBasicAuthString(apiKey);
    AuthResponse response;
    response = new AuthenticationApi().authorize();
    bearerToken = response.getAccessToken();
    ApiKeyAuth bearerAuth = (ApiKeyAuth) client.getAuthentication("bearerToken");
    bearerAuth.setApiKey(bearerToken);
    bearerAuth.setApiKeyPrefix("Bearer");
    securityObject = new SecurityObjectsApi();
  }

  public Optional<Bytes> fetchSecret(final String secretName) {
    try {
      KeyObject secret = securityObject.getSecurityObjectValue(secretName);
      return Optional.of(Bytes.wrap(secret.getValue()));
    } catch (final ApiException e) {
      return Optional.empty();
    }
  }

  public Optional<String> fetchName(final String secretName) {
    try {
      KeyObject secret = securityObject.getSecurityObjectValue(secretName);
      return Optional.of(secret.getName());
    } catch (final ApiException e) {
      return Optional.empty();
    }
  }

  public <R> Collection<R> mapSecret(
      final String secretName, final BiFunction<String, Bytes, R> mapper) {
    final Set<R> result = ConcurrentHashMap.newKeySet();
    try {
      final Optional<String> name = fetchName(secretName);
      final Optional<Bytes> value = fetchSecret(secretName);
      if (name.isPresent() && value.isPresent()) {
        final R object = mapper.apply(name.get(), Bytes.wrap(fetchSecret(secretName).get()));
        result.add(object);
      }
    } catch (final Exception e) {
      LOG.warn("Failed to map secret '{}' to requested object type.", secretName);
    }
    return result;
  }

  public void logout() {
    if (bearerToken != null) {
      try {
        new AuthenticationApi().terminate();
      } catch (final ApiException e) {
        LOG.error("Error logging out: " + e.getMessage());
      }
      bearerToken = null;
    }
  }

  @Override
  public void close() {
    logout();
  }
}
