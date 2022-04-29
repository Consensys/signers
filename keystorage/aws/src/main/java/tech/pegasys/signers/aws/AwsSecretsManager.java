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
package tech.pegasys.signers.aws;

import java.io.Closeable;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.Filter;
import software.amazon.awssdk.services.secretsmanager.model.FilterNameStringType;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretsRequest;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;
import software.amazon.awssdk.services.secretsmanager.paginators.ListSecretsIterable;

public class AwsSecretsManager implements Closeable {

  private static final Logger LOG = LogManager.getLogger();

  private final SecretsManagerClient secretsManagerClient;

  private AwsSecretsManager(final SecretsManagerClient secretsManagerClient) {
    this.secretsManagerClient = secretsManagerClient;
  }

  static AwsSecretsManager createAwsSecretsManager(
      final String accessKeyId, final String secretAccessKey, final String region) {
    final AwsBasicCredentials awsBasicCredentials =
        AwsBasicCredentials.create(accessKeyId, secretAccessKey);
    final StaticCredentialsProvider credentialsProvider =
        StaticCredentialsProvider.create(awsBasicCredentials);

    final SecretsManagerClient secretsManagerClient =
        SecretsManagerClient.builder()
            .credentialsProvider(credentialsProvider)
            .region(Region.of(region))
            .build();

    return new AwsSecretsManager(secretsManagerClient);
  }

  static AwsSecretsManager createAwsSecretsManager() {
    final SecretsManagerClient secretsManagerClient = SecretsManagerClient.builder().build();

    return new AwsSecretsManager(secretsManagerClient);
  }

  public Optional<String> fetchSecret(final String secretName) {
    try {
      final GetSecretValueRequest getSecretValueRequest =
          GetSecretValueRequest.builder().secretId(secretName).build();
      final GetSecretValueResponse valueResponse =
          secretsManagerClient.getSecretValue(getSecretValueRequest);
      return Optional.of(valueResponse.secretString());
    } catch (final ResourceNotFoundException e) {
      return Optional.empty();
    } catch (final SecretsManagerException e) {
      throw new RuntimeException("Failed to fetch secret from AWS Secrets Manager.", e);
    }
  }

  private ListSecretsIterable listSecrets(
      final List<String> tagKeys, final List<String> tagValues) {
    final ListSecretsRequest.Builder listSecretsRequestBuilder = ListSecretsRequest.builder();
    if (!tagKeys.isEmpty()) {
      listSecretsRequestBuilder.filters(
          Filter.builder().key(FilterNameStringType.TAG_KEY).values(tagKeys).build());
    }
    if (!tagValues.isEmpty()) {
      listSecretsRequestBuilder.filters(
          Filter.builder().key(FilterNameStringType.TAG_VALUE).values(tagValues).build());
    }
    return secretsManagerClient.listSecretsPaginator(listSecretsRequestBuilder.build());
  }

  public <R> Collection<R> mapSecrets(
      final List<String> tagKeys,
      final List<String> tagValues,
      final BiFunction<String, String, R> mapper) {
    final Set<R> result = ConcurrentHashMap.newKeySet();
    listSecrets(tagKeys, tagValues)
        .iterator()
        .forEachRemaining(
            listSecretsResponse -> {
              listSecretsResponse
                  .secretList()
                  .parallelStream()
                  .forEach(
                      secretEntry -> {
                        try {
                          final String secretValue = fetchSecret(secretEntry.name()).get();
                          final R obj = mapper.apply(secretEntry.name(), secretValue);
                          if (obj != null) {
                            result.add(obj);
                          } else {
                            LOG.warn(
                                "Mapped '{}' to a null object, and was discarded",
                                secretEntry.name());
                          }
                        } catch (final Exception e) {
                          LOG.warn(
                              "Failed to map secret '{}' to requested object type.",
                              secretEntry.name());
                        }
                      });
            });
    return result;
  }

  @Override
  public void close() {
    this.secretsManagerClient.close();
  }
}
