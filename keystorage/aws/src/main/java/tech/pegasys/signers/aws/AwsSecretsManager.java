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

import java.util.Optional;

import io.vertx.core.json.JsonObject;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

public class AwsSecretsManager {

  private final SecretsManagerClient secretsManagerClient;

  private AwsSecretsManager(SecretsManagerClient secretsManagerClient) {
    this.secretsManagerClient = secretsManagerClient;
  }

  public static AwsSecretsManager createAwsSecretsManager(
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

  public static AwsSecretsManager createAwsSecretsManager(final String region) {
    final SecretsManagerClient secretsManagerClient =
        SecretsManagerClient.builder().region(Region.of(region)).build();

    return new AwsSecretsManager(secretsManagerClient);
  }

  public Optional<String> fetchSecret(final String secretName) {
    try {
      final GetSecretValueRequest getSecretValueRequest =
          GetSecretValueRequest.builder().secretId(secretName).build();
      final GetSecretValueResponse valueResponse =
          secretsManagerClient.getSecretValue(getSecretValueRequest);
      return Optional.of(valueResponse.secretString());
    } catch (SecretsManagerException e) {
      throw new RuntimeException(e.awsErrorDetails().errorMessage());
    }
  }

  public Optional<String> fetchSecretValue(final String secretName, final String secretKey) {
    final Optional<String> secret = fetchSecret(secretName);
    return secret.map(secretValue -> extractValueFromSecret(secretValue, secretKey));
  }

  private String extractValueFromSecret(final String secretValue, final String secretKey) {
    final JsonObject secretValueJson = new JsonObject(secretValue);
    return secretValueJson.getString(secretKey);
  }

  public void close() {
    this.secretsManagerClient.close();
  }
}
