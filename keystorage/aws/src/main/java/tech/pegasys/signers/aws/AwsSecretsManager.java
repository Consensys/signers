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

import io.vertx.core.json.JsonObject;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

public class AwsSecretsManager {

  private String secretName;
  private String keyStoreValue;

  public static SecretsManagerClient createSecretsManagerClient(Region region) {
    return SecretsManagerClient.builder().region(region).build();
  }

  public static String requestSecretValue(
      SecretsManagerClient secretsManagerClient, String secretName) {
    GetSecretValueRequest getSecretValueRequest =
        GetSecretValueRequest.builder().secretId(secretName).build();

    GetSecretValueResponse valueResponse =
        secretsManagerClient.getSecretValue(getSecretValueRequest);
    return valueResponse.secretString();
  }

  public static String extractKeyStoreValue(String secretValue, String secretKey) {
    JsonObject secretValueJson = new JsonObject(secretValue);
    String keyStoreValue = secretValueJson.getString(secretKey);
    return keyStoreValue;
  }

  public String getSecretName() {
    return this.secretName;
  }

  public String getKeyStoreValue() {
    return this.keyStoreValue;
  }

  public static String getKeyStoreValue(
      SecretsManagerClient secretsManagerClient, String secretName, String secretKey) {
    try {
      String secretValue = requestSecretValue(secretsManagerClient, secretName);
      return extractKeyStoreValue(secretValue, secretKey);
    } catch (SecretsManagerException e) {
      throw new RuntimeException(e.awsErrorDetails().errorMessage());
    }
  }

  public AwsSecretsManager(
      SecretsManagerClient secretsManagerClient, String secretName, String secretKey) {
    this.secretName = secretName;
    this.keyStoreValue = getKeyStoreValue(secretsManagerClient, secretName, secretKey);
  }
}
