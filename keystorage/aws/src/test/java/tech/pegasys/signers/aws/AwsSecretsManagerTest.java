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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DeleteSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.Tag;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AwsSecretsManagerTest {

  private static final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private static final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");

  private static final String RO_AWS_ACCESS_KEY_ID = System.getenv("RO_AWS_ACCESS_KEY_ID");
  private static final String RO_AWS_SECRET_ACCESS_KEY = System.getenv("RO_AWS_SECRET_ACCESS_KEY");
  private static final String AWS_REGION = "us-east-2";

  private static final String SECRET_NAME_PREFIX = "signers-aws-integration/";
  private static final String SECRET_VALUE1 = "secret-value1";
  private static final String SECRET_VALUE2 = "secret-value2";
  private static final String SECRET_VALUE3 = "secret-value3";
  private static final String SECRET_VALUE4 = "secret-value4";

  private AwsSecretsManager awsSecretsManagerDefault;
  private AwsSecretsManager awsSecretsManagerExplicit;
  private AwsSecretsManager awsSecretsManagerInvalidCredentials;
  private SecretsManagerAsyncClient testSecretsManagerClient;

  private List<String> testSecretNames;
  private String secretName1WithTagKey1ValA;
  private String secretName2WithTagKey1ValB;
  private String secretName3WithTagKey2ValC;
  private String secretName4WithTagKey2ValB;

  void verifyEnvironmentVariables() {
    Assumptions.assumeTrue(
        RW_AWS_ACCESS_KEY_ID != null, "Set RW_AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        RW_AWS_SECRET_ACCESS_KEY != null, "Set RW_AWS_SECRET_ACCESS_KEY environment variable");
    Assumptions.assumeTrue(
        RO_AWS_ACCESS_KEY_ID != null, "Set RO_AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        RO_AWS_SECRET_ACCESS_KEY != null, "Set RO_AWS_SECRET_ACCESS_KEY environment variable");
  }

  @BeforeAll
  void setup() throws Exception {
    verifyEnvironmentVariables();
    initAwsSecretsManagers();
    initTestSecretsManagerClient();
    createTestSecrets();
  }

  @AfterAll
  void teardown() throws Exception {
    if (awsSecretsManagerDefault != null
        || awsSecretsManagerExplicit != null
        || testSecretsManagerClient != null) {
      deleteTestSecrets();
      closeClients();
    }
  }

  @Test
  void fetchSecretWithDefaultManager() {
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret(secretName1WithTagKey1ValA);
    assertThat(secret).hasValue(SECRET_VALUE1);
  }

  @Test
  void fetchSecretWithExplicitManager() {
    Optional<String> secret = awsSecretsManagerExplicit.fetchSecret(secretName1WithTagKey1ValA);
    assertThat(secret).hasValue(SECRET_VALUE1);
  }

  @Test
  void fetchSecretWithInvalidCredentialsReturnsEmpty() {
    assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(
            () -> awsSecretsManagerInvalidCredentials.fetchSecret(secretName1WithTagKey1ValA))
        .withMessageContaining("Failed to fetch secret from AWS Secrets Manager.");
  }

  @Test
  void fetchingNonExistentSecretReturnsEmpty() {
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret("signers-aws-integration/empty");
    assertThat(secret).isEmpty();
  }

  @Test
  void emptyTagFiltersReturnAllSecrets() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), Collections.emptyList(), AbstractMap.SimpleEntry::new);

    assertThat(secretEntries.stream().map(e -> e.getKey()))
        .contains(
            secretName1WithTagKey1ValA,
            secretName2WithTagKey1ValB,
            secretName3WithTagKey2ValC,
            secretName4WithTagKey2ValB);
  }

  @Test
  void nonExistentTagFiltersReturnsEmpty() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("nonexistent-tag-key"),
            List.of("nonexistent-tag-value"),
            AbstractMap.SimpleEntry::new);

    assertThat(secretEntries).isEmpty();
  }

  @Test
  void listAndMapSecretsWithMatchingTagKeys() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("tagKey1"), Collections.emptyList(), AbstractMap.SimpleEntry::new);

    assertThat(secretEntries.stream().map(e -> e.getKey()))
        .contains(secretName1WithTagKey1ValA, secretName2WithTagKey1ValB)
        .doesNotContain(secretName3WithTagKey2ValC, secretName4WithTagKey2ValB);
    assertThat(secretEntries.stream().map(e -> e.getValue()))
        .contains(SECRET_VALUE1, SECRET_VALUE2)
        .doesNotContain(SECRET_VALUE3, SECRET_VALUE4);
  }

  @Test
  void listAndMapSecretsWithMatchingTagValues() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), List.of("tagValB", "tagValC"), AbstractMap.SimpleEntry::new);

    assertThat(secretEntries.stream().map(e -> e.getKey()))
        .contains(
            secretName2WithTagKey1ValB, secretName3WithTagKey2ValC, secretName4WithTagKey2ValB)
        .doesNotContain(secretName1WithTagKey1ValA);
    assertThat(secretEntries.stream().map(e -> e.getValue()))
        .contains(SECRET_VALUE2, SECRET_VALUE3, SECRET_VALUE4)
        .doesNotContain(SECRET_VALUE1);
  }

  @Test
  void listAndMapSecretsWithMatchingTagKeysAndValues() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("tagKey1"), List.of("tagValB"), AbstractMap.SimpleEntry::new);

    assertThat(secretEntries.stream().map(e -> e.getKey()))
        .contains(secretName2WithTagKey1ValB)
        .doesNotContain(
            secretName1WithTagKey1ValA, secretName3WithTagKey2ValC, secretName4WithTagKey2ValB);
    assertThat(secretEntries.stream().map(e -> e.getValue()))
        .contains(SECRET_VALUE2)
        .doesNotContain(SECRET_VALUE1, SECRET_VALUE3, SECRET_VALUE4);
  }

  @Test
  void throwsAwayObjectsWhichMapToNull() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Collections.emptyList(),
            (name, value) -> {
              if (name.equals(secretName1WithTagKey1ValA)) {
                return null;
              }
              return new AbstractMap.SimpleEntry<>(name, value);
            });

    assertThat(secretEntries.stream().map(e -> e.getKey()))
        .contains(
            secretName2WithTagKey1ValB, secretName3WithTagKey2ValC, secretName4WithTagKey2ValB)
        .doesNotContain(secretName1WithTagKey1ValA);
  }

  @Test
  void throwsAwayObjectsThatFailMapper() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Collections.emptyList(),
            (name, value) -> {
              if (name.equals(secretName1WithTagKey1ValA)) {
                throw new RuntimeException("Arbitrary Failure");
              }
              return new AbstractMap.SimpleEntry<>(name, value);
            });

    assertThat(secretEntries.stream().map(e -> e.getKey()))
        .contains(
            secretName2WithTagKey1ValB, secretName3WithTagKey2ValC, secretName4WithTagKey2ValB)
        .doesNotContain(secretName1WithTagKey1ValA);
  }

  private void initAwsSecretsManagers() {
    awsSecretsManagerDefault = AwsSecretsManager.createAwsSecretsManager();
    awsSecretsManagerExplicit =
        AwsSecretsManager.createAwsSecretsManager(
            RO_AWS_ACCESS_KEY_ID, RO_AWS_SECRET_ACCESS_KEY, AWS_REGION);
    awsSecretsManagerInvalidCredentials =
        AwsSecretsManager.createAwsSecretsManager("invalid", "invalid", AWS_REGION);
  }

  private void initTestSecretsManagerClient() {
    final AwsBasicCredentials awsBasicCredentials =
        AwsBasicCredentials.create(RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY);
    final StaticCredentialsProvider credentialsProvider =
        StaticCredentialsProvider.create(awsBasicCredentials);
    testSecretsManagerClient =
        SecretsManagerAsyncClient.builder()
            .credentialsProvider(credentialsProvider)
            .region(Region.of(AWS_REGION))
            .build();
  }

  private void closeTestSecretsManager() {
    testSecretsManagerClient.close();
  }

  private void closeAwsSecretsManagers() {
    awsSecretsManagerDefault.close();
    awsSecretsManagerExplicit.close();
    awsSecretsManagerInvalidCredentials.close();
  }

  private void closeClients() {
    closeAwsSecretsManagers();
    closeTestSecretsManager();
  }

  private String createSecret(final Tag tag, String secretValue)
      throws ExecutionException, InterruptedException, TimeoutException {
    final String testSecretName = SECRET_NAME_PREFIX + UUID.randomUUID();

    final CreateSecretRequest secretRequest =
        CreateSecretRequest.builder()
            .name(testSecretName)
            .secretString(secretValue)
            .tags(tag)
            .build();

    testSecretsManagerClient.createSecret(secretRequest).get(30, TimeUnit.SECONDS);
    waitUntilSecretAvailable(testSecretName);
    return testSecretName;
  }

  private String createTestSecret(
      final String tagKey, final String tagVal, final String secretValue) throws Exception {
    final Tag testSecretTag = Tag.builder().key(tagKey).value(tagVal).build();
    try {
      return createSecret(testSecretTag, secretValue);
    } catch (Exception e) {
      throw new Exception(e.getMessage());
    }
  }

  private void createTestSecrets() throws Exception {
    secretName1WithTagKey1ValA = createTestSecret("tagKey1", "tagValA", SECRET_VALUE1);
    secretName2WithTagKey1ValB = createTestSecret("tagKey1", "tagValB", SECRET_VALUE2);
    secretName3WithTagKey2ValC = createTestSecret("tagKey2", "tagValC", SECRET_VALUE3);
    secretName4WithTagKey2ValB = createTestSecret("tagKey2", "tagValB", SECRET_VALUE4);
    testSecretNames = new ArrayList<>();
    testSecretNames.addAll(
        List.of(
            secretName1WithTagKey1ValA,
            secretName2WithTagKey1ValB,
            secretName3WithTagKey2ValC,
            secretName4WithTagKey2ValB));
  }

  private void waitUntilSecretAvailable(final String secretName)
      throws ExecutionException, InterruptedException, TimeoutException {
    testSecretsManagerClient
        .getSecretValue(GetSecretValueRequest.builder().secretId(secretName).build())
        .get(30, TimeUnit.SECONDS);
  }

  private void deleteTestSecrets() throws Exception {
    for (String name : testSecretNames) {
      final DeleteSecretRequest deleteSecretRequest =
          DeleteSecretRequest.builder().secretId(name).build();
      testSecretsManagerClient.deleteSecret(deleteSecretRequest).get(30, TimeUnit.SECONDS);
    }
    testSecretNames.clear();
  }
}
