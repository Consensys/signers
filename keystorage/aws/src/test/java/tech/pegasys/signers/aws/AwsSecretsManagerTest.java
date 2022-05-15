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
import java.util.stream.Collectors;

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

  private final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");

  private final String RO_AWS_ACCESS_KEY_ID = System.getenv("RO_AWS_ACCESS_KEY_ID");
  private final String RO_AWS_SECRET_ACCESS_KEY = System.getenv("RO_AWS_SECRET_ACCESS_KEY");
  private final String AWS_REGION = "us-east-2";

  private final String SECRET_NAME_PREFIX = "signers-aws-integration/";
  private final String SECRET_VALUE = "secret-value";

  private AwsSecretsManager awsSecretsManagerDefault;
  private AwsSecretsManager awsSecretsManagerExplicit;
  private AwsSecretsManager awsSecretsManagerInvalidCredentials;
  private SecretsManagerAsyncClient testSecretsManagerClient;

  private List<String> testSecretNames;
  private String secretName1;
  private String secretName2;
  private String secretName3;
  private String secretName4;

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
  void setup() {
    verifyEnvironmentVariables();
    initAwsSecretsManagers();
    initTestSecretsManagerClient();
    createTestSecrets();
  }

  @AfterAll
  void teardown() {
    if (awsSecretsManagerDefault != null
        || awsSecretsManagerExplicit != null
        || testSecretsManagerClient != null) {
      deleteTestSecrets();
      closeClients();
    }
  }

  @Test
  void fetchSecretWithDefaultManager() {
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret(secretName1);
    assertThat(secret).hasValue(SECRET_VALUE);
  }

  @Test
  void fetchSecretWithExplicitManager() {
    Optional<String> secret = awsSecretsManagerExplicit.fetchSecret(secretName1);
    assertThat(secret).hasValue(SECRET_VALUE);
  }

  @Test
  void fetchSecretWithInvalidCredentialsReturnsEmpty() {
    assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> awsSecretsManagerInvalidCredentials.fetchSecret(secretName1))
        .withMessageContaining("Failed to fetch secret from AWS Secrets Manager.");
  }

  @Test
  void fetchingNonExistentSecretReturnsEmpty() {
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret("signers-aws-integration/empty");
    assertThat(secret).isEmpty();
  }

  // emptyTagFiltersReturnAllKeys: search([], []) returns all secrets
  @Test
  void emptyTagFiltersReturnAllSecrets() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), Collections.emptyList(), AbstractMap.SimpleEntry::new);

    final List<String> secretNames =
        secretEntries.stream()
            .map(entry -> String.valueOf(entry.getKey()))
            .collect(Collectors.toList());
    assertThat(secretNames).contains(secretName1, secretName2, secretName3, secretName4);
  }

  // secretsWithMatchingKeysAreReturned: search([k1], []) returns [secret1, secret2]
  @Test
  void listAndMapSecretsWithMatchingTagKeys() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("tagKey1"), Collections.emptyList(), AbstractMap.SimpleEntry::new);

    final List<String> secretNames =
        secretEntries.stream()
            .map(entry -> String.valueOf(entry.getKey()))
            .collect(Collectors.toList());
    assertThat(secretNames)
        .contains(secretName1, secretName2)
        .doesNotContain(secretName3, secretName4);
  }

  // secretsWithMatchingValuesAreReturned: search([], [vB, vC]) returns [secret2, secret3, secret4]
  @Test
  void listAndMapSecretsWithMatchingTagValues() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), List.of("tagValB", "tagValC"), AbstractMap.SimpleEntry::new);

    final List<String> secretNames =
        secretEntries.stream()
            .map(entry -> String.valueOf(entry.getKey()))
            .collect(Collectors.toList());
    assertThat(secretNames)
        .contains(secretName2, secretName3, secretName4)
        .doesNotContain(secretName1);
  }

  // secretsWithMatchingKeysOrValuesAreReturned: search([k1], [vB]) returns [secret2]
  @Test
  void listAndMapSecretsWithMatchingTagKeysAndValues() {

    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("tagKey1"), List.of("tagValB"), AbstractMap.SimpleEntry::new);

    final List<String> secretNames =
        secretEntries.stream()
            .map(entry -> String.valueOf(entry.getKey()))
            .collect(Collectors.toList());
    assertThat(secretNames)
        .contains(secretName2)
        .doesNotContain(secretName1, secretName3, secretName4);
  }

  @Test
  void throwsAwayObjectsWhichMapToNull() {
    Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Collections.emptyList(),
            (name, value) -> {
              if (name.equals(secretName1)) {
                return null;
              }
              return new AbstractMap.SimpleEntry<>(name, value);
            });

    final Optional<AbstractMap.SimpleEntry<String, String>> nullEntry =
        secretEntries.stream().filter(e -> e.getKey().equals(secretName1)).findAny();
    assertThat(nullEntry).isEmpty();
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
    AwsBasicCredentials awsBasicCredentials =
        AwsBasicCredentials.create(RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY);
    StaticCredentialsProvider credentialsProvider =
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

  private String createSecret(final Tag tag) {
    final String testSecretName = SECRET_NAME_PREFIX + "/" + UUID.randomUUID();

    final CreateSecretRequest secretRequest =
        CreateSecretRequest.builder()
            .name(testSecretName)
            .secretString(SECRET_VALUE)
            .tags(tag)
            .build();

    testSecretsManagerClient.createSecret(secretRequest).join();
    waitUntilSecretAvailable(testSecretName);
    return testSecretName;
  }

  private String createTestSecret(final String tagKey, final String tagVal) {
    final Tag testSecretTag = Tag.builder().key(tagKey).value(tagVal).build();
    return createSecret(testSecretTag);
  }

  private void createTestSecrets() {
    secretName1 = createTestSecret("tagKey1", "tagValA");
    secretName2 = createTestSecret("tagKey1", "tagValB");
    secretName3 = createTestSecret("tagKey2", "tagValC");
    secretName4 = createTestSecret("tagKey2", "tagValB");
    testSecretNames = new ArrayList<>();
    testSecretNames.addAll(List.of(secretName1, secretName2, secretName3, secretName4));
  }

  private void waitUntilSecretAvailable(final String secretName) {
    testSecretsManagerClient
        .getSecretValue(GetSecretValueRequest.builder().secretId(secretName).build())
        .join();
  }

  private void deleteTestSecrets() {
    testSecretNames.forEach(
        name -> {
          final DeleteSecretRequest deleteSecretRequest =
              DeleteSecretRequest.builder().secretId(name).build();
          testSecretsManagerClient.deleteSecret(deleteSecretRequest).join();
        });
    testSecretNames.clear();
  }
}
