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
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DeleteSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.Tag;

class AwsSecretsManagerTest {

  private static final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private static final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");

  private static final String RO_AWS_ACCESS_KEY_ID = System.getenv("RO_AWS_ACCESS_KEY_ID");
  private static final String RO_AWS_SECRET_ACCESS_KEY = System.getenv("RO_AWS_SECRET_ACCESS_KEY");
  private static final String AWS_REGION = "us-east-2";
  private static final String testSecretNamePrefix = "signers-aws-integration/";

  private static AwsSecretsManager awsSecretsManagerDefault;
  private static AwsSecretsManager awsSecretsManagerExplicit;
  private static AwsSecretsManager awsSecretsManagerInvalidCredentials;
  private static AwsBasicCredentials awsBasicCredentials;
  private static StaticCredentialsProvider credentialsProvider;
  private static SecretsManagerAsyncClient testSecretsManagerClient;

  private static List<String> testSecretNames = new ArrayList<>();
  private static String secretName1;
  private static String secretName2;
  private static String secretName3;
  private static String secretName4;

  private static final String SECRET_VALUE =
      "{\"crypto\": {\"kdf\": {\"function\": \"scrypt\", \"params\": {\"dklen\": 32, \"n\": 262144, \"r\": 8, \"p\": 1, \"salt\": \"3d9b30b612f4f5e9423dc43c0490396798a179d35dd58d48dc1f5d6d42b07ab6\"}, \"message\": \"\"}, \"checksum\": {\"function\": \"sha256\", \"params\": {}, \"message\": \"c762b7453eab3332cda31d9dee1894cf541373617e591a8e7ab8f14f5830f723\"}, \"cipher\": {\"function\": \"aes-128-ctr\", \"params\": {\"iv\": \"095f79f6bb5daab60355ab6aa894b3c8\"}, \"message\": \"4ca342a769ec1c00d6a6d69e18cdf821f42849d4431da7df827b01ba162ed763\"}}, \"description\": \"\", \"pubkey\": \"8fb7c68f3291b8db46ef86a8b9544cad7052dd7cf817862063d1f151f3c443cd3907830b09a86fe0513f0e863beccf25\", \"path\": \"m/12381/3600/0/0/0\", \"uuid\": \"88fc9701-8670-4378-a3ba-00be25c1330c\", \"version\": 4}";

  static void verifyEnvironmentVariables() {
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
  static void setup() {
    verifyEnvironmentVariables();
    initAwsSecretsManagers();
    initTestSecretsManagerClient();
    createTestSecrets();
  }

  @AfterAll
  static void teardown() {
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

  // secret1: tag(k1, vA)
  // secret2: tag(k1, vB)
  // secret3: tag(k2, vC)
  // secret4: tag(k2, vB)
  private static void createTestSecrets() {
    secretName1 = createTestSecret("secret1", "tagKey1", "tagValA");
    secretName2 = createTestSecret("secret2", "tagKey1", "tagValB");
    secretName3 = createTestSecret("secret3", "tagKey2", "tagValC");
    secretName4 = createTestSecret("secret4", "tagKey2", "tagValB");
    testSecretNames.addAll(List.of(secretName1, secretName2, secretName3, secretName4));
  }

  // emptyTagFiltersReturnAllKeys: search([], []) returns all secrets
  @Test
  void emptyTagFiltersReturnAllKeys() {
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
  void listAndMapSecretsWithMatchingKeysAreReturned() {
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
  void secretsWithMatchingValuesAreReturned() {
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

  // secretsWithMatchingKeysOrValuesAreReturned: search([k1], [vB]) returns [secret1, secret2,
  // secret4]
  @Test
  void secretsWithMatchingKeysOrValuesAreReturned() {

    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("tagKey1"), List.of("tagValB"), AbstractMap.SimpleEntry::new);

    final List<String> secretNames =
        secretEntries.stream()
            .map(entry -> String.valueOf(entry.getKey()))
            .collect(Collectors.toList());
    assertThat(secretNames)
        .contains(secretName1, secretName2, secretName4)
        .doesNotContain(secretName3);
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

  private static void initAwsSecretsManagers() {
    awsSecretsManagerDefault = AwsSecretsManager.createAwsSecretsManager();
    awsSecretsManagerExplicit =
        AwsSecretsManager.createAwsSecretsManager(
            RO_AWS_ACCESS_KEY_ID, RO_AWS_SECRET_ACCESS_KEY, AWS_REGION);
    awsSecretsManagerInvalidCredentials =
        AwsSecretsManager.createAwsSecretsManager("invalid", "invalid", AWS_REGION);
  }

  private static void initTestSecretsManagerClient() {
    awsBasicCredentials =
        AwsBasicCredentials.create(RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY);
    credentialsProvider = StaticCredentialsProvider.create(awsBasicCredentials);
    testSecretsManagerClient =
        SecretsManagerAsyncClient.builder()
            .credentialsProvider(credentialsProvider)
            .region(Region.of(AWS_REGION))
            .build();
  }

  private static void closeTestSecretsManager() {
    testSecretsManagerClient.close();
  }

  private static void closeAwsSecretsManagers() {
    awsSecretsManagerDefault.close();
    awsSecretsManagerExplicit.close();
    awsSecretsManagerInvalidCredentials.close();
  }

  private static void closeClients() {
    closeAwsSecretsManagers();
    closeTestSecretsManager();
  }

  private static String createSecret(final String secretName, final Tag tag) {
    final String testSecretName = testSecretNamePrefix + secretName + "/" + UUID.randomUUID();

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

  private static Tag createTag(final String key, final String value) {
    return Tag.builder().key(key).value(value).build();
  }

  private static String createTestSecret(
      final String testSecretName, final String tagKey, final String tagVal) {
    final Tag testSecretTag = createTag(tagKey, tagVal);
    return createSecret(testSecretName, testSecretTag);
  }

  private static void waitUntilSecretAvailable(final String secretName) {
    testSecretsManagerClient
        .getSecretValue(GetSecretValueRequest.builder().secretId(secretName).build())
        .join();
  }

  private static void deleteTestSecrets() {
    testSecretNames.forEach(
        name -> {
          final DeleteSecretRequest deleteSecretRequest =
              DeleteSecretRequest.builder().secretId(name).build();
          testSecretsManagerClient.deleteSecret(deleteSecretRequest).join();
        });
    testSecretNames.clear();
  }
}
