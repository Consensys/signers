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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

  private static AwsSecretsManager awsSecretsManagerDefault;
  private static AwsSecretsManager awsSecretsManagerExplicit;
  private static AwsSecretsManager awsSecretsManagerInvalidCredentials;
  private static AwsBasicCredentials awsBasicCredentials;
  private static StaticCredentialsProvider credentialsProvider;
  private static SecretsManagerAsyncClient testSecretsManagerClient;
  private static String testSecretName;
  private static String testSecretNamePrefix;
  private static List<String> testSecretNames;
  private static Map<String, String> allTestSecretTags;
  private static Map<String, String> testSecretSingleTag;
  private static Map<String, String> testSecretMultipleTags;
  private static Map<String, String> testSecretSingleSharedTag;
  private static Map<String, String> testSecretMultipleSharedTags;

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
    initTestVariables();
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
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret(testSecretName);
    assertThat(secret).hasValue(SECRET_VALUE);
  }

  @Test
  void fetchSecretWithExplicitManager() {
    Optional<String> secret = awsSecretsManagerExplicit.fetchSecret(testSecretName);
    assertThat(secret).hasValue(SECRET_VALUE);
  }

  @Test
  void fetchSecretWithInvalidCredentialsReturnsEmpty() {
    assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> awsSecretsManagerInvalidCredentials.fetchSecret(testSecretName))
        .withMessageContaining("Failed to fetch secret from AWS Secrets Manager.");
  }

  @Test
  void fetchingNonExistentSecretReturnsEmpty() {
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret("signers-aws-integration/empty");
    assertThat(secret).isEmpty();
  }

  @Test
  void listAndMapSingleSecretWithSingleTag() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            testSecretSingleTag.keySet(),
            testSecretSingleTag.values(),
            AbstractMap.SimpleEntry::new);

    validateMappedSecret(secretEntries, testSecretSingleTag);
  }

  @Test
  void listAndMapSingleSecretWithMultipleTags() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            testSecretMultipleTags.keySet(),
            testSecretMultipleTags.values(),
            AbstractMap.SimpleEntry::new);

    validateMappedSecret(secretEntries, testSecretMultipleTags);
  }

  @Test
  void listAndMapMultipleSecretsWithMultipleTags() {
    final HashMap<String, String> testTags = new HashMap<>();
    testTags.putAll(testSecretMultipleTags);
    testTags.putAll(testSecretSingleTag);

    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            testTags.keySet(), testTags.values(), AbstractMap.SimpleEntry::new);

    validateMappedSecret(secretEntries, testTags);
  }

  @Test
  void listAndMapMultipleSecretsWithSharedTags() {
    final HashMap<String, String> testTags = new HashMap<>();
    testTags.putAll(testSecretSingleTag);
    testTags.putAll(testSecretSingleSharedTag);

    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            testTags.keySet(), testTags.values(), AbstractMap.SimpleEntry::new);

    validateMappedSecret(secretEntries, testTags);
  }

  @Test
  void listAndMapMultipleSecretsWithMultipleAndSharedTags() {
    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            testSecretMultipleSharedTags.keySet(),
            testSecretMultipleSharedTags.values(),
            AbstractMap.SimpleEntry::new);

    validateMappedSecret(secretEntries, testSecretMultipleSharedTags);
  }

  @Test
  void throwsAwayObjectsThatFailMapper() {
    final String failEntryName = testSecretNames.get(1);

    Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            allTestSecretTags.keySet(),
            allTestSecretTags.values(),
            (name, value) -> {
              if (name.equals(failEntryName)) {
                throw new RuntimeException("Arbitrary Failure");
              }
              return new AbstractMap.SimpleEntry<>(name, value);
            });

    validateMappedSecret(secretEntries, allTestSecretTags);
    final Optional<AbstractMap.SimpleEntry<String, String>> failEntry =
        secretEntries.stream().filter(e -> e.getKey().equals(failEntryName)).findAny();
    assertThat(failEntry).isEmpty();
  }

  @Test
  void throwsAwayObjectsWhichMapToNull() {
    final String nullEntryName = testSecretNames.get(1);

    Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            allTestSecretTags.keySet(),
            allTestSecretTags.values(),
            (name, value) -> {
              if (name.equals(nullEntryName)) {
                return null;
              }
              return new AbstractMap.SimpleEntry<>(name, value);
            });

    validateMappedSecret(secretEntries, allTestSecretTags);
    final Optional<AbstractMap.SimpleEntry<String, String>> nullEntry =
        secretEntries.stream().filter(e -> e.getKey().equals("MyBls")).findAny();
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

  private static void initTestVariables() {
    testSecretNames = new ArrayList<>();
    allTestSecretTags = new HashMap<>();
    testSecretSingleTag = new HashMap<>();
    testSecretMultipleTags = new HashMap<>();
    testSecretSingleSharedTag = new HashMap<>();
    testSecretMultipleSharedTags = new HashMap<>();
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

  private static void createSecret(final List<Tag> tags) {
    testSecretName = testSecretNamePrefix + UUID.randomUUID();

    final CreateSecretRequest secretRequest =
        CreateSecretRequest.builder()
            .name(testSecretName)
            .secretString(SECRET_VALUE)
            .tags(tags)
            .build();

    testSecretsManagerClient.createSecret(secretRequest).join();
    testSecretNames.add(testSecretName);
    waitUntilSecretAvailable(testSecretName);
  }

  private static void createTestSecret(final boolean hasMultipleTags, final boolean hasSharedTags) {
    testSecretNamePrefix = "signers-aws-integration/";
    testSecretName = testSecretNamePrefix + UUID.randomUUID();

    final List<Tag> testSecretTags =
        createTestSecretTags(testSecretName, hasMultipleTags, hasSharedTags);
    updateTestTags(testSecretTags, hasMultipleTags, hasSharedTags);
    createSecret(testSecretTags);
  }

  private static void createTestSecrets() {
    createTestSecret(false, false);
    createTestSecret(true, false);
    createTestSecret(false, true);
    createTestSecret(true, true);
  }

  private static void deleteTestSecrets() {
    testSecretNames.forEach(
        name -> {
          final DeleteSecretRequest deleteSecretRequest =
              DeleteSecretRequest.builder().secretId(name).build();
          testSecretsManagerClient.deleteSecret(deleteSecretRequest).join();
        });
    testSecretNames.clear();
    allTestSecretTags.clear();
    testSecretSingleTag.clear();
    testSecretMultipleTags.clear();
    testSecretSingleSharedTag.clear();
    testSecretMultipleSharedTags.clear();
  }

  private static Tag createTag(final String key, final String value) {
    return Tag.builder().key(key).value(value).build();
  }

  private static List<Tag> createTestSecretTags(
      final String secretName, final boolean hasMultipleTags, final boolean hasSharedTags) {
    final List<Tag> testSecretTags = new ArrayList<>();
    testSecretTags.add(createTag(secretName, secretName));
    if (hasMultipleTags) {
      testSecretTags.add(createTag(secretName + "/multiple", "multiple"));
    }
    if (hasSharedTags) {
      allTestSecretTags.forEach((key, value) -> testSecretTags.add(createTag(key, "shared")));
    }
    return testSecretTags;
  }

  private static void updateTestTags(
      final List<Tag> tags, final boolean multipleTags, final boolean sharedTags) {
    tags.forEach(
        tag -> {
          if (!multipleTags && !sharedTags) {
            testSecretSingleTag.put(tag.key(), tag.value());
          } else if (multipleTags && sharedTags) {
            testSecretMultipleTags.put(tag.key(), tag.value());
          } else if (!multipleTags) {
            testSecretSingleSharedTag.put(tag.key(), tag.value());
          } else {
            testSecretMultipleSharedTags.put(tag.key(), tag.value());
          }
        });
    allTestSecretTags = new HashMap<>();
    allTestSecretTags.putAll(testSecretSingleTag);
    allTestSecretTags.putAll(testSecretMultipleTags);
    allTestSecretTags.putAll(testSecretSingleSharedTag);
    allTestSecretTags.putAll(testSecretMultipleSharedTags);
  }

  private static void waitUntilSecretAvailable(final String secretName) {
    testSecretsManagerClient
        .getSecretValue(GetSecretValueRequest.builder().secretId(secretName).build())
        .join();
  }

  private void validateMappedSecret(
      final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries,
      final Map<String, String> testTags) {
    testTags.keySet().stream()
        .filter(tagKey -> testSecretNames.contains(tagKey))
        .collect(Collectors.toList())
        .forEach(
            tagKey ->
                assertThat(tagKey)
                    .isIn(
                        secretEntries.stream()
                            .map(entry -> entry.getKey())
                            .collect(Collectors.toList())));
  }
}
