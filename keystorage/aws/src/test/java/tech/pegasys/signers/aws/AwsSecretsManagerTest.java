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
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DeleteSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.Tag;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AwsSecretsManagerTest {

  private final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");

  private final String RO_AWS_ACCESS_KEY_ID = System.getenv("RO_AWS_ACCESS_KEY_ID");
  private final String RO_AWS_SECRET_ACCESS_KEY = System.getenv("RO_AWS_SECRET_ACCESS_KEY");
  private final String AWS_REGION = "us-east-2";

  private AwsSecretsManager awsSecretsManagerDefault;
  private AwsSecretsManager awsSecretsManagerExplicit;
  private AwsSecretsManager awsSecretsManagerInvalidCredentials;
  private SecretsManagerClient secretsManagerClient;
  private String secretName;
  private String secretNamePrefix;
  private List<String> secretNames;
  private AbstractMap<String, String> secretTags;

  private static final String SECRET_VALUE =
      "{\"crypto\": {\"kdf\": {\"function\": \"scrypt\", \"params\": {\"dklen\": 32, \"n\": 262144, \"r\": 8, \"p\": 1, \"salt\": \"3d9b30b612f4f5e9423dc43c0490396798a179d35dd58d48dc1f5d6d42b07ab6\"}, \"message\": \"\"}, \"checksum\": {\"function\": \"sha256\", \"params\": {}, \"message\": \"c762b7453eab3332cda31d9dee1894cf541373617e591a8e7ab8f14f5830f723\"}, \"cipher\": {\"function\": \"aes-128-ctr\", \"params\": {\"iv\": \"095f79f6bb5daab60355ab6aa894b3c8\"}, \"message\": \"4ca342a769ec1c00d6a6d69e18cdf821f42849d4431da7df827b01ba162ed763\"}}, \"description\": \"\", \"pubkey\": \"8fb7c68f3291b8db46ef86a8b9544cad7052dd7cf817862063d1f151f3c443cd3907830b09a86fe0513f0e863beccf25\", \"path\": \"m/12381/3600/0/0/0\", \"uuid\": \"88fc9701-8670-4378-a3ba-00be25c1330c\", \"version\": 4}";

  private void verifyEnvironmentVariables() {
    Assumptions.assumeTrue(
        RW_AWS_ACCESS_KEY_ID != null, "Set RW_AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        RW_AWS_SECRET_ACCESS_KEY != null, "Set RW_AWS_SECRET_ACCESS_KEY environment variable");
    Assumptions.assumeTrue(
        RO_AWS_ACCESS_KEY_ID != null, "Set RO_AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        RO_AWS_SECRET_ACCESS_KEY != null, "Set RO_AWS_SECRET_ACCESS_KEY environment variable");
  }

  private void setupSecretsManagers() {
    awsSecretsManagerDefault = AwsSecretsManager.createAwsSecretsManager();
    awsSecretsManagerExplicit =
        AwsSecretsManager.createAwsSecretsManager(
            RO_AWS_ACCESS_KEY_ID, RO_AWS_SECRET_ACCESS_KEY, AWS_REGION);
    awsSecretsManagerInvalidCredentials =
        AwsSecretsManager.createAwsSecretsManager("invalid", "invalid", AWS_REGION);
  }

  private void setupSecretsManagerClient() {
    final AwsBasicCredentials awsBasicCredentials =
        AwsBasicCredentials.create(RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY);
    final StaticCredentialsProvider credentialsProvider =
        StaticCredentialsProvider.create(awsBasicCredentials);
    secretsManagerClient =
        SecretsManagerClient.builder()
            .credentialsProvider(credentialsProvider)
            .region(Region.of(AWS_REGION))
            .build();
  }

  private void initializeVariables() {
    secretNames = new ArrayList<>();
    secretTags = new HashMap<String, String>();
  }

  private void closeClients() {
    awsSecretsManagerDefault.close();
    awsSecretsManagerExplicit.close();
    awsSecretsManagerInvalidCredentials.close();
    secretsManagerClient.close();
  }

  void createSecret(
      final boolean multipleSecrets, final boolean multipleTags, final boolean sharedTag) {
    secretNamePrefix = "signers-aws-integration/";
    secretName = secretNamePrefix + UUID.randomUUID();
    secretNames.add(secretName);

    final List<Tag> tags = new ArrayList<>();

    if (sharedTag) {
      secretTags
          .entrySet()
          .forEach(
              entry -> tags.add(Tag.builder().key(entry.getKey()).value(entry.getValue()).build()));
    } else if (multipleTags) {
      tags.add(Tag.builder().key(secretNamePrefix + UUID.randomUUID()).value(secretName).build());
    }

    tags.add(Tag.builder().key(secretNamePrefix + UUID.randomUUID()).value(secretName).build());

    tags.forEach(
        tag -> {
          secretTags.put(tag.key(), tag.value());
        });

    final CreateSecretRequest secretRequest =
        CreateSecretRequest.builder()
            .name(secretName)
            .secretString(SECRET_VALUE)
            .tags(tags)
            .build();
    secretsManagerClient.createSecret(secretRequest);

    if (multipleSecrets) {
      createSecret(false, multipleTags, sharedTag);
    }
  }

  @AfterEach
  void deleteSecrets() {
    secretNames.forEach(
        name -> {
          final DeleteSecretRequest secretRequest =
              DeleteSecretRequest.builder().secretId(name).build();
          secretsManagerClient.deleteSecret(secretRequest);
        });
    secretNames.clear();
    secretTags.clear();
  }

  private void validateMappedSecret(
      final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries,
      final String secretName) {
    final Optional<AbstractMap.SimpleEntry<String, String>> secretEntry =
        secretEntries.stream().filter(e -> e.getKey().equals(secretName)).findAny();
    assertThat(secretEntry).isPresent();
    assertThat(secretEntry.get().getValue()).isEqualTo(SECRET_VALUE);
  }

  @BeforeAll
  void setup() {
    verifyEnvironmentVariables();
    setupSecretsManagers();
    setupSecretsManagerClient();
    initializeVariables();
  }

  @AfterAll
  void teardown() {
    if (awsSecretsManagerDefault != null
        || awsSecretsManagerExplicit != null
        || secretsManagerClient != null) {
      deleteSecrets();
      closeClients();
    }
  }

  @Test
  void fetchSecretWithDefaultManager() {
    createSecret(false, false, false);
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret(secretName);
    assertThat(secret).hasValue(SECRET_VALUE);
  }

  @Test
  void fetchSecretWithExplicitManager() {
    createSecret(false, false, false);
    Optional<String> secret = awsSecretsManagerExplicit.fetchSecret(secretName);
    assertThat(secret).hasValue(SECRET_VALUE);
  }

  @Test
  void fetchSecretWithInvalidCredentialsReturnsEmpty() {
    createSecret(false, false, false);
    assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> awsSecretsManagerInvalidCredentials.fetchSecret(secretName))
        .withMessageContaining("Failed to fetch secret from AWS Secrets Manager.");
  }

  @Test
  void fetchingNonExistentSecretReturnsEmpty() {
    createSecret(false, false, false);
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret("signers-aws-integration/empty");
    assertThat(secret).isEmpty();
  }

  @Test
  void listAndMapSingleSecretWithSingleTag() {
    createSecret(false, false, false);

    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            secretTags.keySet().stream().collect(Collectors.toList()),
            secretTags.values().stream().collect(Collectors.toList()),
            AbstractMap.SimpleEntry::new);

    secretNames.forEach(secretName -> validateMappedSecret(secretEntries, secretName));
  }

  @Test
  void listAndMapSingleSecretWithMultipleTags() {
    createSecret(false, true, false);

    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            secretTags.keySet().stream().collect(Collectors.toList()),
            secretTags.values().stream().collect(Collectors.toList()),
            AbstractMap.SimpleEntry::new);

    secretNames.forEach(secretName -> validateMappedSecret(secretEntries, secretName));
  }

  @Test
  void listAndMapMultipleSecretsWithMultipleTags() {
    createSecret(true, true, false);

    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            secretTags.keySet().stream().collect(Collectors.toList()),
            secretTags.values().stream().collect(Collectors.toList()),
            AbstractMap.SimpleEntry::new);

    secretNames.forEach(secretName -> validateMappedSecret(secretEntries, secretName));
  }

  @Test
  void listAndMapMultipleSecretsWithSharedTags() {
    createSecret(true, false, true);

    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            secretTags.keySet().stream().collect(Collectors.toList()),
            secretTags.values().stream().collect(Collectors.toList()),
            AbstractMap.SimpleEntry::new);

    secretNames.forEach(secretName -> validateMappedSecret(secretEntries, secretName));
  }

  @Test
  void listAndMapMultipleSecretsWithMultipleAndSharedTags() {
    createSecret(true, false, true);
    createSecret(true, true, false);

    final Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            secretTags.keySet().stream().collect(Collectors.toList()),
            secretTags.values().stream().collect(Collectors.toList()),
            AbstractMap.SimpleEntry::new);

    secretNames.forEach(secretName -> validateMappedSecret(secretEntries, secretName));
  }

  @Test
  void throwsAwayObjectsThatFailMapper() {
    createSecret(true, false, false);

    final String failEntryName = secretNames.get(1);

    Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            secretTags.keySet().stream().collect(Collectors.toList()),
            secretTags.values().stream().collect(Collectors.toList()),
            (name, value) -> {
              if (name.equals(failEntryName)) {
                throw new RuntimeException("Arbitrary Failure");
              }
              return new AbstractMap.SimpleEntry<>(name, value);
            });

    validateMappedSecret(secretEntries, secretNames.get(0));

    final Optional<AbstractMap.SimpleEntry<String, String>> failEntry =
        secretEntries.stream().filter(e -> e.getKey().equals(failEntryName)).findAny();
    assertThat(failEntry).isEmpty();
  }

  @Test
  void throwsAwayObjectsWhichMapToNull() {
    createSecret(true, false, false);

    final String nullEntryName = secretNames.get(1);

    Collection<AbstractMap.SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            secretTags.keySet().stream().collect(Collectors.toList()),
            secretTags.values().stream().collect(Collectors.toList()),
            (name, value) -> {
              if (name.equals(nullEntryName)) {
                return null;
              }
              return new AbstractMap.SimpleEntry<>(name, value);
            });

    validateMappedSecret(secretEntries, secretNames.get(0));

    final Optional<AbstractMap.SimpleEntry<String, String>> nullEntry =
        secretEntries.stream().filter(e -> e.getKey().equals("MyBls")).findAny();
    assertThat(nullEntry).isEmpty();
  }
}
