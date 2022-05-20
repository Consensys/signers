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

import java.util.AbstractMap.SimpleEntry;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DescribeSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DescribeSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.awssdk.services.secretsmanager.model.Tag;
import software.amazon.awssdk.services.secretsmanager.model.TagResourceRequest;
import software.amazon.awssdk.services.secretsmanager.model.UntagResourceRequest;
import software.amazon.awssdk.services.secretsmanager.model.UpdateSecretRequest;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AwsSecretsManagerTest {

  private static final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private static final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");

  private static final String RO_AWS_ACCESS_KEY_ID = System.getenv("RO_AWS_ACCESS_KEY_ID");
  private static final String RO_AWS_SECRET_ACCESS_KEY = System.getenv("RO_AWS_SECRET_ACCESS_KEY");
  private static final String AWS_REGION = "us-east-2";

  private static final String SECRET_NAME_PREFIX = "signers-aws-integration/";
  private static final String SECRET_NAME1_KEY1_VALA = SECRET_NAME_PREFIX + "secret1";
  private static final String SECRET_NAME2_KEY1_VALB = SECRET_NAME_PREFIX + "secret2";
  private static final String SECRET_NAME3_KEY2_VALC = SECRET_NAME_PREFIX + "secret3";
  private static final String SECRET_NAME4_KEY2_VALB = SECRET_NAME_PREFIX + "secret4";
  private static final String SECRET_VALUE1 = "secret-value1";
  private static final String SECRET_VALUE2 = "secret-value2";
  private static final String SECRET_VALUE3 = "secret-value3";
  private static final String SECRET_VALUE4 = "secret-value4";

  private AwsSecretsManager awsSecretsManagerDefault;
  private AwsSecretsManager awsSecretsManagerExplicit;
  private AwsSecretsManager awsSecretsManagerInvalidCredentials;
  private SecretsManagerClient testSecretsManagerClient;

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
      closeClients();
    }
  }

  @Test
  void fetchSecretWithDefaultManager() {
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret(SECRET_NAME1_KEY1_VALA);
    assertThat(secret).hasValue(SECRET_VALUE1);
  }

  @Test
  void fetchSecretWithExplicitManager() {
    Optional<String> secret = awsSecretsManagerExplicit.fetchSecret(SECRET_NAME1_KEY1_VALA);
    assertThat(secret).hasValue(SECRET_VALUE1);
  }

  @Test
  void fetchSecretWithInvalidCredentialsReturnsEmpty() {
    assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> awsSecretsManagerInvalidCredentials.fetchSecret(SECRET_NAME1_KEY1_VALA))
        .withMessageContaining("Failed to fetch secret from AWS Secrets Manager.");
  }

  @Test
  void fetchingNonExistentSecretReturnsEmpty() {
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret("signers-aws-integration/empty");
    assertThat(secret).isEmpty();
  }

  @Test
  void emptyTagFiltersReturnAllSecrets() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), Collections.emptyList(), SimpleEntry::new);

    assertThat(secretEntries.stream().map(SimpleEntry::getKey))
        .contains(
            SECRET_NAME1_KEY1_VALA,
            SECRET_NAME2_KEY1_VALB,
            SECRET_NAME3_KEY2_VALC,
            SECRET_NAME4_KEY2_VALB);
  }

  @Test
  void nonExistentTagFiltersReturnsEmpty() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("nonexistent-tag-key"), List.of("nonexistent-tag-value"), SimpleEntry::new);

    assertThat(secretEntries).isEmpty();
  }

  @Test
  void listAndMapSecretsWithMatchingTagKeys() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("tagKey1"), Collections.emptyList(), SimpleEntry::new);

    assertThat(secretEntries.stream().map(SimpleEntry::getKey))
        .contains(SECRET_NAME1_KEY1_VALA, SECRET_NAME2_KEY1_VALB)
        .doesNotContain(SECRET_NAME3_KEY2_VALC, SECRET_NAME4_KEY2_VALB);
    assertThat(secretEntries.stream().map(SimpleEntry::getValue))
        .contains(SECRET_VALUE1, SECRET_VALUE2)
        .doesNotContain(SECRET_VALUE3, SECRET_VALUE4);
  }

  @Test
  void listAndMapSecretsWithMatchingTagValues() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), List.of("tagValB", "tagValC"), SimpleEntry::new);

    assertThat(secretEntries.stream().map(SimpleEntry::getKey))
        .contains(SECRET_NAME2_KEY1_VALB, SECRET_NAME3_KEY2_VALC, SECRET_NAME4_KEY2_VALB)
        .doesNotContain(SECRET_NAME1_KEY1_VALA);
    assertThat(secretEntries.stream().map(SimpleEntry::getValue))
        .contains(SECRET_VALUE2, SECRET_VALUE3, SECRET_VALUE4)
        .doesNotContain(SECRET_VALUE1);
  }

  @Test
  void listAndMapSecretsWithMatchingTagKeysAndValues() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("tagKey1"), List.of("tagValB"), SimpleEntry::new);

    assertThat(secretEntries.stream().map(SimpleEntry::getKey))
        .contains(SECRET_NAME2_KEY1_VALB)
        .doesNotContain(SECRET_NAME1_KEY1_VALA, SECRET_NAME3_KEY2_VALC, SECRET_NAME4_KEY2_VALB);
    assertThat(secretEntries.stream().map(SimpleEntry::getValue))
        .contains(SECRET_VALUE2)
        .doesNotContain(SECRET_VALUE1, SECRET_VALUE3, SECRET_VALUE4);
  }

  @Test
  void throwsAwayObjectsWhichMapToNull() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Collections.emptyList(),
            (name, value) -> {
              if (name.equals(SECRET_NAME1_KEY1_VALA)) {
                return null;
              }
              return new SimpleEntry<>(name, value);
            });

    assertThat(secretEntries.stream().map(SimpleEntry::getKey))
        .contains(SECRET_NAME2_KEY1_VALB, SECRET_NAME3_KEY2_VALC, SECRET_NAME4_KEY2_VALB)
        .doesNotContain(SECRET_NAME1_KEY1_VALA);
  }

  @Test
  void throwsAwayObjectsThatFailMapper() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Collections.emptyList(),
            (name, value) -> {
              if (name.equals(SECRET_NAME1_KEY1_VALA)) {
                throw new RuntimeException("Arbitrary Failure");
              }
              return new SimpleEntry<>(name, value);
            });

    assertThat(secretEntries.stream().map(SimpleEntry::getKey))
        .contains(SECRET_NAME2_KEY1_VALB, SECRET_NAME3_KEY2_VALC, SECRET_NAME4_KEY2_VALB)
        .doesNotContain(SECRET_NAME1_KEY1_VALA);
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
        SecretsManagerClient.builder()
            .credentialsProvider(credentialsProvider)
            .region(Region.of(AWS_REGION))
            .build();
  }

  private void closeClients() {
    closeAwsSecretsManagers();
    closeTestSecretsManager();
  }

  private void closeTestSecretsManager() {
    testSecretsManagerClient.close();
  }

  private void closeAwsSecretsManagers() {
    awsSecretsManagerDefault.close();
    awsSecretsManagerExplicit.close();
    awsSecretsManagerInvalidCredentials.close();
  }

  private void createTestSecrets() {
    createOrUpdateSecret(SECRET_NAME1_KEY1_VALA, "tagKey1", "tagValA", SECRET_VALUE1);
    createOrUpdateSecret(SECRET_NAME2_KEY1_VALB, "tagKey1", "tagValB", SECRET_VALUE2);
    createOrUpdateSecret(SECRET_NAME3_KEY2_VALC, "tagKey2", "tagValC", SECRET_VALUE3);
    createOrUpdateSecret(SECRET_NAME4_KEY2_VALB, "tagKey2", "tagValB", SECRET_VALUE4);
  }

  private void createOrUpdateSecret(
      final String testSecretName,
      final String tagKey,
      final String tagVal,
      final String secretValue) {
    final Tag testSecretTag = Tag.builder().key(tagKey).value(tagVal).build();
    try {
      updateIfDifferentSecretValue(testSecretName, secretValue);
      updateIfDifferentSecretTag(testSecretName, testSecretTag);
    } catch (final ResourceNotFoundException e) {
      createTestSecret(testSecretName, testSecretTag, secretValue);
    }
  }

  private void createTestSecret(final String secretName, final Tag tag, final String secretValue) {
    final CreateSecretRequest secretRequest =
        CreateSecretRequest.builder().name(secretName).secretString(secretValue).tags(tag).build();
    testSecretsManagerClient.createSecret(secretRequest);
  }

  private void updateIfDifferentSecretTag(final String secretName, final Tag newTag) {
    final DescribeSecretResponse describeSecretResponse =
        testSecretsManagerClient.describeSecret(
            DescribeSecretRequest.builder().secretId(secretName).build());
    final boolean hasDifferentSecretTag =
        !describeSecretResponse.hasTags() || !describeSecretResponse.tags().equals(List.of(newTag));
    if (hasDifferentSecretTag) {
      testSecretsManagerClient.untagResource(
          UntagResourceRequest.builder()
              .secretId(secretName)
              .tagKeys(
                  describeSecretResponse.tags().stream().map(Tag::key).collect(Collectors.toList()))
              .build());
      testSecretsManagerClient.tagResource(
          TagResourceRequest.builder().secretId(secretName).tags(newTag).build());
    }
  }

  private void updateIfDifferentSecretValue(final String secretName, final String secretValue) {
    final GetSecretValueResponse getSecretValueResponse =
        testSecretsManagerClient.getSecretValue(
            GetSecretValueRequest.builder().secretId(secretName).build());
    final boolean hasDifferentSecretValue =
        !getSecretValueResponse.secretString().equals(secretValue);
    if (hasDifferentSecretValue) {
      testSecretsManagerClient.updateSecret(
          UpdateSecretRequest.builder().secretId(secretName).secretString(secretValue).build());
    }
  }
}
