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
import static tech.pegasys.signers.aws.SecretsMaps.SECRET_NAME_PREFIX_A;

import java.util.AbstractMap.SimpleEntry;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
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
@EnabledIfEnvironmentVariable(
    named = "RW_AWS_ACCESS_KEY_ID",
    matches = ".*",
    disabledReason = "RW_AWS_ACCESS_KEY_ID env variable is required")
@EnabledIfEnvironmentVariable(
    named = "RW_AWS_SECRET_ACCESS_KEY",
    matches = ".*",
    disabledReason = "RW_AWS_SECRET_ACCESS_KEY env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_ACCESS_KEY_ID",
    matches = ".*",
    disabledReason = "AWS_ACCESS_KEY_ID env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_SECRET_ACCESS_KEY",
    matches = ".*",
    disabledReason = "AWS_SECRET_ACCESS_KEY env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_REGION",
    matches = ".*",
    disabledReason = "AWS_REGION env variable is required")
class AwsSecretsManagerTest {

  private static final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private static final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");

  private static final String RO_AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
  private static final String RO_AWS_SECRET_ACCESS_KEY = System.getenv("AWS_SECRET_ACCESS_KEY");
  private static final String AWS_REGION =
      Optional.ofNullable(System.getenv("AWS_REGION")).orElse("us-east-2");

  private AwsSecretsManager awsSecretsManagerDefault;
  private AwsSecretsManager awsSecretsManagerExplicit;
  private AwsSecretsManager awsSecretsManagerInvalidCredentials;
  private SecretsManagerClient testSecretsManagerClient;

  private final SecretsMaps secretsMaps = new SecretsMaps();

  @BeforeAll
  void setup() {
    initAwsSecretsManagers();
    initTestSecretsManagerClient();
    createTestSecrets();
  }

  private void createTestSecrets() {
    secretsMaps
        .getAllSecretsMap()
        .forEach(
            (key, awsSecret) ->
                createOrUpdateSecret(
                    key,
                    awsSecret.getTagKey(),
                    awsSecret.getTagValue(),
                    awsSecret.getSecretValue()));
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
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String key = secretsMap.keySet().stream().findAny().orElseThrow();
    final Optional<String> secret = awsSecretsManagerDefault.fetchSecret(key);
    assertThat(secret).hasValue(secretsMap.get(key).getSecretValue());
  }

  @Test
  void fetchSecretWithExplicitManager() {
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String key = secretsMap.keySet().stream().findAny().orElseThrow();

    final Optional<String> secret = awsSecretsManagerExplicit.fetchSecret(key);
    assertThat(secret).hasValue(secretsMap.get(key).getSecretValue());
  }

  @Test
  void fetchSecretWithInvalidCredentialsReturnsEmpty() {
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String key = secretsMap.keySet().stream().findAny().orElseThrow();
    assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> awsSecretsManagerInvalidCredentials.fetchSecret(key))
        .withMessageContaining("Failed to fetch secret from AWS Secrets Manager.");
  }

  @Test
  void fetchingNonExistentSecretReturnsEmpty() {
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret(SECRET_NAME_PREFIX_A + "empty");
    assertThat(secret).isEmpty();
  }

  @Test
  void emptyFiltersReturnAllSecrets() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyList(),
            SimpleEntry::new);

    final Set<String> fetchedKeys =
        secretEntries.stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    assertThat(fetchedKeys).containsAll(secretsMaps.getAllSecretsMap().keySet());
  }

  @Test
  void nonExistentTagFiltersReturnsEmpty() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            List.of("nonexistent-tag-key"),
            List.of("nonexistent-tag-value"),
            SimpleEntry::new);

    assertThat(secretEntries).isEmpty();
  }

  @Test
  void nonExistentPrefixFilterReturnsEmpty() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("nonexistent-secret-prefix"),
            Collections.emptyList(),
            Collections.emptyList(),
            SimpleEntry::new);

    assertThat(secretEntries).isEmpty();
  }

  @Test
  void nonExistentPrefixFilterWithTagFilterReturnsEmpty() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("nonexistent-secret-prefix"),
            List.of("tagKey1"),
            Collections.emptyList(),
            SimpleEntry::new);

    assertThat(secretEntries).isEmpty();
  }

  @Test
  void listAndMapSecretsWithPrefix() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of(SECRET_NAME_PREFIX_A),
            Collections.emptyList(),
            Collections.emptyList(),
            SimpleEntry::new);

    final Set<String> fetchedKeys =
        secretEntries.stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    assertThat(fetchedKeys).containsAll(secretsMaps.getPrefixASecretsMap().keySet());
    assertThat(fetchedKeys)
        .doesNotContainAnyElementsOf(secretsMaps.getPrefixBSecretsMap().keySet());
  }

  @Test
  void listAndMapSecretsWithPrefixAndTags() {
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            List.of(SECRET_NAME_PREFIX_A),
            List.of("tagKey1"),
            Collections.emptyList(),
            SimpleEntry::new);

    final Set<String> fetchedKeys =
        secretEntries.stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    final Set<String> expectedKeys =
        secretsMaps.getPrefixASecretsMap().entrySet().stream()
            .filter(v -> Objects.equals("tagKey1", v.getValue().getTagKey()))
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());

    final Set<String> nonExpectedKeys =
        secretsMaps.getPrefixASecretsMap().entrySet().stream()
            .filter(v -> !Objects.equals("tagKey1", v.getValue().getTagKey()))
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());

    assertThat(fetchedKeys).containsAll(expectedKeys);
    assertThat(fetchedKeys).doesNotContainAnyElementsOf(nonExpectedKeys);
    assertThat(fetchedKeys)
        .doesNotContainAnyElementsOf(secretsMaps.getPrefixBSecretsMap().keySet());
  }

  @Test
  void listAndMapSecretsWithMatchingTagKeys() {
    final Set<String> expectedTagKeys = Set.of("tagKey1");
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), expectedTagKeys, Collections.emptyList(), SimpleEntry::new);

    final Set<String> fetchedKeys =
        secretEntries.stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    // tagKey1 keys from both maps should have returned
    final Set<String> expectedKeys =
        secretsMaps.getAllSecretsMap().entrySet().stream()
            .filter(v -> expectedTagKeys.contains(v.getValue().getTagKey()))
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());
    assertThat(fetchedKeys).containsAll(expectedKeys);

    // non-tagKey1 keys should not have been returned
    final Set<String> notExpectedKeys =
        secretsMaps.getAllSecretsMap().entrySet().stream()
            .filter(v -> !expectedTagKeys.contains(v.getValue().getTagKey()))
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());
    assertThat(fetchedKeys).doesNotContainAnyElementsOf(notExpectedKeys);
  }

  @Test
  void listAndMapSecretsWithMatchingTagValues() {
    final Set<String> expectedTagValues = Set.of("tagValB", "tagValC");

    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), Collections.emptyList(), expectedTagValues, SimpleEntry::new);
    final Set<String> fetchedKeys =
        secretEntries.stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    // expected tag values from both maps should have returned
    final Set<String> expectedKeys =
        secretsMaps.getAllSecretsMap().entrySet().stream()
            .filter(v -> expectedTagValues.contains(v.getValue().getTagValue()))
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());
    assertThat(fetchedKeys).containsAll(expectedKeys);

    final Set<String> notExpectedKeys =
        secretsMaps.getAllSecretsMap().entrySet().stream()
            .filter(v -> !expectedTagValues.contains(v.getValue().getTagValue()))
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());
    assertThat(fetchedKeys).doesNotContainAnyElementsOf(notExpectedKeys);
  }

  @Test
  void listAndMapSecretsWithMatchingTagKeysAndValues() {
    final Set<String> expectedTagKeys = Set.of("tagKey1");
    final Set<String> expectedTagValues = Set.of("tagValB");

    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), expectedTagKeys, expectedTagValues, SimpleEntry::new);
    final Set<String> fetchedKeys =
        secretEntries.stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    final Set<String> expectedKeys =
        secretsMaps.getAllSecretsMap().entrySet().stream()
            .filter(
                v ->
                    expectedTagKeys.contains(v.getValue().getTagKey())
                        && expectedTagValues.contains(v.getValue().getTagValue()))
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());
    assertThat(fetchedKeys).containsAll(expectedKeys);

    final Set<String> notExpectedKeys =
        secretsMaps.getAllSecretsMap().keySet().stream()
            .filter(key -> !expectedKeys.contains(key))
            .collect(Collectors.toSet());
    assertThat(fetchedKeys).doesNotContainAnyElementsOf(notExpectedKeys);
  }

  @Test
  void throwsAwayObjectsWhichMapToNull() {
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String expectedKey = secretsMap.keySet().stream().findAny().orElseThrow();

    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyList(),
            (name, value) -> {
              if (name.equals(expectedKey)) {
                return null;
              }
              return new SimpleEntry<>(name, value);
            });
    final Set<String> fetchedKeys =
        secretEntries.stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    final Set<String> expectedKeys =
        secretsMap.keySet().stream()
            .filter(secretValue -> !Objects.equals(expectedKey, secretValue))
            .collect(Collectors.toSet());

    assertThat(fetchedKeys).containsAll(expectedKeys);
    assertThat(fetchedKeys).doesNotContain(expectedKey);
  }

  @Test
  void throwsAwayObjectsThatFailMapper() {
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String expectedKey = secretsMap.keySet().stream().findAny().orElseThrow();
    final Collection<SimpleEntry<String, String>> secretEntries =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyList(),
            (name, value) -> {
              if (name.equals(expectedKey)) {
                throw new RuntimeException("Arbitrary Failure");
              }
              return new SimpleEntry<>(name, value);
            });

    final Set<String> fetchedKeys =
        secretEntries.stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    final Set<String> expectedKeys =
        secretsMap.keySet().stream()
            .filter(secretValue -> !Objects.equals(expectedKey, secretValue))
            .collect(Collectors.toSet());

    assertThat(fetchedKeys).containsAll(expectedKeys);
    assertThat(fetchedKeys).doesNotContain(expectedKey);
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
