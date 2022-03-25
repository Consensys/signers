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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AwsSecretsManagerProviderTest {

  private final String AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
  private final String AWS_SECRET_ACCESS_KEY = System.getenv("AWS_SECRET_ACCESS_KEY");
  private final String AWS_REGION = "us-east-2";
  private final String DIFFERENT_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private final String DIFFERENT_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");
  private final String DIFFERENT_AWS_REGION = "us-east-1";

  private AwsSecretsManagerProvider awsSecretsManagerProvider;

  private void verifyEnvironmentVariables() {
    Assumptions.assumeTrue(
        DIFFERENT_AWS_ACCESS_KEY_ID != null, "Set RW_AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        DIFFERENT_AWS_SECRET_ACCESS_KEY != null,
        "Set RW_AWS_SECRET_ACCESS_KEY environment variable");
    Assumptions.assumeTrue(AWS_ACCESS_KEY_ID != null, "Set AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        AWS_SECRET_ACCESS_KEY != null, "Set AWS_SECRET_ACCESS_KEY environment variable");
  }

  private AwsSecretsManager createDefaultSecretsManager() {
    return awsSecretsManagerProvider.createAwsSecretsManager();
  }

  private AwsSecretsManager createSpecifiedSecretsManager() {
    return awsSecretsManagerProvider.createAwsSecretsManager(
        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION);
  }

  private AwsSecretsManager createSecretsManagerDifferentKeys() {
    return awsSecretsManagerProvider.createAwsSecretsManager(
        DIFFERENT_AWS_ACCESS_KEY_ID, DIFFERENT_AWS_SECRET_ACCESS_KEY, AWS_REGION);
  }

  private AwsSecretsManager createSecretsManagerDifferentRegion() {
    return awsSecretsManagerProvider.createAwsSecretsManager(
        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, DIFFERENT_AWS_REGION);
  }

  private AwsSecretsManager createSecretsManagerDifferentKeysDifferentRegion() {
    return awsSecretsManagerProvider.createAwsSecretsManager(
        DIFFERENT_AWS_ACCESS_KEY_ID, DIFFERENT_AWS_SECRET_ACCESS_KEY, DIFFERENT_AWS_REGION);
  }

  @BeforeAll
  void setup() {
    verifyEnvironmentVariables();
  }

  @BeforeEach
  void initializeCacheableAwsSecretsManagerProvider() {
    awsSecretsManagerProvider = new AwsSecretsManagerProvider(4);
  }

  @AfterEach
  void teardown() {
    awsSecretsManagerProvider.close();
  }

  @Test
  void isSameAsCachedSpecifiedSecretsManager() {
    assertThat(createSpecifiedSecretsManager()).isSameAs(createSpecifiedSecretsManager());
  }

  @Test
  void isSameAsCachedDefaultSecretsManager() {
    assertThat(createDefaultSecretsManager()).isSameAs(createDefaultSecretsManager());
  }

  @Test
  void isSameAsCachedDefaultSecretsManagerAfterCachingSpecified() {
    assertThat(createSpecifiedSecretsManager()).isSameAs(createDefaultSecretsManager());
  }

  @Test
  void isSameAsCorrectCachedSecretsManager() {
    assertThat(createDefaultSecretsManager())
        .isNotSameAs(createSecretsManagerDifferentKeys())
        .isNotSameAs(createSecretsManagerDifferentRegion())
        .isNotSameAs(createSecretsManagerDifferentKeysDifferentRegion())
        .isSameAs(createSpecifiedSecretsManager());
  }

  @Test
  void isNotSameAsSecretsManagerDifferentRegion() {
    assertThat(createSecretsManagerDifferentKeys())
        .isNotSameAs(createSecretsManagerDifferentKeysDifferentRegion());
  }

  @Test
  void validateCacheUpperBound() {
    awsSecretsManagerProvider = new AwsSecretsManagerProvider(1);
    assertThat(createDefaultSecretsManager()) // cache miss, create entry
        .isSameAs(createDefaultSecretsManager()) // cache hit
        .isNotSameAs(createSecretsManagerDifferentKeys()) // cache miss, evict & create entry
        .isNotSameAs(createDefaultSecretsManager()); // cache miss
  }

  @Test
  void secretsManagerIsNotCachedWhenCacheSizeIsSetToZero() {
    awsSecretsManagerProvider = new AwsSecretsManagerProvider(0);
    assertThat(createSpecifiedSecretsManager()).isNotSameAs(createSpecifiedSecretsManager());
  }

  @Test
  void validateClose() {
    final AwsSecretsManager awsSecretsManager = createSpecifiedSecretsManager();
    final AwsSecretsManager differentAwsSecretsManager = createSecretsManagerDifferentKeys();
    awsSecretsManagerProvider.close();
    assertThat(createSpecifiedSecretsManager()).isNotSameAs(awsSecretsManager);
    assertThat(createSecretsManagerDifferentKeys()).isNotSameAs(differentAwsSecretsManager);
  }
}
