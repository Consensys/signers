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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CacheableAwsSecretsManagerTest {

  private final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");
  private final String AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
  private final String AWS_SECRET_ACCESS_KEY = System.getenv("AWS_SECRET_ACCESS_KEY");
  private final String AWS_REGION = "us-east-2";

  private void verifyEnvironmentVariables() {
    Assumptions.assumeTrue(
        RW_AWS_ACCESS_KEY_ID != null, "Set RW_AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        RW_AWS_SECRET_ACCESS_KEY != null, "Set RW_AWS_SECRET_ACCESS_KEY environment variable");
    Assumptions.assumeTrue(AWS_ACCESS_KEY_ID != null, "Set AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        AWS_SECRET_ACCESS_KEY != null, "Set AWS_SECRET_ACCESS_KEY environment variable");
  }

  private AwsSecretsManager createDefaultSecretsManager() {
    return CacheableAwsSecretsManager.createAwsSecretsManager();
  }

  private AwsSecretsManager createSpecifiedSecretsManager() {
    return CacheableAwsSecretsManager.createAwsSecretsManager(
        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION);
  }

  private AwsSecretsManager createSpecifiedSecretsManagerRW() {
    return CacheableAwsSecretsManager.createAwsSecretsManager(
        RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY, AWS_REGION);
  }

  @BeforeAll
  void setup() {
    verifyEnvironmentVariables();
  }

  @AfterEach
  void teardown() {
    CacheableAwsSecretsManager.clearCache();
  }

  @Test
  void returnsCachedSpecifiedSecretsManager() {
    assertThat(createSpecifiedSecretsManager()).isEqualTo(createSpecifiedSecretsManager());
  }

  @Test
  void returnsCachedDefaultSecretsManager() {
    assertThat(createDefaultSecretsManager()).isEqualTo(createDefaultSecretsManager());
  }

  @Test
  void returnsCachedDefaultSecretsManagerAfterCachingSpecified() {
    assertThat(createSpecifiedSecretsManager()).isEqualTo(createDefaultSecretsManager());
  }

  @Test
  void returnsCorrectCachedSecretsManager() {
    assertThat(createSpecifiedSecretsManager())
        .isNotEqualTo(createSpecifiedSecretsManagerRW())
        .isEqualTo(createDefaultSecretsManager());
  }

  @Test
  void validateClearCache() {
    final AwsSecretsManager awsSecretsManager = createSpecifiedSecretsManager();
    final AwsSecretsManager awsSecretsManagerRW = createSpecifiedSecretsManagerRW();
    CacheableAwsSecretsManager.clearCache();
    assertThat(createSpecifiedSecretsManager()).isNotEqualTo(awsSecretsManager);
    assertThat(createSpecifiedSecretsManagerRW()).isNotEqualTo(awsSecretsManagerRW);
  }
}
