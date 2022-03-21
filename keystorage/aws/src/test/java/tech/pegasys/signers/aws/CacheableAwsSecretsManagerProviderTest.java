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
class CacheableAwsSecretsManagerProviderTest {

  private final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");
  private final String AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
  private final String AWS_SECRET_ACCESS_KEY = System.getenv("AWS_SECRET_ACCESS_KEY");
  private final String AWS_REGION = "us-east-2";

  private CacheableAwsSecretsManagerProvider cacheableAwsSecretsManagerProvider;
  private final long cacheMaximumSize = 5;

  private void verifyEnvironmentVariables() {
    Assumptions.assumeTrue(
        RW_AWS_ACCESS_KEY_ID != null, "Set RW_AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        RW_AWS_SECRET_ACCESS_KEY != null, "Set RW_AWS_SECRET_ACCESS_KEY environment variable");
    Assumptions.assumeTrue(AWS_ACCESS_KEY_ID != null, "Set AWS_ACCESS_KEY_ID environment variable");
    Assumptions.assumeTrue(
        AWS_SECRET_ACCESS_KEY != null, "Set AWS_SECRET_ACCESS_KEY environment variable");
  }

  private void initializeCacheableAwsSecretsManagerProvider() {
    cacheableAwsSecretsManagerProvider = new CacheableAwsSecretsManagerProvider(cacheMaximumSize);
  }

  private AwsSecretsManager createDefaultSecretsManager() {
    return cacheableAwsSecretsManagerProvider.createAwsSecretsManager();
  }

  private AwsSecretsManager createSpecifiedSecretsManager() {
    return cacheableAwsSecretsManagerProvider.createAwsSecretsManager(
        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION);
  }

  private AwsSecretsManager createSpecifiedSecretsManagerRW() {
    return cacheableAwsSecretsManagerProvider.createAwsSecretsManager(
        RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY, AWS_REGION);
  }

  @BeforeAll
  void setup() {
    verifyEnvironmentVariables();
    initializeCacheableAwsSecretsManagerProvider();
  }

  @AfterEach
  void teardown() {
    cacheableAwsSecretsManagerProvider.close();
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
    assertThat(createSpecifiedSecretsManager())
        .isNotSameAs(createSpecifiedSecretsManagerRW())
        .isSameAs(createDefaultSecretsManager());
  }

  @Test
  void validateClearCache() {
    final AwsSecretsManager awsSecretsManager = createSpecifiedSecretsManager();
    final AwsSecretsManager awsSecretsManagerRW = createSpecifiedSecretsManagerRW();
    cacheableAwsSecretsManagerProvider.close();
    assertThat(createSpecifiedSecretsManager()).isNotSameAs(awsSecretsManager);
    assertThat(createSpecifiedSecretsManagerRW()).isNotSameAs(awsSecretsManagerRW);
  }
}
