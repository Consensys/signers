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

import java.util.HashMap;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;

public class CacheableAwsSecretsManager {

  private static HashMap<String, AwsSecretsManager> cache = new HashMap<>();

  public static AwsSecretsManager createAwsSecretsManager(
      final String accessKeyId, final String secretAccessKey, final String region) {
    String key = accessKeyId;
    if (cache.containsKey(key)) {
      return cache.get(key);
    } else {
      AwsSecretsManager awsSecretsManager =
          AwsSecretsManager.createAwsSecretsManager(accessKeyId, secretAccessKey, region);
      cache.put(key, awsSecretsManager);
      return awsSecretsManager;
    }
  }

  public static AwsSecretsManager createAwsSecretsManager(final String region) {
    String key = DefaultCredentialsProvider.create().resolveCredentials().accessKeyId();
    if (cache.containsKey(key)) {
      return cache.get(key);
    } else {
      AwsSecretsManager awsSecretsManager = AwsSecretsManager.createAwsSecretsManager(region);
      cache.put(key, awsSecretsManager);
      return awsSecretsManager;
    }
  }

  public static void close() {
    cache.clear();
  }
}
