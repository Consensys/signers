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

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;

public class CacheableAwsSecretsManager {

  private static final Cache<String, AwsSecretsManager> awsSecretsManagerCache =
      CacheBuilder.newBuilder().build();

  private static AwsSecretsManager fromCacheOrCallable(
      final String key, Callable<? extends AwsSecretsManager> loader) {
    try {
      return awsSecretsManagerCache.get(key, loader);
    } catch (ExecutionException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  public static AwsSecretsManager createAwsSecretsManager(
      final String accessKeyId, final String secretAccessKey, final String region) {
    final String key = accessKeyId;
    return fromCacheOrCallable(
        key,
        new Callable<AwsSecretsManager>() {
          @Override
          public AwsSecretsManager call() {
            return AwsSecretsManager.createAwsSecretsManager(accessKeyId, secretAccessKey, region);
          }
        });
  }

  public static AwsSecretsManager createAwsSecretsManager() {
    final String key = DefaultCredentialsProvider.create().resolveCredentials().accessKeyId();
    return fromCacheOrCallable(
        key,
        new Callable<AwsSecretsManager>() {
          @Override
          public AwsSecretsManager call() {
            return AwsSecretsManager.createAwsSecretsManager();
          }
        });
  }

  public static void clearCache() {
    awsSecretsManagerCache.invalidateAll();
  }
}
