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

import java.io.Closeable;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;

public class CacheableAwsSecretsManagerProvider implements Closeable {

  private static final Logger LOGGER = LogManager.getLogger();
  private final Cache<AwsKeyIdentifier, AwsSecretsManager> awsSecretsManagerCache;

  public CacheableAwsSecretsManagerProvider(final long maximumSize) {
    awsSecretsManagerCache = CacheBuilder.newBuilder().maximumSize(maximumSize).build();
  }

  private AwsSecretsManager fromCacheOrCallable(
      final AwsKeyIdentifier awsKeyIdentifier, Callable<? extends AwsSecretsManager> loader) {
    try {
      return awsSecretsManagerCache.get(awsKeyIdentifier, loader);
    } catch (ExecutionException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  public AwsSecretsManager createAwsSecretsManager(
      final String accessKeyId, final String secretAccessKey, final String region) {
    return fromCacheOrCallable(
        new AwsKeyIdentifier(accessKeyId, Region.of(region)),
        () -> AwsSecretsManager.createAwsSecretsManager(accessKeyId, secretAccessKey, region));
  }

  public AwsSecretsManager createAwsSecretsManager() {
    final String accessKeyId =
        DefaultCredentialsProvider.create().resolveCredentials().accessKeyId();
    final Region region = DefaultAwsRegionProviderChain.builder().build().getRegion();
    return fromCacheOrCallable(
        new AwsKeyIdentifier(accessKeyId, region),
        () -> AwsSecretsManager.createAwsSecretsManager());
  }

  @Override
  public void close() {
    awsSecretsManagerCache
        .asMap()
        .values()
        .forEach(
            awsSecretsManager -> {
              try {
                awsSecretsManager.close();
              } catch (RuntimeException e) {
                LOGGER.warn("Unable to close AWS Secrets Manager", e);
              }
            });
    awsSecretsManagerCache.invalidateAll();
  }
}
