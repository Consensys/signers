/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.signers.common;

import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SecretValueMapperUtil {
  private static final Logger LOG = LogManager.getLogger();

  public static <R> Set<R> mapSecretValue(
      BiFunction<String, String, R> mapper, String propKey, String secretValue) {
    final AtomicLong valuesIndex = new AtomicLong(0);
    return secretValue
        .lines()
        .map(
            v -> {
              long index = valuesIndex.getAndIncrement();
              final R obj = mapper.apply(propKey, v);
              if (obj == null) {
                LOG.warn("Secret Value {}:{} was not mapped and discarded.", propKey, index);
              }
              return obj;
            })
        .filter(Objects::nonNull)
        .collect(Collectors.toSet());
  }
}
