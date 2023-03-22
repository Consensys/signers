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

import java.util.Collection;
import java.util.Collections;

/** Contains Collection of Secret value result and count of errors. */
public class SecretValueResult<R> {
  private final Collection<R> values;
  private int errorCount;

  SecretValueResult(final Collection<R> values, final int errorCount) {
    this.values = values;
    this.errorCount = errorCount;
  }

  public static <R> SecretValueResult<R> errorResult() {
    return new SecretValueResult<>(Collections.emptyList(), 1);
  }

  public static <R> SecretValueResult<R> newInstance(
      final Collection<R> values, final int errorCount) {
    return new SecretValueResult<>(values, errorCount);
  }

  public void merge(final SecretValueResult<R> other) {
    this.values.addAll(other.values);
    this.errorCount += other.errorCount;
  }

  public Collection<R> getValues() {
    return values;
  }

  public int getErrorCount() {
    return errorCount;
  }
}
