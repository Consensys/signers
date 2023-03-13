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

/**
 * Contains Collection of Secret value result and collection of exceptions which may have raised.
 */
public class SecretValueResult<R> {
  private final Collection<R> values;
  private final int errorCount;

  public SecretValueResult(final Collection<R> values, final int errorCount) {
    this.values = values;
    this.errorCount = errorCount;
  }

  public Collection<R> getValues() {
    return values;
  }

  public int getErrorCount() {
    return errorCount;
  }
}
