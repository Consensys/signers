/*
 * Copyright 2020 ConsenSys AG.
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
package tech.pegasys.signers.interlock.handlers;

import tech.pegasys.signers.interlock.InterlockClientException;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

public class ExceptionConverter implements Function<ExecutionException, InterlockClientException> {

  @Override
  public InterlockClientException apply(final ExecutionException e) {
    final Throwable cause = e.getCause();

    if (cause instanceof InterlockClientException) {
      return (InterlockClientException) cause;
    }

    if (cause instanceof TimeoutException) {
      return new InterlockClientException("Interlock response handling timed out.", cause);
    }

    return new InterlockClientException(
        "Interlock response handling failed: " + cause.getMessage(), cause);
  }
}
