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
package tech.pegasys.signers.yubihsm.exceptions;

import tech.pegasys.signers.yubihsm.model.Errors;

public class YubiHsmException extends RuntimeException {
  Errors yhError;

  public YubiHsmException() {
    super();
    yhError = null;
  }

  public YubiHsmException(final String message) {
    super(message);
    yhError = null;
  }

  public YubiHsmException(final Throwable cause) {
    super(cause);
    yhError = null;
  }

  public YubiHsmException(final String message, final Throwable cause) {
    super(message, cause);
    yhError = null;
  }

  public YubiHsmException(final Errors error) {
    super();
    yhError = error;
  }

  public YubiHsmException(final Errors error, final String message) {
    super(message);
    yhError = error;
  }

  public YubiHsmException(final Errors error, final Throwable cause) {
    super(cause);
    yhError = error;
  }

  public YubiHsmException(final Errors error, final String message, final Throwable cause) {
    super(message, cause);
    yhError = error;
  }

  public Errors getYubiHsmError() {
    return yhError;
  }

  public void setYubiHsmError(final Errors error) {
    yhError = error;
  }
}
