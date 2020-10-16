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
package tech.pegasys.signers.yubihsm.model;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/** See <a href="https://developers.yubico.com/YubiHSM2/Concepts/Errors.html">YubiHSM Errors</a> */
public enum Errors {
  OK((byte) 0x00, "Success"),
  INVALID_COMMAND((byte) 0x01, "Unknown command"),
  INVALID_DATA((byte) 0x02, "Malformed data for the command"),
  INVALID_SESSION((byte) 0x03, "The session has expired or does not exist"),
  AUTHENTICATION_FAILED((byte) 0x04, "Wrong Authentication Key"),
  SESSIONS_FULL((byte) 0x05, "No more available sessions"),
  SESSION_FAILED((byte) 0x06, "Session setup failed"),
  STORAGE_FAILED((byte) 0x07, "Storage full"),
  WRONG_LENGTH((byte) 0x08, "Wrong data length for the command"),
  INSUFFICIENT_PERMISSIONS((byte) 0x09, "Insufficient permissions for the command"),
  LOG_FULL((byte) 0x0a, "The log is full and force audit is enabled"),
  OBJECT_NOT_FOUND((byte) 0x0b, "No object found matching given ID and Type"),
  INVALID_ID((byte) 0x0c, "Invalid ID"),
  SSH_CA_CONSTRAINT_VIOLATION((byte) 0x0e, "Constraints in SSH Template not met"),
  INVALID_OTP((byte) 0x0f, "OTP decryption failed"),
  DEMO_MODE((byte) 0x10, "Demo device must be power-cycled"),
  OBJECT_EXISTS((byte) 0x11, "Unable to overwrite object");

  private final byte errorCode;
  private final String description;

  private static final Map<Byte, Errors> BY_ID_MAP;

  static {
    BY_ID_MAP =
        Arrays.stream(Errors.values())
            .collect(Collectors.toMap(Errors::getErrorCode, Function.identity()));
  }

  public static Errors byErrorCode(byte errorCode) {
    return BY_ID_MAP.get(errorCode);
  }

  Errors(final byte code, final String description) {
    this.errorCode = code;
    this.description = description;
  }

  public byte getErrorCode() {
    return errorCode;
  }

  public String getDescription() {
    return description;
  }

  @Override
  public String toString() {
    return String.format("0x%02x:%s", errorCode, description);
  }
}
