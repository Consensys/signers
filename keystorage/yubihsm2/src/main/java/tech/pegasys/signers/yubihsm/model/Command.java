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

/** @See <a href="https://developers.yubico.com/YubiHSM2/Commands/">YubiHSM Commands</a> */
public enum Command {
  ECHO((byte) 0x01, "Echo"),
  CREATE_SESSION((byte) 0x03, "Create Session"),
  AUTHENTICATE_SESSION((byte) 0x04, "Authenticate Session"),
  SESSION_MESSAGE((byte) 0x05, "Session Message"),
  DEVICE_INFO((byte) 0x06, "Get Device Info"),
  RESET_DEVICE((byte) 0x08, "Reset Device"),
  CLOSE_SESSION((byte) 0x40, "Close Session"),
  GET_STORAGE_INFO((byte) 0x041, "Get Storage Info"),
  PUT_OPAQUE((byte) 0x42, "Put Opaque"),
  GET_OPAQUE((byte) 0x43, "Get Opaque"),
  PUT_AUTHENTICATION_KEY((byte) 0x44, "Put Authentication Key"),
  PUT_ASYMMETRIC_KEY((byte) 0x45, "Put Asymmetric Key"),
  GENERATE_ASYMMETRIC_KEY((byte) 0x46, "Generate Asymmetric Key"),
  SIGN_PKCS1((byte) 0x47, "Sign Pkcs1"),
  LIST_OBJECTS((byte) 0x48, "List Objects"),
  DECRYPT_PKCS1((byte) 0x49, "Decrypt Pkcs1"),
  EXPORT_WRAPPED((byte) 0x4a, "Export Wrapped"),
  IMPORT_WRAPPED((byte) 0x4b, "Import Wrapped"),
  PUT_WRAP_KEY((byte) 0x4c, "Put Wrap Key"),
  GET_LOG_ENTRIES((byte) 0x4d, "Get Log Entries"),
  GET_OBJECT_INFO((byte) 0x4e, "Get Object Info"),
  SET_OPTION((byte) 0x4f, "Set Option"),
  GET_OPTION((byte) 0x50, "Get Option"),
  GET_PSEUDO_RANDOM((byte) 0x51, "Get Pseudo Random"),
  PUT_HMAC_KEY((byte) 0x52, "Put Hmac Key"),
  SIGN_HMAC((byte) 0x53, "Sign Hmac"),
  GET_PUBLIC_KEY((byte) 0x54, "Get Public Key"),
  SIGN_PSS((byte) 0x55, "Sign Pss"),
  SIGN_ECDSA((byte) 0x56, "Sign Ecdsa"),
  DERIVE_ECDH((byte) 0x57, "Derive Ecdh"),
  DELETE_OBJECT((byte) 0x58, "Delete Object"),
  DECRYPT_OAEP((byte) 0x59, "Decrypt Oaep"),
  GENERATE_HMAC_KEY((byte) 0x5a, "Generate Hmac Key"),
  GENERATE_WRAP_KEY((byte) 0x5b, "Generate Wrap Key"),
  VERIFY_HMAC((byte) 0x5c, "Verify Hmac"),
  SIGN_SSH_CERTIFICATE((byte) 0x5d, "Sign SSH Certificate"),
  PUT_TEMPLATE((byte) 0x5e, "Put Template"),
  GET_TEMPLATE((byte) 0x5f, "Get Template"),
  DECRYPT_OTP((byte) 0x60, "Decrypt Otp"),
  CREATE_OTP_AEAD((byte) 0x61, "Create Otp Aead"),
  RANDOMIZE_OTP_AEAD((byte) 0x62, "Randomize Otp Aead"),
  REWRAP_OTP_AEAD((byte) 0x63, "Re-wrap Otp Aead"),
  SIGN_ATTESTATION_CERTIFICATE((byte) 0x64, "Sign Attestation Certificate"),
  PUT_OTP_AEAD_KEY((byte) 0x65, "Put Otp Aead Key"),
  GENERATE_OTP_AEAD_KEY((byte) 0x66, "Generate Otp Aead Key"),
  SET_LOG_INDEX((byte) 0x67, "Set Log Index"),
  WRAP_DATA((byte) 0x68, "Wrap Data"),
  UNWRAP_DATA((byte) 0x69, "Unwrap Data"),
  SIGN_EDDSA((byte) 0x6a, "Sign Eddsa"),
  BLINK_DEVICE((byte) 0x6b, "Blink Device"),
  CHANGE_AUTHENTICATION_KEY((byte) 0x6c, "Change Authentication Key"),
  ERROR((byte) 0x7f, "Error");

  private final byte commandCode;
  private final String description;

  private static final Map<Byte, Command> BY_ID_MAP;

  static {
    BY_ID_MAP =
        Arrays.stream(Command.values())
            .collect(Collectors.toMap(Command::getCommandCode, Function.identity()));
  }

  public static Command byCode(byte code) {
    return BY_ID_MAP.get(code);
  }

  /**
   * Returns whether a command code represents an error
   *
   * @param command The command code to check
   * @return True if the command code represents an error response code. False otherwise
   */
  public static boolean isError(final byte command) {
    return command == ERROR.getCommandCode();
  }

  Command(final byte code, final String description) {
    this.commandCode = code;
    this.description = description;
  }

  public byte getCommandCode() {
    return commandCode;
  }

  public String getDescription() {
    return description;
  }

  /** Return the expected response code in case of a successful execution of this command */
  public byte getCommandResponse() {
    if (commandCode == ERROR.commandCode) {
      return commandCode;
    }
    return (byte) (commandCode | 0x80);
  }

  @Override
  public String toString() {
    return String.format("0x%02x:%s", commandCode, description);
  }
}
