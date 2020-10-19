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
package tech.pegasys.signers.yubihsm.util;

import tech.pegasys.signers.yubihsm.backend.YubiHsmBackend;
import tech.pegasys.signers.yubihsm.exceptions.YubiHsmException;
import tech.pegasys.signers.yubihsm.model.Command;
import tech.pegasys.signers.yubihsm.model.Errors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class CommandUtils {
  private static final Logger LOG = LogManager.getLogger();

  public static final int COMMAND_ID_SIZE = 1;
  public static final int COMMAND_INPUT_LENGTH_SIZE = 2;

  private static final int RESPONSE_CODE_INDEX = 0;
  private static final int RESPONSE_LENGTH_INDEX = 1;
  private static final int RESPONSE_DATA_INDEX = 3;
  private static final int ERROR_RESPONSE_LENGTH = 4;
  private static final Bytes ERROR_RESPONSE_START =
      Bytes.of(Command.ERROR.getCommandCode(), (byte) 0, (byte) 1);

  public static Bytes sendCmd(final YubiHsmBackend backend, final Command cmd, final Bytes data) {
    final Bytes msg = getFullCommand(cmd, data);
    final Bytes response = backend.send(msg);
    return parseCmdResponse(cmd, response);
  }

  /**
   * @param cmd
   * @param responseLength
   * @param expectedLength
   * @throws YubiHsmException If the the response length does not match the expected length
   */
  public static void verifyResponseLength(
      final Command cmd, final int responseLength, final int expectedLength) {
    if (responseLength != expectedLength) {
      throw new YubiHsmException(
          "Response to "
              + cmd.getDescription()
              + " command expected to contains "
              + expectedLength
              + " bytes, but was "
              + responseLength
              + " bytes instead");
    }
  }

  public static Bytes getFullCommand(final Command cmd, final Bytes data) {
    final Bytes commandCode = Bytes.of(cmd.getCommandCode());
    final Bytes dataLength = Bytes.ofUnsignedShort(data.size());
    final Bytes meta = Bytes.wrap(commandCode, dataLength);
    if (data.size() > 0) {
      return Bytes.wrap(meta, data);
    }
    return meta;
  }

  /**
   * Strip leading response code and length of response and return response only
   *
   * @param response
   * @return
   */
  public static Bytes parseCmdResponse(final Command cmd, final Bytes response) {
    if (response.isEmpty()) {
      throw new IllegalArgumentException("Empty response from device");
    }

    final byte responseCode = response.get(RESPONSE_CODE_INDEX);

    validateCmdResponseCode(cmd, response, responseCode);
    validateCmdResponseLength(response);
    return response.slice(RESPONSE_DATA_INDEX).copy();
  }

  private static void validateCmdResponseLength(final Bytes response) {
    if (response.size() < 3) {
      throw new YubiHsmException("Response is too short. ");
    }

    final int expectedResponseLength =
        (response.get(RESPONSE_LENGTH_INDEX + 1) & 0xFF)
            | ((response.get(RESPONSE_LENGTH_INDEX) & 0XFF) << 8);
    final int actualResponseLength = response.size() - COMMAND_ID_SIZE - COMMAND_INPUT_LENGTH_SIZE;
    if (expectedResponseLength != actualResponseLength) {
      String error =
          "Unexpected response length. Expected: "
              + expectedResponseLength
              + ", Actual: "
              + actualResponseLength;
      LOG.warn(error);
      throw new YubiHsmException(error);
    }
  }

  private static void validateCmdResponseCode(
      final Command cmd, final Bytes response, final byte responseCode) {
    if (responseCode == cmd.getCommandResponse()) {
      // we are good
      LOG.debug("Response received from device for command {}", cmd.getDescription());
    } else {
      final Errors error = getResponseError(response);
      if (error != null) {
        LOG.warn("Device return error code: {}", error);
        throw new YubiHsmException(error);
      } else {
        final String errMessage =
            "Unrecognized response from server: " + response.toUnprefixedHexString();
        LOG.warn(errMessage);
        throw new YubiHsmException(errMessage);
      }
    }
  }

  private static Errors getResponseError(final Bytes deviceResponse) {
    if (isErrorResponse(deviceResponse)) {
      return Errors.byErrorCode(deviceResponse.get(RESPONSE_DATA_INDEX));
    }
    return null;
  }

  /**
   * Returns whether data is actually an error message as defined by the YubiHSM.
   *
   * @param deviceResponse
   * @return True if the first 3 bytes of the device response are: 0x7f 0x00 0x01 (The fourth byte
   *     is the error code). False otherwise
   */
  private static boolean isErrorResponse(final Bytes deviceResponse) {
    if (deviceResponse == null || deviceResponse.size() != ERROR_RESPONSE_LENGTH) {
      return false;
    }

    return ERROR_RESPONSE_START.equals(deviceResponse.slice(0, 3));
  }
}
