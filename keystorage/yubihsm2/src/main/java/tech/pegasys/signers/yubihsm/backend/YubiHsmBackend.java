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
package tech.pegasys.signers.yubihsm.backend;

import tech.pegasys.signers.yubihsm.exceptions.YubiHsmConnectionException;

import org.apache.tuweni.bytes.Bytes;

public interface YubiHsmBackend {
  /**
   * Sends a raw message to the device and returns a response
   *
   * @param message The data to send to the device (including the command)
   * @return The device response
   * @throws YubiHsmConnectionException If connection with the device fails
   */
  Bytes send(Bytes message) throws YubiHsmConnectionException;
}
