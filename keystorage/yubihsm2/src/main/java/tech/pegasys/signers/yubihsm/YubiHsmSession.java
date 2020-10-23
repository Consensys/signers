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
package tech.pegasys.signers.yubihsm;

import org.apache.tuweni.bytes.Bytes;

public interface YubiHsmSession extends AutoCloseable {

  /**
   * Fetch key as opaque data from YubiHSM
   *
   * @param opaqueObjId Opaque object id
   * @param opaqueDataFormat Specify format of stored data i.e. HEX or ASCII
   * @return data as Bytes
   * @throws YubiHsmException if unable to fetch data
   */
  Bytes fetchOpaqueData(short opaqueObjId, OpaqueDataFormat opaqueDataFormat)
      throws YubiHsmException;

  /** Logout from session and close all resources. */
  @Override
  void close();
}
