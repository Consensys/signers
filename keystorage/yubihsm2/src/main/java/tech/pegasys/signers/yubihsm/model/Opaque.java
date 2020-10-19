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

import static java.nio.charset.StandardCharsets.US_ASCII;

import tech.pegasys.signers.yubihsm.YubiHsmSession;

import org.apache.tuweni.bytes.Bytes;

/** @See <a href="https://developers.yubico.com/YubiHSM2/Commands/Get_Opaque.html">Opaque</a> */
public class Opaque {
  private final short opaqueId;

  public enum OutputFormat {
    ASCII,
    HEX
  }

  public Opaque(final short opaqueId) {
    this.opaqueId = opaqueId;
  }

  /**
   * Fetch Opaque Data
   * @param yubiHsmSession YubiHsmSession to use
   * @param outputFormat Use ASCII or HEX output format of opaque data
   * @return Opaque data in Bytes
   */
  public Bytes getOpaque(final YubiHsmSession yubiHsmSession, final OutputFormat outputFormat) {
    final Bytes response =
        yubiHsmSession.sendSecureCmd(Command.GET_OPAQUE, Bytes.ofUnsignedShort(opaqueId));
    if (outputFormat == OutputFormat.ASCII) {
      return Bytes.fromHexString(new String(response.toArrayUnsafe(), US_ASCII));
    }
    return response;
  }
}
