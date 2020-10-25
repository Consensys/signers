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
package tech.pegasys.signers.yubihsm.pkcs11;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Configuration required by YubiHSM PKCS11 module.
 *
 * @see <a href="https://developers.yubico.com/YubiHSM2/Component_Reference/PKCS_11/">Reference</a>
 */
public class Configuration {
  private final Path pkcs11ModulePath;
  private final String connectorUrl;
  private final Optional<String> additionalConfiguration;
  private final char[] pin;

  public Configuration(
      final Path pkcs11ModulePath,
      final String connectorUrl,
      final Optional<String> additionalConfiguration,
      final short authId,
      final String password) {
    this.pkcs11ModulePath = pkcs11ModulePath;
    this.connectorUrl = connectorUrl;
    // pin is 16 bit hex of auth id (0 padded) and password
    this.pin = String.format("%04X%s", authId, password).toCharArray();
    this.additionalConfiguration = additionalConfiguration;
  }

  public Path getPkcs11ModulePath() {
    return pkcs11ModulePath;
  }

  /** @return char[] PIN for authenticated PKCS11 session */
  public char[] getPin() {
    return pin;
  }

  /**
   * YubiHSM PKCS11 module's configuration string in lieu of configuration file.
   *
   * <p>YubiHSM's PKCS11 module requires yubihsm_pkcs11.conf in current directory. Returning the
   * options as a String is alternate way to initialize the PKCS11 module (via pReserve field of
   * C_Initialize).
   *
   * @return YubiHSM PKCS11 Configuration options in String format
   */
  public String getPkcs11ModuleConfiguration() {
    return String.format("connector=%s %s", connectorUrl, additionalConfiguration.orElse(""))
        .trim();
  }
}
