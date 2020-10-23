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

public class Configuration {
  private final Path pkcs11ModulePath;
  private final String connectorUrl;
  private final Optional<String> caCertPath;
  private final Optional<String> proxyUrl;
  private final short authId;
  private final String password;

  public Configuration(
      final Path pkcs11ModulePath,
      final String connectorUrl,
      final Optional<String> caCertPath,
      final Optional<String> proxyUrl,
      final short authId,
      final String password) {
    this.pkcs11ModulePath = pkcs11ModulePath;
    this.connectorUrl = connectorUrl;
    this.authId = authId;
    this.password = password;
    this.caCertPath = caCertPath;
    this.proxyUrl = proxyUrl;
  }

  public Path getPkcs11ModulePath() {
    return pkcs11ModulePath;
  }

  public char[] getPin() {
    return String.format("%04X%s", authId, password).toCharArray();
  }

  public String getPkcs11Conf() {
    return "connector="
        + connectorUrl
        + caCertPath.map(s -> " cacert=" + s).orElse("")
        + proxyUrl.map(s -> " proxy=" + s).orElse("");
  }
}
