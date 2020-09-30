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
package tech.pegasys.signers.yubihsm2;

import static tech.pegasys.signers.yubihsm2.ProcessUtil.executeProcess;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

/**
 * Access secrets/opaque data from Yubi HSM 2. https://developers.yubico.com/YubiHSM2/. It is
 * assumed that yubi hsm sdk is installed on the system which contains yubihsm-shell. This class
 * uses yubihsm-shell, which is a thin wrapper over libyubihsm.
 */
public class YubiHsm2 {
  private final List<String> yubiHsmShellPathArgs;
  private final String connectorUrl;
  private final short authKey;
  private final String password;
  private final Optional<String> caCertPath;
  private final Optional<String> proxyUrl;
  private final Optional<Map<String, String>> additionalEnvVars;

  /**
   * Parameters that will be passed to yubihsm-shell process to fetch opaque data
   *
   * @param yubiHsmShellPathArgs Path to yubihsm-shell binary and any additional arguments to pass.
   * @param additionalEnvVars Optional environment variables map that can be passed to yubihsm-shell
   * @param connectorUrl YubiHSM connector URL. http://127.0.01:12345 or yhusb://serial=123456
   * @param authKeyObjId The auth key object id
   * @param password Password
   * @param caCertPath Optional CA Cert if connector is running in https mode
   * @param proxyUrl Optional proxy url if a proxy should be used to access connector url
   */
  public YubiHsm2(
      final List<String> yubiHsmShellPathArgs,
      final Optional<Map<String, String>> additionalEnvVars,
      final String connectorUrl,
      final short authKeyObjId,
      final String password,
      Optional<String> caCertPath,
      Optional<String> proxyUrl) {
    this.yubiHsmShellPathArgs = yubiHsmShellPathArgs;
    this.additionalEnvVars = additionalEnvVars;
    this.connectorUrl = connectorUrl;
    this.authKey = authKeyObjId;
    this.password = password;
    this.caCertPath = caCertPath;
    this.proxyUrl = proxyUrl;
  }

  /**
   * Fetch opaque data from yubi hsm 2
   *
   * @param opaqueObjId The object id of opaque data to retrieve
   * @param outformat Optional output format to be passed to yubishell process.
   * @return The data stored against opaque object id.
   * @throws YubiHsmException In case of errors in invoking process or if command returns error.
   */
  public String fetchOpaqueData(final short opaqueObjId, final Optional<OutputFormat> outformat)
      throws YubiHsmException {
    try {
      return executeProcess(
          getOpaqueDataArgs(opaqueObjId, outformat),
          additionalEnvVars.orElse(Collections.emptyMap()),
          password);
    } catch (final IOException | TimeoutException | InterruptedException e) {
      throw new YubiHsmException("Error in invoking yubihsm-shell process: " + e.getMessage());
    }
  }

  private List<String> getOpaqueDataArgs(
      final short opaqueObjectId, final Optional<OutputFormat> outformat) {
    final ArrayList<String> args = new ArrayList<>(yubiHsmShellPathArgs);
    args.add("--connector=" + connectorUrl);
    args.add("--authkey=" + authKey);
    args.add("--object-id=" + opaqueObjectId);
    args.add("--action=get-opaque");
    args.add("--outformat=" + outformat.orElse(OutputFormat.DEFAULT).getValue());
    caCertPath.ifPresent(s -> args.add("--cacert=" + s));
    proxyUrl.ifPresent(s -> args.add("--proxy=" + s));
    return args;
  }
}
