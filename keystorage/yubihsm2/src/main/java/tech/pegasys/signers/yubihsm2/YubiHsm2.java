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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

import org.apache.commons.io.IOUtils;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

/**
 * Access secrets (BLS Keys) from Yubi HSM 2. https://developers.yubico.com/YubiHSM2/. It is assumed
 * that yubi hsm sdk is installed on the system which contains yubihsm-shell. This class uses
 * yubihsm-shell, which is a thin wrapper over libyubihsm, to talk to yubihsm.
 */
public class YubiHsm2 {
  private static final String YUBI_SHELL = "yubihsm-shell";
  private final Optional<String> yubiHsmShellPath;
  private final String connectorUrl;
  private final short authKey;
  private final String password;
  private final Optional<String> caCert;
  private final Optional<String> proxy;

  /**
   * Construct YubiHSM with parameters that will be passed to yubihsm-shell process
   *
   * @param connectorUrl YubiHSM connector URL. http://127.0.01:12345 or yhusb://serial=123456
   * @param authKeyObjId The auth key object id
   * @param password Password
   * @param yubiHsmShellPath Optional path which contains yubihsm-shell binary. If empty current
   *     directory will be used.
   * @param caCert Optional CA Cert if connector is running in https mode
   * @param proxy Optional proxy url if a proxy should be used to access connector url
   */
  public YubiHsm2(
      final String connectorUrl,
      final short authKeyObjId,
      final String password,
      final Optional<String> yubiHsmShellPath,
      Optional<String> caCert,
      Optional<String> proxy) {
    this.yubiHsmShellPath = yubiHsmShellPath;
    this.connectorUrl = connectorUrl;
    this.authKey = authKeyObjId;
    this.password = password;
    this.caCert = caCert;
    this.proxy = proxy;
  }

  public String fetchKey(final short opaqueObjId) throws YubiHsmException {
    try {
      return getOutputFromYubiHsmShell(buildCliArgs(opaqueObjId));
    } catch (final IOException | TimeoutException | InterruptedException e) {
      throw new YubiHsmException("Error in invoking yubihsm-shell process." + e.getMessage());
    }
  }

  private String getOutputFromYubiHsmShell(final String[] args)
      throws IOException, TimeoutException, InterruptedException {
    final ProcessResult processResult =
        new ProcessExecutor()
            .command(args)
            .readOutput(true)
            .redirectInput(IOUtils.toInputStream(password + "\n", StandardCharsets.UTF_8.name()))
            .destroyOnExit()
            .execute();

    final List<String> linesAsUTF8 = processResult.getOutput().getLinesAsUTF8();
    if (processResult.getExitValue() == 0) {
      return linesAsUTF8.get(linesAsUTF8.size() - 1);
    }

    throw new YubiHsmException(
        "Unable to fetch data from YubiHSM: " + linesAsUTF8.get(linesAsUTF8.size() - 1));
  }

  private String[] buildCliArgs(final short opaqueObjectId) {
    final ArrayList<String> args = new ArrayList<>();

    args.add(Path.of(yubiHsmShellPath.orElse("."), YUBI_SHELL).toString());
    args.add("--connector=" + connectorUrl);
    args.add("--authkey=" + authKey);
    args.add("--object-id=" + opaqueObjectId);
    args.add("--action=get-opaque");
    args.add("--outformat=hex");
    caCert.ifPresent(s -> args.add("--cacert=" + s));
    proxy.ifPresent(s -> args.add("--proxy=" + s));
    return args.toArray(String[]::new);
  }
}
