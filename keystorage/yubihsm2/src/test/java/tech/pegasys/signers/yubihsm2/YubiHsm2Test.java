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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URL;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import com.google.common.io.Resources;
import org.junit.jupiter.api.Test;

public class YubiHsm2Test {
  private static final short DEFAULT_AUTH_KEY = (short) 1;
  private static final String DEFAULT_PASSWORD = "password";

  @Test
  public void validKeysAreFetchedSuccessfully() {
    final YubiHsm2 yubiHsm2 =
        new YubiHsm2(
            yubiHsmSimulatorBinArgs(),
            Optional.empty(),
            "http://localhost:12345",
            DEFAULT_AUTH_KEY,
            DEFAULT_PASSWORD,
            Optional.empty(),
            Optional.empty());

    final String key = yubiHsm2.fetchOpaqueData((short) 1, Optional.of(OutputFormat.ASCII));
    assertThat(key).isEqualTo("3ee2224386c82ffea477e2adf28a2929f5c349165a4196158c7f3a2ecca40f35");
  }

  private static List<String> yubiHsmSimulatorBinArgs() {
    final URL simulatorSource = Resources.getResource("YubiShellSimulator.java");
    return List.of(
        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "-cp",
        System.getProperty("java.class.path"),
        simulatorSource.getPath());
  }
}
