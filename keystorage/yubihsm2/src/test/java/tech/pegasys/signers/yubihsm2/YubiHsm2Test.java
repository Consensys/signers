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

import java.util.Optional;

import org.apache.commons.lang3.time.StopWatch;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

// manual dev test - Make sure yubihsm2 is plugged in and connector daemon is running
// uncomment system properties in setup method and modify accordingly
class YubiHsm2Test {
  private YubiHsm2 yubiHsm2;
  private static final String BLS_KEY =
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
  private static final short OPAQUE_DATA_OBJECT_ID = (short) 4;

  @BeforeEach
  void setup() {
    System.setProperty("yubihsmConnector", "http://localhost:12345");
    System.setProperty("yubiHsmAuthId", "2");
    System.setProperty("yubiHsmPassword", "password");
    System.setProperty("yubiHsmPath", "/Users/usmansaleem/dev/yubihsm2-sdk/bin");

    final String yubihsmConnector = System.getProperty("yubihsmConnector");
    final String yubiHsmAuthId = System.getProperty("yubiHsmAuthId");
    final String yubiHsmPassword = System.getProperty("yubiHsmPassword");
    final String yubiShellPath = System.getProperty("yubiHsmPath");
    final Optional<String> caCert = Optional.empty();
    final Optional<String> proxy = Optional.empty();

    Assumptions.assumeThat(yubihsmConnector).isNotEmpty();
    Assumptions.assumeThat(yubiHsmAuthId).isNotEmpty();
    Assumptions.assumeThat(yubiHsmPassword).isNotEmpty();
    Assumptions.assumeThat(yubiShellPath).isNotEmpty();

    yubiHsm2 =
        new YubiHsm2(
            yubihsmConnector,
            Short.parseShort(yubiHsmAuthId),
            yubiHsmPassword,
            Optional.of(yubiShellPath),
            caCert,
            proxy);
  }

  @Test
  void validDataIsReturnedFromYubiHSM() {

    final StopWatch stopWatch = new StopWatch();
    for (int i = 0; i < 10; i++) {
      stopWatch.start();
      final String blsKey = yubiHsm2.fetchKey(OPAQUE_DATA_OBJECT_ID);
      stopWatch.stop();
      System.out.println("Time Taken:" + stopWatch.toString());
      stopWatch.reset();

      Assertions.assertThat(blsKey).isEqualToIgnoringCase(BLS_KEY);
    }
  }
}
