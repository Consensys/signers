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

// manual dev test -
// Make sure yubihsm2 is plugged in
// for http/https url scheme, make sure connector daemon is running
// for yhusb://serial=123456 url scheme, no connector daemon is required.
// uncomment system properties in setup method and modify accordingly
class YubiHsm2Test {
  private YubiHsm2 yubiHsm2;

  @BeforeEach
  void setup() {
    // System.setProperty("yubihsmConnector", "yhusb://serial=123456");
    // System.setProperty("yubiHsmAuthId", "2");
    // System.setProperty("yubiHsmPassword", "password");
    // System.setProperty("yubiHsmPath", "/Users/dev/yubihsm2-sdk/bin");

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
    final String[] expectedKeys =
        new String[] {
          "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
          "73d51abbd89cb8196f0efb6892f94d68fccc2c35f0b84609e5f12c55dd85aba8",
          "39722cbbf8b91a4b9045c5e6175f1001eac32f7fcd5eccda5c6e62fc4e638508",
          "4c9326bb9805fa8f85882c12eae724cef0c62e118427f5948aefa5c428c43c93",
          "384a62688ee1d9a01c9d58e303f2b3c9bc1885e8131565386f75f7ae6ca8d147",
          "4b6b5c682f2db7e510e0c00ed67ac896c21b847acadd8df29cf63a77470989d2",
          "13086d684f4b1a1632178a8c5be08a2fb01287c4a78313c41373701eb8e66232",
          "25296867ee96fa5b275af1b72f699efcb61586565d4c3c7e41f4b3e692471abd",
          "10e1a313e573d96abe701d8848742cf88166dd2ded38ac22267a05d1d62baf71",
          "0bdeebbad8f9b240192635c42f40f2d02ee524c5a3fe8cda53fb4897b08c66fe",
          "5e8d5667ce78982a07242739ab03dc63c91e830c80a5b6adca777e3f216a405d"
        };

    final StopWatch stopWatch = new StopWatch();
    for (int i = 0; i < expectedKeys.length; i++) {
      stopWatch.start();
      final String blsKey = yubiHsm2.fetchKey((short) (i + 4));
      stopWatch.stop();
      System.out.println("Fetched: " + blsKey + ", Time Taken:" + stopWatch.toString());
      stopWatch.reset();

      Assertions.assertThat(blsKey).isEqualToIgnoringCase(expectedKeys[i]);
    }
  }
}
