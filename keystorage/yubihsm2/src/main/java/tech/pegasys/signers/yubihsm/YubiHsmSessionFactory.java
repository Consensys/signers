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

import tech.pegasys.signers.yubihsm.pkcs11.Configuration;
import tech.pegasys.signers.yubihsm.pkcs11.YubiHsmSessionPkcs11;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class YubiHsmSessionFactory {
  private static final Logger LOG = LogManager.getLogger();

  public static YubiHsmSession createYubiHsmSession(final Configuration configuration) {
    final YubiHsmSessionPkcs11 yubiHsmSessionPkcs11 = new YubiHsmSessionPkcs11(configuration);
    try {
      yubiHsmSessionPkcs11.init();
      return yubiHsmSessionPkcs11;
    } catch (final YubiHsmException e) {
      LOG.warn("Error happened during initialization, cleaning resources...");
      yubiHsmSessionPkcs11.close();
      throw e;
    }
  }
}
