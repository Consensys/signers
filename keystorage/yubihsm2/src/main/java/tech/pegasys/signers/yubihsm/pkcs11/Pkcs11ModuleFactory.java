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

import tech.pegasys.signers.yubihsm.YubiHsmException;

import java.io.IOException;
import java.nio.file.Path;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.TokenException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class Pkcs11ModuleFactory {
  private static final Logger LOG = LogManager.getLogger();

  public static Module initPkcs11Module(final Path pkcs11ModulePath, final String pkcs11Config) {
    final Module module;
    try {
      module = Module.getInstance(pkcs11ModulePath.toString());
    } catch (final IOException e) {
      throw new YubiHsmException(e.getMessage(), e);
    }

    LOG.debug("Initializing PKCS11 module with conf: {}", pkcs11Config);
    final DefaultInitializeArgs defaultInitializeArgs = new DefaultInitializeArgs();
    defaultInitializeArgs.setReserved(pkcs11Config);

    try {
      module.initialize(defaultInitializeArgs);
    } catch (final TokenException e) {
      LOG.error("Unable to initialize PKCS11 module {}", e.getMessage());
      throw new YubiHsmException("Unable to initialize PKCS11 module " + e.getMessage(), e);
    }

    return module;
  }
}
