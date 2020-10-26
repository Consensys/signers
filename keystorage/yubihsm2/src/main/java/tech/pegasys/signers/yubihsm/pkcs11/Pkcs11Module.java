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

public class Pkcs11Module implements AutoCloseable {
  private static final Logger LOG = LogManager.getLogger();
  private final Module module;

  /**
   * Create Pkcs11 Module.
   *
   * @see <a href="https://developers.yubico.com/YubiHSM2/Component_Reference/PKCS_11/">YubiHSM
   *     Configuration Options</a>
   * @param pkcs11ModulePath The path to pkcs11 module .so or .dylib
   * @param pkcs11InitConfig The pkcs11 module's initialization configuration string in lieu of
   *     configuration file
   */
  public Pkcs11Module(final Path pkcs11ModulePath, final String pkcs11InitConfig) {
    final Module module;
    try {
      module = Module.getInstance(pkcs11ModulePath.toString());
    } catch (final IOException e) {
      throw new YubiHsmException(e.getMessage(), e);
    }

    LOG.debug("Initializing PKCS11 module with conf: {}", pkcs11InitConfig);
    final DefaultInitializeArgs defaultInitializeArgs = new DefaultInitializeArgs();
    defaultInitializeArgs.setReserved(pkcs11InitConfig);

    try {
      module.initialize(defaultInitializeArgs);
    } catch (final TokenException e) {
      LOG.error("Unable to initialize PKCS11 module {}", e.getMessage());
      throw new YubiHsmException("Unable to initialize PKCS11 module " + e.getMessage(), e);
    }

    this.module = module;
  }

  public Module getModule() {
    return module;
  }

  @Override
  public void close() {
    LOG.trace("Finalizing Module");
    if (module != null) {
      try {
        module.finalize(null);
      } catch (final TokenException e) {
        LOG.warn("Unable to finalize module: " + e.getMessage());
      }
    }
  }
}
