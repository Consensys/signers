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
package tech.pegasys.signers.hsm;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HSMWalletProvider {

  protected static final Logger LOG = LogManager.getLogger();

  private final HSMCrypto crypto;
  private final HSMWallet wallet;

  private final String pin;
  private boolean initialized = false;

  public HSMWalletProvider(final HSMConfig config) {
    pin = config.getPin();
    crypto = new HSMCrypto(config.getLibrary());
    wallet = new HSMWallet(this.crypto, config.getSlot());
  }

  public void initialize() {
    crypto.initialize();
    wallet.open(pin);
    initialized = true;
    LOG.debug("Successfully initialized hsm slot");
  }

  public void shutdown() {
    wallet.close();
    crypto.shutdown();
    initialized = false;
  }

  public HSMWallet getWallet() {
    if (!initialized) initialize();
    return wallet;
  }

  public HSMCrypto getCrypto() {
    if (!initialized) initialize();
    return crypto;
  }
}
