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

public class HSMWalletProvider {

  private final HSMCrypto crypto;
  private final HSMWallet wallet;

  private String library;
  private String slotLabel;
  private String slotPin;
  private boolean initialized = false;

  public HSMWalletProvider(final HSMConfig config) {
    library = config.getLibrary();
    if (library.isEmpty()) {
      library = System.getenv("PKCS11_HSM_LIB");
    }
    slotLabel = config.getSlot();
    if (slotLabel.isEmpty()) {
      slotLabel = System.getenv("PKCS11_HSM_SLOT");
    }
    slotPin = config.getPin();
    if (slotPin.isEmpty()) {
      slotPin = System.getenv("PKCS11_HSM_PIN");
    }
    crypto = new HSMCrypto(library);
    wallet = new HSMWallet(this.crypto, this.slotLabel);
  }

  public void initialize() {
    crypto.initialize();
    wallet.open(slotPin);
    initialized = true;
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
