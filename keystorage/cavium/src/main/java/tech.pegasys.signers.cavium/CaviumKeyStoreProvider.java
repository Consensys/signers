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
package tech.pegasys.signers.cavium;

import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.List;

import com.google.common.base.Splitter;

public class CaviumKeyStoreProvider extends HSMKeyStoreProvider {

  public CaviumKeyStoreProvider(final CaviumConfig config) {
    library = config.getLibrary();
    slotPin = config.getPin();
    if (slotPin != null && slotPin.contains(":")) {
      List<String> s = Splitter.on(':').splitToList(slotPin);
      System.setProperty("HSM_PARTITION", "PARTITION_1");
      System.setProperty("HSM_USER", s.get(0));
      System.setProperty("HSM_PASSWORD", s.get(1));
    }
  }

  @Override
  public void initialize() throws HSMKeyStoreInitializationException {
    try {
      provider = new com.cavium.provider.CaviumProvider();
      Security.addProvider(provider);
      keyStore = KeyStore.getInstance("CloudHSM");
    } catch (Exception ex) {
      LOG.debug(ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE, ex);
    }
    try {
      keyStore.load(null, slotPin.toCharArray());
    } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
      LOG.debug(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE, ex);
    }
    LOG.debug("Successfully initialized cavium key store");
  }
}
