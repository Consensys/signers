/*
 * Copyright 2019 ConsenSys AG.
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
package tech.pegasys.signers.secp256k1.cavium;

import static com.google.common.base.Preconditions.checkArgument;

import tech.pegasys.signers.cavium.HSMKeyStoreProvider;

import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;

public class CaviumKeyStoreSigner extends HSMKeyStoreSigner {

  public CaviumKeyStoreSigner(final HSMKeyStoreProvider provider, String address) {
    super(provider, address);
  }

  @Override
  protected PrivateKey getPrivateKeyHandle() {
    checkArgument(provider.getKeyStore() != null, "Cavium key store provider is not initialized");
    Key privateKey = provider.getKey(address);
    if (privateKey == null) {
      try {
        privateKey = (PrivateKey) provider.getKeyStore().getKey(address, "".toCharArray());
      } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException ex) {
        LOG.trace(ex);
        throw new RuntimeException("Failed to query key store");
      }
      if (privateKey == null) {
        throw new RuntimeException("Failed to get private key from key store");
      }
      provider.addKey(address, privateKey);
    }
    return (PrivateKey) privateKey;
  }

  @Override
  protected PublicKey getPublicKeyHandle() {
    checkArgument(provider.getKeyStore() != null, "Cavium key store provider is not initialized");
    String alias = address.replaceFirst("0x", "1x");
    Key publicKey = provider.getKey(alias);
    if (publicKey == null) {
      try {
        publicKey = (PublicKey) provider.getKeyStore().getKey(alias, "".toCharArray());
      } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException ex) {
        LOG.trace(ex);
        throw new RuntimeException("Failed to query key store");
      }
      if (publicKey == null) {
        throw new RuntimeException("Failed to get public key from key store");
      }
      provider.addKey(alias, publicKey);
    }
    return (PublicKey) publicKey;
  }
}
