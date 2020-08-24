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
package tech.pegasys.signers.secp256k1.hsm;

import tech.pegasys.signers.hsm.HSMWallet;
import tech.pegasys.signers.hsm.HSMWalletProvider;
import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;
import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.Signer;
import tech.pegasys.signers.secp256k1.common.SignerInitializationException;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.web3j.crypto.Hash;

public class HSMSigner implements Signer {

  protected static final Logger LOG = LogManager.getLogger();
  private final HSMWalletProvider provider;
  private final HSMWallet wallet;
  private final ECPublicKey publicKey;
  private final String address;

  public HSMSigner(final HSMWalletProvider provider, final String address) {
    this.provider = provider;
    this.address = address;
    this.wallet = provider.getWallet();
    try {
      this.publicKey = EthPublicKeyUtils.createPublicKey(wallet.getPublicKey(address));
    } catch (RuntimeException ex) {
      LOG.trace(ex);
      throw new SignerInitializationException("Failed to initialize hsm signer", ex);
    }
  }

  @Override
  public Signature sign(final byte[] data) {
    final byte[] hash = Hash.sha3(data);
    BigInteger[] s = wallet.sign(hash, address);
    return new Signature(s[0], s[1], s[2]);
  }

  @Override
  public ECPublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public void shutdown() {
    provider.shutdown();
  }
}
