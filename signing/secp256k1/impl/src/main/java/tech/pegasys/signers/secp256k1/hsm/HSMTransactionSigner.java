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

import tech.pegasys.signers.hsm.HSMCrypto;
import tech.pegasys.signers.hsm.HSMWallet;
import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.TransactionSigner;

import java.math.BigInteger;

import org.web3j.crypto.Hash;

public class HSMTransactionSigner implements TransactionSigner {

  private final HSMCrypto crypto;
  private final HSMWallet wallet;
  private final String address;

  public HSMTransactionSigner(
      final HSMCrypto crypto, final HSMWallet wallet, final String address) {
    this.crypto = crypto;
    this.wallet = wallet;
    this.address = address;
  }

  @Override
  public Signature sign(final byte[] data) {
    final byte[] hash = Hash.sha3(data);
    BigInteger[] s = wallet.sign(hash, address);
    return new Signature(s[0], s[1], s[2]);
  }

  @Override
  public String getAddress() {
    return address;
  }

  @Override
  public void shutdown() {
    wallet.close();
    crypto.shutdown();
  }
}
