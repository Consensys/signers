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
package tech.pegasys.signers.secp256k1;

import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.Signer;
import tech.pegasys.signers.secp256k1.api.TransactionSigner;

import org.web3j.crypto.Keys;

public class DefaultTransactionSigner implements TransactionSigner {

  private final Signer signer;

  public DefaultTransactionSigner(final Signer signer) {
    this.signer = signer;
  }

  @Override
  public Signature sign(final byte[] data) {
    return signer.sign(data);
  }

  @Override
  public String getPublicKey() {
    return signer.getPublicKey();
  }

  /**
   * Deprecated in favour of using getPublicKey, caller is responsible for deriving information
   * (such as Ethereum Address) from the key as necessary.
   *
   * @return The Ethereum address of this signer.
   */
  @Deprecated
  @Override
  public String getAddress() {
    return "0x" + Keys.getAddress(signer.getPublicKey());
  }
}
