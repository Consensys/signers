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
package tech.pegasys.signers.secp256k1.filebased;

import tech.pegasys.signers.secp256k1.PublicKeyImpl;
import tech.pegasys.signers.secp256k1.api.PublicKey;
import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.Signer;

import java.math.BigInteger;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;

public class CredentialSigner implements Signer {

  private final Credentials credentials;
  private final PublicKeyImpl publicKey;

  public CredentialSigner(final Credentials credentials) {
    this.credentials = credentials;
    this.publicKey = new PublicKeyImpl(credentials.getEcKeyPair().getPublicKey());
  }

  @Override
  public Signature sign(final byte[] data) {
    final SignatureData signature = Sign.signMessage(data, credentials.getEcKeyPair());
    return new Signature(
        new BigInteger(signature.getV()),
        new BigInteger(1, signature.getR()),
        new BigInteger(1, signature.getS()));
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }
}
