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

import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;
import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.Signer;

import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.ECPublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;

public class CredentialSigner implements Signer {

  public static final String CURVE_NAME = "secp256k1";
  public static final ECDomainParameters CURVE;

  private final Credentials credentials;
  private final ECPublicKey publicKey;
  private final boolean needToHash;

  static {
    Security.addProvider(new BouncyCastleProvider());

    final X9ECParameters params = SECNamedCurves.getByName(CURVE_NAME);
    CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
  }

  public CredentialSigner(final Credentials credentials, final boolean needToHash) {
    this.credentials = credentials;
    this.publicKey = EthPublicKeyUtils.createPublicKey(credentials.getEcKeyPair().getPublicKey());
    this.needToHash = needToHash;
  }

  public CredentialSigner(final Credentials credentials) {
    this(credentials, true);
  }

  @Override
  public Signature sign(final byte[] data) {
    final SignatureData signature = Sign.signMessage(data, credentials.getEcKeyPair(), needToHash);
    return new Signature(
        new BigInteger(signature.getV()),
        new BigInteger(1, signature.getR()),
        new BigInteger(1, signature.getS()));
  }

  @Override
  public boolean verify(final byte[] data, final Signature signature) {
    final byte[] dataToVerify = needToHash ? Hash.sha3(data) : data;
    final ECDSASigner signer = new ECDSASigner();
    final Bytes toDecode =
        Bytes.wrap(Bytes.of((byte) 4), Bytes.wrap(EthPublicKeyUtils.toByteArray(publicKey)));
    final ECPublicKeyParameters params =
        new ECPublicKeyParameters(CURVE.getCurve().decodePoint(toDecode.toArrayUnsafe()), CURVE);
    signer.init(false, params);
    try {
      return signer.verifySignature(dataToVerify, signature.getR(), signature.getS());
    } catch (final NullPointerException e) {
      // Bouncy Castle contains a bug that can cause NPEs given specially crafted signatures.
      // Those signatures are inherently invalid/attack sigs so we just fail them here rather
      // than crash the thread.
      return false;
    }
  }

  @Override
  public ECPublicKey getPublicKey() {
    return publicKey;
  }
}
