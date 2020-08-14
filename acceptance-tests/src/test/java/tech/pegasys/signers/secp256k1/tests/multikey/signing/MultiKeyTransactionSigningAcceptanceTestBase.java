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
package tech.pegasys.signers.secp256k1.tests.multikey.signing;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.web3j.crypto.Sign.publicKeyFromPrivate;
import static org.web3j.crypto.Sign.signedMessageToKey;
import static org.web3j.utils.Numeric.toBigInt;
import static org.web3j.utils.Numeric.toBytesPadded;

import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;
import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.Signer;
import tech.pegasys.signers.secp256k1.tests.multikey.MultiKeyAcceptanceTestBase;

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Sign.SignatureData;

public class MultiKeyTransactionSigningAcceptanceTestBase extends MultiKeyAcceptanceTestBase {

  private static final byte[] DATA_TO_SIGN = "42".getBytes(UTF_8);
  private static final String PRIVATE_KEY =
      "8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";
  public static final String PUBLIC_KEY_HEX_STRING =
      "09b02f8a5fddd222ade4ea4528faefc399623af3f736be3c44f03e2df22fb792f3931a4d9573d333ca74343305762a753388c3422a86d98b713fc91c1ea04842";

  public static final ECPublicKey pubKey =
      EthPublicKeyUtils.createPublicKey(Bytes.fromHexString(PUBLIC_KEY_HEX_STRING));

  void verifySignature() {
    final Optional<Signer> signer = signerProvider.getSigner(pubKey);
    assertThat(signer).isNotEmpty();

    final BigInteger privateKey = new BigInteger(1, Bytes.fromHexString(PRIVATE_KEY).toArray());
    final BigInteger expectedPublicKey = publicKeyFromPrivate(privateKey);

    final Signature signature = signer.get().sign(DATA_TO_SIGN);

    final BigInteger messagePublicKey = recoverPublicKey(signature);
    assertThat(messagePublicKey).isEqualTo(expectedPublicKey);

    final ECDSASignature ecdsaSignature = new ECDSASignature(signature.getR(), signature.getS());
    assertThat(ecdsaSignature.isCanonical()).isTrue();
  }

  private BigInteger recoverPublicKey(final Signature signature) {
    try {
      final byte[] v = signature.getV().toByteArray();
      final byte[] r = toBytesPadded(toBigInt(signature.getR().toByteArray()), 32);
      final byte[] s = toBytesPadded(toBigInt(signature.getS().toByteArray()), 32);
      final SignatureData signatureData = new SignatureData(v, r, s);
      return signedMessageToKey(DATA_TO_SIGN, signatureData);
    } catch (SignatureException e) {
      throw new IllegalStateException("signature cannot be recovered", e);
    }
  }
}
