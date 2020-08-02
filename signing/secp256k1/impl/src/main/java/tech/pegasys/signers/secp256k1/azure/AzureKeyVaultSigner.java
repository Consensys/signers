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
package tech.pegasys.signers.secp256k1.azure;

import tech.pegasys.signers.secp256k1.PublicKeyImpl;
import tech.pegasys.signers.secp256k1.api.PublicKey;
import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.Signer;

import java.math.BigInteger;
import java.util.Arrays;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;

public class AzureKeyVaultSigner implements Signer {

  private static final Logger LOG = LogManager.getLogger();

  final CryptographyClient cryptoClient;
  private final PublicKeyImpl publicKey;
  private final SignatureAlgorithm signingAlgo =
      SignatureAlgorithm.fromString("ECDSA256");

  public AzureKeyVaultSigner(final CryptographyClient cryptoClient, final Bytes publicKey) {
    this.cryptoClient = cryptoClient;
    this.publicKey = new PublicKeyImpl(publicKey);
  }

  @Override
  public Signature sign(byte[] data) {
    final byte[] hash = Hash.sha3(data);
    final SignResult result = cryptoClient.sign(signingAlgo, hash);
    final byte[] signature = result.getSignature();

    if (signature.length != 64) {
      throw new RuntimeException(
          "Invalid signature from the key vault signing service, must be 64 bytes long");
    }

    // reference: blog by Tomislav Markovski
    // https://tomislav.tech/2018-02-05-ethereum-keyvault-signing-transactions/
    // The output of this will be a 64 byte array. The first 32 are the value for R and the rest is
    // S.
    final BigInteger R = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
    final BigInteger S = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));

    // The Azure Signature MAY be in the "top" of the curve, which is illegal in Ethereum
    // thus it must be transposed to the lower intersection.
    final ECDSASignature initialSignature = new ECDSASignature(R, S);
    final ECDSASignature canonicalSignature = initialSignature.toCanonicalised();

    // Now we have to work backwards to figure out the recId needed to recover the signature.
    final int recId = recoverKeyIndex(canonicalSignature, hash);
    if (recId == -1) {
      throw new RuntimeException(
          "Could not construct a recoverable key. Are your credentials valid?");
    }

    final int headerByte = recId + 27;
    return new Signature(
        BigInteger.valueOf(headerByte), canonicalSignature.r, canonicalSignature.s);
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  private int recoverKeyIndex(final ECDSASignature sig, final byte[] hash) {
    final BigInteger publicKey = new BigInteger(1, this.publicKey.getValue());
    for (int i = 0; i < 4; i++) {
      final BigInteger k = Sign.recoverFromSignature(i, sig, hash);
      LOG.trace("recovered key: {}", k);
      if (k != null && k.equals(publicKey)) {
        return i;
      }
    }
    return -1;
  }
}
