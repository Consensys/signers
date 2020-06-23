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

import tech.pegasys.signers.cavium.HSMKeyStoreProvider;
import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.TransactionSigner;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

public class HSMKeyStoreSigner implements TransactionSigner {

  protected static final Logger LOG = LogManager.getLogger();
  protected static final String CURVE = "secp256k1";
  protected static final String ALGORITHM = "NONEwithECDSA";

  protected final HSMKeyStoreProvider provider;
  protected final String address;

  public HSMKeyStoreSigner(final HSMKeyStoreProvider provider, String address) {
    this.provider = provider;
    this.address = address;
  }

  @Override
  public Signature sign(final byte[] data) {
    PrivateKey privateKey = getPrivateKey();

    final byte[] hash = Hash.sha3(data);
    java.security.Signature sig;
    try {
      sig = java.security.Signature.getInstance(ALGORITHM, provider.getProvider());
    } catch (NoSuchAlgorithmException ex) {
      LOG.trace(ex);
      throw new RuntimeException("Failed to get hsm signing service for this algorithm");
    }
    try {
      sig.initSign(privateKey);
    } catch (InvalidKeyException ex) {
      LOG.trace(ex);
      throw new RuntimeException(
          "Failed to initialize hsm signing service with private key handle");
    }
    try {
      sig.update(hash);
    } catch (SignatureException ex) {
      LOG.trace(ex);
      throw new RuntimeException("Failed to initialize hsm signing service with provided hash");
    }
    byte[] signature;
    try {
      signature = sig.sign();
    } catch (SignatureException ex) {
      LOG.trace(ex);
      throw new RuntimeException("Failed to sign provided hash with hsm signing service");
    }

    // Extract the R and S values of the signature from an DER encoded signature
    BigInteger R = null, S = null;
    ASN1Primitive asn1Signature;
    try {
      ByteArrayInputStream inStream = new ByteArrayInputStream(signature);
      ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
      asn1Signature = asnInputStream.readObject();
      asnInputStream.close();
    } catch (Exception ex) {
      LOG.trace(ex);
      throw new RuntimeException(
          "Failed to decode DER encoded signature produced by hsm signing service");
    }
    if (asn1Signature instanceof ASN1Sequence) {
      ASN1Sequence asn1Sequence = (ASN1Sequence) asn1Signature;
      ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
      for (ASN1Encodable asn1Encodable : asn1Encodables) {
        ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
        if (asn1Primitive instanceof ASN1Integer) {
          ASN1Integer asn1Integer = (ASN1Integer) asn1Primitive;
          BigInteger integer = asn1Integer.getValue();
          if (R == null) R = integer;
          else S = integer;
        }
      }
    }
    // The signature MAY be in the "top" of the curve, which is illegal in Ethereum thus it must be
    // transposed to the lower intersection.
    final ECDSASignature initialSignature = new ECDSASignature(R, S);
    final ECDSASignature canonicalSignature = initialSignature.toCanonicalised();

    // Now we have to work backwards to figure out the recId needed to recover the signature.
    final int recId = recoverKeyIndex(canonicalSignature, hash, address);
    if (recId == -1) {
      throw new RuntimeException(
          "Could not construct a recoverable key. Are your credentials valid?");
    }

    final int headerByte = recId + 27;
    return new Signature(
        BigInteger.valueOf(headerByte), canonicalSignature.r, canonicalSignature.s);
  }

  protected PrivateKey getPrivateKey() {
    PrivateKeyEntry privateKeyEntry = null;
    try {
      privateKeyEntry = (PrivateKeyEntry) provider.getKeyStore().getEntry(address, null);
    } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException ex) {
      LOG.trace(ex);
      throw new RuntimeException("Failed to query key store");
    }
    if (privateKeyEntry == null) {
      throw new RuntimeException("Failed to get private key from key store");
    }
    return privateKeyEntry.getPrivateKey();
  }

  @Override
  public String getAddress() {
    return address;
  }

  // recoverKeyIndex works backwards to figure out the recId needed to recover the signature
  private int recoverKeyIndex(final ECDSASignature sig, final byte[] hash, String address) {
    final String addressRecovered = address.toLowerCase().substring(2);
    for (int i = 0; i < 4; i++) {
      final BigInteger k = Sign.recoverFromSignature(i, sig, hash);
      if (k != null && addressRecovered.equals(Keys.getAddress(k))) {
        return i;
      }
    }
    return -1;
  }
}
