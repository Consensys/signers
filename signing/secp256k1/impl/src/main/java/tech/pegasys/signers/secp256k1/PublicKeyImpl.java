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

import tech.pegasys.signers.secp256k1.api.PublicKey;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.Objects;

import com.google.common.base.MoreObjects;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.util.BigIntegers;
import org.web3j.utils.Numeric;

public class PublicKeyImpl implements PublicKey {

  private static final int PUBLIC_KEY_SIZE = 64;

  private final ECPoint value;

  public static PublicKey fromEthBytes(final Bytes value) {
    final Bytes x = value.slice(0, 32);
    final Bytes y = value.slice(32, 32);
    final ECPoint ecPoint =
        new ECPoint(Numeric.toBigInt(x.toArrayUnsafe()), Numeric.toBigInt(y.toArrayUnsafe()));
    return new PublicKeyImpl(ecPoint);
  }

  public static PublicKey fromEthBigInt(final BigInteger value) {
    final Bytes ethBytes = Bytes.wrap(Numeric.toBytesPadded(value, PUBLIC_KEY_SIZE));
    return fromEthBytes(ethBytes);
  }

  public PublicKeyImpl(final ECPoint value) {
    this.value = value;
  }

  @Override
  public ECPoint getValue() {
    return value;
  }

  @Override
  public byte[] toEthBytes() {
    final Bytes xBytes = Bytes32.wrap(BigIntegers.asUnsignedByteArray(32, value.getAffineX()));
    final Bytes yBytes = Bytes32.wrap(BigIntegers.asUnsignedByteArray(32, value.getAffineY()));
    return Bytes.concatenate(xBytes, yBytes).toArray();
  }

  @Override
  public String toEthHexString() {
    return Bytes.wrap(toEthBytes()).toHexString();
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this).add("value", value).toString();
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final PublicKeyImpl publicKey = (PublicKeyImpl) o;
    return Objects.equals(value, publicKey.value);
  }

  @Override
  public int hashCode() {
    return Objects.hash(value);
  }
}
