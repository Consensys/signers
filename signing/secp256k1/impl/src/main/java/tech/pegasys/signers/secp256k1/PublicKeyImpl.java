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
import java.util.Objects;

import org.apache.tuweni.bytes.Bytes;
import org.web3j.utils.Numeric;

public class PublicKeyImpl implements PublicKey {

  private static final int PUBLIC_KEY_SIZE = 64;

  private final Bytes value;

  public PublicKeyImpl(final Bytes value) {
    this.value = value;
  }

  public PublicKeyImpl(final BigInteger value) {
    this.value = Bytes.wrap(Numeric.toBytesPadded(value, PUBLIC_KEY_SIZE));
  }

  @Override
  public byte[] getValue() {
    return value.toArrayUnsafe();
  }

  @Override
  public String toString() {
    return value.toHexString();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final PublicKeyImpl other = (PublicKeyImpl) o;
    return other.value.compareTo(value) == 0;
  }

  @Override
  public int hashCode() {
    return Objects.hash(value);
  }
}
