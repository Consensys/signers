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
package tech.pegasys.signers.hsm;

import java.math.BigInteger;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

public class HSMWallet {

  private static final int PUBLIC_KEY_SIZE = 64;

  private final HSMCrypto crypto;
  private final String slotLabel;
  private long slotIndex;

  public HSMWallet(HSMCrypto crypto, String slotLabel) {
    this.crypto = crypto;
    this.slotLabel = slotLabel;
    this.slotIndex = -1L;
  }

  public String getStatus() {
    boolean isLoggedIn = crypto.isLoggedIn(slotIndex);
    return isLoggedIn ? "Open" : "Closed";
  }

  public String getLabel() {
    return slotLabel;
  }

  public void open(String slotPin) {
    slotIndex = crypto.getSlotIndex(slotLabel);
    crypto.login(slotIndex, slotPin);
  }

  public void close() {
    if (slotIndex < 0L) return;
    if (crypto.isLoggedIn(slotIndex)) {
      crypto.logout(slotIndex);
    }
  }

  public List<String> getAddresses() {
    return crypto.getAddresses(slotIndex);
  }

  public boolean contains(String address) {
    return crypto.containsAddress(slotIndex, address);
  }

  public void clear() {
    List<String> addresses = crypto.getAddresses(slotIndex);
    for (String address : addresses) {
      crypto.deleteECKeyPair(slotIndex, address);
    }
  }

  public String generate() {
    return crypto.generateECKeyPair(slotIndex);
  }

  public BigInteger[] sign(byte[] hash, String address) {
    return crypto.sign(slotIndex, hash, address);
  }

  public Bytes getPublicKey(String address) {
    BigInteger bi = Sign.publicFromPoint(crypto.getPublicKey(slotIndex, address));
    return Bytes.wrap(Numeric.toBytesPadded(bi, PUBLIC_KEY_SIZE));
  }
}
