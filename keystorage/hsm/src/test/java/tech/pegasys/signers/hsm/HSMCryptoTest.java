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
package tech.pegasys.signers.hsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Hash;

public class HSMCryptoTest {

  private static HSMCrypto c;
  private static String library;
  private static String label;
  private static long slot;
  private static String pin;
  private static String addr = "0x54193350E4D46B58088158148f156E031Ad1B284";

  @BeforeAll
  public static void beforeAll() {
    Properties p = new Properties();
    InputStream is = ClassLoader.getSystemResourceAsStream("softhsm-wallet-000" + ".properties");
    try {
      p.load(is);
      library = p.getProperty("library");
      label = p.getProperty("slot");
      pin = p.getProperty("pin");
    } catch (IOException e) {
      fail("Properties file not found");
    }

    org.junit.jupiter.api.Assumptions.assumeTrue((new File(library)).exists());
    c = new HSMCrypto(library);
    c.initialize();
    slot = c.getSlotIndex(label);
  }

  @AfterAll
  public static void afterAll() {
    if (c != null) {
      c.shutdown();
    }
  }

  @Test
  public void initialize() {
    HSMCrypto ce = new HSMCrypto(library + "101");
    assertThrows(HSMCryptoException.class, () -> ce.initialize());
  }

  @Test
  public void login() {
    assertDoesNotThrow(() -> c.login(slot, pin));
    assertThat(c.isLoggedIn(slot)).isTrue();
    assertDoesNotThrow(() -> c.logout(slot));
    assertThrows(HSMCryptoException.class, () -> c.logout(slot));
    assertThrows(HSMCryptoException.class, () -> c.login(slot, pin + "101"));
    assertThrows(HSMCryptoException.class, () -> c.login(slot, ""));
    assertThrows(HSMCryptoException.class, () -> c.login(slot + 1, pin));
    assertThat(c.isLoggedIn(slot)).isFalse();
  }

  @Test
  public void generate() {
    c.login(slot, pin);
    String address = c.generateECKeyPair(slot);
    assertThat(address).isNotNull();
    assertThrows(HSMCryptoException.class, () -> c.generateECKeyPair(slot + 1));
    c.logout(slot);
    assertThrows(HSMCryptoException.class, () -> c.generateECKeyPair(slot));
  }

  @Test
  public void contains() {
    c.login(slot, pin);
    assertThat(c.containsAddress(slot, addr)).isFalse();
    assertThrows(HSMCryptoException.class, () -> c.containsAddress(slot + 1, addr));
    String address = c.generateECKeyPair(slot);
    assertThat(c.containsAddress(slot, address)).isTrue();
    c.logout(slot);
    assertThat(c.containsAddress(slot, address)).isFalse();
  }

  @Test
  public void list() {
    c.login(slot, pin);
    String address = c.generateECKeyPair(slot);
    List<String> addressesLoggedIn = c.getAddresses(slot);
    assertThat(addressesLoggedIn).isNotEmpty();
    assertThat(addressesLoggedIn).contains(address);
    c.logout(slot);
    List<String> addressesLoggedOut = c.getAddresses(slot);
    assertThat(addressesLoggedOut).isEmpty();
  }

  @Test
  public void delete() {
    c.login(slot, pin);
    String address = c.generateECKeyPair(slot);
    assertDoesNotThrow(() -> c.deleteECKeyPair(slot, address));
    assertThat(c.containsAddress(slot, address)).isFalse();
    assertThrows(HSMCryptoException.class, () -> c.deleteECKeyPair(slot, address));
    c.logout(slot);
    assertThrows(HSMCryptoException.class, () -> c.deleteECKeyPair(slot, address));
  }

  @Test
  public void sign() {
    final byte[] data = {1, 2, 3};
    final byte[] hash = Hash.sha3(data);
    c.login(slot, pin);
    String address = c.generateECKeyPair(slot);
    BigInteger[] sigLoggedIn = c.sign(slot, hash, address);
    assertThat(sigLoggedIn).isNotNull();
    assertThrows(HSMCryptoException.class, () -> c.sign(slot + 1, hash, address));
    c.logout(slot);
    assertThrows(HSMCryptoException.class, () -> c.sign(slot, hash, address));
    c.login(slot, pin);
    assertThrows(HSMCryptoException.class, () -> c.sign(slot, hash, addr));
    c.logout(slot);
  }
}
