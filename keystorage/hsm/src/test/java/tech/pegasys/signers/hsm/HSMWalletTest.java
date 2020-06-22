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

public class HSMWalletTest {

  private static HSMCrypto c;
  private static String library;
  private static String slot;
  private static String pin;

  @BeforeAll
  public static void beforeAll() {
    Properties p = new Properties();
    InputStream is = ClassLoader.getSystemResourceAsStream("softhsm-wallet-001" + ".properties");
    try {
      p.load(is);
      library = p.getProperty("library");
      slot = p.getProperty("slot");
      pin = p.getProperty("pin");
    } catch (IOException e) {
      fail("Properties file not found");
    }

    org.junit.jupiter.api.Assumptions.assumeTrue((new File(library)).exists());
    c = new HSMCrypto(library);
    c.initialize();
  }

  @AfterAll
  public static void afterAll() {
    if (c != null) {
      c.shutdown();
    }
  }

  @Test
  public void open() {
    HSMWallet w = new HSMWallet(c, slot);
    assertDoesNotThrow(() -> w.open(pin));
    assertDoesNotThrow(() -> w.close());
    assertThrows(HSMCryptoException.class, () -> w.open(pin + "101"));
    HSMWallet v = new HSMWallet(c, slot + "101");
    assertThrows(HSMCryptoException.class, () -> v.open(pin));
  }

  @Test
  public void status() {
    HSMWallet w = new HSMWallet(c, slot);
    w.open(pin);
    assertThat(w.getStatus()).isEqualTo("Open");
    w.close();
    assertThat(w.getStatus()).isEqualTo("Closed");
  }

  @Test
  public void label() {
    HSMWallet w = new HSMWallet(c, slot);
    assertThat(w.getLabel()).isEqualTo(slot);
  }

  @Test
  public void generate() {
    HSMWallet w = new HSMWallet(c, slot);
    w.open(pin);
    String address = w.generate();
    assertThat(address).isNotNull();
    w.close();
    assertThrows(HSMCryptoException.class, () -> w.generate());
  }

  @Test
  public void contains() {
    HSMWallet w = new HSMWallet(c, slot);
    w.open(pin);
    String address = w.generate();
    assertThat(w.contains(address)).isTrue();
    w.close();
    assertThat(w.contains(address)).isFalse();
  }

  @Test
  public void list() {
    HSMWallet w = new HSMWallet(c, slot);
    w.open(pin);
    String address = w.generate();
    List<String> addresses = w.getAddresses();
    assertThat(addresses).isNotEmpty();
    assertThat(addresses).contains(address);
    w.close();
    assertThat(w.getAddresses()).isEmpty();
  }

  @Test
  public void clear() {
    HSMWallet w = new HSMWallet(c, slot);
    w.open(pin);
    w.generate();
    assertDoesNotThrow(() -> w.clear());
    assertThat(w.getAddresses()).isEmpty();
    w.generate();
    w.close();
  }

  @Test
  public void sign() {
    final byte[] data = {1, 2, 3};
    HSMWallet w = new HSMWallet(c, slot);
    w.open(pin);
    String address = w.generate();
    BigInteger[] sig = w.sign(data, address);
    assertThat(sig).isNotNull();
    w.close();
  }
}
