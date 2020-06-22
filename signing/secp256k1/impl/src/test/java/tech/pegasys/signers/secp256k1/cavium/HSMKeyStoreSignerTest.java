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

import static org.junit.jupiter.api.Assertions.fail;

import tech.pegasys.signers.cavium.HSMKeyStoreProvider;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class HSMKeyStoreSignerTest {

  private static String library;
  private static String slot;
  private static String pin;

  private static HSMKeyStoreProvider ksp;
  private static HSMKeyStoreSigner kss;

  @BeforeAll
  public static void beforeAll() {
    Properties p = new Properties();
    InputStream is = ClassLoader.getSystemResourceAsStream("cavium-configs/softhsm.properties");
    try {
      p.load(is);
      library = p.getProperty("library");
      slot = p.getProperty("slot");
      pin = p.getProperty("pin");
    } catch (IOException e) {
      fail("Properties file not found");
    }

    org.junit.jupiter.api.Assumptions.assumeTrue((new File(library).exists()));
    ksp = new HSMKeyStoreProvider(library, slot, pin);
    kss = (HSMKeyStoreSigner) (new HSMKeyStoreSignerFactory(ksp)).createSigner("0x");
  }

  @AfterAll
  public static void afterAll() {
    if (kss != null) {
      kss.shutdown();
    }
    if (ksp != null) {
      ksp.shutdown();
    }
  }

  @Test
  void generateTest() {
    //    String address = kgr.generate();
    //    System.out.println("Generated: " + address);
    //    boolean exists = kgr.exists(address);
    //    assertThat(exists).isTrue();
    //    List<String> addresses = kgr.getAll();
    //    assertThat(addresses).contains(address);
    //    KeyStore.PrivateKeyEntry privateKeyEntry = null;
    //    try {
    //      privateKeyEntry = (KeyStore.PrivateKeyEntry) ksp.getKeyStore().getEntry(address, null);
    //    } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
    //      fail("Failed to retrieve private key handle");
    //    }
    //    assertThat(privateKeyEntry).isNotNull();
    //    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
    //    assertThat(privateKey).isNotNull();
  }

  @Test
  void getAllTest() {
    //    String address = kgr.generate();
    //    System.out.println("Generated: " + address);
    //    List<String> addresses = kgr.getAll();
    //    assertThat(addresses).isNotEmpty();
    //    for (String a : addresses) {
    //      System.out.println("Listed: " + a);
    //    }
  }
}
