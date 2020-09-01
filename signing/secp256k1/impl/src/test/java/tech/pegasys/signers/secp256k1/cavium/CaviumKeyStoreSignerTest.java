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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import tech.pegasys.signers.cavium.CaviumConfig;
import tech.pegasys.signers.cavium.CaviumKeyStoreProvider;
import tech.pegasys.signers.secp256k1.api.Signature;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CaviumKeyStoreSignerTest {

  private static String library;
  private static String pin;
  private static String address;
  private static byte[] data = {1, 2, 3};

  private static CaviumKeyStoreProvider ksp;
  private static HSMKeyStoreSigner kss;

  @BeforeAll
  public static void beforeAll() {

    Properties p = new Properties();
    InputStream is = ClassLoader.getSystemResourceAsStream("cavium-configs/cavium.properties");
    try {
      p.load(is);
      library = p.getProperty("library");
      pin = p.getProperty("pin");
      address = p.getProperty("address");
    } catch (IOException e) {
      fail("Properties file not found");
    }

    org.junit.jupiter.api.Assumptions.assumeTrue((new File(library).exists()));
    ksp = new CaviumKeyStoreProvider(new CaviumConfig(library, pin));
    kss = (CaviumKeyStoreSigner) (new CaviumKeyStoreSignerFactory(ksp)).createSigner(address);
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
  public void signTest() {
    Signature sig = kss.sign(data);
    assertThat(sig).isNotNull();
  }
}
