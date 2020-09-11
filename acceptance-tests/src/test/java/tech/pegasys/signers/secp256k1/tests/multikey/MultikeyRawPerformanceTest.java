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
package tech.pegasys.signers.secp256k1.tests.multikey;

import java.io.IOException;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import tech.pegasys.signers.secp256k1.MultiKeyTomlFileUtil;

import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import org.assertj.core.util.Lists;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;

public class MultikeyRawPerformanceTest extends MultiKeyAcceptanceTestBase {

  @Test
  public void testFindingTheRightKey(@TempDir Path testDir)
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CipherException, IOException {
    final int KEY_COUNT = 100;
    final List<ECKeyPair> keys = Lists.newArrayList();

    for (int i = 0; i < KEY_COUNT; i++) {
      final ECKeyPair keyPair = Keys.createEcKeyPair();
      final String privKey = Numeric.toHexStringWithPrefix(keyPair.getPrivateKey());
      final String pubKey = Numeric.toHexStringWithPrefix(keyPair.getPublicKey());
      final String keyFilename =
          WalletUtils.generateWalletFile("password", keyPair, testDir.toFile(), false);
      MultiKeyTomlFileUtil.createFileBasedTomlFileAt(
          testDir.resolve(Keys.getAddress(pubKey) + ".toml"), keyFilename, "password");
      keys.add(keyPair);
    }

    setup(testDir);

    final List<ECPublicKey> loadedKeys = new ArrayList(signerProvider.availablePublicKeys());

    final long start = System.currentTimeMillis();
    signerProvider.getSigner(loadedKeys.get(50));
    System.out.printf(
        "Time taken = %dms (total keys = %d)",
        System.currentTimeMillis() - start, loadedKeys.size());
  }
}
