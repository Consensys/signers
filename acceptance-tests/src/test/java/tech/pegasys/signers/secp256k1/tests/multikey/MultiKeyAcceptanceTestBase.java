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
package tech.pegasys.signers.secp256k1.tests.multikey;

import tech.pegasys.signers.secp256k1.api.FileSelector;
import tech.pegasys.signers.secp256k1.api.PublicKey;
import tech.pegasys.signers.secp256k1.multikey.MultiKeyTransactionSignerProvider;

import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;

import org.web3j.crypto.Keys;

public class MultiKeyAcceptanceTestBase {

  private static class DefaultFileSelector implements FileSelector<PublicKey> {

    @Override
    public Filter<Path> getCollectiveFilter() {
      return entry -> entry.endsWith("toml");
    }

    @Override
    public Filter<Path> getSpecificConfigFileFilter(final PublicKey publicKey) {
      return entry -> {
        String addressToMatch = Keys.getAddress(publicKey.toString());
        if (addressToMatch.startsWith("0x")) {
          addressToMatch = addressToMatch.substring(2);
        }
        return entry.endsWith(addressToMatch + ".toml");
      };
    }
  }

  protected MultiKeyTransactionSignerProvider signerProvider;

  protected void setup(final Path tomlDirectory) {
    this.signerProvider =
        MultiKeyTransactionSignerProvider.create(tomlDirectory, new DefaultFileSelector());
  }
}
