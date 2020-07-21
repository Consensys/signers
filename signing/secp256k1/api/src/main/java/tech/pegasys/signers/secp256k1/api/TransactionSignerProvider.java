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
package tech.pegasys.signers.secp256k1.api;

import java.util.Optional;
import java.util.Set;

public interface TransactionSignerProvider {

  Optional<TransactionSigner> getSigner(String address);

  /**
   * Deprecated in fovour of availablePublicKeys().
   *
   * @return A set of strings representing the Ethereum Addresses of available signers.
   */
  @Deprecated
  Set<String> availableAddresses();

  Set<String> availablePublicKeys();

  default void shutdown() {}
}
