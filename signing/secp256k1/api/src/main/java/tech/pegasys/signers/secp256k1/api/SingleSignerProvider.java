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

import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

public class SingleSignerProvider implements SignerProvider {

  private final Signer signer;

  public SingleSignerProvider(final Signer signer) {
    if (signer == null) {
      throw new IllegalArgumentException("SingleSignerFactory requires a non-null Signer");
    }
    this.signer = signer;
  }

  @Override
  public Optional<Signer> getSigner(final ECPublicKey publicKey) {
    if ((signer.getPublicKey() != null) && signer.getPublicKey().getW().equals(publicKey.getW())) {
      return Optional.of(signer);
    } else {
      return Optional.empty();
    }
  }

  @Override
  public Set<ECPublicKey> availablePublicKeys() {
    return signer.getPublicKey() != null ? Set.of(signer.getPublicKey()) : Collections.emptySet();
  }
}
