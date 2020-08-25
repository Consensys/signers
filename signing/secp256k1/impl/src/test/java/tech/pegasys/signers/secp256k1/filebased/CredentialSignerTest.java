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
package tech.pegasys.signers.secp256k1.filebased;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.signers.secp256k1.api.Signature;

import java.math.BigInteger;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;

class CredentialSignerTest {
  private static final String SECP_PRIVATE_KEY =
      "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4";

  @Test
  void needToHashFlagAffectsProducedSignature() {
    final Credentials credentials = Credentials.create(ECKeyPair.create(BigInteger.ONE));

    final CredentialSigner hashingSigner = new CredentialSigner(credentials);
    final CredentialSigner nonHashingSigner = new CredentialSigner(credentials, false);

    final byte[] data = "Hello World".getBytes(UTF_8);

    assertThat(hashingSigner.getPublicKey().getEncoded())
        .isEqualTo(nonHashingSigner.getPublicKey().getEncoded());
    assertThat(hashingSigner.sign(data))
        .isEqualToComparingFieldByField(nonHashingSigner.sign(Hash.sha3(data)));
  }

  @Test
  void verifiesDataWasSignedBySignersPublicKey() {
    final ECKeyPair ecKeyPair =
        ECKeyPair.create(Bytes.fromHexString(SECP_PRIVATE_KEY).toArrayUnsafe());
    final Credentials credentials = Credentials.create(ecKeyPair);
    final CredentialSigner signer = new CredentialSigner(credentials);

    final Bytes data = Bytes.wrap("This is an example of a signed message.".getBytes(UTF_8));
    final Signature signature = signer.sign(data.toArray());
    assertThat(signer.verify(data.toArray(), signature)).isTrue();
  }

  @Test
  void verifiesDataWithoutHashingWasSignedBySignersPublicKey() {
    final ECKeyPair ecKeyPair =
        ECKeyPair.create(Bytes.fromHexString(SECP_PRIVATE_KEY).toArrayUnsafe());
    final Credentials credentials = Credentials.create(ecKeyPair);
    final CredentialSigner signer = new CredentialSigner(credentials, false);

    final Bytes data = Bytes.wrap("This is an example of a signed message.".getBytes(UTF_8));
    final Bytes hashedData = Bytes.wrap(Hash.sha3(data.toArrayUnsafe()));

    final Signature signature = signer.sign(hashedData.toArray());
    assertThat(signer.verify(hashedData.toArray(), signature)).isTrue();
  }
}
