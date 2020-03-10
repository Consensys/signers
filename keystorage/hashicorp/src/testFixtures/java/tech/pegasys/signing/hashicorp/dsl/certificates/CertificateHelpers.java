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
package tech.pegasys.signing.hashicorp.dsl.certificates;

import com.google.common.base.Charsets;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.StringJoiner;
import org.apache.tuweni.net.tls.TLS;

public class CertificateHelpers {

  public static KeyStore loadP12KeyStore(final File pkcsFile, final String password)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException {
    final KeyStore store = KeyStore.getInstance("pkcs12");
    try (final InputStream keystoreStream = new FileInputStream(pkcsFile)) {
      store.load(keystoreStream, password.toCharArray());
    } catch (IOException e) {
      throw new RuntimeException("Unable to load keystore.", e);
    }
    return store;
  }

  public static void populateFingerprintFile(
      final Path knownHostsPath,
      final MySelfSignedCertificate selfSignedCert,
      final Optional<Integer> port)
      throws IOException, CertificateEncodingException {

    final StringBuilder fingerPrintsToAdd = new StringBuilder();
    final String portFragment = port.map(p -> String.format(":%d", p)).orElse("");
    final String fingerprint =
        TLS.certificateHexFingerprint(selfSignedCert.getCertificate());
    fingerPrintsToAdd.append(String.format("localhost%s %s%n", portFragment, fingerprint));
    fingerPrintsToAdd.append(String.format("127.0.0.1%s %s%n", portFragment, fingerprint));
    Files.writeString(knownHostsPath, fingerPrintsToAdd.toString());
  }

  public static Path createJksTrustStore(
      final Path parentDir, final MySelfSignedCertificate selfSignedCert, final PrivateKey privKey,
      final String password) {
    try {

      final KeyStore ks = KeyStore.getInstance("JKS");
      ks.load(null, null);

      final Certificate certificate = selfSignedCert.getCertificate();
      ks.setCertificateEntry("clientCert", certificate);
      ks.setKeyEntry(
          "client", privKey, password.toCharArray(), new Certificate[]{certificate});

      final Path tempKeystore = parentDir.resolve("keystore.jks");
      try (final FileOutputStream output = new FileOutputStream(tempKeystore.toFile())) {
        ks.store(output, password.toCharArray());
      }

      return tempKeystore;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to construct a JKS keystore.");
    }
  }

  public static Path createPkcs12TrustStore(
      final Path parentDir, final MySelfSignedCertificate selfSignedCert, final PrivateKey privKey,
      final String password) {
    try {

      final KeyStore ks = KeyStore.getInstance("pkcs12");
      ks.load(null, null);

      final Certificate certificate = selfSignedCert.getCertificate();
      ks.setCertificateEntry("clientCert", certificate);
      ks.setKeyEntry(
          "client", privKey, password.toCharArray(), new Certificate[]{certificate});

      final Path tempKeystore = parentDir.resolve("keystore.jks");
      try (final FileOutputStream output = new FileOutputStream(tempKeystore.toFile())) {
        ks.store(output, password.toCharArray());
      }

      return tempKeystore;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to construct a JKS keystore.");
    }
  }
}
