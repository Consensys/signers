/*
 * Copyright (C) 2019 ConsenSys AG.
 *
 * The source code is provided to licensees of PegaSys Plus for their convenience and internal
 * business use. These files may not be copied, translated, and/or distributed without the express
 * written permission of an authorized signatory for ConsenSys AG.
 */
package tech.pegasys.signers.dsl.hashicorp;

import static java.nio.file.Files.createFile;
import static java.nio.file.Files.createTempDirectory;
import static java.nio.file.Files.writeString;
import static java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.GROUP_READ;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;
import static java.nio.file.attribute.PosixFilePermissions.asFileAttribute;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Hashicorp Vault docker is created in server mode with TLS enabled. This requires passing self
 * signed certificates as defined by this class to the vault docker container as mount directory.
 * This class uses Java system property 'user.home' to create a temporary mount directory and
 * generate tls certs in it as it is typically enabled in docker preference in MacOSx and Windows.
 * See "docker -> Preferences -> File Sharing" to manage mount points.
 */
public class HashicorpVaultCerts {
  private static final Path MOUNT_PARENT_DIR =
      Path.of(System.getProperty("user.home", System.getProperty("java.io.tmpdir", "/tmp")));
  private static final Logger LOG = LogManager.getLogger();
  private static final String TEMP_PREFIX = ".vault-at";

  // the certs are generated using command:
  /*
  cat <<EOF > ./req.conf
  [req]
  distinguished_name = req_distinguished_name
  x509_extensions = v3_req
  prompt = no
  [req_distinguished_name]
  C = AU
  ST = QLD
  L = Brisbane
  O = PegaSys
  OU = Prod Dev
  CN = localhost
  [v3_req]
  keyUsage = keyEncipherment, dataEncipherment
  extendedKeyUsage = serverAuth
  subjectAltName = @alt_names
  [alt_names]
  DNS.1 = localhost
  IP.1 = 127.0.0.1
  EOF

  openssl req -x509 -nodes -days 36500 -newkey rsa:2048 -keyout vault.key -out vault.crt \
   -config req.conf -extensions 'v3_req'
   */
  private static final String VAULT_CERTIFICATE =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIDkzCCAnugAwIBAgIJAJMg61XCCKQjMA0GCSqGSIb3DQEBCwUAMGcxCzAJBgNV\n"
          + "BAYTAkFVMQwwCgYDVQQIDANRTEQxETAPBgNVBAcMCEJyaXNiYW5lMRAwDgYDVQQK\n"
          + "DAdQZWdhU3lzMREwDwYDVQQLDAhQcm9kIERldjESMBAGA1UEAwwJbG9jYWxob3N0\n"
          + "MCAXDTE5MTAwNjA2MDIyNloYDzIxMTkwOTEyMDYwMjI2WjBnMQswCQYDVQQGEwJB\n"
          + "VTEMMAoGA1UECAwDUUxEMREwDwYDVQQHDAhCcmlzYmFuZTEQMA4GA1UECgwHUGVn\n"
          + "YVN5czERMA8GA1UECwwIUHJvZCBEZXYxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIw\n"
          + "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALB2AZbsnQxOq2dRGJ8sUNluL+E4\n"
          + "SPbG9VCGW/AxV6ZUZCEGDeHvpWnplcuEM1O82/X8bmGwrD/Pd6pJrKaoZxSBPw7l\n"
          + "uLyRqmZxFaJN41iKofoRp8pdJymQMYXgdSu1TxZFXu5e/rxKCHjS7UKLiWpmxDnv\n"
          + "5FaAMhP0Fq2JWRJJGkJuEnCO2i/RHwcSbdVsDC8keMzC+tqoI0jNAiDr8aDsJDfU\n"
          + "ROO1eKB2coj9no8cJWj84nh1o81fCMTC9Ikv9rjWiKOW9QqyM+BfA6DN9uzbbr4f\n"
          + "il86qs3pZT+ouSD3hJlfjdlG+53pWCDbCNJ3rzGId/+omWItUiz1hTs6rJ8CAwEA\n"
          + "AaNAMD4wCwYDVR0PBAQDAgQwMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBoGA1UdEQQT\n"
          + "MBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAaS/BAXL1hphD\n"
          + "Z/WBUYGv3kEII69/hq9WegCM+YQ/xvR8yMOODpK0nsLWD1lMOn3XP0Kuib/viCm4\n"
          + "f6iANxz99k7EXRWNSd0KHiVFhiYb23bBSwZ+tubIvynxRLnQu6vIYt2duVDO5e1O\n"
          + "B3cR7R20mL6yCPHpm/qq2PcC3t60JYoQrnCSmjGZpnC6M6QrqXbzL8tmwg2UjnTP\n"
          + "MHlIA1gBg4AlCwHDGUE8V+0FE29eEgXElnfA1J+nXGKfIcgQjiMGeSeqdszRuN+1\n"
          + "x/hLjDkWt00HRsmaPrz+SCBh3wPQYjwDsPYJwrpR29e1MgdHfoP0hjCoFsczhpvq\n"
          + "U93KqKM/+g==\n"
          + "-----END CERTIFICATE-----\n";
  private static final String VAULT_KEY =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCwdgGW7J0MTqtn\n"
          + "URifLFDZbi/hOEj2xvVQhlvwMVemVGQhBg3h76Vp6ZXLhDNTvNv1/G5hsKw/z3eq\n"
          + "SaymqGcUgT8O5bi8kapmcRWiTeNYiqH6EafKXScpkDGF4HUrtU8WRV7uXv68Sgh4\n"
          + "0u1Ci4lqZsQ57+RWgDIT9BatiVkSSRpCbhJwjtov0R8HEm3VbAwvJHjMwvraqCNI\n"
          + "zQIg6/Gg7CQ31ETjtXigdnKI/Z6PHCVo/OJ4daPNXwjEwvSJL/a41oijlvUKsjPg\n"
          + "XwOgzfbs226+H4pfOqrN6WU/qLkg94SZX43ZRvud6Vgg2wjSd68xiHf/qJliLVIs\n"
          + "9YU7OqyfAgMBAAECggEAC1SIZZhrvQ6QEuIyIoZF6rAYgu2KQc4kkjcOUC3a4uMo\n"
          + "SraIzakFhfdplte2M/o8ZV7/92XQqYg4tsZkP48wjzB9TAeUBQeVWV6JdRJrNpQw\n"
          + "Mk5P575zdUe85kuzOks5+MQbhFK1KIHYaWmhslQjTqGql82/a45vqLhTfHEFNxc/\n"
          + "OEE2o9ZWu17HfAgPHe4UyLKwAwqkJ/cRsBuKHeIGoBlFSwDb1LAPT5P3kMTPP/U+\n"
          + "OrGyShZvOh5TYESfv0p/9qCXx9RP0Aqh+FFoZmQ3nwxrYAWsGz0fMPPE4B+kb/Zz\n"
          + "stVRhemAHtMr0e7vUG7rNrJrwKV/mzcz0AmERPYTgQKBgQDcl0pEvOiv3mUJ3ftM\n"
          + "A4RQ7HK0AjLwNa2Mh4MQljPB9RL7DIrn0BMfWuBqzysu5WgLw0Tx0uWP5hulFghg\n"
          + "JJYKUcOCoj2Y246BcfKvFje/NLj8+MJWhUaD1wwlVfqJ5dMHQFjxoU7bi+m5Cjf5\n"
          + "Lou1BWv5dlPolgV2jKvi6E1upQKBgQDMyUnVLnqxg7PwfNRDhibWGlTEcVYsjeh7\n"
          + "EE03DWM6P88ZVb3A/3FvroMZ7przwMqZKhpvcXFWD1Ikf4UK6FusFzkVESkzCYPw\n"
          + "jGR/3oDske0/XxhT6unIqcltbM/5uAvuqzcDr/+LnATQa6P1ZbuSpubPJAXUxO2D\n"
          + "lMT96iUu8wKBgAQmcIZEi5grdfkujPjMJCQlnq7WT8EHMYGwVv3r5YNjqfzBKqfb\n"
          + "2VBAtHIt/aD/PerivJxUHG+No72CYZv1dEEzcps1lDUZBGBZFXjH0TquskBIKdfY\n"
          + "4A/A7wCQ0orfoQ3E3yeEomgtBLOvhogQoR5BwNtLp557nBSz5tP5DOPlAoGAbEdR\n"
          + "/qIgxZN5pQKbyUg5aKNrhqLWiaBO+CLacO1nNflfK2omdtGZzQ9cym1bCN87QFj+\n"
          + "uUYmQva+3AWA9w98yTVOPVFhk1bIqHvS97lSOcO+ye8iEdz3193OX0lVfhhOVte4\n"
          + "sv5wBAVuljUT8EDmONh+2a+WVbX6T8RtlEQlfPkCgYAQZ8EKMz8eLtN6a7axdoqx\n"
          + "e8ptl/fXXU9ZWcoIye7UPR8LZu6sHb4D1qBD3Byd2amH58naOFuXCEFQW32cILmt\n"
          + "WbAbixF4lrOaEkuJJlY6ggOVrE8XCUC+7lPCNkfR0e4ez4Xo+xEcoXWMMiqpQXqY\n"
          + "Aob9dMPDHPZOmKJQld89Cw==\n"
          + "-----END PRIVATE KEY-----\n";

  private static final Set<PosixFilePermission> DIR_POSIX_PERMISSIONS =
      EnumSet.of(
          OWNER_READ,
          OWNER_WRITE,
          OWNER_EXECUTE,
          GROUP_READ,
          GROUP_EXECUTE,
          OTHERS_READ,
          OTHERS_EXECUTE);
  private static final Set<PosixFilePermission> FILES_POSIX_PERMISSIONS =
      EnumSet.of(OWNER_READ, OWNER_WRITE, GROUP_READ, OTHERS_READ);

  private final Path trustStoreDirectory;
  private final Path tlsCertificate;
  private final Path tlsPrivateKey;

  public HashicorpVaultCerts() {
    try {
      final boolean isPosix =
          FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
      final List<FileAttribute<?>> dirAttr =
          isPosix ? singletonList(asFileAttribute(DIR_POSIX_PERMISSIONS)) : emptyList();
      final List<FileAttribute<?>> fileAttr =
          isPosix ? singletonList(asFileAttribute(FILES_POSIX_PERMISSIONS)) : emptyList();

      trustStoreDirectory =
          createTempDirectory(
              MOUNT_PARENT_DIR, TEMP_PREFIX, dirAttr.toArray(FileAttribute<?>[]::new));
      tlsCertificate =
          createFile(
              trustStoreDirectory.resolve("vault.crt"), fileAttr.toArray(FileAttribute<?>[]::new));
      tlsPrivateKey =
          createFile(
              trustStoreDirectory.resolve("vault.key"), fileAttr.toArray(FileAttribute<?>[]::new));

      LOG.debug("Temporary cert directory: {}", trustStoreDirectory.toString());

      writeString(tlsCertificate, VAULT_CERTIFICATE);
      writeString(tlsPrivateKey, VAULT_KEY);

      Runtime.getRuntime().addShutdownHook(new Thread(this::cleanup));
    } catch (IOException ioe) {
      throw new RuntimeException("Unable to create temporary certificates", ioe);
    }
  }

  private void cleanup() {
    try {
      FileUtils.deleteDirectory(trustStoreDirectory.toFile());
    } catch (IOException e) {
      LOG.warn("Deletion failed for tls certificates", e);
    }
  }

  public Path getTrustStoreDirectory() {
    return trustStoreDirectory;
  }

  public Path getTlsCertificate() {
    return tlsCertificate;
  }

  public Path getTlsPrivateKey() {
    return tlsPrivateKey;
  }
}
