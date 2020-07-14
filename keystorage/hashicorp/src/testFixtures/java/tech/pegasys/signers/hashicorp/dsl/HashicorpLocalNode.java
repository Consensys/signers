package tech.pegasys.signers.hashicorp.dsl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zeroturnaround.exec.ProcessExecutor;
import tech.pegasys.signers.hashicorp.dsl.certificates.SelfSignedCertificate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

public class HashicorpLocalNode implements HashicorpNode {
    private static final Logger LOG = LogManager.getLogger();


    private final Optional<SelfSignedCertificate> serverTlsCertificate;
    private final Path vault;

    public HashicorpLocalNode(final Path vault, final SelfSignedCertificate serverTlsCertificate) {
        this.vault = vault;
        this.serverTlsCertificate = Optional.ofNullable(serverTlsCertificate);
    }

    public HashicorpLocalNode(final Path vault) {
        this(vault, null);
    }

    void start() throws InterruptedException, TimeoutException, IOException, CertificateEncodingException {
        final List<String> env = getVaultServerEnv();
        LOG.info(env);

        final String vaultVersion = new ProcessExecutor(vault.toString(), "--version").readOutput(true).execute().outputUTF8();
        LOG.info("Vault Version: " + vaultVersion);
    }

    @Override
    public void shutdown() {

    }

    @Override
    public String getVaultToken() {
        return null;
    }

    @Override
    public String getHost() {
        return null;
    }

    @Override
    public int getPort() {
        return 0;
    }

    @Override
    public Optional<SelfSignedCertificate> getServerCertificate() {
        return serverTlsCertificate;
    }

    @Override
    public void addSecretsToVault(final Map<String, String> entries, final String path) {

    }

    @Override
    public String getHttpApiPathForSecret(final String secretPath) {
        return null;
    }

    private List<String> getVaultServerEnv() throws IOException, CertificateEncodingException {
        return List.of(
                        "VAULT_LOCAL_CONFIG={\"storage\": {\"inmem\":{}}, "
                                + "\"default_lease_ttl\": \"168h\", \"max_lease_ttl\": \"720h\", "
                                + "\"listener\": {\"tcp\": {"
                                + "\"address\":\"0.0.0.0:0\""
                                + ","
                                + tlsEnvConfig()
                                + "}}}",
                        "VAULT_SKIP_VERIFY=true");

    }

    private String tlsEnvConfig() throws IOException, CertificateEncodingException {
        if (!isTlsEnabled()) {
            return "\"tls_disable\":\"true\"";
        }

        final Path certificate = Files.createTempFile("at_dsl_cert", ".crt");
        final Path privateKey = Files.createTempFile("at_dsl_priv", ".key");

        serverTlsCertificate.get().writeCertificateToFile(certificate);
        serverTlsCertificate.get().writePrivateKeyToFile(privateKey);


        return String.format("\"tls_min_version\": \"tls12\", \"tls_cert_file\": \"%s\", \"tls_key_file\": \"%s\"",
                certificate, privateKey);
    }

    private boolean isTlsEnabled() {
        return serverTlsCertificate.isPresent();
    }
}
