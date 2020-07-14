package tech.pegasys.signers.hashicorp.dsl;

import com.github.dockerjava.api.DockerClient;
import tech.pegasys.signers.hashicorp.dsl.certificates.SelfSignedCertificate;

import java.util.Map;
import java.util.Optional;

public class HashicorpDockerNode implements HashicorpNode {
    private final Optional<SelfSignedCertificate> serverTlsCertificate;
    private final DockerClient dockerClient;
    private HashicorpVaultDocker hashicorpVaultDocker;

    HashicorpDockerNode(final DockerClient dockerClient) {
        this(dockerClient, null);
    }

    HashicorpDockerNode(
            final DockerClient dockerClient, final SelfSignedCertificate serverTlsCertificate) {
        this.dockerClient = dockerClient;
        this.serverTlsCertificate = Optional.ofNullable(serverTlsCertificate);
    }

    void start() {
        final HashicorpVaultDockerCertificate hashicorpVaultDockerCertificate =
                serverTlsCertificate.map(HashicorpVaultDockerCertificate::create).orElse(null);

        hashicorpVaultDocker =
                HashicorpVaultDocker.createVaultDocker(dockerClient, hashicorpVaultDockerCertificate);
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
    }

    @Override
    public synchronized void shutdown() {
        if (hashicorpVaultDocker != null) {
            hashicorpVaultDocker.shutdown();
            hashicorpVaultDocker = null;
        }
    }

    @Override
    public String getVaultToken() {
        return hashicorpVaultDocker.getHashicorpRootToken();
    }

    @Override
    public String getHost() {
        return hashicorpVaultDocker.getIpAddress();
    }

    @Override
    public int getPort() {
        return hashicorpVaultDocker.getPort();
    }

    @Override
    public Optional<SelfSignedCertificate> getServerCertificate() {
        return serverTlsCertificate;
    }

    /* Note: Path should be the "subpath" of the secret - not the full HTTP path.
    The full HTTP Path will be returned.
     */
    @Override
    public void addSecretsToVault(final Map<String, String> entries, final String path) {
        hashicorpVaultDocker.addSecretsToVault(entries, path);
    }

    @Override
    public String getHttpApiPathForSecret(final String secretPath) {
        // *ALL* Hashicorp Http API endpoints are prefixed by "/v1"
        // KV-V2 insert "data" after the rootpath, and before the signing key path (so, just gotta
        // handle that)
        return hashicorpVaultDocker.getHttpApiPathForSecret(secretPath);
    }
}
