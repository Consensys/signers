package tech.pegasys.signers.yubihsm.backend;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;

public class YubiHsmBackendTestFactory {
    public static YubiHsmBackend createYubiHsmBackend(final Path tempDir) {
        final Path knownServersFile = tempDir.resolve("knownServersFile.txt");
        final Optional<Duration> timeout = Optional.of(Duration.ofSeconds(3));
        final YubihsmConnectorBackend backend =
                new YubihsmConnectorBackend(
                        URI.create("http://localhost:12345"), timeout, timeout, knownServersFile);
        backend.enableDebugHeader();
        return backend;
    }
}
