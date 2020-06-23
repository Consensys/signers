### Build EthSigner 
```
./gradlew build
```
Go to the distribution directory:
```
cd build/distributions/
```
Expand the distribution archive:
```
tar -xzf ethsigner-<version>.tar.gz
```
Move to the expanded folder and display the help to confirm installation.
```
cd ethsigner-<version>/
bin/ethsigner --help
```
### Single key signing
Start the service
```
ethsigner --chain-id=44844 --http-listen-host=127.0.0.1 --http-listen-port=9545 --downstream-http-host=127.0.0.1 --downstream-http-port=8545 --downstream-http-request-timeout=30000 --logging="DEBUG" cavium-signer --library="/opt/cloudhsm/lib/libcloudhsm_pkcs11.so" --slot-pin="alice:391019314" --eth-address="0x6f1A840f52aD25A43D3BB8e75d104418b4CB5dFC"
```
### Multiple key signing
Start the service
```
ethsigner --chain-id=44844 --http-listen-host=127.0.0.1 --http-listen-port=9545 --downstream-http-host=127.0.0.1 --downstream-http-port=8545 --downstream-http-request-timeout=30000 --logging="DEBUG" multikey-signer --directory="./keysAndPasswords" --library="/opt/cloudhsm/lib/libcloudhsm_pkcs11.so" --slot-label="cavium" --slot-pin="alice:391019314" 
```