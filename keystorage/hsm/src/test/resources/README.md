###Install SoftHSM
####Linux
As a prerequisite you might need to install the following dependencies if not already present 
```
apt install gcc make automake libtool autoconf pkg-config libssl-dev -y
```
Clone the repo
```
git clone https://github.com/opendnssec/SoftHSMv2
cd SoftHSMv2/
sh autogen.sh
./configure
make
make install
```
The last command may require super user permissions in which case one should also do 
```
sudo chmod 1777 /var/lib/softhsm
```
####Mac
```
brew install softhsm
```
###Initialize SoftHSM
```
softhsm2-util --init-token --slot 0 --label WALLET-000 --pin us3rs3cur3 --so-pin sup3rs3cur3
softhsm2-util --init-token --slot 1 --label WALLET-001 --pin us3rs3cur3 --so-pin sup3rs3cur3
softhsm2-util --init-token --slot 2 --label WALLET-002 --pin us3rs3cur3 --so-pin sup3rs3cur3
softhsm2-util --init-token --slot 3 --label WALLET-003 --pin us3rs3cur3 --so-pin sup3rs3cur3
softhsm2-util --show-slots
```
###Run SoftHSM in Docker
Build the image
```
docker build --tag softhsm2:2.5.0 .
```
Run the image
```
docker run -ti --rm softhsm2:2.5.0 sh -l
```
Test 
```
softhsm2-util --show-slots
```
The docker image comes with pre-initialized slots
###Build EthSigner 
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
###Single key signing
Start the service
```
ethsigner --chain-id=44844 --http-listen-host=127.0.0.1 --http-listen-port=9545 --downstream-http-host=127.0.0.1 --downstream-http-port=8545 --downstream-http-request-timeout=30000 --logging="DEBUG" hsm-signer --library="/usr/local/lib/softhsm/libsofthsm2.so" --slot-label="WALLET-001" --slot-pin="us3rs3cur3" --eth-address="0x107FcB98Ee41078027620920A77d6e5aB372957d"
```
###Multiple key signing
Start the service
```
ethsigner --chain-id=44844 --http-listen-host=127.0.0.1 --http-listen-port=9545 --downstream-http-host=127.0.0.1 --downstream-http-port=8545 --downstream-http-request-timeout=30000 --logging="DEBUG" multikey-signer --directory="./keysAndPasswords" --library="/usr/local/lib/softhsm/libsofthsm2.so" --slot-label="WALLET-001" --slot-pin="us3rs3cur3"  
```