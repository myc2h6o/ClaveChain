# ClaveChain

Blockchain retrieving trusted outer source data through intel SGX.

## Introduction
- Blockchain is using Ethereum and retrieving outer source data based on TLS.
- Use [Intel SGX](https://software.intel.com/en-us/sgx) as trusted middle man.
- Use [curl](https://curl.haxx.se/) for http request to call blockchain.
- Use [mbedTLS for SGX ported by fanz](https://github.com/bl4ck5un/mbedtls-SGX) for TLS and ecdsa stuff.
- Use keccak sha3 hash implementation [here](http://create.stephan-brumme.com/hash-library/#keccak).

## Source code structure
- `Chain`: Ethereum smart contracts
- `Clave`: Middle man monitor
- `Geth`: Ethereum geth config and starting command
- `GethViewer`: Single page for local geth data viewer
- `OuterData`: Stub server for retrieving trusted outer source data
- `Tools`: Helping tools

## Related work
- [Town Crier: An Authenticated Data Feed for Smart Contracts](http://eprint.iacr.org/2016/168.pdf)
