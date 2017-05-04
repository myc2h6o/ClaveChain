# Clave
---
## Prerequisites
- [Intel Sgx Sdk](https://software.intel.com/en-us/sgx)

## Compile and build
- Windows: Visual Studio 2015
- Linux: Using Makefile

## Run in Simulation mode
- Windows
    * Set build configuration to Simulation x86
    * Set App as starting project
    * Configure setting of App: Debug->Working Directory as $(ProjectDir)..\Simulation (the enclave dll is under this folder)
- Linux
-     make SGX_MODE=SIM
