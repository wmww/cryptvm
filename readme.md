# CryptVM
An attempt to build a Brainfuck VM with homomorphic encryption

__NOTE: CryptVM will not be further developed. You may be interested in [arcanevm](https://github.com/f-prime/arcanevm), which is a separate implementation of the same idea, and where future efforts will be directed.__

## Current state
A bunch of infrastructure and accessing the tape at an encrypted location is implemented

## Building
```
git submodule update --init --recursive
mkdir build && cd build
cmake ..
make
./cryptvm
```
