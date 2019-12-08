# CryptVM
An attempt to build a Brainfuck VM with homomorphic encryption

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
