# Evrprogpow

> C/C++ implementation of evrprogpow – the Evrmore Proof of Work algorithm
> Note: This is the reference implementation of evrprogpow

This repository was forked from https://github.com/RavenCommunity/cpp-kawpow

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Test vectors](#test-vectors)
- [Optimizations](#optimizations)
- [Maintainer](#maintainer)
- [License](#license)


## Install

Build from source using CMake on Ubuntu 22.04

```sh
sudo apt install gcc-9 g++-9 libevent-dev

mkdir build
cd build
cmake -DCMAKE_C_COMPILER=/usr/bin/gcc-9 -DCMAKE_CXX_COMPILER=/usr/bin/g++-9 ..
cmake --build .
```

Build from source using CMake.

```sh
mkdir build
cd build
cmake ..
cmake --build .
```

Build the evrhash module (often used in python for ElectrumX server;
often done in a virtualenv)

```
python setup.py install
```


## Usage

See [ethash.hpp] for list of exported function and documentation.


## Test vectors

- [ProgPoW test vectors](test/unittests/progpow_test_vectors.hpp)


## Optimizations

This section decscribes the optimizations, modification and tweaks applied
in this library in relation to [Ethash reference implementation].

The library contains a set of micro-benchmarks. Build and run `bench` tool.

### Seed hash is computed on the fly.
   
Seed hash is sequence of keccak256 hashes applied the epoch number of times.
Time needed to compute seed hash is negligible comparing to time needed to build
light cache. Computing seed hash for epoch 10000 takes ~ 5 ms, building light
cache for epoch 1 takes ~ 500 ms.

### Dataset size is computed on the fly

Computing the size of full dataset and light cache requires finding the largest
prime number given an upper bound. For similar reasons as with seed hash, this
is computed on the fly. The procedure used is quite naive and forks well only
up to 40-bit number, so some additional improvement can be done in future.
   
    
## Maintainer

Hans Schmidt [@Hans-Schmidt]  
Paweł Bylica [@chfast]

## License

Licensed under the [Apache License, Version 2.0].


[@chfast]: https://github.com/chfast
[Apache License, Version 2.0]: LICENSE
[ethash.hpp]: include/ethash/ethash.hpp
[Ethash reference implementation]: https://github.com/ethereum/wiki/wiki/Ethash
