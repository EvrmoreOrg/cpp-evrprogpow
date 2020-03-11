# ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
# Copyright 2018-2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

add_subdirectory(benchmarks)
add_subdirectory(fakeminer)
add_subdirectory(integration)
add_subdirectory(tools)
add_subdirectory(unittests)
add_subdirectory(lightverify)
add_subdirectory(daemon)

if(ETHASH_FUZZING)
    add_subdirectory(fuzzing)
endif()
