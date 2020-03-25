// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
/// Shared test cases.

#pragma once

// Put in anonymous namespace to allow be include in multiple files
// but also make iteration over test cases easy with range-based for loop.
namespace
{
struct hash_test_case
{
    int block_number;
    const char* header_hash_hex;
    const char* nonce_hex;
    const char* mix_hash_hex;
    const char* final_hash_hex;
};

hash_test_case hash_test_cases[] = {
    {
        0,
        "2a8de2adf89af77358250bf908bf04ba94a6e8c3ba87775564a41d269a05e4ce",
        "4242424242424242",
        "89b6b75f64a89b05393536d14ccea1f8b40d8dffab98d5a812e2f9210d5118d3",
        "89b612bfaf68f940af983f44fc22df6dfc2836a8f6d5f9da4ebe483d868761c5",
    },
    {
        2,
        "100cbec5e5ef82991290d0d93d758f19082e71f234cf479192a8b94df6da6bfe",
        "307692cf71b12f6d",
        "8cdb6f34b433e7871a672c925a7516c469596739b720112b8513e34843cd811f",
        "c6ad74a4ea186a1563bc42606601ab8100712c828394b9eb7f5d37bb5905ca0a",
    },
    {
        2683077,
        "0313d03c5ed78694c90ecb3d04190b82d5b222c75ba4cab83383dde4d11ed512",
        "8c5eaec000788d41",
        "052f29b0ea082c24f61fc1c3384de2805fedeccd48d92b10c48ed9c09ae34f7a",
        "4fd5a26e463e692ebfd7db5865944fe00c4e4adae189d0fc8155e025e60692f9",
    },
    {
        5000000,
        "bc544c2baba832600013bd5d1983f592e9557d04b0fb5ef7a100434a5fc8d52a",
        "4617a20003ba3f25",
        "a25fa04b54699e1db81a58501af4dda06216f7e17713406af0c9a72765a9d9c3",
        "00f9ac66c49a290c8befe9db144cf88a9fe5e761fa1564cecf539c13eec8d35b",
    },
    {
        5000001,
        "2cd14041cfc3bd13064cfd58e26c0bddf1e97a4202c4b8076444a7cd4515f8c3",
        "1af47f2007922384",
        "fcd2884114f61bc39c34c4f52ee36aaf22b66037c4b523ada29efe71cb79750f",
        "c293d1a78b773dd1709f029347a384abc4472fe5d23f703d4757e610ae8f5bae",
    },
    {
        5000002,
        "9e79bced19062baf7c47e516ad3a1bd779222404d05b4205def30a13c7d87b5b",
        "c9a044201dd998f2",
        "1d5b97ac3d2c6a7e5cc34d48cb05251db68db2c2d9cfc9c9c6f01146d47f6dd4",
        "c6d434f7ce14378855af7b370acf9085f21c0aea5c1b55d90d74968e89accfc5",
    },
    {
        5306861,
        "53a005f209a4dc013f022a5078c6b38ced76e767a30367ff64725f23ec652a9f",
        "d337f82001e992c5",
        "e5088e744e78343b155944647ff92c625286841bd1c687a1e778778e078151ca",
        "9c48d5ff9744beb63214001acb735bd440ab3e153a56093a223405e32f769543",
    },
};
}  // namespace