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
        "58f759ede17a706c93f13030328bcea40c1d1341fb26f2facd21ceb0dae57017",
        "dd47fd2d98db51078356852d7c4014e6a5d6c387c35f40e2875b74a256ed7906",
    },
    {
        2,
        "100cbec5e5ef82991290d0d93d758f19082e71f234cf479192a8b94df6da6bfe",
        "307692cf71b12f6d",
        "e55d02c555a7969361cf74a9ec6211d8c14e4517930a00442f171bdb1698d175",
        "ab9b13423cface72cbec8424221651bc2e384ef0f7a560e038fc68c8d8684829",
    },
    {
        2683077,
        "0313d03c5ed78694c90ecb3d04190b82d5b222c75ba4cab83383dde4d11ed512",
        "8c5eaec000788d41",
        "99ee3c3e67abe0ee677903379fe4846b2c04b2e9582dfe2a73bea357a9943aae",
        "a3e50b3bab6dd19500d550d3494d9a20050b7679554ed4e43fe707223bd19591",
    },
    {
        5000000,
        "bc544c2baba832600013bd5d1983f592e9557d04b0fb5ef7a100434a5fc8d52a",
        "4617a20003ba3f25",
        "51428ed3f969ff0e205a3727cefa0f22b7c0d1162197158a93ad272524dfeb54",
        "7b19738f9876ba222334588734506913ca18c8a59c118ca93fbc6e415d154fd7",
    },
    {
        5000001,
        "2cd14041cfc3bd13064cfd58e26c0bddf1e97a4202c4b8076444a7cd4515f8c3",
        "1af47f2007922384",
        "025de930a0ece09a2240822b6bdd715b481e7a2fe2f990b8aa84cf72c947029d",
        "6e11142c70abce99244e4332116dc61c897a44d6f8c6adb231f4d5322a3d9132",
    },
    {
        5000002,
        "9e79bced19062baf7c47e516ad3a1bd779222404d05b4205def30a13c7d87b5b",
        "c9a044201dd998f2",
        "30a4777f63a6a386e5523726c64c8de1a676a54c7782629f09af9d425aa93b66",
        "51a63f18f351ac64dc478c4e316cf3379654e60b667e6423977160041cd20cc0",
    },
    {
        5306861,
        "53a005f209a4dc013f022a5078c6b38ced76e767a30367ff64725f23ec652a9f",
        "d337f82001e992c5",
        "3431011050f134f289b001cc47cd40756fc0a341af56d12a6c883f28e4b02c35",
        "0195c63731e2817811a144aa32f984b9098536d70c97f9420bc93675c8e0bdf4",
    },
};
}  // namespace