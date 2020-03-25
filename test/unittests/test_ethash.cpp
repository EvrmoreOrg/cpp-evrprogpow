// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#pragma GCC diagnostic ignored "-Wpedantic"
#pragma clang diagnostic ignored "-Wpedantic"

#include <ethash/endianness.hpp>
#include <ethash/ethash-internal.hpp>
#include <ethash/ethash.hpp>
#include <ethash/keccak.hpp>

#include "helpers.hpp"
#include "test_cases.hpp"

#include <gtest/gtest.h>

#include <array>
#include <future>

using namespace ethash;

namespace
{
struct test_context_full : epoch_context
{
    hash1024* full_dataset;
};

/// Creates the epoch context of the correct size but filled with fake data.
epoch_context_ptr create_epoch_context_mock(int epoch_number)
{
    // Prepare a constant endianness-independent cache item.
    hash512 fill;
    static constexpr uint64_t fill_word = 0xe14a54a1b2c3d4e5;
    std::fill_n(fill.word64s, sizeof(hash512) / sizeof(uint64_t), le::uint64(fill_word));

    static const size_t context_alloc_size = std::max(sizeof(epoch_context), sizeof(hash512));

    // The copy of ethash_create_epoch_context() but without light cache building:

    const int light_cache_num_items = calculate_light_cache_num_items(epoch_number);
    const size_t light_cache_size = get_light_cache_size(light_cache_num_items);
    const size_t alloc_size = context_alloc_size + light_cache_size;

    char* const alloc_data = static_cast<char*>(std::malloc(alloc_size));
    hash512* const light_cache = reinterpret_cast<hash512*>(alloc_data + context_alloc_size);
    std::fill_n(light_cache, light_cache_num_items, fill);

    epoch_context* const context = new (alloc_data) epoch_context{
        epoch_number,
        light_cache_num_items,
        light_cache,
        nullptr,
        calculate_full_dataset_num_items(epoch_number),
    };
    return {context, ethash_destroy_epoch_context};
}

hash512 copy(const hash512& h) noexcept
{
    return h;
}
}

TEST(ethash, revision)
{
    static_assert(ethash::revision[0] == '2', "");
    static_assert(ethash::revision[1] == '3', "");
    EXPECT_EQ(ethash::revision, "23");
    EXPECT_EQ(ethash::revision, (std::string{"23"}));
}

TEST(hash, hash256_from_bytes)
{
    const uint8_t bytes[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    auto h = hash256_from_bytes(bytes);
    EXPECT_EQ(to_hex(h), "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

TEST(hash, hash512_init)
{
    hash512 hash = {};
    for (auto w : hash.word64s)
        EXPECT_EQ(w, 0);

    hash512 hash2 = copy({});
    for (auto w : hash2.word64s)
        EXPECT_EQ(w, 0);
}

TEST(hash, hash1024_init)
{
    hash1024 hash = {};
    for (auto w : hash.word64s)
        EXPECT_EQ(w, 0);
}

struct dataset_size_test_case
{
    int epoch_number;
    uint64_t light_cache_size;
    uint64_t full_dataset_size;
};

/// Test cases for dataset sizes are random picked from generated ethash sizes.
/// See https://github.com/ethereum/wiki/wiki/Ethash#data-sizes.
static dataset_size_test_case dataset_size_test_cases[] = {
    {0, 16776896, 1073739904},
    {14, 18611392, 1191180416},
    {17, 19004224, 1216345216},
    {56, 24116672, 1543503488},
    {158, 37486528, 2399139968},
    {203, 43382848, 2776625536},
    {211, 44433344, 2843734144},
    {272, 52427968, 3355440512},
    {350, 62651584, 4009751168},
    {412, 70778816, 4529846144},
    {464, 77593664, 4966054784},
    {530, 86244416, 5519703424},
    {656, 102760384, 6576662912},
    {657, 102890432, 6585055616},
    {658, 103021888, 6593443456},
    {739, 113639104, 7272921472},
    {751, 115212224, 7373585792},
    {798, 121372352, 7767849088},
    {810, 122945344, 7868512384},
    {862, 129760832, 8304715136},
    {882, 132382528, 8472492928},
    {920, 137363392, 8791260032},
    {977, 144832448, 9269411456},
    {1093, 160038464, 10242489472},
    {1096, 160430656, 10267656064},
    {1119, 163446592, 10460589952},
    {1125, 164233024, 10510923392},
    {1165, 169475648, 10846469248},
    {1168, 169866304, 10871631488},
    {1174, 170655424, 10921964672},
    {1211, 175504832, 11232345728},
    {1244, 179830208, 11509169024},
    {1410, 201588544, 12901672832},
    {1418, 202636352, 12968786816},
    {1436, 204996544, 13119782528},
    {1502, 213645632, 13673430656},
    {1512, 214956992, 13757316224},
    {1535, 217972672, 13950253696},
    {1538, 218364736, 13975417216},
    {1554, 220461632, 14109635968},
    {1571, 222690368, 14252243072},
    {1602, 226754368, 14512291712},
    {1621, 229243328, 14671675264},
    {1630, 230424512, 14747172736},
    {1698, 239335232, 15317596544},
    {1746, 245628736, 15720251264},
    {1790, 251395136, 16089346688},
    {1818, 255065792, 16324230016},
    {1912, 267386432, 17112759424},
    {1928, 269482688, 17246976896},
    {1956, 273153856, 17481857408},
    {2047, 285081536, 18245220736},
    {30000, 3948936512, 252731976832},
    {32639, 4294836032, 274869514624},
};

TEST(ethash, light_cache_size)
{
    for (const auto& t : dataset_size_test_cases)
    {
        int num_items = calculate_light_cache_num_items(t.epoch_number);
        size_t size = get_light_cache_size(num_items);
        EXPECT_EQ(size, t.light_cache_size) << "epoch: " << t.epoch_number;
    }
}

TEST(ethash, full_dataset_size)
{
    for (const auto& t : dataset_size_test_cases)
    {
        const int num_items = calculate_full_dataset_num_items(t.epoch_number);
        const uint64_t size = get_full_dataset_size(num_items);
        EXPECT_EQ(size, t.full_dataset_size) << "epoch: " << t.epoch_number;
    }
}


struct epoch_seed_test_case
{
    const int epoch_number;
    const char* const epoch_seed_hex;
};

static epoch_seed_test_case epoch_seed_test_cases[] = {
    {0, "0000000000000000000000000000000000000000000000000000000000000000"},
    {1, "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"},
    {171, "a9b0e0c9aca72c07ba06b5bbdae8b8f69e61878301508473379bb4f71807d707"},
    {2048, "20a7678ca7b50829183baac2e1e3c43fa3c4bcbc171b11cf5a9f30bebd172920"},
    {29998, "1222b1faed7f93098f8ae498621fb3479805a664b70186063861c46596c66164"},
    {29999, "ee1d0f61b054dff0f3025ebba821d405c8dc19a983e582e9fa5436fc3e7a07d8"},
};

TEST(ethash, calculate_epoch_seed)
{
    for (auto& t : epoch_seed_test_cases)
    {
        const hash256 epoch_seed = calculate_epoch_seed(t.epoch_number);
        EXPECT_EQ(epoch_seed, to_hash256(t.epoch_seed_hex));
    }
}


TEST(ethash, find_epoch_number_double_ascending)
{
    const hash256 seed_29998 = to_hash256(epoch_seed_test_cases[4].epoch_seed_hex);
    const hash256 seed_29999 = to_hash256(epoch_seed_test_cases[5].epoch_seed_hex);

    int epoch = find_epoch_number(seed_29998);
    EXPECT_EQ(epoch, 29998);

    // The second call should be fast.
    epoch = find_epoch_number(seed_29999);
    EXPECT_EQ(epoch, 29999);
}

TEST(ethash, find_epoch_number_double_descending)
{
    const hash256 seed_29998 = to_hash256(epoch_seed_test_cases[4].epoch_seed_hex);
    const hash256 seed_29999 = to_hash256(epoch_seed_test_cases[5].epoch_seed_hex);

    int epoch = find_epoch_number(seed_29999);
    EXPECT_EQ(epoch, 29999);

    // The second call should be fast.
    epoch = find_epoch_number(seed_29998);
    EXPECT_EQ(epoch, 29998);
}

TEST(ethash, find_epoch_number_sequential)
{
    hash256 seed = {};
    for (int i = 0; i < 30000; ++i)
    {
        auto e = find_epoch_number(seed);
        EXPECT_EQ(e, i);
        seed = keccak256(seed);
    }
}

TEST(ethash, find_epoch_number_sequential_gap)
{
    constexpr int start_epoch = 200;
    hash256 seed = calculate_epoch_seed(start_epoch);
    for (int i = start_epoch; i < 30000; ++i)
    {
        auto e = find_epoch_number(seed);
        EXPECT_EQ(e, i);
        seed = keccak256(seed);
    }
}

TEST(ethash, find_epoch_number_descending)
{
    for (int i = 2050; i >= 2000; --i)
    {
        auto seed = calculate_epoch_seed(i);
        auto e = find_epoch_number(seed);
        EXPECT_EQ(e, i);
    }

    for (int i = 50; i >= 0; --i)
    {
        auto seed = calculate_epoch_seed(i);
        auto e = find_epoch_number(seed);
        EXPECT_EQ(e, i);
    }
}

TEST(ethash, find_epoch_number_invalid)
{
    hash256 fake_seed = {};
    fake_seed.word32s[0] = 1;
    int epoch = find_epoch_number(fake_seed);
    EXPECT_EQ(epoch, -1);
}

TEST(ethash, find_epoch_number_epoch_too_high)
{
    hash256 seed = calculate_epoch_seed(30000);
    int epoch = find_epoch_number(seed);
    EXPECT_EQ(epoch, -1);
}

TEST(ethash_multithreaded, find_epoch_number_sequential)
{
    auto fn = [] {
        hash256 seed = {};
        for (int i = 0; i < 30000; ++i)
        {
            auto e = find_epoch_number(seed);
            EXPECT_EQ(e, i);
            seed = keccak256(seed);
        }
    };

    std::array<std::future<void>, 4> futures;
    for (auto& f : futures)
        f = std::async(std::launch::async, fn);
    for (auto& f : futures)
        f.wait();
}

TEST(ethash, get_epoch_number)
{
    EXPECT_EQ(get_epoch_number(0), 0);
    EXPECT_EQ(get_epoch_number(1), 0);
    EXPECT_EQ(get_epoch_number(7499), 0);
    EXPECT_EQ(get_epoch_number(7500), 1);
    EXPECT_EQ(get_epoch_number(7501), 1);
    EXPECT_EQ(get_epoch_number(7502), 1);
    EXPECT_EQ(get_epoch_number(1245000), 166);
}

TEST(ethash, light_cache)
{
    struct light_cache_test_case
    {
        const int epoch_number;
        const char* const hash;
    };

    light_cache_test_case test_cases[] = {
        {0, "35ded12eecf2ce2e8da2e15c06d463aae9b84cb2530a00b932e4bbc484cde353"},
        {171, "468ef97519bd780a0dbd19d46c099118d6f4b777c1b8d0d4b0d6f62a5018100e"},
        {2047, "47e5913c1f0ffffa5ba1049f6d7960259a5e7e8736e3f032cc7a04e7b29ffb42"},
    };

    for (const auto& t : test_cases)
    {
        auto context = create_epoch_context(t.epoch_number);
        const uint8_t* const light_cache_data = context->light_cache[0].bytes;
        const size_t light_cache_size =
            static_cast<size_t>(context->light_cache_num_items) * sizeof(context->light_cache[0]);
        const hash256 light_cache_hash = keccak256(light_cache_data, light_cache_size);
        EXPECT_EQ(light_cache_hash, to_hash256(t.hash));
    }
}

TEST(ethash, fake_dataset_partial_items)
{
    struct full_dataset_item_test_case
    {
        uint32_t index;
        const char* hash_hex;
    };

    // clang-format off
    full_dataset_item_test_case test_cases[] = {
        {0,          "249b779178ab36972cf2c8510bb121124570bd1558da801773ba575c3a5c82f486770788b2e6093040b1e9f582bea6f7033368ff3633359f7d9aad20cc57e08c"},
        {1,          "2c482904daa8167586456a2e97e2308c8d74d9f5fc531536dfbe0afc48f9ab865b8d3d990cb071e1b16f211aacd740ec2404ce1333936a19eeb3e62aeed08fc8"},
        {13,         "e121c4dc1d64d741a4a41a79752b57dfb08ee56bda1dccbaf042a299d4cd8990759b984f4b9f4864820c6768b7ea789484bda1a262e9393a2d921245b95cc965"},
        {171,        "fb03f4551f78d4159faa97b8f1b28d9cdf8dc2e210d8ff740f72022ff0c760edca516925376be2e646f4d530590985a506a6fc4023a0422841d8ad70382d8e4f"},
        {571,        "0eac6b9d4504550a715e1c5c1df3c158ae0a6c8f6a303184c33e30e946dd03521c6e6f122418b6d31debd83a28cc732b7b0f5239c1188dce04c5a341e93222b2"},
        {620,        "4a47668b57cda8b58e88a68e6d4fc61b2172e2a171f3e73f84eb11e56810be4b9a357149be2684d2ea820406320e89aa5cd647a9b7b0e08d7a442890a34eb8f8"},
        {514079,     "ca48b22da0f0a12c1b6d1f0258e2e5459b333b4faa43f61e5e26ff0400d18d6e3802337600f84aa682e35bdb7ec7a9323d23e414aa1f248951a66c0d523e18e5"},
        {852881,     "c20b047af2d39a9ec386b20d5b76c6e1046ff8a78e6d218c9bf4c7028092440808c6bd7987a2976829b53bef400ceb613e0def725fea8f906814f8a64bbda334"},
        {6133492,    "562bda8b8a1d4be16468c28912eb5e9baae6ed58ab78dbfa5e4189c22c0017a75015641db72720363771a1c66d01d25f646bd2283ddb3a7b927bf16fc685a63b"},
        {6133493,    "18ee243b900e199a19c9f86a66784af6716f7b7a1a720a9a37fcad5c0e22d78f6d6f24fae4fc61584fafa02be520fae7f775f41d2c5eedf0cc79658e3a69f8cc"},
        {211322105,  "c4b21987196f3634cf928971fba49db92a4e5c557a4f7c64495313c7015aa4d7ab667282e0dc6eb30cc0e7b1757034451e16785b8958b99c8632e0fe8f340b2d"},
        {740620450,  "3bf190e64d003ada99af01ef1e5a361677fc85611b913877de459edbd3a89ea5ff06d890d4b9a82dd9d72f509a40e65ab73a75462eb8805516b7ada9e7c0f3e0"},
        {4294967295, "fcc77b447e1a88bb497eee86e2f1718310ae9add3277e944e3f139c948fc95d0a11867cd962e1332c185b15b85fbd64ec67299a1a83e3c316629d1985f13709d"},
    };
    // clang-format on

    // Mock the epoch context.
    auto context = create_epoch_context_mock(0);

    for (const auto& t : test_cases)
    {
        const auto full_index = t.index / 2;
        const auto part_index = t.index % 2;

        const auto full_item = calculate_dataset_item_1024(*context, full_index);
        const auto& part_item = full_item.hash512s[part_index];
        EXPECT_EQ(to_hex(part_item), t.hash_hex) << "index: " << t.index;
    }
}

TEST(ethash, fake_dataset_items)
{
    struct full_dataset_item_test_case
    {
        uint32_t index;
        const char* hash1_hex;
        const char* hash2_hex;
    };

    // clang-format off
    full_dataset_item_test_case test_cases[] = {
        {0,
            "249b779178ab36972cf2c8510bb121124570bd1558da801773ba575c3a5c82f486770788b2e6093040b1e9f582bea6f7033368ff3633359f7d9aad20cc57e08c",
            "2c482904daa8167586456a2e97e2308c8d74d9f5fc531536dfbe0afc48f9ab865b8d3d990cb071e1b16f211aacd740ec2404ce1333936a19eeb3e62aeed08fc8"},
        {1,
            "7545c0be918e21dc7cf36443e4197af7b5707bb6149745a1131de8e13287498a5c04846978cdae7e02ddaa8c389ef50bd3687d3b4cfb577c66e73febb0ff0820",
            "25ac24c17584eaf9ea498fe4bbf6513ddfaca06e57508b59c68e0e8acefadf336a50b70cd63b8ba1f200ac04c5f3185b73193e7db76321bdb8af28b7fbb2ab45"},
        {13,
            "14b94000fb36d5ef29eb4341a51a4a90e3db3ad8473410ee3c4083670f6d9f03dcd411e3d605131fa7d15439ec2c3774f005eaf730d6cfe80b01f16a669e027b",
            "96e4c3b30dbf230175d5362154485164858e824790b18326137785980836a1cc478faa484327579a983f2e66e00a8a4d59ff7168d56fb5753cd3746c5a677012"},
        {171,
            "cd3254c571e3f47515666fcaeacf6f510e2fc85cc8180d5c28f7d221811e91ee0da1174fef0b4bb70eb8171a6fc8ad1d9e7ce71492417aa247c66ad33bd5884c",
            "e530fffbb66e45a8cbdea6173f84992bb83ae45bdd579eed985aba39f7a2ed9686b02dc423a60a7b4737b116611ae125593f23ef3498b59435cb152f7abe0727"},
        {571,
            "476ea1ba2c171b70212b51bf49d0a02a9fbb22a5969cafd959224978c76feda896dc6df9e8e49b132d16c404cdc518098aafe7d1c6c25e243031a63dc1b6d47e",
            "5a83fa04e7c9d85e0e69a7d64741467e7760071da31c014afdfa71fa6bfbc593f4cd85624529a0f19746086a89b0784167e695944e08023a12345926dbc69e49"},
        {620,
            "64cdf7def22cbdecb79fbfd848b8effdfb229c3a555e74eb25bfc49b8c0a66257dec7cee535722f593c8ae5fc3f8e1b33b000578543b0cf025c01e1d3a74d12f",
            "0ef57bf68a61a1ef1c92fca43dc235e8f265da7c910a7360ffa14867c0fe0395aca9a2d6086e7226b84b4ac476044eb9344dde59704fca8bccccdb82239487e3"},
        {514079,
            "90e1c65bd1e9aae7c4cb64fc62c1dc54f4a32ba00596014e978a91a443ead5a22ddff96ec1d549e829999b7221dc3fcd2e136678827a2a283f0313d6b9352440",
            "e683fe2bbbcb603f475d22610ac4c1bf4ac99fd6e4790fba8640d9b9eb5c3e4a8c47499e809ccc59bac5b114602ad6bc1bedf781788dd3b3c5d426d9afb2c740"},
        {852881,
            "11c04c1a7931df3a6905494c4f0d6516a76f96acc849f4fcea62211aca82eb623aa32975dc88497d10fe2e96f3ec20653f31d7a92c3686f03406cfe174352578",
            "f95d10e7ced0df2429eedf29b88ba7b0309254c95bc49021f3d67d337e164af84fadbb470daf41fa6ab153626e43dfe95b0ddfd464fccf219fc86a01642a18f2"},
        {6133492,
            "6c0a3a13cced68a25b9df6360ede9b25725fcb036723554a3570eb2a151ea44cd5d6fff1675a7a95cc1d7621a80d988290adea9704138b4b3a9ec59809e2499e",
            "cf8e58bcd46f26ed20fa23dbf44a41ec949e5e6e762d84e83bab4b61c45304fa0e5a160f831a7f3ca54c6e2c1dbea7b43a72f82a419754814b67fdd7b61516f0"},
        {6133493,
            "ad0ed455758a7bbf4b48f0031e0cc8b01fe794d5586421adab8a1c8e7e425076564ee4663ffc64dbf0ba9a3af4f957b53939d2a95a6cfd737c75bb6b106133a5",
            "014932e3023890f2bfc983b8ad827f83e4311d5a794093120ee879ccded934a15c51eca3aa8ed85c1d58b4d202582b743ff0c83f66c46ea7ec85d185d3dd317e"},
        {211322105,
            "a460b1bbbf93ee8bb729126aeaee33921f07f34584c4aacd850e9d0ae5ffb4f0bf94d7843b388709ab22ed5c76707d6d104fa96541491556ac506c4926cd6f63",
            "03c5cb0d9248c67af849fae111db462e8955a5cf570482ae8b18f0800ad0e7b185d448fb30447fa0cda8968ce777ed701c4b84090742468a70b419c61417579d"},
        {740620450,
            "a9361ed6719d85ea2cb8cb66d7bd0bdd923d687d4bb70b84558abb52555da479e9fc6aa0eaf26dd3daa358dbeab555648a6b9dae93cf8006bdee4a7b13cae9a7",
            "52dd8e1b6d4371ea5292748dcf2c233e85092d74584d0553df8d8f0bca82ccfa42d9a73900664fada532539d4328699d58e5c73c79421d6b64354f5b03c204a9"},
        {4294967295,
            "5a73e9813bc6bc68cfd32ee479e14eb4a7feacaf9b4256bd6980ed6fdae30b8120a199638ba41626d2dfb79205447bb821817a840597507bbabc447ba65fbcc2",
            "fcc77b447e1a88bb497eee86e2f1718310ae9add3277e944e3f139c948fc95d0a11867cd962e1332c185b15b85fbd64ec67299a1a83e3c316629d1985f13709d"},
    };
    // clang-format on

    // Mock the epoch context.
    auto context = create_epoch_context_mock(0);

    for (const auto& t : test_cases)
    {
        const hash1024 item1024 = calculate_dataset_item_1024(*context, t.index);
        EXPECT_EQ(to_hex(item1024.hash512s[0]), t.hash1_hex) << "index: " << t.index;
        EXPECT_EQ(to_hex(item1024.hash512s[1]), t.hash2_hex) << "index: " << t.index;

        const hash512 item512_0 = calculate_dataset_item_512(*context, int64_t(t.index) * 2);
        EXPECT_EQ(to_hex(item512_0), t.hash1_hex) << "index: " << t.index;

        const hash512 item512_1 = calculate_dataset_item_512(*context, int64_t(t.index) * 2 + 1);
        EXPECT_EQ(to_hex(item512_1), t.hash2_hex) << "index: " << t.index;

        const hash2048 item2048 = calculate_dataset_item_2048(*context, t.index / 2);
        EXPECT_EQ(to_hex(item2048.hash512s[(t.index % 2) * 2]), t.hash1_hex);
        EXPECT_EQ(to_hex(item2048.hash512s[(t.index % 2) * 2 + 1]), t.hash2_hex);
    }
}


TEST(ethash, dataset_items_epoch13)
{
    struct full_dataset_item_test_case
    {
        uint32_t index;
        const char* hash1_hex;
        const char* hash2_hex;
    };

    // clang-format off
    full_dataset_item_test_case test_cases[] = {
        {0,
            "bbae35d16fcdb5bd8f968cc3058d5122cc7d33051bcab1fb91b36611365a6ee5df00073f7af5ee474d0402796e8f861c586fdc0eb5fbc4fe882b5c7add3060f4",
            "03aaefbded42b87083cdefc33e05155de09e197c590310c1547e12a656fa7a56f4131bf8690a4075d1c4e86881b8c0dd2e8477d3af4f862c9a07e0a55d11eae5"},
        {1,
            "2174179fc00dbf56d0dcc67483e4e95a2a5d749fc32f2cddf0903b08a35ab8ef115361c6e34024895404a4857435201db9b96edabe6911147cec415e05c04441",
            "58619ad66ce26819bde6e54dd2f150e22c5fdb3a86209a583a284dc117844644654448b5a3ed20bc90bcc50e0e2687e8a373e8a5354d0a6d64d5af1fa40d8f92"},
        {13,
            "a54402f64d8eabf8278fdba3ed454da8b50e222be0198c8d91e781de73247c01a760a70c6c5fba27b1037379e3b15a10f6f8662c09c409e9c9daaea895affd42",
            "f10eb7f5d94c019ff8cf002da340a3e66fcc0a6e94fdf384b15e03cfaac7cb56990ebad95940b27e16e881f7655fabfa6c1023083b6fce4d40e4ff313a1ebf6e"},
        {171,
            "b16294310bd5f5a7df4ee5c73d26bd4ee18b9f828de7d65111c1708c221663843af38a36b127219633adf2d5c377c02c4b99588efb78c4f0d575c7440c1edf1f",
            "0619ccc34b48ce9825b58e2a45c7d72a971ea3624804eae2cbd96ba6a8eca6706abdc62c1ccc102b109851334e2b6b4eb6324c284949bcdb2959575fdaafd102"},
        {571,
            "775e657ef8b2734d126e4c38e1853c4ed780351c270acb79839e71550d5a633573097da20dcab53d678754b27c06d931f40fc510c320056ea0ba5811c11a93c8",
            "dd8973d774c0e5790a5ff12f9461a938a1517ada0ad3270d5fbe7361cd8b1e147806891fca1b99d15424c7ca3ca0b3dea17c67e7ec93932c9af5f18be9e49157"},
        {620,
            "6cdc84719cfd9ffbef9ab876dfe15fa1f15c8d3cde45db39490e41698a4517e73501047b25a7e57a4a50027bd4122effe1df9a4717a88abd1ba35946647051d9",
            "97504e2362880f10c15f37aad066ab1279316b6aa70069ac3e62af1d0b4b56529041a09f4732f48a0257c86e3cee00bd288199a3e6ae8af9b7ae9b6ba17523ad"},
        {514079,
            "935a8a8562d07ca4c8416e129e0bc89248bb12280990629d382bdc5e8c14a418df0519f3c99082d18380530e8dc544838eb6cbb507d3538cd1a762f8ad8f123d",
            "2cc447bda863ae2b36a818d632001eb76c65173d0dccb31ade07b2c405b74993284316f7b97cabb24dfad82bf4d81d138259375d6d3bdec7ad180f52c9eea9b8"},
        {852881,
            "b16eb0032daaf0e27b21d36f0ef84772aa7172302e0c746592c958a46fce392381eb919a2e3b30f0a676bb97d6058e11367ada7a4197e4c0a0a1ea5d2718fc2a",
            "25a8767c3ec55c307ec1a61bebe1b63420fab963e6fedaf2595efdf42ba5a8d0fabd577c39c9ed30ab6cdd1cac2be3b70067ff3d64342d3082d87f099858160d"},
        {6133492,
            "36291b7728d7ff4150d77c1e66b07e24d02d7e8169199206bd1e0e12c44be7fdd6d6282007c414334330abce76cb4a41c4db18936d9310d1d111f29ee4804cd0",
            "e38365e687f7359ce5688250174b72b7fce482a7353d136d8afa8ebbfa65b98940997f2addb9032593b03df281e3a56132ee22c860be23fdb3d71ae0b2a06c15"},
        {6133493,
            "67bf82e5857f3870593f8f3e61761e11d117f8d105cb7cfce1d9dfd38bad03b9c7e8321685453311f48da7a886450722895cba8a38593cea7b433a54c2cd89d3",
            "fe3037b80a4617b2da1e37b765d8615587dd2af8a803b75a0ad51539d73af2b627f31288b260b35c517146089534b154fd5ce717b5beac2a1183b894696d56d7"},
        {211322105,
            "0b0fe98577fe811f79d9f44cd047793d0dc319fc5e79f0338b0f15d25045688f5771ac93fb115ea81849391cabc8439acf3d54fd3cc546e36cc5d83edc2f0cd9",
            "b63c30bfa1fb579b183a2d72aff6316a1a6586aba1464ea2739f60ad1880f86609753e9f76b395874b62210cc3fce95efbfaad8ae5f17dd0524405c050503d9d"},
        {740620450,
            "700b5b6df0477540f9a45c05adf9fac6b063c23df4fb0711934d70c723de8d5776ceb2637157f59e88e37350d7ba8ed74dea06c9451676b3fcbfbf8cbfba1d98",
            "e4f7066012bb94313b7dbe61d23c66d9b4c56287ceab483de1c53d31d08995cb221fef0b66497f07f9eb527441057b739dd205754563904a739bb8e13d5c97fc"},
        {4294967295,
            "17e9134009bf22b2ff5e216aff5793c22133a41845e8ebd6420a930fc47d1cb92ee86aa5ff883b5234f4a7b9554ba284a377d4d98697476a10d85a0f8b2432f1",
            "b79a3d547063ae1dcbc55e2d972b0a566e93459371d9bcfc208cbef7b67f2cce6b79a50f53e4173c3629a7c2a663f04b2eae07c2ec57044810b13eef180b8711"},
    };
    // clang-format on


    // Create example epoch context.
    const auto context = create_epoch_context(13);

    for (const auto& t : test_cases)
    {
        const hash1024 item = calculate_dataset_item_1024(*context, t.index);
        EXPECT_EQ(to_hex(item.hash512s[0]), t.hash1_hex) << "index: " << t.index;
        EXPECT_EQ(to_hex(item.hash512s[1]), t.hash2_hex) << "index: " << t.index;
    }
}

TEST(ethash, verify_hash_light)
{
    epoch_context_ptr context{nullptr, ethash_destroy_epoch_context};

    for (const auto& t : hash_test_cases)
    {
        const int epoch_number = t.block_number / epoch_length;
        const uint64_t nonce = std::stoull(t.nonce_hex, nullptr, 16);
        const hash256 header_hash = to_hash256(t.header_hash_hex);
        const hash256 mix_hash = to_hash256(t.mix_hash_hex);
        const hash256 boundary = to_hash256(t.final_hash_hex);

        if (!context || context->epoch_number != epoch_number)
            context = create_epoch_context(epoch_number);

        result r = hash(*context, header_hash, nonce);
        EXPECT_EQ(to_hex(r.final_hash), t.final_hash_hex);
        EXPECT_EQ(to_hex(r.mix_hash), t.mix_hash_hex);

        bool v = verify_final_hash(header_hash, mix_hash, nonce, boundary);
        EXPECT_TRUE(v);
        v = verify(*context, header_hash, mix_hash, nonce, boundary);
        EXPECT_TRUE(v);

        const bool within_significant_boundary = r.final_hash.bytes[0] == 0;
        if (within_significant_boundary)
        {
            v = verify_final_hash(header_hash, mix_hash, nonce + 1, boundary);
            EXPECT_FALSE(v) << t.final_hash_hex;
        }

        v = verify(*context, header_hash, mix_hash, nonce + 1, boundary);
        EXPECT_FALSE(v);
    }
}

TEST(ethash, verify_hash)
{
    epoch_context_full_ptr context{nullptr, ethash_destroy_epoch_context_full};

    for (const auto& t : hash_test_cases)
    {
        const int epoch_number = t.block_number / epoch_length;
        const uint64_t nonce = std::stoull(t.nonce_hex, nullptr, 16);
        const hash256 header_hash = to_hash256(t.header_hash_hex);

        const int full_dataset_num_items = calculate_full_dataset_num_items(epoch_number);
        const uint64_t full_dataset_size = get_full_dataset_size(full_dataset_num_items);

        if (!context || context->epoch_number != epoch_number)
            context = create_epoch_context_full(epoch_number);

#if _WIN32 && !_WIN64
        // On Windows 32-bit you can only allocate ~ 2GB of memory.
        static constexpr uint64_t allocation_size_limit = uint64_t(2) * 1024 * 1024 * 1024;
        if (!context && full_dataset_size > allocation_size_limit)
            continue;
#endif
        ASSERT_NE(context, nullptr);
        EXPECT_GT(full_dataset_size, 0);

        result r = hash(*context, header_hash, nonce);
        EXPECT_EQ(to_hex(r.final_hash), t.final_hash_hex);
        EXPECT_EQ(to_hex(r.mix_hash), t.mix_hash_hex);
    }
}

TEST(ethash, verify_final_hash_only)
{
    auto& context = get_ethash_epoch_context_0();
    const hash256 header_hash = {};
    const hash256 mix_hash = {};
    uint64_t nonce = 3221208;
    const hash256 boundary =
        to_hash256("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    EXPECT_TRUE(verify_final_hash(header_hash, mix_hash, nonce, boundary));
    EXPECT_FALSE(verify(context, header_hash, mix_hash, nonce, boundary));
}

TEST(ethash, verify_boundary)
{
    auto& context = get_ethash_epoch_context_0();
    hash256 example_header_hash =
        to_hash256("e74e5e8688d3c6f17885fa5e64eb6718046b57895a2a24c593593070ab71f5fd");
    uint64_t nonce = 6666;
    auto r = hash(context, example_header_hash, nonce);
    hash256 boundary_eq =
        to_hash256("fb9c5f1976144a9c5639b05ac447fcab4ce32bf7796f0a5e47aa5f74f6fa4269");

    hash256 boundary_gt = boundary_eq;
    ++boundary_gt.bytes[31];
    auto boundary_gt_hex = "fb9c5f1976144a9c5639b05ac447fcab4ce32bf7796f0a5e47aa5f74f6fa426a";
    EXPECT_EQ(to_hex(boundary_gt), boundary_gt_hex);

    hash256 boundary_lt = boundary_eq;
    --boundary_lt.bytes[31];
    auto boundary_lt_hex = "fb9c5f1976144a9c5639b05ac447fcab4ce32bf7796f0a5e47aa5f74f6fa4268";
    EXPECT_EQ(to_hex(boundary_lt), boundary_lt_hex);

    EXPECT_EQ(r.final_hash, boundary_eq);
    EXPECT_EQ(to_hex(r.final_hash), to_hex(boundary_eq));

    EXPECT_TRUE(verify(context, example_header_hash, r.mix_hash, nonce, boundary_eq));
    EXPECT_TRUE(verify(context, example_header_hash, r.mix_hash, nonce, boundary_gt));
    EXPECT_FALSE(verify(context, example_header_hash, r.mix_hash, nonce, boundary_lt));
}

TEST(ethash_multithreaded, small_dataset)
{
    // This test creates an extremely small dataset for full search to discover
    // sync issues between threads.

    constexpr size_t num_treads = 8;
    constexpr int num_dataset_items = 501;
    const hash256 boundary =
        to_hash256("0004000000000000000000000000000000000000000000000000000000000000");

    auto context = create_epoch_context_mock(0);
    const_cast<int&>(context->full_dataset_num_items) = num_dataset_items;

    std::unique_ptr<hash1024[]> full_dataset{new hash1024[num_dataset_items]{}};
    reinterpret_cast<test_context_full*>(context.get())->full_dataset = full_dataset.get();
    auto context_full = reinterpret_cast<epoch_context_full*>(context.get());

    std::array<std::future<search_result>, num_treads> futures;
    for (auto& f : futures)
    {
        f = std::async(
            std::launch::async, [&] { return search(*context_full, {}, boundary, 40000, 10000); });
    }

    for (auto& f : futures)
        EXPECT_EQ(f.get().nonce, 40214);
}

TEST(ethash, small_dataset)
{
    constexpr int num_dataset_items = 501;
    const hash256 boundary =
        to_hash256("0080000000000000000000000000000000000000000000000000000000000000");

    auto context = create_epoch_context_mock(0);
    const_cast<int&>(context->full_dataset_num_items) = num_dataset_items;

    std::unique_ptr<hash1024[]> full_dataset{new hash1024[num_dataset_items]{}};
    reinterpret_cast<test_context_full*>(context.get())->full_dataset = full_dataset.get();
    auto context_full = reinterpret_cast<epoch_context_full*>(context.get());

    auto solution = search_light(*context, {}, boundary, 330, 10);
    EXPECT_TRUE(solution.solution_found);
    EXPECT_EQ(solution.nonce, 334);
    auto final_hash_hex = "000f051b8d5c7dbaaed0803978928a45fa77b44eebfa3a8c94ed62fadf050863";
    EXPECT_EQ(to_hex(solution.final_hash), final_hash_hex);
    auto mix_hash_hex = "5bc53aa9a1b2990344ce4c5310337da48f0bea45a5c72e8a82c1c868aca3f934";
    EXPECT_EQ(to_hex(solution.mix_hash), mix_hash_hex);

    solution = search(*context_full, {}, boundary, 330, 10);
    EXPECT_TRUE(solution.solution_found);
    EXPECT_EQ(solution.nonce, 334);
    final_hash_hex = "000f051b8d5c7dbaaed0803978928a45fa77b44eebfa3a8c94ed62fadf050863";
    EXPECT_EQ(to_hex(solution.final_hash), final_hash_hex);
    mix_hash_hex = "5bc53aa9a1b2990344ce4c5310337da48f0bea45a5c72e8a82c1c868aca3f934";

    solution = search_light(*context, {}, boundary, 483, 10);
    EXPECT_FALSE(solution.solution_found);
    EXPECT_EQ(solution.final_hash, hash256{});
    EXPECT_EQ(solution.mix_hash, hash256{});
    EXPECT_EQ(solution.nonce, 0);

    solution = search(*context_full, {}, boundary, 483, 10);
    EXPECT_FALSE(solution.solution_found);
    EXPECT_EQ(solution.final_hash, hash256{});
    EXPECT_EQ(solution.mix_hash, hash256{});
    EXPECT_EQ(solution.nonce, 0);
}

#if !__APPLE__

// The Out-Of-Memory tests try to allocate huge memory buffers. This fails on
// Linux and Windows, but not on macOS. Because the macOS tries too hard
// the tests go forever.
// The tests are disabled on macOS at compile time (instead of using GTest
// filter) because we don't want developers using macOS to be hit by this
// behavior.

#if __linux__
#include <sys/resource.h>

namespace
{
rlimit orig_limit;

bool set_memory_limit(size_t size)
{
    getrlimit(RLIMIT_AS, &orig_limit);
    rlimit limit = orig_limit;
    limit.rlim_cur = size;
    return setrlimit(RLIMIT_AS, &limit) == 0;
}

bool restore_memory_limit()
{
    return setrlimit(RLIMIT_AS, &orig_limit) == 0;
}
}  // namespace

#else

namespace
{
bool set_memory_limit(size_t)
{
    return true;
}

bool restore_memory_limit()
{
    return true;
}
}  // namespace

#endif

static constexpr bool arch64bit = sizeof(void*) == 8;

TEST(ethash, create_context_oom)
{
    static constexpr int epoch = arch64bit ? 3000 : 300;
    static constexpr size_t expected_size = arch64bit ? 26239565696 : 3590324096;
    const int num_items = calculate_full_dataset_num_items(epoch);
    const uint64_t full_dataset_size = get_full_dataset_size(num_items);
    const size_t size = static_cast<size_t>(full_dataset_size);
    ASSERT_EQ(size, full_dataset_size);
    ASSERT_EQ(size, expected_size);

    ASSERT_TRUE(set_memory_limit(1024 * 1024 * 1024));
    auto* context = ethash_create_epoch_context_full(epoch);
    ASSERT_TRUE(restore_memory_limit());
    EXPECT_EQ(context, nullptr);
}
#endif

namespace
{
struct is_less_or_equal_test_case
{
    const char* a_hex;
    const char* b_hex;
    bool excected_result;
};

is_less_or_equal_test_case is_less_or_equal_test_cases[] = {
    {"0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000", true},
    {"0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000", false},
    {"0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001", true},
    {"0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000100", true},
    {"1000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001", false},
    {"1000000000000000000000000000000000000000000000000000000000000000",
        "0010000000000000000000000000000000000000000000000000000000000000", false},
    {"0000000000000000000000000010000000000000000000000000000000000000",
        "0000000000000000000000000001000000000000000000000000000000000000", false},
    {"0000000000000000000000000010000000000000000000000000000000000000",
        "0000000000000000000000000010000000000000000000000000000000000000", true},
    {"1000000000000000000000000000000000000000000000000000000000000001",
        "1000000000000000000000000000000000000000000000000000000000000002", true},
    {"2000000000000000000000000000000000000000000000000000000000000001",
        "1000000000000000000000000000000000000000000000000000000000000002", false},
    {"1000000000000000000000000000000000000000000000000000000000000000",
        "2000000000000000000000000000000000000000000000000000000000000000", true},
    {"1000000000000000200000000000000000000000000000000000000000000000",
        "2000000000000000100000000000000000000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaa100000000000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaa100000000000000000000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaa100000000000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaa200000000000000000000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaa200000000000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaa100000000000000000000000000000000000000000000000", false},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10000000000000000000000000000000", false},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1000000000000000", true},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2000000000000000", true},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1000000000000000", false},
};
}  // namespace

TEST(ethash, is_less_or_equal)
{
    for (const auto& t : is_less_or_equal_test_cases)
    {
        auto a = to_hash256(t.a_hex);
        auto b = to_hash256(t.b_hex);
        EXPECT_EQ(is_less_or_equal(a, b), t.excected_result);
    }
}
