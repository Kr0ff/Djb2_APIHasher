#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINE 2048
#define SEED    0x12345678

DWORD64 djb2(PBYTE str);

DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

/*
This has been obtained from:
- https://stackoverflow.com/questions/7666509/hash-function-for-string
*/

uint32_t FNV(const void* key, int len, uint32_t h)
{
    // Source: https://github.com/aappleby/smhasher/blob/master/src/Hashes.cpp
    h ^= 2166136261UL;
    const uint8_t* data = (const uint8_t*)key;
    for (int i = 0; i < len; i++)
    {
        h ^= data[i];
        h *= 16777619;
    }
    return h;
}

uint32_t MurmurOAAT_32(const char* str, uint32_t h)
{
    // One-byte-at-a-time hash based on Murmur's mix
    // Source: https://github.com/aappleby/smhasher/blob/master/src/Hashes.cpp
    for (; *str; ++str) {
        h ^= *str;
        h *= 0x5bd1e995;
        h ^= h >> 15;
    }
    return h;
}

DWORD64 KR_v2_hash(PBYTE str)
{
    // Source: https://stackoverflow.com/a/45641002/5407270
    // a.k.a. Java String hashCode()
    DWORD64 hashval = 0;
    for (hashval = 0; *str != '\0'; str++)
        hashval = *str + 31 * hashval;
    return hashval;
}

uint32_t Jenkins_one_at_a_time_hash(const char* str, size_t len)
{
    uint32_t hash, i;
    for (hash = i = 0; i < len; ++i)
    {
        hash += str[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

/*
uint32_t crc32b(const uint8_t* str) {
    // Source: https://stackoverflow.com/a/21001712
    unsigned int byte, crc, mask;
    int i = 0, j;
    crc = 0xFFFFFFFF;
    while (str[i] != 0) {
        byte = str[i];
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
        i = i + 1;
    }
    return ~crc;
}
*/

inline uint32_t _rotl32(uint32_t x, int32_t bits)
{
    return x << bits | x >> (32 - bits);      // C idiom: will be optimized to a single operation
}

DWORD64 Coffin_hash(PBYTE input) {
    // Source: https://stackoverflow.com/a/7666668/5407270
    DWORD64 result = 0x55555555;
    while (*input) {
        result ^= *input++;
        result = _rotl32(result, 5);
    }
    return result;
}

uint32_t x17(const void* key, int len, uint32_t h)
{
    // Source: https://github.com/aappleby/smhasher/blob/master/src/Hashes.cpp
    const uint8_t* data = (const uint8_t*)key;
    for (int i = 0; i < len; ++i)
    {
        h = 17 * h + (data[i] - ' ');
    }
    return h ^ (h >> 16);
}