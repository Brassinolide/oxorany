#pragma once
#ifdef _DEBUG
    #define oxorany
#else

#include <bit>

#ifdef _MSC_VER
    #define OXORANY_FORCEINLINE __forceinline
#else
    #define OXORANY_FORCEINLINE __attribute__((always_inline)) inline
#endif

#define oxorany(any) _lxy_oxor_any_::oxor_any<decltype(_lxy_oxor_any_::typeofs(any)), _lxy_oxor_any_::array_size(any), __COUNTER__>(any, std::make_index_sequence<sizeof(decltype(any))>()).get()

// 仅64字节有效，超出部分将被截断忽略
namespace simple_sha {
    static constexpr std::array<uint32_t, 8> iv = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    static constexpr uint32_t k[8] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    };

    static consteval uint32_t rotr(uint32_t x, int n) noexcept {
        return (x >> n) | (x << (32 - n));
    }
    static consteval uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept {
        return (x & y) ^ (~x & z);
    }
    static consteval uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static consteval uint32_t sigma0(uint32_t x) noexcept {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    static consteval uint32_t sigma1(uint32_t x) noexcept {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static consteval std::array<uint32_t, 8> compress(const std::array<uint32_t, 16>& w) noexcept {
        auto state = iv;

        for (int i = 0; i < 8; ++i) {
            uint32_t T1 = state[7] + sigma1(state[4]) + ch(state[4], state[5], state[6]) + k[i] + w[i];
            uint32_t T2 = sigma0(state[0]) + maj(state[0], state[1], state[2]);

            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3] + T1;
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = T1 + T2;
        }

        return state;
    }

    static OXORANY_FORCEINLINE constexpr uint64_t fmix64(uint64_t k) noexcept {
        k ^= k >> 33;
        k *= 0xff51afd7ed558ccdULL;
        k ^= k >> 33;
        k *= 0xc4ceb9fe1a85ec53ULL;
        k ^= k >> 33;
        return k;
    }

    static OXORANY_FORCEINLINE constexpr uint64_t mix_two(uint64_t a, uint64_t b) noexcept {
        uint64_t h = fmix64(a + 0x9e3779b97f4a7c15ULL);
        h ^= b;
        return fmix64(h);
    }

    static consteval std::array<uint32_t, 16> to_words(std::string_view s) noexcept {
        std::array<uint32_t, 16> w{};
        for (size_t i = 0; i < s.size() && i < 64; ++i) {
            int word_idx = i / 4;
            int byte_idx = i % 4;
            w[word_idx] |= static_cast<uint32_t>(static_cast<unsigned char>(s[i])) << (24 - byte_idx * 8);
        }
        return w;
    }

    static consteval uint64_t hash(std::string_view input) noexcept {
        auto state = compress(to_words(input));

        uint64_t a = (static_cast<uint64_t>(state[0]) << 32) | state[1];
        uint64_t b = (static_cast<uint64_t>(state[2]) << 32) | state[3];
        uint64_t c = (static_cast<uint64_t>(state[4]) << 32) | state[5];
        uint64_t d = (static_cast<uint64_t>(state[6]) << 32) | state[7];

        return mix_two(a, mix_two(b, mix_two(c, d)));
    }
}

namespace _lxy_oxor_any_ {
    volatile uint64_t g_x = 0;
    volatile uint64_t& X() {
        return g_x;
    }

    volatile uint64_t g_y = 0;
    volatile uint64_t& Y() {
        return g_y;
    }

    static constexpr uint64_t base_key = simple_sha::hash(__TIME__ __DATE__ __FILE__);

    static consteval uint64_t xorshift64star(uint64_t state) noexcept {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        return state * 0x2545F4914F6CDD1DULL;
    }

    template<size_t n, uint64_t s = 1>
    static consteval uint64_t random_uint64() noexcept {
        static_assert(s != 0);

        uint64_t state = s;
        for (size_t i = 0; i < n; ++i) {
            state = xorshift64star(state);
        }
        return state;
    }

    template<typename T, size_t size>
    static OXORANY_FORCEINLINE constexpr size_t array_size(const T(&)[size]) { return size; }

    template<typename T>
    static OXORANY_FORCEINLINE constexpr size_t array_size(T) { return 0; }

    template<typename T, size_t size>
    static inline T typeofs(const T(&)[size]);

    template<typename T>
    static inline T typeofs(T);

    // TODO: 使用更复杂的加解密算法

    template<size_t key>
    static OXORANY_FORCEINLINE constexpr uint8_t encrypt_byte(uint8_t c, size_t i) {
        return static_cast<uint8_t>(((c + (key * 7)) ^ (i + key)));
    }

    template<size_t key>
    static OXORANY_FORCEINLINE constexpr uint8_t decrypt_byte(uint8_t c, size_t i) {
        //a ^ b == (a + b) - 2 * (a & b)
        size_t a = c;
        size_t b = i + key;
        //size_t a_xor_b = (a + b) - 2 * (a & b);
        size_t a_xor_b = (a + b) - ((a & b) + (b & a));
        //size_t a_xor_b = (a + b) - (a & b) - (b & a); 
        return static_cast<uint8_t>((a_xor_b)-(key * 7));
    }

    template<uint64_t key>
    static OXORANY_FORCEINLINE consteval uint64_t limit() noexcept {
        constexpr uint64_t bcf_value[] = {
            1, 2, 3, 4, 5,
            6, 8, 9, 10, 16,
            32, 40, 64, 66, 100,
            128, 512, 1000, 1024, 4096,
            'a', 'z', 'A', 'Z', '*' };

        return bcf_value[key % std::size(bcf_value)];
    }

    template<typename return_type, uint64_t key, size_t size>
    static OXORANY_FORCEINLINE const return_type decrypt(uint8_t(&buffer)[size]) {
        volatile uint8_t source;
        volatile uint8_t decrypted; //do not assign initial value
        volatile uint64_t stack_x;
        volatile uint64_t stack_y;

    loc_start_1:
        stack_x = X();
        stack_y = Y();
    loc_start_2:
        for (size_t i = 0; i < size; i++) {
            source = buffer[i];
        loc_start_3:
            if (stack_x <= i) {
                
                if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);//fake
                }
                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 1 + 1) {
                    //unreachable
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                    goto loc_unreachable_9;
                }
                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 2 + 1) {
                    //unreachable
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                    goto loc_unreachable_8;
                }
                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 3 + 1) {
                    //unreachable
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                    goto loc_unreachable_7;
                }
                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 4 + 1) {
                    //unreachable
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                    goto loc_unreachable_6;
                }
                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 5 + 1) {
                    //unreachable
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                    goto loc_unreachable_5;
                }
                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 6 + 1) {
                    //unreachable
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                    goto loc_unreachable_4;
                }
                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 7 + 1) {
                    //unreachable
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                    goto loc_unreachable_3;
                }
                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 8 + 1) {
                    //unreachable
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                    goto loc_unreachable_2;
                }
                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 9 + 1) {
                    //unreachable
                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                    goto loc_unreachable_1;
                }
            loc_start_4:
                if (stack_y <= i) {
                    if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);//fake
                    }
                    else if (stack_x == stack_y + limit<key * __COUNTER__>() % 1 + 1) {
                        //unreachable
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                        goto loc_unreachable_1;
                    }
                    else if (stack_x == stack_y + limit<key * __COUNTER__>() % 2 + 1) {
                        //unreachable
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                        goto loc_unreachable_2;
                    }
                    else if (stack_x == stack_y + limit<key * __COUNTER__>() % 3 + 1) {
                        //unreachable
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                        goto loc_unreachable_3;
                    }
                    else if (stack_x == stack_y + limit<key * __COUNTER__>() % 4 + 1) {
                        //unreachable
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                        goto loc_unreachable_4;
                    }
                    else if (stack_x == stack_y + limit<key * __COUNTER__>() % 5 + 1) {
                        //unreachable
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                        goto loc_unreachable_5;
                    }
                    else if (stack_x == stack_y + limit<key * __COUNTER__>() % 6 + 1) {
                        //unreachable
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                        goto loc_unreachable_6;
                    }
                    else if (stack_x == stack_y + limit<key * __COUNTER__>() % 7 + 1) {
                        //unreachable
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                        goto loc_unreachable_7;
                    }
                    else if (stack_x == stack_y + limit<key * __COUNTER__>() % 8 + 1) {
                        //unreachable
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                        goto loc_unreachable_8;
                    }
                    else if (stack_x == stack_y + limit<key * __COUNTER__>() % 9 + 1) {
                        //unreachable
                        decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                        goto loc_unreachable_9;
                    }
                loc_start_5:
                    if (stack_x + stack_y <= i) {
                        if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                            decrypted = decrypt_byte<key>(source, i);//real
                        }
                        else if (stack_x == stack_y + limit<key * __COUNTER__>() % 1 + 1) {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            goto loc_unreachable_9;
                        }
                        else if (stack_x == stack_y + limit<key * __COUNTER__>() % 2 + 1) {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            goto loc_unreachable_8;
                        }
                        else if (stack_x == stack_y + limit<key * __COUNTER__>() % 3 + 1) {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            goto loc_unreachable_7;
                        }
                        else if (stack_x == stack_y + limit<key * __COUNTER__>() % 4 + 1) {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            goto loc_unreachable_6;
                        }
                        else if (stack_x == stack_y + limit<key * __COUNTER__>() % 5 + 1) {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            goto loc_unreachable_5;
                        }
                        else if (stack_x == stack_y + limit<key * __COUNTER__>() % 6 + 1) {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            goto loc_unreachable_4;
                        }
                        else if (stack_x == stack_y + limit<key * __COUNTER__>() % 7 + 1) {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            goto loc_unreachable_3;
                        }
                        else if (stack_x == stack_y + limit<key * __COUNTER__>() % 8 + 1) {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            goto loc_unreachable_2;
                        }
                        else if (stack_x == stack_y + limit<key * __COUNTER__>() % 9 + 1) {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            goto loc_unreachable_1;
                        }
                    loc_start_6:
                        if (stack_x + stack_y != limit<key * __COUNTER__>()) {
                            if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>() % 1 + 1) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_1;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>() % 2 + 1) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_2;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>() % 3 + 1) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_3;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>() % 4 + 1) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_4;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>() % 5 + 1) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_5;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>() % 6 + 1) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_6;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>() % 7 + 1) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_7;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>() % 8 + 1) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_8;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>() % 9 + 1) {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_9;
                            }
                        loc_start_7:
                            if (stack_x < limit<key * __COUNTER__>()) {
                                if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                }
                                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 1 + 1) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    goto loc_unreachable_9;
                                }
                                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 2 + 1) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    goto loc_unreachable_8;
                                }
                                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 3 + 1) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    goto loc_unreachable_7;
                                }
                                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 4 + 1) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    goto loc_unreachable_6;
                                }
                                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 5 + 1) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    goto loc_unreachable_5;
                                }
                                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 6 + 1) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    goto loc_unreachable_4;
                                }
                                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 7 + 1) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    goto loc_unreachable_3;
                                }
                                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 8 + 1) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    goto loc_unreachable_2;
                                }
                                else if (stack_x == stack_y + limit<key * __COUNTER__>() % 9 + 1) {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    goto loc_unreachable_1;
                                }
                            loc_start_8:
                                if (stack_y < limit<key * __COUNTER__>()) {
                                loc_start_9:
                                    buffer[i] = decrypted;//assign
                                }
                                else {
                                    //unreachable
                                    decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                    decrypted += decrypted;
                                loc_unreachable_1:
                                    buffer[i] = decrypt_byte<key * __COUNTER__>(source, i);
                                loc_unreachable_2:
                                    stack_y++;
                                loc_unreachable_3:
                                    i--;
                                }
                            }
                            else {
                                //unreachable
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                decrypted += buffer[i];
                            loc_unreachable_4:
                                buffer[i] = decrypt_byte<key * __COUNTER__>(source, i);
                                buffer[i] += decrypted;
                            loc_unreachable_5:
                                stack_x += stack_y;
                            loc_unreachable_6:
                                i--;
                                i -= decrypted;
                            }
                        }
                        else {
                            //unreachable
                            decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                            decrypted -= buffer[i];
                        loc_unreachable_7:
                            buffer[i] = decrypt_byte<key * __COUNTER__>(source, i);
                            stack_y++;
                            i -= buffer[i];
                            i -= stack_y;
                        loc_unreachable_8:
                            buffer[i] = decrypt_byte<key * __COUNTER__>(source, i);
                            stack_x++;
                            i--;
                            i -= stack_x;
                        loc_unreachable_9:
                            i += buffer[i];
                            i += stack_y;
                            continue;
                        }
                    }
                    else {
                        //unreachable
                        while (true) {
                            if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_1;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_2;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_3;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_4;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_5;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_6;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_7;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_8;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_9;
                            }
                            else if (stack_x == stack_y + limit<key * __COUNTER__>()) {
                                continue;
                            }
                            else {
                                stack_x = stack_y + limit<key * __COUNTER__>();
                                stack_y = stack_x + limit<key * __COUNTER__>();
                            }

                            if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_start_1;
                            }
                            else if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_start_2;
                            }
                            else if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_start_3;
                            }
                            else if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_start_4;
                            }
                            else if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_start_5;
                            }
                            else if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_start_6;
                            }
                            else if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_start_7;
                            }
                            else if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_start_8;
                            }
                            else if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_start_9;
                            }
                            else if (stack_x < stack_y + limit<key * __COUNTER__>()) {
                                continue;
                            }
                            else {
                                stack_x = stack_y + limit<key * __COUNTER__>();
                                stack_y = stack_x + limit<key * __COUNTER__>();
                            }

                            if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_9;
                            }
                            else if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_8;
                            }
                            else if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_7;
                            }
                            else if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_6;
                            }
                            else if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_5;
                            }
                            else if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_4;
                            }
                            else if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_3;
                            }
                            else if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_2;
                            }
                            else if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                decrypted = decrypt_byte<key * __COUNTER__>(source, i);
                                goto loc_unreachable_1;
                            }
                            else if (stack_x > stack_y + limit<key * __COUNTER__>()) {
                                continue;
                            }
                            else {
                                stack_x = stack_y + limit<key * __COUNTER__>();
                                stack_y = stack_x + limit<key * __COUNTER__>();
                            }
                        }
                    }
                }
                else {
                    //unreachable
                    //Ooops, Decompilation failure:
                    //401000: stack frame is too big
                    return reinterpret_cast<return_type>(buffer + ((key * __COUNTER__) % 0x400000 + 0x1400000));
                }
            }
            else {
                //unreachable
                //Ooops, Decompilation failure:
                //401000: stack frame is too big
                return reinterpret_cast<return_type>(buffer + ((key * __COUNTER__) % 0x1400000 + 0x400000));
            }
        }

        return reinterpret_cast<return_type>(buffer);
    }

    static consteval size_t align(size_t n, size_t a) noexcept {
        return (n + a - 1) & ~(a - 1);
    }

    template<typename any_t, size_t ary_size, size_t counter>
    class oxor_any {
    public:
        template<size_t... indices>
        OXORANY_FORCEINLINE constexpr oxor_any(const any_t(&any)[ary_size], std::index_sequence<indices...>) :
            buffer_{ encrypt_byte<session_key_>(((uint8_t*)&any)[indices], indices)... } {
        }

        OXORANY_FORCEINLINE const any_t* get() { return decrypt<const any_t*, session_key_>(buffer_); }

    private:
        static constexpr uint64_t session_key_ = simple_sha::mix_two(ary_size, simple_sha::mix_two(counter, base_key));
        
        uint8_t buffer_[ary_size];
    };

    template<typename any_t, size_t counter>
    class oxor_any<any_t, 0, counter> {
    public:
        template<size_t... indices>
        OXORANY_FORCEINLINE constexpr oxor_any(any_t any, std::index_sequence<indices...>) :
            buffer_{ encrypt_byte<session_key_>(reinterpret_cast<uint8_t*>(&any)[indices], indices)... } {
        }

        OXORANY_FORCEINLINE const any_t get() { return *decrypt<const any_t*, session_key_>(buffer_); }

    private:
        static constexpr uint64_t session_key_ = simple_sha::mix_two(sizeof(any_t), simple_sha::mix_two(counter, base_key));
        
        uint8_t buffer_[sizeof(any_t)];
    };
}

#endif // _DEBUG
