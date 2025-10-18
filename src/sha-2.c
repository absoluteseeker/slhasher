/*
 *   Slhasher - a command-line tool to compute hashes
 *
 *   Copyright (C) 2025  absoluteseeker  absoluteseeker@proton.me
 *
 *   Slhasher is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Slhasher is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Slhasher.  If not, see <https://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "functions.h"
#include "options.h"
#include "sha-2.h"

// functions for SHA-256

static inline uint32_t s0_sha256(const uint32_t *words, const uint8_t i){
    return rightrotate(words[i - 15], 7) ^ rightrotate(words[i - 15], 18) ^ (words[i - 15] >> 3);
}

static inline uint32_t s1_sha256(const uint32_t *words, const uint8_t i){
    return rightrotate(words[i - 2], 17) ^ rightrotate(words[i - 2], 19) ^ (words[i - 2] >> 10);
}

static inline uint32_t S0_sha256(const uint32_t A){
    return rightrotate(A, 2) ^ rightrotate(A, 13) ^ rightrotate(A, 22);
}

static inline uint32_t S1_sha256(const uint32_t E){
    return rightrotate(E, 6) ^ rightrotate(E, 11) ^ rightrotate(E, 25);
}

        // extend_words_sha256()
        // creates 48 32-bit new words in the "words" array
        // used in sha256()

static inline void extend_words_sha256(uint32_t *words){
    for(uint8_t word_index = 16; word_index < 64; word_index++){
        words[word_index] = words[word_index - 16] + s0_sha256(words, word_index) + words[word_index - 7] + s1_sha256(words, word_index);
    }
}

    // sha256()
    // computes the hash of "buffer" using the SHA-2 algorithm (32-bit version)
    // used in md_file() and md_string()

void sha256(const uint8_t *restrict buffer, uint32_t *restrict words, const uint32_t nb_read_bytes, const uint32_t buffer_size, struct function_infos *restrict func){

    ldiv_t result = ldiv(nb_read_bytes, func->md.block_size_in_bytes);

    const uint16_t nb_blocks_in_buffer = (nb_read_bytes == buffer_size) ? result.quot : ((result.rem >= func->md.block_size_without_input_size) ? result.quot + 2 : result.quot + 1);

    uint32_t A, B, C, D, E, F, G, H = 0;

    for(uint16_t block_index = 0; block_index < nb_blocks_in_buffer; block_index++){
        A = func->md.hash_values[0];
        B = func->md.hash_values[1];
        C = func->md.hash_values[2];
        D = func->md.hash_values[3];
        E = func->md.hash_values[4];
        F = func->md.hash_values[5];
        G = func->md.hash_values[6];
        H = func->md.hash_values[7];


        __builtin_memset(words, 0, 256);

        split_into_big_endian_words(buffer, words, block_index);

        extend_words_sha256(words);

        for(uint8_t word_index = 0; word_index < 64; word_index++){
            uint32_t temp1 = H + S1_sha256(E) + ch(E, F, G) + func->md.K_table[word_index] + words[word_index];
            uint32_t temp2 = S0_sha256(A) + maj(A, B, C);

            H = G;
            G = F;
            F = E;
            E = D + temp1;
            D = C;
            C = B;
            B = A;
            A = temp1 + temp2;
        }

        func->md.hash_values[0] += A;
        func->md.hash_values[1] += B;
        func->md.hash_values[2] += C;
        func->md.hash_values[3] += D;
        func->md.hash_values[4] += E;
        func->md.hash_values[5] += F;
        func->md.hash_values[6] += G;
        func->md.hash_values[7] += H;

    }
}



// functions for SHA-512

static inline uint64_t s0_sha512(const uint64_t *words, const uint8_t i){
    return rightrotate_u64(words[i - 15], 1) ^ rightrotate_u64(words[i - 15], 8) ^ (words[i - 15] >> 7);
}

static inline uint64_t s1_sha512(const uint64_t *words, const uint8_t i){
    return rightrotate_u64(words[i - 2], 19) ^ rightrotate_u64(words[i - 2], 61) ^ (words[i - 2] >> 6);
}

static inline uint64_t S0_sha512(const uint64_t A){
    return rightrotate_u64(A, 28) ^ rightrotate_u64(A, 34) ^ rightrotate_u64(A, 39);
}

static inline uint64_t S1_sha512(const uint64_t E){
    return rightrotate_u64(E, 14) ^ rightrotate_u64(E, 18) ^ rightrotate_u64(E, 41);
}

        // split_into_big_endian_words_sha512()
        // splits each block in "buffer" into 16 64-bit words
        // used in sha512()

static inline void split_into_big_endian_words_sha512(const uint8_t *restrict buffer, uint64_t *restrict words, const uint16_t block_index){
    for(uint8_t word_index = 0; word_index < 16; word_index++){                                 // the loop looks like this in order to allow the compiler to vectorize it
        words[word_index] = (((uint64_t) buffer[block_index * 128 + word_index * 8]) << 56) |   // at -O3 (high optimization level)
                            (((uint64_t) buffer[block_index * 128 + word_index * 8 + 1]) << 48) | // it will be improved in future versions
                            (((uint64_t) buffer[block_index * 128 + word_index * 8 + 2]) << 40) |
                            (((uint64_t) buffer[block_index * 128 + word_index * 8 + 3]) << 32) |
                            (((uint64_t) buffer[block_index * 128 + word_index * 8 + 4]) << 24) |
                            (((uint64_t) buffer[block_index * 128 + word_index * 8 + 5]) << 16) |
                            (((uint64_t) buffer[block_index * 128 + word_index * 8 + 6]) << 8) |
                            (((uint64_t) buffer[block_index * 128 + word_index * 8 + 7]));
    }
}

        // extend_words_sha512()
        // creates 64 64-bit new words in the "words" array
        // used in sha512()

static inline void extend_words_sha512(uint64_t *words){
    for(uint8_t word_index = 16; word_index < 80; word_index++){
        words[word_index] = words[word_index - 16] + s0_sha512(words, word_index) + words[word_index - 7] + s1_sha512(words, word_index);
    }
}

static inline uint64_t ch_u64(const uint64_t B, const uint64_t C, const uint64_t D){ // 64-bit equivalent to ch()
    return (B & C) | (~B & D);
}

static inline uint64_t maj_u64(const uint64_t B, const uint64_t C, const uint64_t D){ // 64-bit equivalent to maj()
    return (B & C) ^ (B & D) ^ (C & D);
}

    // sha512()
    // computes the hash of "buffer" using the SHA-2 algorithm (64-bit version)
    // used in md_file() and md_string()

void sha512(const uint8_t *restrict buffer, uint64_t *restrict words, const uint32_t nb_read_bytes, const uint32_t buffer_size, struct function_infos *restrict func){

    ldiv_t result = ldiv(nb_read_bytes, func->md.block_size_in_bytes);

    const uint16_t nb_blocks_in_buffer = (nb_read_bytes == buffer_size) ? result.quot : ((result.rem >= func->md.block_size_without_input_size) ? result.quot + 2 : result.quot + 1);

    uint64_t A, B, C, D, E, F, G, H;

    for(uint16_t block_index = 0; block_index < nb_blocks_in_buffer; block_index++){
        A = func->md.hash_values_u64[0];
        B = func->md.hash_values_u64[1];
        C = func->md.hash_values_u64[2];
        D = func->md.hash_values_u64[3];
        E = func->md.hash_values_u64[4];
        F = func->md.hash_values_u64[5];
        G = func->md.hash_values_u64[6];
        H = func->md.hash_values_u64[7];

        __builtin_memset(words, 0, 640);

        split_into_big_endian_words_sha512(buffer, words, block_index);

        extend_words_sha512(words);

        for(uint8_t word_index = 0; word_index < 80; word_index++){
            uint64_t temp1 = H + S1_sha512(E) + ch_u64(E, F, G) + func->md.K_table_u64[word_index] + words[word_index];
            uint64_t temp2 = S0_sha512(A) + maj_u64(A, B, C);

            H = G;
            G = F;
            F = E;
            E = D + temp1;
            D = C;
            C = B;
            B = A;
            A = temp1 + temp2;

        }

        func->md.hash_values_u64[0] += A;
        func->md.hash_values_u64[1] += B;
        func->md.hash_values_u64[2] += C;
        func->md.hash_values_u64[3] += D;
        func->md.hash_values_u64[4] += E;
        func->md.hash_values_u64[5] += F;
        func->md.hash_values_u64[6] += G;
        func->md.hash_values_u64[7] += H; 

    }
}




