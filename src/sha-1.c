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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "functions.h"
#include "options.h"
#include "sha-1.h"

    // xor()
    // XORs "B", "c" and "D" together: 3 uint32_t -> 1 uint32_t
    // used in sha1()

static inline uint32_t xor(const uint32_t B, const uint32_t C, const uint32_t D){
    return B ^ C ^ D;
}

    // extend_words_sha1()
    // appends 64 new words to "words": 1 array of uint32_t (16 words) -> 1 array of uint32_t (80 words)
    // used in sha1()

static void extend_words_sha1(uint32_t *words){
    for(uint8_t i = 16; i < 80; i++){
        uint32_t new_word = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
        words[i] = leftrotate(new_word, 1);
    }
}

    // sha1()
    // performs the hashing of "buffer" using the SHA-1 algorithm
    // used in md_file() and md_string()

void sha1(const uint8_t *restrict buffer, uint32_t *restrict words, const uint32_t nb_read_bytes, const uint32_t buffer_size, struct function_infos *restrict func){

    ldiv_t result = ldiv(nb_read_bytes, 64);

    const uint16_t nb_blocks_in_buffer = (nb_read_bytes == buffer_size) ? result.quot : ((result.rem >= func->md.block_size_without_input_size) ? result.quot + 2 : result.quot + 1);

    uint32_t A, B, C, D, E, K = 0;

    uint32_t (*fpointer)(uint32_t, uint32_t, uint32_t) = NULL;

    for(size_t block_index = 0; block_index < nb_blocks_in_buffer; block_index++){
        A = func->md.hash_values[0];
        B = func->md.hash_values[1];
        C = func->md.hash_values[2];
        D = func->md.hash_values[3];
        E = func->md.hash_values[4];

        __builtin_memset(words, 0, 320);

        split_into_big_endian_words(buffer, words, block_index);

        extend_words_sha1(words);

        for(uint8_t word_index = 0; word_index < func->md.nb_words; word_index++){
            if(word_index < 20){
                fpointer = ch;
                K = func->md.K_table[0];
            } else if(word_index >= 20 && word_index < 40){
                fpointer = xor;
                K = func->md.K_table[1];
            } else if(word_index >= 40 && word_index < 60){
                fpointer = maj;
                K = func->md.K_table[2];
            } else{
                fpointer = xor;
                K = func->md.K_table[3];
            }
            uint32_t temp = leftrotate(A, 5) + fpointer(B, C, D) + E + K + words[word_index];
            E = D;
            D = C;
            C = leftrotate(B, 30);
            B = A;
            A = temp;
 
        }

        func->md.hash_values[0] += A;
        func->md.hash_values[1] += B;
        func->md.hash_values[2] += C;
        func->md.hash_values[3] += D;
        func->md.hash_values[4] += E;
    }
}



