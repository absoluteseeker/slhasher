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
#include "md5.h"

    // F()
    // creates a new 32-bit word from "w1", "w2" and "w3": 3 uint32_t -> 1 uint32_t
    // used in md5()

static inline uint32_t F(const uint32_t w1, const uint32_t w2, const uint32_t w3){
    return (w1 & w2) ^ (~w1 & w3);
}

    // G()
    // creates a new 32-bit word from "w1", "w2" and "w3": 3 uint32_t -> 1 uint32_t
    // used in md5()

static inline uint32_t G(const uint32_t w1, const uint32_t w2, const uint32_t w3){
    return (w1 & w3) | (w2 & ~w3);
}

    // H()
    // creates a new 32-bit word from "w1", "w2" and "w3": 3 uint32_t -> 1 uint32_t
    // used in md5()

static inline uint32_t H(const uint32_t w1, const uint32_t w2, const uint32_t w3){
    return w1 ^ w2 ^ w3;
}

    // I()
    // creates a new 32-bit word from "w1", "w2" and "w3": 3 uint32_t -> 1 uint32_t
    // used in md5()

static inline uint32_t I(const uint32_t w1, const uint32_t w2, const uint32_t w3){
    return w2 ^ (w1 | ~w3);
}

    // md5()
    // performs the hashing of "buffer" using the MD5 algorithm
    // used in md_file() and md_string()

void md5(const uint8_t *restrict buffer, uint32_t *restrict words, const uint32_t nb_read_bytes, const uint32_t buffer_size, struct function_infos *restrict func){

    const uint8_t s_table[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    ldiv_t result = ldiv(nb_read_bytes, func->md.block_size_in_bytes);

    uint16_t nb_blocks_in_buffer;

    if(nb_read_bytes == buffer_size){
        nb_blocks_in_buffer = result.quot;
    } else{
        nb_blocks_in_buffer = (result.rem >= func->md.block_size_without_input_size) ? result.quot + 2 : result.quot + 1;
    }

    uint32_t A, B, C, D;

    uint32_t (*fpointer)(uint32_t, uint32_t, uint32_t);

    for(size_t block_index = 0; block_index < nb_blocks_in_buffer; block_index++){

        __builtin_memset(words, 0, 64);



        __builtin_memcpy(words, buffer + block_index * 64, 64);

        A = func->md.hash_values[0];
        B = func->md.hash_values[1];
        C = func->md.hash_values[2];
        D = func->md.hash_values[3];


        for(uint8_t i = 0; i < 64; i++){
            uint8_t word_index;
            if(i < 16){
                fpointer = F;
                word_index = i;
            } else if(i >= 16 && i < 32){
                fpointer = G;
                word_index = (5 * i + 1) % 16;
            } else if(i >= 32 && i < 48){
                fpointer = H;
                word_index = (3 * i + 5) % 16;
            } else{
                fpointer = I;
                word_index = (7 * i) % 16;
            }

            uint32_t temp = A + fpointer(B, C, D) + words[word_index] + func->md.K_table[i];
            A = D;
            D = C;
            C = B;
            B += leftrotate(temp, s_table[i]);


        }
        func->md.hash_values[0] += A;
        func->md.hash_values[1] += B;
        func->md.hash_values[2] += C;
        func->md.hash_values[3] += D;
    }
}
