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


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "functions.h"
#include "options.h"

    // split_into_big_endian_words()
    // fills the "words" array with the data from "buffer": 64 uint8_t -> 16 big-endian uint32_t
    // used in sha1() and sha2()

void split_into_big_endian_words(const uint8_t *restrict buffer, uint32_t *restrict words, const uint16_t block_index){

    for(uint8_t word_index = 0; word_index < 16; word_index++){
        words[word_index] =  (((uint32_t) buffer[block_index * 64 + word_index * 4]) << 24) |
                             (((uint32_t) buffer[block_index * 64 + word_index * 4 + 1]) << 16) |
                             (((uint32_t) buffer[block_index * 64 + word_index * 4 + 2]) << 8) |
                             (((uint32_t) buffer[block_index * 64 + word_index * 4 + 3]));
    }
}

    // add_size_in_big_endian()
    // appends the input's size in bits to the last block to complete the padding:  1 uint64_t ->  8 uint8_t in big-endian order
    // used in sha1() and sha2()

void add_size_in_big_endian(uint8_t *input, const uint64_t input_length, const uint64_t padded_input_length){
    uint64_t input_len_in_bits = input_length * 8;
    for(uint8_t k = 0; k < 8; k++){
        uint8_t byte = (uint8_t)((input_len_in_bits >> (7 - k) * 8));
        input[padded_input_length + k] = byte;
    }


}

    // add_size_in_little_endian()
    // appends the input's size in bits to the last block to complete the padding:  1 uint64_t ->  8 uint8_t arranged in little-endian order
    // used in md5()

void add_size_in_little_endian(uint8_t *input, const uint64_t input_length, const uint64_t padded_input_length){
    const uint64_t input_len_in_bits = input_length * 8;
	
	__builtin_memcpy(input + padded_input_length, &input_len_in_bits, 8);
   
	/*for(uint8_t k = 0; k < 8; k++){
        uint8_t byte = (uint8_t)((input_len_in_bits >> k * 8) & 0xFF);
        input[(padded_input_length - 8) + k] = byte;
    }
	*/
}
