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


#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <stdint.h>
#include "options.h"


    // leftrotate()
    // rotates the bits of "word" leftwards by a given "shift": 1 uint32_t -> 1 uint32_t
    // used in md5()

static inline uint32_t leftrotate(const uint32_t word, const uint8_t shift){
    return (word << shift) | (word >> (32 - shift));
}

    // rightrotate()
    // rotates the bits of "word" rightwards by a given "shift": 1 uint32_t -> 1 uint32_t
    // used in sha1() and sha256()

static inline uint32_t rightrotate(const uint32_t word, const uint8_t shift){
    return (word >> shift) | (word << (32 - shift));
}

    // rightrotate_u64()
    // same as rightrotate but "word" is 64-bit long: 1 uint64_t -> 1 uint64_t
    // used in sha512()

static inline uint64_t rightrotate_u64(const uint64_t word, const uint8_t shift){
    return (word >> shift) | (word << (64 - shift));
}

    // ch()
    // performs bitwise operations on "B", "C" and "D" to create a new word: 3 uint32_t -> 1 uint32_t
    // used in sha1() and sha256()

static inline uint32_t ch(const uint32_t B, const uint32_t C, const uint32_t D){
    return (B & C) ^ (~B & D);
}

    // maj()
    // performs bitwise operations on "B", "C" and "D" to create a new word: 3 uint32_t -> 1 uint32_t
    // used in sha1() and sha256()

static inline uint32_t maj(const uint32_t B, const uint32_t C, const uint32_t D){
    return (B & C) ^ (B & D) ^ (C & D);
}

void split_into_big_endian_words(const uint8_t *buffer, uint32_t *words, const uint16_t block_index);

void add_size_in_big_endian(uint8_t *padded_input, const uint64_t input_length, const uint64_t padded_input_length);

void add_size_in_little_endian(uint8_t *padded_input, const uint64_t input_length, const uint64_t padded_input_length);

#endif
