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


#ifndef OPTIONS_H
#define OPTIONS_H
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

static inline double now_sec(void) {    // little function used to measure execution time
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}



enum main_mode { HELP, VERSION, HASHING }; // holds the mode

enum source_type { STRING, UFILE }; // holds the data source (string or file)

typedef struct user_choices {
    enum main_mode mode;
    enum source_type source;
    char *data_to_hash;
    char *compare_string;   // holds the reference hash
    bool sumfile;
} user_choices;



enum function_type { MERKLE_DAMGARD, SPONGE }; // holds the different types of construction (as of now: Merkle-Damgard and sponge)

enum chosen_function_md { MD5, SHA_1, SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_t, TIGER, TIGER_2 }; // holds the functions based on the Merkle-Damgard construction

struct m_d {
    enum chosen_function_md name;
    uint8_t nb_words;
    uint8_t word_size_in_bytes;
    uint8_t block_size_in_bytes;
    uint8_t block_size_without_input_size; // block_size - sizeof(input_size)
    union {
        uint32_t *hash_values;                // holds the hash values for function using 32-bit words
        uint64_t *hash_values_u64;          // holds the hash values for function using 64-bit words
    };
    union {
        uint32_t *K_table;                  // holds the round constants for functions using 32-bit words
        uint64_t *K_table_u64;              // holds the round constants for functions using 64-bit words
    };
    uint8_t nb_hval_in_hash;
    uint16_t t;                             // in SHA-512/t: value of t
    char *sha512_t;                         // in SHA-512/t: string to hash in order to produce the initial hash values used to hash the input
};

enum sha3_instances { SHA3_224, SHA3_256, SHA3_384, SHA3_512 }; // holds the instance of SHA-3

struct sha_3 {
    enum sha3_instances instance;
    uint16_t rate;                  // holds the rate <=> block_size in M-D functions
    uint8_t suffix;                 // holds the suffix that is first appended to the input during padding
};

typedef struct function_infos { // holds all the chosen function's informations
    enum function_type type;
    union {
        struct m_d md;
        struct sha_3 sha3;
    };
    uint8_t hash_size_in_bytes; // size of the computed hash in bytes
} function_infos;

#endif
