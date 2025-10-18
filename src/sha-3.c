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
#include <sys/stat.h>
#include "options.h"

static const uint32_t biggest_input_size = 500000;

        // coord: used in rho()

static const uint8_t coord[24][3] = {{0, 1, 1}, {2, 0, 3}, {1, 2, 6}, {2, 1, 10}, {3, 2, 15}, {3, 3, 21}, {0, 3, 28}, {1, 0, 36},
                                    {3, 1, 45}, {1, 3, 55}, {4, 1, 2}, {4, 4, 14}, {0, 4, 27}, {3, 0, 41}, {4, 3, 56}, {3, 4, 8},
                                    {2, 3, 25}, {2, 2, 43}, {0, 2, 62}, {4, 0, 18}, {2, 4, 39}, {4, 2, 61}, {1, 4, 20}, {1, 1, 44}
                                    };

        // used in iota()
static const uint64_t round_consts[24] = {0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
                                          0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
                                          0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
                                          0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
                                         };

        // choose_buffer_size()
        // calculates the buffer size depending on the input size
        // used in sha3_file() and sha3_string()

static uint32_t choose_buffer_size(const uint64_t input_size, const struct function_infos *func){ 
    uint32_t buffer_size;

    if(input_size > biggest_input_size){
        buffer_size = 2000 * func->sha3.rate;
    } else{
        lldiv_t result = lldiv(input_size, func->sha3.rate);
		buffer_size = (result.rem >= func->sha3.rate - 1) ? (result.quot + 2) * func->sha3.rate : (result.quot + 1) * func->sha3.rate;
    }
    return buffer_size;
}

        // padding()
        // adds the suffix, zeroes (if necessary) and a 1 bit (0x80) at the input's end
        // used in sha3_file() and sha3_string()

static void padding(uint8_t *input, uint32_t *nb_read_bytes, const struct function_infos *func){
    const uint8_t remainder = *nb_read_bytes % func->sha3.rate;

    const uint8_t nb_padding_bytes = (remainder == func->sha3.rate - 1) ? func->sha3.rate : func->sha3.rate - 1 - remainder;

    input[*nb_read_bytes] = func->sha3.suffix;

    if(nb_padding_bytes > 0) __builtin_memset(input + *nb_read_bytes + 1, 0, nb_padding_bytes);

    input[*nb_read_bytes + nb_padding_bytes] = 0x80;

    *nb_read_bytes += nb_padding_bytes + 1;
}

        // absorb()
        // XOR's the current block (in "input") with the "state"
        // used in sha3()

static inline void absorb(const uint8_t *restrict input, uint64_t state[5][5], const uint32_t block_index, const uint16_t rate){

    uint64_t *loading = (uint64_t *)__builtin_alloca(rate);

    __builtin_memcpy(loading, input + block_index * rate, rate);

    for(uint8_t i = 0; i < (rate / 8); i++){
        state[i / 5][i % 5] ^= loading[i];
    }
}

        // squeeze()
        // produces the final hash by "squeezing" the required amount of bytes from the "state"
        // used in sha3_file() and sha3_string()

static uint8_t *squeeze(const uint64_t state[5][5], const uint8_t hash_size_in_bytes){
    uint8_t *digest = (uint8_t *)malloc(hash_size_in_bytes);
    if(!digest){
        perror("Memory allocation failed");
        return NULL;
    }

    for(uint8_t byte_index = 0; byte_index < hash_size_in_bytes; byte_index++){
        digest[byte_index] = (uint8_t )(state[byte_index / 40][(byte_index / 8) % 5] >> 8 * (byte_index % 8));
    }

    return digest;
}

static inline uint64_t leftrotate(const uint64_t word, const uint8_t shift){
    return (word << shift) | (word >> (64 - shift));
}

        // used in keccak()
static inline void theta(uint64_t state[5][5]){
    uint64_t C[5] = {0};

    for(uint8_t i = 0; i < 5; i++){
        C[i] = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ^ state[4][i];
    }

    for(uint8_t j = 0; j < 5; j++){
        uint8_t a = (j - 1 < 0) ? 4 : j - 1;
        uint64_t D = C[a] ^ leftrotate(C[(j + 1) % 5], 1);


        state[0][j] ^= D; //SIMD
        state[1][j] ^= D;
        state[2][j] ^= D;
        state[3][j] ^= D;
        state[4][j] ^= D;
    }
}

        // used in keccak()
static inline void rho(uint64_t state[5][5]){

    for(uint8_t i = 0; i < 24; i++){
        state[coord[i][0]][coord[i][1]] = leftrotate(state[coord[i][0]][coord[i][1]], coord[i][2]);
    }
}

        // used in keccak()
static inline void pi(uint64_t state[5][5]){
    uint64_t temp_state[5][5] = {0};

    __builtin_memcpy(temp_state, state, 200);


    for(uint8_t i = 0; i < 5; i++){
        for(uint8_t j = 0; j < 5; j++){
            state[i][j] = temp_state[j][(j + 3 * i) % 5];
        }
    }
}

        // used in keccak()
static inline void chi(uint64_t state[5][5]){
    uint64_t temp_state[5][5] = {0};

    __builtin_memcpy(temp_state, state, 200);

    for(uint8_t i = 0; i < 5; i++){
        for(uint8_t j = 0; j < 5; j++){
            state[i][j] ^= (((temp_state[i][((j + 1) % 5)]) ^ 0xFFFFFFFFFFFFFFFFULL) & (temp_state[i][((j + 2) % 5)]));
        }
    }
}

        // used in keccak()
static inline void iota(uint64_t state[5][5], uint64_t round_const){
    state[0][0] ^= round_const;
}

    // keccak()
    // modifies the state in a non-linear/non-predictable way thaks to the 5 little functions (theta, rho, pi, chi, iota)
    // used in sha3()

static void keccak(uint64_t state[5][5]){
    for(uint8_t round = 0; round < 24; round++){
        theta(state);
        rho(state);
        pi(state);
        chi(state);
        iota(state, round_consts[round]);
    }
}

    // sha3()
    // applies the Keccak algorithm to "buffer"
    // used in sha3_file() and sha3_string()

static void sha3(uint8_t *buffer, const uint32_t nb_bytes, uint64_t state[5][5], const uint16_t rate){
    const uint16_t nb_blocks = nb_bytes / rate;

    for(uint16_t block_index = 0; block_index < nb_blocks; block_index++){
        absorb(buffer, state, block_index, rate);
        keccak(state);
    }
}

    // sha3_file()
    // performs the hashing of a file using the SHA-3 algorithm
    // used in main()

uint8_t *sha3_file(const char *restrict file_name, struct function_infos *restrict func){

    FILE *f = fopen(file_name, "rb");
    if(!f){
        perror("File opening failed");
        goto error;
    }

    struct stat file_stats;

    if(stat(file_name, &file_stats) != 0){  // gets file size by looking at its metadata
        fprintf(stderr, "Reading file informations failed.\n");
        goto close_f;
    }

    const uint64_t file_size = file_stats.st_size;
    if(file_size == 0){
        fprintf(stderr, "Error: file \"%s\" is empty.\n", file_name);
        goto close_f;
    }

    const uint32_t buffer_size = choose_buffer_size(file_size, func);

    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if(!buffer){
        perror("Memory allocation failed");
        goto close_f;
    }

    uint32_t nb_read_bytes = 0;

    uint32_t nb_bytes = 0;

    uint64_t state[5][5] = {0};

    while((nb_read_bytes = fread(buffer, 1, buffer_size, f)) > 0){

        nb_bytes = nb_read_bytes;

        if(nb_read_bytes < buffer_size){
            if(nb_read_bytes == buffer_size - 1){ // end of file is reached but there is not enougn room left in "buffer" for the padding
                uint8_t *temp = (uint8_t *)realloc(buffer, buffer_size + func->sha3.rate); // -> realloc is necessary
                if(!temp){
                    perror("Memory resizing failed");
                    goto free_buffer;
                }

                buffer = temp;
            }

            padding(buffer, &nb_read_bytes, func);
        }


        sha3(buffer, nb_read_bytes, state, func->sha3.rate);
    }

    if(nb_bytes == buffer_size){ // buffer size is a multiple of file size -> adds padding and applies sha3()
        padding(buffer, 0, func);

        sha3(buffer, func->sha3.rate, state, func->sha3.rate);
    }

    fclose(f);
    free(buffer);

    return squeeze(state, func->hash_size_in_bytes); // final result is returned

free_buffer:
    free(buffer);
close_f:
    fclose(f);
error:
    return NULL;
}

    // sha3_string()
    // performs the hashing of a string of characters using the SHA-3 algorithm
    // used in main()

uint8_t *sha3_string(const char *restrict input, struct function_infos *restrict func){
    uint32_t input_size = strlen(input);

    if(input_size > 8000){  // for large data amounts, sha3_file() must be used
        fprintf(stderr, "Warning: the size of provided character string excesses the security boundaries.\n");
        fprintf(stderr, "For large data amounts, use the file mode.\n");
        goto error;
    }

    const uint32_t buffer_size = choose_buffer_size(input_size, func);

    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if(!buffer){
        perror("Memory allocation failed");
        goto error;
    }

    buffer = memcpy(buffer, input, input_size); // copies "input" data into "buffer"
    if(!buffer){
        perror("Copying data failed");
        goto error;
    }

    uint64_t state[5][5] = {0};

    padding(buffer, &input_size, func);

    sha3(buffer, buffer_size, state, func->sha3.rate);

    free(buffer);

    return squeeze(state, func->hash_size_in_bytes); // final result is returned

error:
    return NULL;

}





