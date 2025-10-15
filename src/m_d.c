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
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "functions.h"
#include "options.h"
#include "md5.h"
#include "sha-1.h"
#include "sha-2.h"
#include "tiger.h"
#include "m_d.h"

static const uint32_t buffer_size_max = 256000;

    // choose_buffer_size()
    // calculates the buffer size depending on the input size
    // used in md_file() and md_string()

static uint32_t choose_buffer_size(const uint64_t input_size, const struct function_infos *func){
    uint32_t buffer_size;
    if(input_size > buffer_size_max){
        buffer_size = buffer_size_max;
    } else{
        lldiv_t result = lldiv(input_size, func->md.block_size_in_bytes);
        buffer_size = (result.rem >= func->md.block_size_without_input_size) ? (result.quot + 2) * func->md.block_size_in_bytes : (result.quot + 1) * func->md.block_size_in_bytes;
    }
    return buffer_size;
}

    // padding()
    // appends the padding at the input's end: (1 bit (0x80) and zeroes if necessary)
    // used in md_file() and md_string()

static void padding(uint8_t *buffer, const uint32_t nb_read_bytes, uint8_t *nb_padding_bytes, const struct function_infos *func){
    uint8_t remainder = nb_read_bytes % func->md.block_size_in_bytes;

    *nb_padding_bytes = (remainder >= func->md.block_size_without_input_size) ? (func->md.block_size_in_bytes - remainder + func->md.block_size_without_input_size) : func->md.block_size_without_input_size - remainder;

	buffer[nb_read_bytes] = (func->md.name == TIGER) ? 0x01 : 0x80;

    if(*nb_padding_bytes > 1){
        __builtin_memset(buffer + nb_read_bytes + 1, 0, *nb_padding_bytes);
    }
}

    // assemble_hval_big_endian()
    // puts the 32-bit hash values together in big-endian to produce the final hash
    // used in md_file() and md_string()

static uint8_t *assemble_hval_big_endian(uint8_t *restrict digest, const struct function_infos *restrict func){
    for(uint8_t i = 0; i < func->hash_size_in_bytes / 4; i++){      // to encourage the compiler to auto-vectorize
        digest[i * 4] =     (uint8_t)(func->md.hash_values[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(func->md.hash_values[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(func->md.hash_values[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(func->md.hash_values[i]);
    }

    return digest;
}

    // assemble_hval_big_endian_sha512()
    // puts the 64-bit hash values together in big-endian to produce the final hash
    // used in md_file() and md_string()

static uint8_t *assemble_hval_big_endian_sha512(uint8_t *digest, const struct function_infos *func){
    for(uint8_t i = 0; i < func->md.nb_hval_in_hash; i ++){
        digest[i * 8] =     (uint8_t)(func->md.hash_values_u64[i] >> 56);  // i *4 instead of i * 8
        digest[i * 8 + 1] = (uint8_t)(func->md.hash_values_u64[i] >> 48);
        digest[i * 8 + 2] = (uint8_t)(func->md.hash_values_u64[i] >> 40);
        digest[i * 8 + 3] = (uint8_t)(func->md.hash_values_u64[i] >> 32);
        digest[i * 8 + 4] = (uint8_t)(func->md.hash_values_u64[i] >> 24);
        digest[i * 8 + 5] = (uint8_t)(func->md.hash_values_u64[i] >> 16);
        digest[i * 8 + 6] = (uint8_t)(func->md.hash_values_u64[i] >> 8);
        digest[i * 8 + 7] = (uint8_t)(func->md.hash_values_u64[i]);
    }

    return digest;
}

    // assemble_hval_little_endian()
    // puts the 32-bit hash values together in little-endian to produce the final hash
    // used in md_file() and md_string() -> only for MD5 as of version 1.0

static uint8_t *assemble_hval_little_endian(uint8_t *restrict digest, const struct function_infos *restrict func){
    for(uint8_t i = 0; i < func->hash_size_in_bytes / 4; i++){
        digest[i * 4]     = (uint8_t)(func->md.hash_values[i]);
        digest[i * 4 + 1] = (uint8_t)(func->md.hash_values[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(func->md.hash_values[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(func->md.hash_values[i] >> 24);
    }
    
    return digest;
}

    // md_file()
    // performs the hashing of a file using a function based on the Merkle-Damgard construction
    // used in main()

uint8_t *md_file(const char *file_name, struct function_infos *func){
 
    FILE *f = fopen(file_name, "rb"); // opens the file and check for failure
    if(__builtin_expect(!f, 0)){
        perror("File opening failed");
        goto error;
    }

    struct stat file_stats;

    if(stat(file_name, &file_stats) != 0){ // gets the file size by reading the metadata
        fprintf(stderr, "Reading file informations failed.\n");
        goto close_f;
    }

    uint64_t file_size = file_stats.st_size;
    if(file_size == 0){                         // return if file is empty
        fprintf(stderr, "Error: file \"%s\" is empty.\n", file_name);
        goto close_f;
    }


    const uint32_t buffer_size = choose_buffer_size(file_size, func);

    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if(__builtin_expect(!buffer, 0)){
        perror("Memory allocation failed");
        goto close_f;
    }

    uint32_t nb_read_bytes = 0; // holds the number of bytes read after each fread() call

    if(func->md.word_size_in_bytes == 8){ // for functions: SHA-384, SHA-512, SHA512/t

        uint64_t *words = (uint64_t *)calloc(func->md.nb_words, 8);
        if(!words){
            perror("Memory allocation failed");
            goto free_buffer;
        }

        uint32_t nb_bytes = 0;

        while((nb_read_bytes = fread(buffer, 1, buffer_size, f)) > 0){ // Slhasher uses fread() as of version 1.0
                                                                       // use of syscalls for faster reading will be added in future versions
            nb_bytes = nb_read_bytes;

            if(nb_read_bytes < buffer_size){    // buffer is not completely filled -> end of file reached

                if(nb_read_bytes >= buffer_size - func->hash_size_in_bytes){ // end of file is reached but there is not enough space in "buffer" to add
                    uint8_t *temp = (uint8_t *)realloc(buffer, buffer_size + func->md.block_size_in_bytes); // the padding and the input size -> realloc
                    if(__builtin_expect(!temp, 0)){
                        perror("Memory resizing failed");
                        goto free_buffer;
                    }
                    buffer = temp;
                }

                uint8_t nb_padding_bytes;

                padding(buffer, nb_read_bytes, &nb_padding_bytes, func);


		// the first 8 bytes of the block's last 16 bytes are just zeroed for now
		// that's fine as long as the input's size is not bigger than 2^64 - 1 bytes
		// I'll make sure to add support for input sizes coded on 128 bits (up to 2^128 - 1 bytes) in the future, 
		// as it is described in the official SHA-512 specification
				if(func->md.name != TIGER && func->md.name != TIGER_2) {
                	__builtin_memset(buffer + nb_read_bytes + nb_padding_bytes, 0, 8);
				
                	nb_padding_bytes += 8;

                	add_size_in_big_endian(buffer, file_size, nb_read_bytes + nb_padding_bytes + 8);
				} else { 
					const uint64_t file_size_bits = file_size * 8;
					__builtin_memcpy(buffer + nb_read_bytes + nb_padding_bytes, &file_size_bits, 8); 
				} 
            }

            if(func->md.name != TIGER && func->md.name != TIGER_2) sha512(buffer, words, nb_read_bytes, buffer_size, func); // hashes the current "buffer"
			if(func->md.name == TIGER || func->md.name == TIGER_2) tiger(buffer, words, nb_read_bytes, buffer_size, func);
        }

        if(nb_bytes == buffer_size){ // end of file is reached but the file size is a multiple of the buffer size -> we hash the block containing
            uint8_t nb_padding_bytes; // the padding and the input size

            padding(buffer, 0, &nb_padding_bytes, func);
			if(func->md.name != TIGER && func->md.name != TIGER_2){
            	for(uint8_t b = nb_padding_bytes; b < nb_padding_bytes + 8; b++) buffer[b] = 0;

            	nb_padding_bytes += 8;

            	add_size_in_big_endian(buffer, file_size, nb_padding_bytes + 8);

            	sha512(buffer, words, 0, buffer_size, func);
			} else{
				const uint64_t file_size_bits = file_size * 8;
                __builtin_memcpy(buffer + nb_read_bytes + nb_padding_bytes, &file_size_bits, 8);
				tiger(buffer, words, nb_read_bytes, buffer_size, func);
			}
        }

        free(words);

    } else if(func->md.word_size_in_bytes == 4){ // for functions: MD5, SHA-1, SHA-224, SHA-256

        uint32_t *words = (uint32_t *)calloc(64, func->md.nb_words * 4);
        if(__builtin_expect(!words, 0)){
            perror("Memory allocation failed.");
            goto free_buffer;
        }

	void (*funcpointer)(const uint8_t *, uint32_t *, const uint32_t, const uint32_t, struct function_infos *) = NULL; // the function is called through
															  // a function pointer
        switch(func->md.name){
        case MD5:
            funcpointer = md5;
            break;
        case SHA_1:
            funcpointer = sha1;
            break;
        case SHA_224:
            funcpointer = sha256;
            break;
        case SHA_256:
            funcpointer = sha256;
            break;
        default:
            break;
        }

        uint32_t nb_bytes = 0;

        while((nb_read_bytes = fread(buffer, 1, buffer_size, f)) > 0){

            nb_bytes = nb_read_bytes;
            if(nb_read_bytes < buffer_size){

                if(nb_read_bytes >= buffer_size - func->hash_size_in_bytes){

                    uint8_t *temp = (uint8_t *)realloc(buffer, (buffer_size + func->md.block_size_in_bytes));
                    if(__builtin_expect(!temp, 0)){
                        perror("Memory resizing failed");
                        goto free_buffer;
                    }

                    buffer = temp;
                }

                uint8_t nb_padding_bytes;

                padding(buffer, nb_read_bytes, &nb_padding_bytes, func);

                if(func->md.name == MD5){
                    add_size_in_little_endian(buffer, file_size, nb_read_bytes + nb_padding_bytes + 8);
                } else{
                    add_size_in_big_endian(buffer, file_size, nb_read_bytes + nb_padding_bytes + 8);
                }
            }

            funcpointer(buffer, words, nb_read_bytes, buffer_size, func);
        }

        if(nb_bytes == buffer_size){
            uint8_t nb_padding_bytes;

            padding(buffer, 0, &nb_padding_bytes, func);

            if(func->md.name == MD5){
                add_size_in_little_endian(buffer, file_size, nb_padding_bytes + 8);
            } else{
                add_size_in_big_endian(buffer, file_size, nb_padding_bytes + 8);
            }

            funcpointer(buffer, words, 0, buffer_size, func);
        }

        free(words);
    } else{
        fprintf(stderr, "Error: incorrect data.\n");
        goto free_buffer;
    }


    uint8_t *digest = (uint8_t *)malloc(func->md.word_size_in_bytes * func->md.nb_hval_in_hash); // array that will store the final hash
    if(__builtin_expect(!digest, 0)){
        perror("Memory allocation failed");
        goto free_buffer;
    }

    fclose(f);
    free(buffer);
	
	if(func->md.name == TIGER || func->md.name == TIGER_2){
		__builtin_memcpy(digest, &(func->md.hash_values_u64[0]), 8);
		__builtin_memcpy(digest + 8, &(func->md.hash_values_u64[1]), 8);
		__builtin_memcpy(digest + 16, &(func->md.hash_values_u64[2]), 8);
		return digest;
	}

    if(func->md.word_size_in_bytes == 8){
        return assemble_hval_big_endian_sha512(digest, func);
    } else{
        if(func->md.name == MD5){
            return assemble_hval_little_endian(digest, func);
        } else{
            return assemble_hval_big_endian(digest, func);
        }
    }

free_buffer:
    free(buffer);
close_f:
    fclose(f);
error:
    return NULL;

}

    // md_string()
    // performs the hashing of a string using a function based on the Merkle-Damgard construction
    // used in main()

uint8_t *md_string(const char *input_string, struct function_infos *func){
    const uint64_t string_len = strlen(input_string);

    if(string_len > 8000){ // for big inputs, file mode must be used
        fprintf(stderr, "Warning: the size of provided character string excesses the security boundaries.\n");
        fprintf(stderr, "For large data amounts, use the file mode.\n");
        goto error;
    }

    const uint32_t buffer_size = choose_buffer_size(string_len, func);

    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if(__builtin_expect(!buffer, 0)){
        perror("Memory allocation failed");
        goto error;
    }

    buffer = memcpy(buffer, input_string, string_len);
    if(__builtin_expect(!buffer, 0)){
        perror("Copying data failed");
        goto error;
    }

    uint8_t nb_padding_bytes = 0;
    padding(buffer, string_len, &nb_padding_bytes, func);

    if(func->md.word_size_in_bytes == 8){
        //for(uint16_t b = string_len + nb_padding_bytes; b < string_len + nb_padding_bytes + 8; b++) buffer[b] = 0;
		if(func->md.name != TIGER && func->md.name != TIGER_2) {
			__builtin_memset(buffer + string_len + nb_padding_bytes, 0, 8);
        	nb_padding_bytes += 8;

        	add_size_in_big_endian(buffer, string_len, string_len + nb_padding_bytes + 8);
		} else {
			uint64_t string_len_bits = string_len * 8;
			__builtin_memcpy(buffer + string_len + nb_padding_bytes, &string_len_bits, 8);	
		}
        uint64_t *words = (uint64_t *)calloc(func->md.nb_words, 8);
        if(__builtin_expect(!words, 0)){
            perror("Memory allocation failed");
            goto free_buffer;
        }
		

        if(func->md.name != TIGER && func->md.name != TIGER_2) sha512(buffer, words, string_len, buffer_size, func);
		if(func->md.name == TIGER || func->md.name == TIGER_2) tiger(buffer, words, string_len, buffer_size, func);
        free(words);

    } else if(func->md.word_size_in_bytes == 4){
        if(func->md.name == MD5){
            add_size_in_little_endian(buffer, string_len, string_len + nb_padding_bytes + 8);
        } else{
            add_size_in_big_endian(buffer, string_len, string_len + nb_padding_bytes + 8);
        }

        uint32_t *words = (uint32_t *)calloc(func->md.nb_words, 4);
        if(__builtin_expect(!words, 0)){
            perror("Memory allocation failed");
            goto free_buffer;
        }

        void (*funcpointer)(const uint8_t *, uint32_t *, const uint32_t, const uint32_t, struct function_infos *) = NULL;

        switch(func->md.name){
        case MD5:
            funcpointer = md5;
            break;
        case SHA_1:
            funcpointer = sha1;
            break;
        case SHA_224:
            funcpointer = sha256;
            break;
        case SHA_256:
            funcpointer = sha256;
            break;
        default:
            break;
        }

        funcpointer(buffer, words, string_len, buffer_size, func);

        free(words);
    } else{
        fprintf(stderr, "Error: incorrect data.\n");
        goto free_buffer;
    }

    uint8_t *digest = (uint8_t *)malloc(func->hash_size_in_bytes);
    if(__builtin_expect(!digest, 0)){
        perror("Memory allocation failed");
        goto free_buffer;
    }

    free(buffer);

    if(func->md.name == SHA_512_t && func->md.sha512_t) {free(func->md.sha512_t); func->md.sha512_t = NULL;}
	
	if(func->md.name == TIGER || func->md.name == TIGER_2){
        __builtin_memcpy(digest, &(func->md.hash_values_u64[0]), 8);
        __builtin_memcpy(digest + 8, &(func->md.hash_values_u64[1]), 8);
        __builtin_memcpy(digest + 16, &(func->md.hash_values_u64[2]), 8);
        return digest;
    }

    if(func->md.word_size_in_bytes == 8) return assemble_hval_big_endian_sha512(digest, func);
    if(func->md.name == MD5){
        return assemble_hval_little_endian(digest, func);
    } else{
        return assemble_hval_big_endian(digest, func);
    }

free_buffer:
    free(buffer);
error:
    return NULL;

}

    // base_string_sha512/t()
    // creates the string "SHA-512/t" by replacing t with the user's chosen value; this string's hash will give the initial hash values for the input: 1 string -> 1 string
    // used in analyze_input()

bool base_string_sha512t(const char *restrict arg, struct function_infos *restrict func){
    if(strlen(arg) > 12){
        fprintf(stderr, "Error: \"%s\" is not a valid argument\n", arg);
        goto error;
    }

    const char *t_224 = "224";
    const char *t_256 = "256";
    const char *value = NULL;

    if(strncmp(arg + 9, t_224, 3) == 0){
        func->md.t = 224;
        value = t_224;
    } else if(strncmp(arg + 9, t_256, 3) == 0){
        func->md.t = 256;
        value = t_256;
    } else{
        fprintf(stderr, "Error: SHA-512/t: invalid value for t\n");
        goto error;
    }

    //printf("t = %d\n", func->md.t);

    char *base_string = (char *)malloc(12 * sizeof(char));
    if(!base_string){
        perror("Memory allocation failed");
        goto error;
    }

    const char ref_str[9] = "SHA-512/";

    char *temp = strcpy(base_string, ref_str);
    if(!temp){
        perror("Copying memory failed");
        goto free_buffer;
    }
    base_string = temp;

    strcat(base_string, value);

    func->md.sha512_t = base_string;

    return true;

free_buffer:
    free(base_string);
error:
    return false;
}

    // generate_hval_sha512t()
    // computes the initial hash values for the input from the string created by base_string_sha512/t(): 1 string -> 8 uint64_t
    // used in analyze_input()

bool generate_hval_sha512t(struct function_infos *func){
    uint64_t *hash_values = (uint64_t *)calloc(8, 8);
    if(!hash_values){
        perror("Memory allocation failed");
        goto error;
    }

    uint8_t *hash_values_source = md_string(func->md.sha512_t, func);
    if(!hash_values_source){
        goto free_buffer;
    }

    for(uint8_t value_index = 0; value_index < 8; value_index++){
        hash_values[value_index] = (((uint64_t) hash_values_source[value_index * 8]) << 56) |
                                   (((uint64_t) hash_values_source[value_index * 8 + 1]) << 48) |
                                   (((uint64_t) hash_values_source[value_index * 8 + 2]) << 40) |
                                   (((uint64_t) hash_values_source[value_index * 8 + 3]) << 32) |
                                   (((uint64_t) hash_values_source[value_index * 8 + 4]) << 24) |
                                   (((uint64_t) hash_values_source[value_index * 8 + 5]) << 16) |
                                   (((uint64_t) hash_values_source[value_index * 8 + 6]) << 8) |
                                   (((uint64_t) hash_values_source[value_index * 8 + 7]));
    }

    func->md.hash_values_u64 = hash_values;

    free(hash_values_source);
    free(func->md.sha512_t);

    return true;

free_buffer:
    free(hash_values);
error:
    return false;
}

