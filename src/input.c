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
#include <stdbool.h>
#include <string.h>
#include "options.h"
#include "m_d.h"
#include "input.h"


static const char curr_version[15] = "slhasher 1.0"; // current version of Slhasher, used in print_version()


// values for MD5

    // initial hash values for MD5

uint32_t hash_values_md5[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

    // round constants for MD5

uint32_t K_table_md5[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};


// values for SHA-1

    // initial hash values for SHA-1

uint32_t hash_values_sha1[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    // round constants for SHA-1

uint32_t K_table_sha1[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};


// values for SHA-256

    // initial hash values for SHA-224

uint32_t hash_values_sha224[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

    // initial hash values for SHA-256

uint32_t hash_values_sha256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    // round constants for SHA-224 and SHA-256

uint32_t K_table_sha256[64] =  {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


// values for SHA-512

    // initial hash values for SHA-384

uint64_t hash_values_sha384[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                                  0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

    // initial hash values for SHA-512

uint64_t hash_values_sha512[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

    // initial hash values for SHA-512/t

uint64_t hash_values_sha512t[8] = {0xcfac43c256196cad, 0x1ec20b20216f029e, 0x99cb56d75b315d8e, 0x00ea509ffab89354, 0xf4abf7da08432774, 0x3ea0cd298e9bc9ba, 0xba267c0e5ee418ce, 0xfe4568bcb6db84dc};

    // round constants for SHA-384, SHA512 and SHA-512/t

uint64_t K_table_sha512[80] =  {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
                                0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
                                0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
                                0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
                                0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
                                0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
                                0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
                                0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
                                0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
                                0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
                                0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
                                0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
                                0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
                                0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
                                0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
                                0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};


    // analyze_input()
    // parses the user input to determine what to do
    // used in main()

bool analyze_input(const int argc, char **restrict argv, struct function_infos *func, struct user_choices *choices){


    const char dash = '-';

    const char *md5 = "--md5";
    const char *sha1 = "--sha1";
    const char *sha224 = "--sha224";
    const char *sha256 = "--sha256";
    const char *sha384 = "--sha384";
    const char *sha512 = "--sha512";
    const char *sha512t = "--sha512/";
    const char *sha3_224 = "--sha3-224";
    const char *sha3_256 = "--sha3-256";
    const char *sha3_384 = "--sha3-384";
    const char *sha3_512 = "--sha3-512";

    const char *help = "--help";
    const char *version = "--version";
    const char *str = "--string";
    const char *sumfile = "--sumfile";

    if(argc < 2){       // return early if input is completely incorrect
        fprintf(stderr, "Error: not enough arguments have been submitted.\n");
        return false;
    }

    if(argc > 5){
        fprintf(stderr, "Error: too many arguments have been submitted.\n");
        return false;
    }

    for(uint8_t arg_index = 1; arg_index < argc; arg_index++){
        if(argv[arg_index][0] == dash && argv[arg_index][1] == dash){
            if(strcmp(argv[arg_index], help) == 0){
                choices->mode = HELP;
                return true;
            } else if(strcmp(argv[arg_index], version) == 0){
                choices->mode = VERSION;
                return true;
            } else if(strcmp(argv[arg_index], str) == 0){
                choices->source = STRING;
                continue;
	    	} else if(strcmp(argv[arg_index], sumfile) == 0){
				choices->sumfile = true;
				continue;		
            } else if(strcmp(argv[arg_index], md5) == 0 || strcmp(argv[arg_index], sha1) == 0 || strcmp(argv[arg_index], sha224) == 0 || strcmp(argv[arg_index], sha256) == 0){
                if(strcmp(argv[arg_index], md5) == 0){
                    func->md.name = MD5;
                } else if(strcmp(argv[arg_index], sha1) == 0){
                    func->md.name = SHA_1;
                } else if(strcmp(argv[arg_index], sha224) == 0){
                    func->md.name = SHA_224;
                } else if(strcmp(argv[arg_index], sha256) == 0){
                    func->md.name = SHA_256;
                }
            } else if(strcmp(argv[arg_index], sha384) == 0 || strcmp(argv[arg_index], sha512) == 0 || strncmp(argv[arg_index], sha512t, 9) == 0){
                if(strcmp(argv[arg_index], sha384) == 0){
                    func->md.name = SHA_384;
                } else if(strcmp(argv[arg_index], sha512) == 0){
                    func->md.name = SHA_512;
                } else if(strncmp(argv[arg_index], sha512t, 9) == 0){
                    func->md.name = SHA_512_t;
                    func->md.nb_words = 80;
                    func->md.word_size_in_bytes = 8;
                    func->md.block_size_in_bytes = 128;
                    func->md.block_size_without_input_size = 112;
                    func->md.K_table_u64 = K_table_sha512;
                    func->md.hash_values_u64 = hash_values_sha512t;
                    func->hash_size_in_bytes = 64;
                    func->md.nb_hval_in_hash = 8;

                    if(!base_string_sha512t(argv[arg_index], func)){ // builds the string that will be hashed in order to produce the initial hash values
                        return false;
                    }

                    if(!generate_hval_sha512t(func)){ // generates the initial hash values starting from the aforementioned string
                        return false;
                    }
                }
            } else if(strcmp(argv[arg_index], sha3_224) == 0 || strcmp(argv[arg_index], sha3_256) == 0 || strcmp(argv[arg_index], sha3_384) == 0 || strcmp(argv[arg_index], sha3_512) == 0){
                func->type = SPONGE;

                if(strcmp(argv[arg_index], sha3_224) == 0){
                    func->sha3.instance = SHA3_224;
                } else if(strcmp(argv[arg_index], sha3_256) == 0){
                    func->sha3.instance = SHA3_256;
                } else if(strcmp(argv[arg_index], sha3_384) == 0){
                    func->sha3.instance = SHA3_384;
                } else{
                    func->sha3.instance = SHA3_512;
                }
                continue;
            } else{
                fprintf(stderr, "Error: \"%s\" is not a valid argument.\n", argv[arg_index]);
                return false;
            }
        } else{
            if(!(choices->data_to_hash)){
                choices->data_to_hash = argv[arg_index];    // file name or string
            } else if(!(choices->compare_string)){
                choices->compare_string = argv[arg_index]; // reference hash
            } else{
                fprintf(stderr, "Warning: \"%s\": invalid argument\nHelp: slhasher --help\n", argv[arg_index]);
                return false;
            }
        }
    }

    if(!(choices->data_to_hash)){
        fprintf(stderr, "Error: no data to hash submitted.\n");
        return false;
    }

    return true;
}

    // fill_func_infos()
    // fills the "func" struct with the appropriate data, depending on the user's choices
    // used in main()

void fill_func_infos(struct function_infos *func){


    switch(func->type){
    case SPONGE:
        func->sha3.suffix = 0x06;
        switch(func->sha3.instance){
        case SHA3_224:
            func->sha3.rate = 144;
            func->hash_size_in_bytes = 28;
            break;
        case SHA3_256:
            func->sha3.rate = 136;
            func->hash_size_in_bytes = 32;
            break;
        case SHA3_384:
            func->sha3.rate = 104;
            func->hash_size_in_bytes = 48;
            break;
        case SHA3_512:
            func->sha3.rate = 72;
            func->hash_size_in_bytes = 64;
            break;
        }
        break;
    case MERKLE_DAMGARD:
        if(func->md.name == SHA_384 || func->md.name == SHA_512 || func->md.name == SHA_512_t){
            func->md.nb_words = 80;
            func->md.word_size_in_bytes = 8;
            func->md.block_size_in_bytes = 128;
            func->md.block_size_without_input_size = 112;
            func->md.K_table_u64 = K_table_sha512;
            switch(func->md.name){
            case SHA_384:
                func->md.hash_values_u64 = hash_values_sha384;
                func->hash_size_in_bytes = 48;
                func->md.nb_hval_in_hash = 6;
                break;
            case SHA_512:
                func->md.hash_values_u64 = hash_values_sha512;
                func->hash_size_in_bytes = 64;
                func->md.nb_hval_in_hash = 8;
                break;
            case SHA_512_t:
                func->hash_size_in_bytes = func->md.t / 8;
                func->md.nb_hval_in_hash = 4;
                func->md.t = 0;
                break;
            default:
                break;
            }
        } else{
            func->md.word_size_in_bytes = 4;
            func->md.block_size_in_bytes = 64;
            func->md.block_size_without_input_size = 56;
            switch(func->md.name){
            case MD5:
                func->md.nb_words = 16;
                func->md.hash_values = hash_values_md5;
                func->md.K_table = K_table_md5;
                func->hash_size_in_bytes = 16;
                func->md.nb_hval_in_hash = 4;
                break;
            case SHA_1:
                func->md.nb_words = 80;
                func->md.hash_values = hash_values_sha1;
                func->md.K_table = K_table_sha1;
                func->hash_size_in_bytes = 20;
                func->md.nb_hval_in_hash = 5;
                break;
            case SHA_224:
                func->md.nb_words = 64;
                func->md.hash_values = hash_values_sha224;
                func->md.K_table = K_table_sha256;
                func->hash_size_in_bytes = 28;
                func->md.nb_hval_in_hash = 7;
                break;
            case SHA_256:
                func->md.nb_words = 64;
                func->md.hash_values = hash_values_sha256;
                func->md.K_table = K_table_sha256;
                func->hash_size_in_bytes = 32;
                func->md.nb_hval_in_hash = 8;
                break;
            default:
                break;
            }
        }
    }


}

    // print_help()
    // prints basic help in the terminal for the user
    // used in main()

void print_help(){
    printf("Slhasher - A command line tool to compute hashes\n");
    printf("Usage: slhasher [OPTIONS] [INPUT] [REF]\n");
    printf("OPTIONS:\n");
    printf("  - functions:\n");
    printf("      --md5\n      --sha1\n      --sha224\n      --sha256\n      --sha384\n      --sha512\n      --sha512/224\n      --sha512/256\n");
    printf("      --sha3-224\n      --sha3-256\n      --sha3-384\n      --sha3-512\n");
    printf("  - other options:\n");
    printf("      --string      specifies that the input is a string of characters\n");
	printf("      --sumfile     reads a sum file (file that contains a file name and its hash) and checks whether the file's hash is identical to the reference hash\n");
    printf("      --help        prints this help\n");
    printf("      --version     prints the current version of Slhasher\n");
    printf("INPUT:\n   input can be a file (default) or a string of characters\n");
    printf("REF:\n     a string of characters representing the reference hash (in hexadecimal) that will be compared with the computed hash\n");
    printf("See the README.md file for more information.\n");
}

    // print_version()
    // prints the user's version of Slhasher
    // used in main()

void print_version(void){
    printf("%s\n", curr_version);
}

    // convert_char_hex()
    // translates a char string to its numeric counterpart: "a1" (char) -> 0xa1 (uint8_t)
    // used in main() to compare the computed hash with the reference hash

uint8_t *convert_char_hex(char *restrict input, const struct function_infos *restrict func){ // this function assumes that the referenece hash is in hexadecimal format
    const char *conv_table1 = "0123456789abcdef";

    const char *uppercase_table = "ABCDEF";

    const char *lowercase_table = "abcdef";

    for(uint16_t i = 0; i < strlen(input); i++){
        for(uint8_t j = 0; j < 6; j++){
            if(input[i] == uppercase_table[j]) input[i] = lowercase_table[j]; // converts all the uppercase letters to their lowercase counterparts
        }
    }

    uint8_t *input_hex = (uint8_t *)calloc(func->hash_size_in_bytes, 1); // allocates memory for the string of char translated in numbers
    if(!input_hex){
        perror("Memory allocation failed");
        return NULL;
    }

    char splited_input[64][2];

    uint8_t char_index = 0;
    for(uint8_t couple_index = 0; couple_index < func->hash_size_in_bytes; couple_index++){ // splits the string in couples of char
        splited_input[couple_index][0] = input[char_index++];
        splited_input[couple_index][1] = input[char_index++];
    }

    for(uint8_t byte_index = 0; byte_index < func->hash_size_in_bytes; byte_index++){ // converts each char to its numeric equivalent
        for(uint8_t i = 0; i < 16; i++){
            if(splited_input[byte_index][0] == conv_table1[i]) input_hex[byte_index] += i * 16;
            if(splited_input[byte_index][1] == conv_table1[i]) input_hex[byte_index] += i;
        }
    }

    return input_hex; // returns the translated string, that can now be compared with the computed hash
}
		
bool parse_sum_file(struct user_choices *choices){
	char *file_name = (char *)malloc(501);  // allocates memory for the ref hash and the file name
	if(__builtin_expect(!file_name, 0)){
		perror("Memory allocation failed");
		goto ret_false;
	}
	
	char *ref_hash  = (char *)malloc(140);
	if(__builtin_expect(!ref_hash, 0)){
		perror("Memory allocation failed");
		goto free_filename;
	}

	FILE *f = fopen(choices->data_to_hash, "rb"); // opens the sum file
	if(__builtin_expect(!f, 0)){
		perror("File opening failed");
		goto free_refhash;
	}
	
	char buffer[550];
	const uint16_t nb_char = fread(buffer, 1, 550, f); // copies the file's data to buffer
	if(nb_char > 530) {                               //  if file is too big, returns
		fprintf(stderr, "Error: file \"%s\" is too big\n", choices->data_to_hash);
		fclose(f);
		goto free_refhash;
	}

	fclose(f); // closes the sum file
	
	const char* const first_space = strchr(buffer, ' '); // pointer to the first space (normally right after the ref hash)
	if(!first_space){                                    // if NULL -> no space -> bad format
		fprintf(stderr, "Error: file \"%s\" is not properly formated\n", choices->data_to_hash);
		goto free_refhash;
	}

	__builtin_memcpy(ref_hash, buffer, first_space - buffer); // copies the ref hash to ref_hash
	ref_hash[first_space - buffer]= '\0';                     // adds the null terminator
	const uint16_t ref_hash_len = strlen(ref_hash);
	if(ref_hash_len > 128){                           // if read hash size != from expected size -> returns
		fprintf(stderr, "Error: \"%s\": reference hash is too long\n", choices->data_to_hash);
		goto free_refhash;
	}

	if((buffer[ref_hash_len + 1] != ' ' && buffer[ref_hash_len + 1] != '*') || buffer[ref_hash_len + 2] == ' ') { // second sep char is neither ' ' nor * -> returns
		fprintf(stderr, "Error: file \"%s\" is not properly formated\n", choices->data_to_hash);                  // first char of file name is ' ' -> returns
		goto free_refhash;
	}

	__builtin_mempcpy(file_name, first_space + 2, nb_char - (first_space - buffer + 3)); // copies the file name to file_name
	file_name[nb_char - (first_space - buffer + 3)] = '\0';                              // adds the null terminator

	choices->data_to_hash = file_name;             // ref hash and file name seem ok -> gives the pointers to struct user_choices
	choices->compare_string = ref_hash;
	
	return true;

free_refhash:
	free(ref_hash);
free_filename:
	free(file_name);
ret_false:
	return false;

}




