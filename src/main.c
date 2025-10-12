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
#include "input.h"
#include "m_d.h"
#include "sha-3.h"



int main(int argc, char *argv[])
{

    function_infos func;
    func.type = MERKLE_DAMGARD; // by default -> most common

    user_choices choices;
    choices.mode = HASHING;
    choices.source = UFILE;
    choices.compare_string = NULL;
    choices.data_to_hash = NULL;

    if(analyze_input(argc, argv, &func, &choices) == false){
        fprintf(stderr, "Aborted.\n");
        return -1;
    }

    fill_func_infos(&func);

    switch(choices.mode){
    case HELP:
        print_help();
        break;
    case VERSION:
        print_version();
        break;
    case HASHING:
        uint8_t *_hash = NULL;

        switch(func.type){
        case MERKLE_DAMGARD:
            switch(choices.source){
            case STRING:
                _hash = md_string(choices.data_to_hash, &func);
                break;
            case UFILE:
                _hash = md_file(choices.data_to_hash, &func);
                break;
            }
            if(func.md.name == SHA_512_t && func.md.t == 0) free(func.md.hash_values_u64); // free() the hash values array that was allocated 
											   // in generate_hval_sha512t()
            break;
        case SPONGE:
            switch(choices.source){
            case STRING:

                _hash = sha3_string(choices.data_to_hash, &func);

                break;
            case UFILE:
                _hash = sha3_file(choices.data_to_hash, &func);
                break;
            }
            break;
        }

        if(!_hash){
            fprintf(stderr, "Aborted.\n");
            return -1;
        } else{
            printf("Thus spoke Slhasher: ");

            for(uint8_t i = 0; i < func.hash_size_in_bytes; i++) printf("%02x", _hash[i]); // prints the hash to the user

            if(choices.source == STRING){       // prints the source (file name or char string)
                printf("  \"%s\"\n", choices.data_to_hash);
            } else{
                printf("  %s\n", choices.data_to_hash);
            }

            if(choices.compare_string != NULL){        // compares the computed hash with the provided reference hash
                if(strlen(choices.compare_string) != func.hash_size_in_bytes * 2){
                    fprintf(stderr, "Warning: check failed: bad size for reference hash\n");
                    return -1;
                }

                uint8_t *usr_ref = convert_char_hex(choices.compare_string, &func);

                if(memcmp(_hash, usr_ref, func.hash_size_in_bytes) == 0){
                    printf("Check: passed - hashes are identical\n");
                } else{
                    printf("Check: failed - hashes are different\n");
                }

                free(usr_ref);
            }
        }

        free(_hash);
        break;
    }


    return 0;
}
