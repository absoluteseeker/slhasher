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


#ifndef SHA_3_H
#define SHA_3_H

#include <stdint.h>
#include "options.h"

uint8_t *sha3_file(const char *file_name, struct function_infos *func);

uint8_t *sha3_string(const char *input, struct function_infos *func);

#endif
