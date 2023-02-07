/**
 * Copyright (C) Jay Sorg 2023
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LIBPCSCD_PRIV_H
#define _LIBPCSCD_PRIV_H

#include "arch.h"
#include "parse.h"

#define xnew(_type, _num) (_type *) malloc((_num) * sizeof(_type));
#define xnew0(_type, _num) (_type *) calloc(_num, sizeof(_type));

#if defined(B_ENDIAN)
#define in_uint32 in_uint32_be
#define out_uint32 out_uint32_be
#else
#define in_uint32 in_uint32_le
#define out_uint32 out_uint32_le
#endif

struct pcscd_context_priv
{
    struct pcscd_context context;
    struct stream in_s;
};

#endif
