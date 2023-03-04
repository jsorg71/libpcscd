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

struct pcscd_context_priv
{
    struct pcscd_context context;
    struct stream in_s;
    struct stream out_s;
};

#define LOG_ERROR lctx, 0
#define LOG_WARN  lctx, 1
#define LOG_INFO  lctx, 2
#define LOG_DEBUG lctx, 3

#define LOGS "[%s][%d][%s]:"
#define LOGP __FILE__, __LINE__, __FUNCTION__

#if !defined(__FUNCTION__) && defined(__FUNC__)
#define LOG_PRE const char* __FUNCTION__ = __FUNC__; (void)__FUNCTION__;
#else
#define LOG_PRE
#endif

#if !defined(LOG_LEVEL)
#define LOG_LEVEL 1
#endif
#if LOG_LEVEL > 0
#define LOGLN(_context, _args) do { \
    struct pcscd_context* lctx = _context; \
    LOG_PRE \
    lctx->log_msg _args ; } while (0)
#else
#define LOGLN(_context, _args)
#endif
#if LOG_LEVEL > 10
#define LOGLND(_context, _args) do { \
    struct pcscd_context* lctx = _context; \
    LOG_PRE \
    lctx->log_msg _args ; } while (0)
#else
#define LOGLND(_context, _args)
#endif

#endif
