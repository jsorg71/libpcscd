
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
};

#endif
