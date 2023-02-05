
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpcscd.h>

#include "libpcscd_priv.h"

/*****************************************************************************/
int
pcscd_create_context(struct pcscd_settings* settings,
                     struct pcscd_context** context)
{
    struct pcscd_context_priv* self;

    self = xnew0(struct pcscd_context_priv, 1);
    if (self == NULL)
    {
        return LIBPCSCD_ERROR_MEMORY;
    }
    *context = &(self->context);
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
int
pcscd_delete_context(struct pcscd_context* context)
{
    free(context);
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_func(struct pcscd_context_priv* self, struct stream* s)
{
    printf("default_func:\n");
    return LIBPCSCD_ERROR_PARSE;
}

/*****************************************************************************/
static int
establish_context(struct pcscd_context_priv* self, struct stream* s)
{
    int scope;
    int hcontext;
    int result;

    printf("establish_context:\n");
    if (!s_check_rem(s, 12))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32_le(s, scope);
    in_uint32_le(s, hcontext);
    in_uint32_le(s, result);
    return self->context.establish_context(&(self->context), scope,
                                           hcontext, result);
}

/*****************************************************************************/
static int
release_context(struct pcscd_context_priv* self, struct stream* s)
{
    int hcontext;
    int result;

    printf("release_context:\n");
    if (!s_check_rem(s, 8))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32_le(s, hcontext);
    in_uint32_le(s, result);
    return self->context.release_context(&(self->context), hcontext, result);
}

/*****************************************************************************/
static int
connect(struct pcscd_context_priv* self, struct stream* s)
{
    int hcontext;
    const char* reader;
    int sharemode;
    int preferredprotocols;
    int card;
    int activeprotocol;
    int result;

    printf("connect:\n");
    if (!s_check_rem(s, 152))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32_le(s, hcontext);
    in_uint8p(s, reader, 128);
    in_uint32_le(s, sharemode);
    in_uint32_le(s, preferredprotocols);
    in_uint32_le(s, card);
    in_uint32_le(s, activeprotocol);
    in_uint32_le(s, result);
    return self->context.connect(&(self->context), hcontext, reader,
                                 sharemode, preferredprotocols, card,
                                 activeprotocol, result);
}

/*****************************************************************************/
static int
reconnect(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int sharemode;
    int preferredprotocols;
    int initialization;
    int activeprotocol;
    int result;

    printf("reconnect:\n");
    if (!s_check_rem(s, 24))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32_le(s, card);
    in_uint32_le(s, sharemode);
    in_uint32_le(s, preferredprotocols);
    in_uint32_le(s, initialization);
    in_uint32_le(s, activeprotocol);
    in_uint32_le(s, result);
    return self->context.reconnect(&(self->context), card, sharemode,
                                   preferredprotocols, initialization,
                                   activeprotocol, result);
}

/*****************************************************************************/
static int
disconnect(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int disposition;
    int result;

    printf("disconnect:\n");
    if (!s_check_rem(s, 12))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32_le(s, card);
    in_uint32_le(s, disposition);
    in_uint32_le(s, result);
    return self->context.disconnect(&(self->context), card,
                                   disposition, result);
}

/*****************************************************************************/
static int
begin_transaction(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int result;

    printf("begin_transaction:\n");
    if (!s_check_rem(s, 8))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32_le(s, card);
    in_uint32_le(s, result);
    return self->context.begin_transaction(&(self->context), card, result);
}

/*****************************************************************************/
static int
end_transaction(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int disposition;
    int result;

    printf("end_transaction:\n");
    if (!s_check_rem(s, 12))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32_le(s, card);
    in_uint32_le(s, disposition);
    in_uint32_le(s, result);
    return self->context.end_transaction(&(self->context), card,
                                         disposition, result);
}

/*****************************************************************************/
static int
cmd_version(struct pcscd_context_priv* self, struct stream* s)
{
    int major;
    int minor;
    int result;

    printf("cmd_version:\n");
    if (!s_check_rem(s, 12))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32_le(s, major);
    in_uint32_le(s, minor);
    in_uint32_le(s, result);
    return self->context.cmd_version(&(self->context), major, minor, result);
}

/*****************************************************************************/
static int
cmd_get_readers_state(struct pcscd_context_priv* self, struct stream* s)
{
    printf("cmd_get_readers_state:\n");
    return self->context.cmd_get_readers_state(&(self->context));
}

/*****************************************************************************/
static int
cmd_wait_reader_state_change(struct pcscd_context_priv* self, struct stream* s)
{
    printf("cmd_wait_reader_state_change:\n");
    return self->context.cmd_wait_reader_state_change(&(self->context));
}

/*****************************************************************************/
static int
cmd_stop_waiting_reader_state_change(struct pcscd_context_priv* self,
                                     struct stream* s)
{
    printf("cmd_stop_waiting_reader_state_change:\n");
    return self->context.cmd_stop_waiting_reader_state_change(&(self->context));
}

typedef int (*message_proc)(struct pcscd_context_priv* self,
                            struct stream* s);

#define LNUM_FUNCS 20

static message_proc g_funcs[LNUM_FUNCS + 1] =
{
    default_func,                           /* 0 */
    establish_context,                      /* 1 */
    release_context,                        /* 2 */
    default_func,                           /* 3 */
    connect,                                /* 4 */
    reconnect,                              /* 5 */
    disconnect,                             /* 6 */
    begin_transaction,                      /* 7 */
    end_transaction,                        /* 8 */
    default_func,                           /* 9 */
    default_func,                           /* 10 */
    default_func,                           /* 11 */
    default_func,                           /* 12 */
    default_func,                           /* 13 */
    default_func,                           /* 14 */
    default_func,                           /* 15 */
    default_func,                           /* 16 */
    cmd_version,                            /* 17 */
    cmd_get_readers_state,                  /* 18 */
    cmd_wait_reader_state_change,           /* 19 */
    cmd_stop_waiting_reader_state_change    /* 20 */
};

/*****************************************************************************/
int
pcscd_process_data_in(struct pcscd_context* context,
                      const void* data, int data_bytes)
{
    struct pcscd_context_priv* self;
    struct stream* s;
    struct stream new_s;
    char* holdp;
    char* holdend;
    int size_needed;
    int in_s_size;
    int left;
    int error;
    int size;
    int code;

    //printf("pcscd_process_data_in:\n");
    self = (struct pcscd_context_priv*)context;
    s = &(self->in_s);
    in_s_size = (int)(s->end - s->data);
    size_needed = in_s_size + data_bytes;
    if (s->size < size_needed)
    {
        memset(&new_s, 0, sizeof(new_s));
        new_s.data = xnew(char, size_needed);
        if (new_s.data == NULL)
        {
            return LIBPCSCD_ERROR_MEMORY;
        }
        new_s.size = size_needed;
        new_s.end = new_s.data;
        memcpy(new_s.end, s->data, in_s_size);
        new_s.end += in_s_size;
        free(s->data);
        *s = new_s;
    }
    memcpy(s->end, data, data_bytes);
    s->end += data_bytes;
    s->p = s->data;
    for (;;)
    {
        if (!s_check_rem(s, 8))
        {
            //printf("pcscd_process_data_in: no more data header\n");
            return LIBPCSCD_ERROR_NONE;
        }
        in_uint32_le(s, size);
        in_uint32_le(s, code);
        if (!s_check_rem(s, size))
        {
            //printf("pcscd_process_data_in: no more data body\n");
            return LIBPCSCD_ERROR_NONE;
        }
        printf("pcscd_process_data_in: size %d code %d\n", size, code);
        /* save p and end */
        holdp = s->p;
        holdend = s->end;
        /* setup temp end */
        s->end = s->p + size;
        /* process message */
        if ((code < 0) || (code > LNUM_FUNCS))
        {
            printf("pcscd_process_data_in: error 0x%8.8x\n", LIBPCSCD_ERROR_PARSE);
            return LIBPCSCD_ERROR_PARSE;
        }
        error = g_funcs[code](self, s);
        if (error != LIBPCSCD_ERROR_NONE)
        {
            printf("pcscd_process_data_in: error %d code %d\n", error, code);
            //return error;
        }
        /* restore p to next message and end to old end */
        s->p = holdp + size;
        s->end = holdend;
        /* what is left, move up, can be zero */
        left = (int)(s->end - s->p);
        //printf("pcscd_process_data_in: left %d size %d\n", left, size);
        memmove(s->data, s->data + 8 + size, left);
        s->end -= 8 + size;
        s->p = s->data;
    }
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
int
pcscd_establish_context_reply(struct pcscd_context* context,
                              int scope, int hcontext, int result)
{
    struct stream out_s;
    char data[12];

    printf("pcscd_establish_context_reply:\n");
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32_le(&out_s, scope);
    out_uint32_le(&out_s, hcontext);
    out_uint32_le(&out_s, result);
    return context->send_to_app(context, out_s.data, 12);
}

/*****************************************************************************/
int
pcscd_release_context_reply(struct pcscd_context* context,
                            int hcontext, int result)
{
    struct stream out_s;
    char data[8];

    printf("pcscd_release_context_reply:\n");
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32_le(&out_s, hcontext);
    out_uint32_le(&out_s, result);
    return context->send_to_app(context, out_s.data, 8);
}

/*****************************************************************************/
int
pcscd_connect_reply(struct pcscd_context* context, int hcontext,
                    const char* reader, int sharemode,
                    int preferredprotocols, int card,
                    int activeprotocol, int result)
{
    struct stream out_s;
    char data[152];
    char text[132];

    printf("pcscd_connect_reply:\n");
    memset(data, 0, sizeof(data));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32_le(&out_s, hcontext);
    strncpy(text, reader, 128);
    out_uint8a(&out_s, text, 128);
    out_uint32_le(&out_s, sharemode);
    out_uint32_le(&out_s, preferredprotocols);
    out_uint32_le(&out_s, card);
    out_uint32_le(&out_s, activeprotocol);
    out_uint32_le(&out_s, result);
    return context->send_to_app(context, out_s.data, 152);
}

/*****************************************************************************/
int
pcscd_reconnect_reply(struct pcscd_context* context, int card,
                      int sharemode, int preferredprotocols,
                      int activeprotocol, int initialization, int result)
{
    struct stream out_s;
    char data[24];

    printf("pcscd_reconnect_reply:\n");
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32_le(&out_s, card);
    out_uint32_le(&out_s, sharemode);
    out_uint32_le(&out_s, preferredprotocols);
    out_uint32_le(&out_s, activeprotocol);
    out_uint32_le(&out_s, initialization);
    out_uint32_le(&out_s, result);
    return context->send_to_app(context, out_s.data, 24);
}

/*****************************************************************************/
int
pcscd_disconnect_reply(struct pcscd_context* context, int card,
                       int disposition, int result)
{
    struct stream out_s;
    char data[12];

    printf("pcscd_disconnect_reply:\n");
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32_le(&out_s, card);
    out_uint32_le(&out_s, disposition);
    out_uint32_le(&out_s, result);
    return context->send_to_app(context, out_s.data, 12);
}

/*****************************************************************************/
int
pcscd_begin_transaction_reply(struct pcscd_context* context, int card,
                              int result)
{
    struct stream out_s;
    char data[8];

    printf("pcscd_begin_transaction_reply:\n");
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32_le(&out_s, card);
    out_uint32_le(&out_s, result);
    return context->send_to_app(context, out_s.data, 8);
}

/*****************************************************************************/
int
pcscd_end_transaction_reply(struct pcscd_context* context, int card,
                            int disposition, int result)
{
    struct stream out_s;
    char data[12];

    printf("pcscd_end_transaction_reply:\n");
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32_le(&out_s, card);
    out_uint32_le(&out_s, disposition);
    out_uint32_le(&out_s, result);
    return context->send_to_app(context, out_s.data, 12);
}

/*****************************************************************************/
int
pcscd_cmd_version_reply(struct pcscd_context* context,
                        int major, int minor, int result)
{
    struct stream out_s;
    char data[12];

    printf("pcscd_cmd_version_reply:\n");
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32_le(&out_s, major);
    out_uint32_le(&out_s, minor);
    out_uint32_le(&out_s, result);
    return context->send_to_app(context, out_s.data, 12);
}

/*****************************************************************************/
int
pcscd_cmd_get_readers_state_reply(struct pcscd_context* context,
                                  struct pcsc_reader_state* states)
{
    printf("pcscd_cmd_get_readers_state_reply:\n");
    return context->send_to_app(context, states,
                                sizeof(struct pcsc_reader_state) * 16);
}

/*****************************************************************************/
int
pcscd_wait_reader_state_change_reply(struct pcscd_context* context,
                                     int timeout, int result)
{
    struct stream out_s;
    char data[8];

    printf("pcscd_wait_reader_state_change_reply:\n");
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32_le(&out_s, timeout);
    out_uint32_le(&out_s, result);
    return context->send_to_app(context, out_s.data, 8);
}
