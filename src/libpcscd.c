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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpcscd.h>

#include "libpcscd_priv.h"

/*****************************************************************************/
static int
default_log_msg(struct pcscd_context* context, int log_level,
                const char* msg, ...)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_send_to_app(struct pcscd_context* context,
                    const void* data, int bytes)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_establish_context(struct pcscd_context* context,
                          int dwscope, int hcontext, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_release_context(struct pcscd_context* context,
                        int hcontext, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_connect(struct pcscd_context* context, int hcontext,
                const char* reader, int sharemode,
                int preferredprotocols, int card,
                int activeprotocol, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_reconnect(struct pcscd_context* context, int card,
                  int sharemode, int preferredprotocols,
                  int initialization, int activeprotocol, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_disconnect(struct pcscd_context* context, int card,
                   int disposition, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_begin_transaction(struct pcscd_context* context,
                          int card, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_end_transaction(struct pcscd_context* context,
                        int card, int disposition, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_transmit(struct pcscd_context* context, int card,
                 int send_ior_protocol, int send_ior_pcilength,
                 int send_bytes,
                 int recv_ior_protocol, int recv_ior_pcilength,
                 int recv_bytes, int result, const void* senddata)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_control(struct pcscd_context* context, int card, int controlcode,
                int sendbytes, int recvbytes, int bytesreturned,
                int result, const void* senddata)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_status(struct pcscd_context* context, int card, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_cancel(struct pcscd_context* context, int hcontext, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_get_attrib(struct pcscd_context* context, int card, int attrid,
                   void* attr, int attrlen, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_set_attrib(struct pcscd_context* context, int card, int attrid,
                   const void* attr, int attrlen, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_cmd_version(struct pcscd_context* context,
                    int major, int minor, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_cmd_get_readers_state(struct pcscd_context* context)
{
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_cmd_wait_reader_state_change(struct pcscd_context* context,
                                     int timeout, int result)
{
    return LIBPCSCD_ERROR_NONE;
}
/*****************************************************************************/
static int
default_cmd_stop_waiting_reader_state_change(struct pcscd_context* context,
                                             int timeout, int result)
{
    return LIBPCSCD_ERROR_NONE;
}

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
    self->context.log_msg = default_log_msg;
    self->context.send_to_app = default_send_to_app;
    self->context.establish_context = default_establish_context;
    self->context.release_context = default_release_context;
    self->context.connect = default_connect;
    self->context.reconnect = default_reconnect;
    self->context.disconnect = default_disconnect;
    self->context.begin_transaction = default_begin_transaction;
    self->context.end_transaction = default_end_transaction;
    self->context.transmit = default_transmit;
    self->context.control = default_control;
    self->context.status = default_status;
    self->context.cancel = default_cancel;
    self->context.get_attrib = default_get_attrib;
    self->context.set_attrib = default_set_attrib;
    self->context.cmd_version = default_cmd_version;
    self->context.cmd_get_readers_state = default_cmd_get_readers_state;
    self->context.cmd_wait_reader_state_change =
        default_cmd_wait_reader_state_change;
    self->context.cmd_stop_waiting_reader_state_change =
        default_cmd_stop_waiting_reader_state_change;
    *context = &(self->context);
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
int
pcscd_delete_context(struct pcscd_context* context)
{
    struct pcscd_context_priv* self;

    self = (struct pcscd_context_priv*)context;
    free(self->in_s.data);
    free(self);
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
default_func(struct pcscd_context_priv* self, struct stream* s)
{
    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    return LIBPCSCD_ERROR_IMPL;
}

/*****************************************************************************/
static int
establish_context(struct pcscd_context_priv* self, struct stream* s)
{
    int scope;
    int hcontext;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 12))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, scope);
    in_uint32(s, hcontext);
    in_uint32(s, result);
    return self->context.establish_context(&(self->context), scope,
                                           hcontext, result);
}

/*****************************************************************************/
static int
release_context(struct pcscd_context_priv* self, struct stream* s)
{
    int hcontext;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 8))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, hcontext);
    in_uint32(s, result);
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

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 152))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, hcontext);
    in_uint8p(s, reader, 128);
    in_uint32(s, sharemode);
    in_uint32(s, preferredprotocols);
    in_uint32(s, card);
    in_uint32(s, activeprotocol);
    in_uint32(s, result);
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

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 24))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, card);
    in_uint32(s, sharemode);
    in_uint32(s, preferredprotocols);
    in_uint32(s, initialization);
    in_uint32(s, activeprotocol);
    in_uint32(s, result);
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

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 12))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, card);
    in_uint32(s, disposition);
    in_uint32(s, result);
    return self->context.disconnect(&(self->context), card,
                                    disposition, result);
}

/*****************************************************************************/
static int
begin_transaction(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 8))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, card);
    in_uint32(s, result);
    return self->context.begin_transaction(&(self->context), card, result);
}

/*****************************************************************************/
static int
end_transaction(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int disposition;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 12))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, card);
    in_uint32(s, disposition);
    in_uint32(s, result);
    return self->context.end_transaction(&(self->context), card,
                                         disposition, result);
}

/*****************************************************************************/
static int
transmit(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int sendiorprotocol;
    int sendiorpcilength;
    int sendbytes;
    int recviorprotocol;
    int recviorpcilength;
    int recvbytes;
    int result;
    char* senddata;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 32))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, card);
    in_uint32(s, sendiorprotocol);
    in_uint32(s, sendiorpcilength);
    in_uint32(s, sendbytes);
    in_uint32(s, recviorprotocol);
    in_uint32(s, recviorpcilength);
    in_uint32(s, recvbytes);
    in_uint32(s, result);
    senddata = NULL;
    if (sendbytes > 0)
    {
        if (!s_check_rem(s, sendbytes))
        {
            return LIBPCSCD_ERROR_PARSE;
        }
        in_uint8p(s, senddata, sendbytes);
    }
    return self->context.transmit(&(self->context),
                                  card, sendiorprotocol, sendiorpcilength,
                                  sendbytes,
                                  recviorprotocol, recviorpcilength,
                                  recvbytes, result, senddata);
}

/*****************************************************************************/
static int
control(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int controlcode;
    int sendbytes;
    int recvbytes;
    int bytesreturned;
    int result;
    char* senddata;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 24))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, card);
    in_uint32(s, controlcode);
    in_uint32(s, sendbytes);
    in_uint32(s, recvbytes);
    in_uint32(s, bytesreturned);
    in_uint32(s, result);
    senddata = NULL;
    if (sendbytes > 0)
    {
        if (!s_check_rem(s, sendbytes))
        {
            return LIBPCSCD_ERROR_PARSE;
        }
        in_uint8p(s, senddata, sendbytes);
    }
    return self->context.control(&(self->context), card, controlcode,
                                 sendbytes, recvbytes, bytesreturned,
                                 result, senddata);
}

/*****************************************************************************/
static int
status(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 8))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, card);
    in_uint32(s, result);
    return self->context.status(&(self->context), card, result);
}

/*****************************************************************************/
static int
cancel(struct pcscd_context_priv* self, struct stream* s)
{
    int hcontext;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 8))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, hcontext);
    in_uint32(s, result);
    return self->context.cancel(&(self->context), hcontext, result);
}
/*****************************************************************************/
static int
get_attrib(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int attrid;
    char* attr;
    int attrlen;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 280))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, card);
    in_uint32(s, attrid);
    in_uint8p(s, attr, 264);
    in_uint32(s, attrlen);
    in_uint32(s, result);
    return self->context.get_attrib(&(self->context), card, attrid,
                                    attr, attrlen, result);
}

/*****************************************************************************/
static int
set_attrib(struct pcscd_context_priv* self, struct stream* s)
{
    int card;
    int attrid;
    char* attr;
    int attrlen;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 280))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, card);
    in_uint32(s, attrid);
    in_uint8p(s, attr, 264);
    in_uint32(s, attrlen);
    in_uint32(s, result);
    return self->context.set_attrib(&(self->context), card, attrid,
                                    attr, attrlen, result);
}

/*****************************************************************************/
static int
cmd_version(struct pcscd_context_priv* self, struct stream* s)
{
    int major;
    int minor;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (!s_check_rem(s, 12))
    {
        return LIBPCSCD_ERROR_PARSE;
    }
    in_uint32(s, major);
    in_uint32(s, minor);
    in_uint32(s, result);
    return self->context.cmd_version(&(self->context), major, minor, result);
}

/*****************************************************************************/
static int
cmd_get_readers_state(struct pcscd_context_priv* self, struct stream* s)
{
    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    return self->context.cmd_get_readers_state(&(self->context));
}

/*****************************************************************************/
static int
cmd_wait_reader_state_change(struct pcscd_context_priv* self, struct stream* s)
{
    int timeout;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (s_check_rem(s, 8))
    {
        in_uint32(s, timeout);
        in_uint32(s, result);
    }
    else
    {
        timeout = 0;
        result = 0;
    }
    return self->context.cmd_wait_reader_state_change
            (&(self->context), timeout, result);
}

/*****************************************************************************/
static int
cmd_stop_waiting_reader_state_change(struct pcscd_context_priv* self,
                                     struct stream* s)
{
    int timeout;
    int result;

    LOGLND(&(self->context), (LOG_INFO, LOGS, LOGP));
    if (s_check_rem(s, 8))
    {
        in_uint32(s, timeout);
        in_uint32(s, result);
    }
    else
    {
        timeout = 0;
        result = 0;
    }
    return self->context.cmd_stop_waiting_reader_state_change
            (&(self->context), timeout, result);
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
    transmit,                               /* 9 */
    control,                                /* 10 */
    status,                                 /* 11 */
    default_func,                           /* 12 */
    cancel,                                 /* 13 */
    default_func,                           /* 14 */
    get_attrib,                             /* 15 */
    set_attrib,                             /* 16 */
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
    int extrabytes;
    int missedbytes;

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    if (data_bytes < 0)
    {
        return LIBPCSCD_ERROR_PARAM;
    }
    if ((data == NULL) && (data_bytes > 0))
    {
        return LIBPCSCD_ERROR_PARAM;
    }
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
            /* not enough yet, ok */
            return LIBPCSCD_ERROR_NONE;
        }
        in_uint32(s, size);
        in_uint32(s, code);
        if (!s_check_rem(s, size))
        {
            /* not enough yet, ok */
            return LIBPCSCD_ERROR_NONE;
        }
        /* transmit and control have some extra data after the message */
        extrabytes = 0;
        if (code == 9) /* tramsit */
        {
            if (!s_check_rem(s, 16))
            {
                /* not enough yet, ok */
                return LIBPCSCD_ERROR_NONE;
            }
            holdp = s->p;
            in_uint8s(s, 12); /* card, sendiorprotocol, sendiorpcilength */
            in_uint32(s, extrabytes); /* sendbytes */
            s->p = holdp;
        }
        else if (code == 10) /* control */
        {
            if (!s_check_rem(s, 12))
            {
                /* not enough yet, ok */
                return LIBPCSCD_ERROR_NONE;
            }
            holdp = s->p;
            in_uint8s(s, 8); /* card, controlcode */
            in_uint32(s, extrabytes); /* sendbytes */
            s->p = holdp;
        }
        if (!s_check_rem(s, size + extrabytes))
        {
            /* not enough yet, ok */
            return LIBPCSCD_ERROR_NONE;
        }
        /* at this point we can not return til bottom of loop */
        size += extrabytes;
        /* save p and end */
        holdp = s->p;
        holdend = s->end;
        /* setup temp end */
        s->end = s->p + size;
        /* process message */
        if ((code < 0) || (code > LNUM_FUNCS))
        {
            error = LIBPCSCD_ERROR_CODE;
        }
        else
        {
            error = g_funcs[code](self, s);
        }
        /* check that all the data was processed */
        if (error == LIBPCSCD_ERROR_NONE)
        {
            missedbytes = (int)(s->end - s->p);
            if (missedbytes != 0)
            {
                error = LIBPCSCD_ERROR_MISSED;
            }
        }
        /* restore p to next message and end to old end */
        s->p = holdp + size;
        s->end = holdend;
        /* what is left, move up, left can be zero */
        left = (int)(s->end - s->p);
        memmove(s->data, s->data + 8 + size, left);
        s->end -= 8 + size;
        s->p = s->data;
        if (error != LIBPCSCD_ERROR_NONE)
        {
            return error;
        }
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

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, scope);
    out_uint32(&out_s, hcontext);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 12);
}

/*****************************************************************************/
int
pcscd_release_context_reply(struct pcscd_context* context,
                            int hcontext, int result)
{
    struct stream out_s;
    char data[8];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, hcontext);
    out_uint32(&out_s, result);
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
    char text[LIBPCSCD_MAX_READER_NAME_LEN + 16];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    memset(data, 0, sizeof(data));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, hcontext);
    strncpy(text, reader, LIBPCSCD_MAX_READER_NAME_LEN);
    out_uint8a(&out_s, text, LIBPCSCD_MAX_READER_NAME_LEN);
    out_uint32(&out_s, sharemode);
    out_uint32(&out_s, preferredprotocols);
    out_uint32(&out_s, card);
    out_uint32(&out_s, activeprotocol);
    out_uint32(&out_s, result);
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

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, card);
    out_uint32(&out_s, sharemode);
    out_uint32(&out_s, preferredprotocols);
    out_uint32(&out_s, activeprotocol);
    out_uint32(&out_s, initialization);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 24);
}

/*****************************************************************************/
int
pcscd_disconnect_reply(struct pcscd_context* context, int card,
                       int disposition, int result)
{
    struct stream out_s;
    char data[12];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, card);
    out_uint32(&out_s, disposition);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 12);
}

/*****************************************************************************/
int
pcscd_begin_transaction_reply(struct pcscd_context* context, int card,
                              int result)
{
    struct stream out_s;
    char data[8];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, card);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 8);
}

/*****************************************************************************/
int
pcscd_end_transaction_reply(struct pcscd_context* context, int card,
                            int disposition, int result)
{
    struct stream out_s;
    char data[12];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, card);
    out_uint32(&out_s, disposition);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 12);
}

/*****************************************************************************/
int
pcscd_transmit_reply(struct pcscd_context* context, int card,
                     int sendiorprotocol, int sendiorpcilength,
                     int sendbytes,
                     int recviorprotocol, int recviorpcilength,
                     int recvbytes, int result, const void* recvdata)
{
    struct stream out_s;
    char data[32];
    int rv;

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, card);
    out_uint32(&out_s, sendiorprotocol);
    out_uint32(&out_s, sendiorpcilength);
    out_uint32(&out_s, sendbytes);
    out_uint32(&out_s, recviorprotocol);
    out_uint32(&out_s, recviorpcilength);
    out_uint32(&out_s, recvbytes);
    out_uint32(&out_s, result);
    rv = context->send_to_app(context, out_s.data, 32);
    if ((rv == LIBPCSCD_ERROR_NONE) && (recvbytes > 0))
    {
        rv = context->send_to_app(context, recvdata, recvbytes);
    }
    return rv;
}

/*****************************************************************************/
int
pcscd_control_reply(struct pcscd_context* context, int card, int controlcode,
                    int sendbytes, int recvbytes, int bytesreturned,
                    int result, const void* recvdata)
{
    struct stream out_s;
    char data[24];
    int rv;

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, card);
    out_uint32(&out_s, controlcode);
    out_uint32(&out_s, sendbytes);
    out_uint32(&out_s, recvbytes);
    out_uint32(&out_s, bytesreturned);
    out_uint32(&out_s, result);
    rv = context->send_to_app(context, out_s.data, 24);
    if ((rv == LIBPCSCD_ERROR_NONE) && (bytesreturned > 0))
    {
        rv = context->send_to_app(context, recvdata, bytesreturned);
    }
    return rv;
}

/*****************************************************************************/
int
pcscd_status_reply(struct pcscd_context* context, int card, int result)
{
    struct stream out_s;
    char data[8];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, card);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 8);
}

/*****************************************************************************/
int
pcscd_cancel_reply(struct pcscd_context* context, int hcontext, int result)
{
    struct stream out_s;
    char data[8];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, hcontext);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 8);
}

/*****************************************************************************/
int
pcscd_get_attrib_reply(struct pcscd_context* context, int card, int attrid,
                       const void* attr, int attrlen, int result)
{
    struct stream out_s;
    char data[280];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, card);
    out_uint32(&out_s, attrid);
    if ((attrlen < 0) || (attrlen > 264))
    {
        return LIBPCSCD_ERROR_PARAM;
    }
    out_uint8a(&out_s, attr, attrlen);
    out_uint8s(&out_s, 264 - attrlen);
    out_uint32(&out_s, attrlen);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 280);
}

/*****************************************************************************/
int
pcscd_set_attrib_reply(struct pcscd_context* context, int card, int attrid,
                       const void* attr, int attrlen, int result)
{
    struct stream out_s;
    char data[280];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, card);
    out_uint32(&out_s, attrid);
    if ((attrlen < 0) || (attrlen > 264))
    {
        return LIBPCSCD_ERROR_PARAM;
    }
    out_uint8a(&out_s, attr, attrlen);
    out_uint8s(&out_s, 264 - attrlen);
    out_uint32(&out_s, attrlen);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 280);
}

/*****************************************************************************/
int
pcscd_cmd_version_reply(struct pcscd_context* context,
                        int major, int minor, int result)
{
    struct stream out_s;
    char data[12];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, major);
    out_uint32(&out_s, minor);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 12);
}

/*****************************************************************************/
int
pcscd_cmd_get_readers_state_reply(struct pcscd_context* context,
                                  struct pcsc_reader_state* states,
                                  int num_states)
{
    int rv;
    int send_bytes;
    struct pcsc_reader_state blank_state;

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    if (num_states < 0)
    {
        LOGLND(context, (LOG_ERROR, LOGS "num_states %d", LOGP, num_states));
        return LIBPCSCD_ERROR_PARAM;
    }
    if (num_states > 16)
    {
        num_states = 16;
    }
    rv = LIBPCSCD_ERROR_NONE;
    if (num_states > 0)
    {
        send_bytes = sizeof(struct pcsc_reader_state) * num_states;
        rv = context->send_to_app(context, states, send_bytes);
    }
    if ((rv == LIBPCSCD_ERROR_NONE) && (num_states < 16))
    {
        send_bytes = sizeof(blank_state);
        memset(&blank_state, 0, send_bytes);
        while ((num_states < 16) && (rv == LIBPCSCD_ERROR_NONE))
        {
            rv = context->send_to_app(context, &blank_state, send_bytes);
            num_states++;
        }
    }
    return rv;
}

/*****************************************************************************/
int
pcscd_wait_reader_state_change_reply(struct pcscd_context* context,
                                     int timeout, int result)
{
    struct stream out_s;
    char data[8];

    LOGLND(context, (LOG_INFO, LOGS, LOGP));
    out_s.data = data;
    out_s.p = out_s.data;
    out_uint32(&out_s, timeout);
    out_uint32(&out_s, result);
    return context->send_to_app(context, out_s.data, 8);
}
