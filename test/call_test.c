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
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libpcscd.h>

#include <winscard.h>

#define LUDS_SCK_FILE "/tmp/libpcscd.socket"
#define LMAX(_val1, _val2) (_val1) > (_val2) ? _val1 : _val2

static int g_version_major = 0;
static int g_version_minor = 0;

struct call_test_info
{
    struct pcscd_context* context;
    int listen_sck;
    int sck;
    int sockets[2]; /* thread socket pair */
    int got_con;
    pthread_mutex_t mutex;
    struct establish_context_test_info
    {
        volatile int callcount;
        int in_dwscope;
        int out_hcontext;
        int out_result;
    } establish_context_test;
    struct release_context_test_info
    {
        volatile int callcount;
        int in_hcontext;
        int out_result;
    } release_context_test;
    struct connect_test_info
    {
        volatile int callcount;
        int in_hcontext;
        char in_reader[128];
        int in_sharemode;
        int in_preferredprotocols;
        int out_card;
        int out_activeprotocol;
        int out_result;
    } connect_test;
    struct reconnect_test_info
    {
        volatile int callcount;
        int in_card;
        int in_sharemode;
        int in_preferredprotocols;
        int in_initialization;
        int out_activeprotocol;
        int out_result;
    } reconnect_test;
    struct disconnect_test_info
    {
        volatile int callcount;
        int in_card;
        int in_disposition;
        int out_result;
    } disconnect_test;
    struct begin_transaction_test_info
    {
        volatile int callcount;
        int in_card;
        int out_result;
    } begin_transaction_test;
    struct end_transaction_test_info
    {
        volatile int callcount;
        int in_card;
        int in_disposition;
        int out_result;
    } end_transaction_test;
    struct transmit_test_info
    {
        volatile int callcount;
        int in_card;
        int in_sendiorprotocol;
        int in_sendiorpcilength;
        int in_sendbytes;
        int in_recviorprotocol;
        int in_recviorpcilength;
        int in_recvbytes;
        const char* in_senddata;
        int out_recviorprotocol;
        int out_recviorpcilength;
        int out_recvbytes;
        int out_result;
        char* out_recvdata;
    } transmit_test;
    struct control_test_info // not done
    {
        volatile int callcount;
        int in_card;
        int in_controlcode;
        int in_sendbytes;
        int in_recvbytes;
        const char* in_senddata;
        int out_bytesreturned;
        int out_result;
        char* out_recvdata;
    } control_test;
    struct status_test_info
    {
        volatile int callcount;
        int in_card;
        int out_result;
    } status_test;
    struct cancel_test_info
    {
        volatile int callcount;
        int in_hcontext;
        int out_result;
    } cancel_test;
    struct get_attrib_test_info
    {
        volatile int callcount;
        int in_card;
        int in_attrid;
        int in_attrlen;
        char* out_attr[264];
        int out_attrlen;
        int out_result;
    } get_attrib_test;
    struct set_attrib_test_info
    {
        volatile int callcount;
        int in_card;
        int in_attrid;
        int in_attrlen;
        char* in_attr[264];
        int out_result;
    } set_attrib_test;
    struct my_cmd_version_test_info
    {
        volatile int callcount;
        int in_major;
        int in_minor;
        int out_major;
        int out_minor;
        int out_result;
    } my_cmd_version_test;
    struct cmd_get_readers_state_test_info
    {
        volatile int callcount;
        struct pcsc_reader_state states[16];
    } cmd_get_readers_state_test;
    struct cmd_wait_reader_state_change_test_info
    {
        volatile int callcount;
    } cmd_wait_reader_state_change_test;
    struct cmd_stop_waiting_reader_state_change_test_info
    {
        volatile int callcount;
    } cmd_stop_waiting_reader_state_change_test;
};

/*****************************************************************************/
/* print a hex dump to stdout*/
static void
hexdump(const void* p, int len)
{
    unsigned char *line;
    int i;
    int thisline;
    int offset;

    line = (unsigned char *)p;
    offset = 0;

    while (offset < len)
    {
        printf("%04x ", offset);
        thisline = len - offset;

        if (thisline > 16)
        {
            thisline = 16;
        }

        for (i = 0; i < thisline; i++)
        {
            printf("%02x ", line[i]);
        }

        for (; i < 16; i++)
        {
            printf("   ");
        }

        for (i = 0; i < thisline; i++)
        {
            printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');
        }

        printf("\n");
        offset += thisline;
        line += thisline;
    }
}

static const char g_log_pre[][8] =
{
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG"
};

/*****************************************************************************/
static int
my_log_msg(struct pcscd_context* context, int log_level, const char* msg, ...)
{
    va_list ap;
    char text[256];

    va_start(ap, msg);
    vsnprintf(text, sizeof(text), msg, ap);
    printf("[%s]%s\n", g_log_pre[log_level % 4], text);
    va_end(ap);
    return 0;
}

/*****************************************************************************/
static int
my_send_to_app(struct pcscd_context* context, const void* data, int bytes)
{
    struct call_test_info* cti;
    int error;
    const char* data8;

    //printf("my_send_to_app: bytes %d\n", bytes);
    cti = (struct call_test_info*)(context->user[0]);
    data8 = (const char*)data;
    while (bytes > 0)
    {
        error = send(cti->sck, data8, bytes, 0);
        if (error < 1)
        {
            return LIBPCSCD_ERROR_SEND;
        }
        data8 += error;
        bytes -= error;
    }
    return LIBPCSCD_ERROR_NONE;
}

/*****************************************************************************/
static int
my_establish_context(struct pcscd_context* context,
                     int dwscope, int hcontext, int result)
{
    struct call_test_info* cti;

    //printf("my_establish_context: dwscope %d hcontext %d result %d\n",
    //       dwscope, hcontext, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->establish_context_test.callcount++;
    cti->establish_context_test.in_dwscope = dwscope;
    hcontext = cti->establish_context_test.out_hcontext;
    result = cti->establish_context_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_establish_context_reply(context, dwscope, hcontext, result);
}

/*****************************************************************************/
static int
my_release_context(struct pcscd_context* context, int hcontext, int result)
{
    struct call_test_info* cti;

    //printf("my_release_context: hcontext %d result %d\n", hcontext, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->release_context_test.callcount++;
    cti->release_context_test.in_hcontext = hcontext;
    result = cti->release_context_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_release_context_reply(context, hcontext, result);
}

/*****************************************************************************/
static int
my_connect(struct pcscd_context* context, int hcontext,
           const char* reader, int sharemode,
           int preferredprotocols, int card, int activeprotocol, int result)
{
    struct call_test_info* cti;

    //printf("my_connect: hcontext %d result %d\n", hcontext, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->connect_test.callcount++;
    cti->connect_test.in_hcontext = hcontext;
    strncpy(cti->connect_test.in_reader, reader, 127);
    cti->connect_test.in_sharemode = sharemode;
    cti->connect_test.in_preferredprotocols = preferredprotocols;
    card = cti->connect_test.out_card;
    activeprotocol = cti->connect_test.out_activeprotocol;
    result = cti->connect_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_connect_reply(context, hcontext, reader, sharemode,
                               preferredprotocols, card,
                               activeprotocol, result);
}

/*****************************************************************************/
static int
my_reconnect(struct pcscd_context* context, int card,
             int sharemode, int preferredprotocols,
             int initialization, int activeprotocol, int result)
{
    struct call_test_info* cti;

    //printf("my_reconnect: card %d result %d\n", card, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->reconnect_test.callcount++;
    cti->reconnect_test.in_card = card;
    cti->reconnect_test.in_sharemode = sharemode;
    cti->reconnect_test.in_preferredprotocols = preferredprotocols;
    cti->reconnect_test.in_initialization = initialization;
    activeprotocol = cti->reconnect_test.out_activeprotocol;
    result = cti->reconnect_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_reconnect_reply(context, card, sharemode,
                                 preferredprotocols, initialization,
                                 activeprotocol, result);
}

/*****************************************************************************/
static int
my_disconnect(struct pcscd_context* context, int card,
              int disposition, int result)
{
    struct call_test_info* cti;

    //printf("my_disconnect: card %d result %d\n", card, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->disconnect_test.callcount++;
    cti->disconnect_test.in_card = card;
    cti->disconnect_test.in_disposition = disposition;
    result = cti->disconnect_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_disconnect_reply(context, card, disposition, result);
}

/*****************************************************************************/
static int
my_begin_transaction(struct pcscd_context* context,
                     int card, int result)
{
    struct call_test_info* cti;

    //printf("my_begin_transaction: card %d result %d\n", card, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->begin_transaction_test.callcount++;
    cti->begin_transaction_test.in_card = card;
    result = cti->begin_transaction_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_begin_transaction_reply(context, card, result);
}

/*****************************************************************************/
static int
my_end_transaction(struct pcscd_context* context,
                   int card, int disposition, int result)
{
    struct call_test_info* cti;

    //printf("my_end_transaction: card %d result %d\n", card, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->end_transaction_test.callcount++;
    cti->end_transaction_test.in_card = card;
    cti->end_transaction_test.in_disposition = disposition;
    result = cti->end_transaction_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_end_transaction_reply(context, card, disposition, result);
}

/*****************************************************************************/
static int
my_transmit(struct pcscd_context* context, int card,
            int sendiorprotocol, int sendiorpcilength,
            int sendbytes,
            int recviorprotocol, int recviorpcilength,
            int recvbytes, int result, const char* senddata)
{
    struct call_test_info* cti;
    char* recvdata;

    //printf("my_transmit: card %d result %d send_bytes %d recv_bytes %d\n",
    //       card, result, sendbytes, recvbytes);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->transmit_test.callcount++;
    cti->transmit_test.in_card = card;
    cti->transmit_test.in_sendiorprotocol = sendiorprotocol;
    cti->transmit_test.in_sendiorpcilength = sendiorpcilength;
    cti->transmit_test.in_sendbytes = sendbytes;
    cti->transmit_test.in_recviorprotocol = recviorprotocol;
    cti->transmit_test.in_recviorpcilength = recviorpcilength;
    cti->transmit_test.in_recvbytes = recvbytes;
    cti->transmit_test.in_senddata = senddata;
    recviorprotocol = cti->transmit_test.out_recviorprotocol;
    recviorpcilength = cti->transmit_test.out_recviorpcilength;
    recvbytes = cti->transmit_test.out_recvbytes;
    result = cti->transmit_test.out_result;
    recvdata = cti->transmit_test.out_recvdata;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_transmit_reply(context, card,
                                sendiorprotocol, sendiorpcilength,
                                sendbytes,
                                recviorprotocol, recviorpcilength,
                                recvbytes, result, recvdata);
}

/*****************************************************************************/
static int
my_control(struct pcscd_context* context, int card, int controlcode,
           int sendbytes, int recvbytes, int bytesreturned,
           int result, const char* senddata)
{
    struct call_test_info* cti;
    char* recvdata;

    //printf("my_control: card %d result %d\n", card, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->control_test.callcount++;
    cti->control_test.in_card = card;
    cti->control_test.in_controlcode = controlcode;
    cti->control_test.in_sendbytes = sendbytes;
    cti->control_test.in_recvbytes = recvbytes;
    cti->control_test.in_senddata = senddata;
    bytesreturned = cti->control_test.out_bytesreturned;
    result = cti->control_test.out_result;
    recvdata = cti->control_test.out_recvdata;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_control_reply(context, card, controlcode,
                               sendbytes, recvbytes, bytesreturned,
                               result, recvdata);
}

/*****************************************************************************/
static int
my_status(struct pcscd_context* context, int card, int result)
{
    struct call_test_info* cti;

    //printf("my_status: card %d result %d\n", card, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->status_test.callcount++;
    cti->status_test.in_card = card;
    result = cti->status_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_status_reply(context, card, result);
}

/*****************************************************************************/
static int
my_cancel(struct pcscd_context* context, int hcontext, int result)
{
    struct call_test_info* cti;

    //printf("my_cancel: hcontext %d result %d\n", hcontext, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->cancel_test.callcount++;
    cti->cancel_test.in_hcontext = hcontext;
    result = cti->cancel_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_cancel_reply(context, hcontext, result);
}

/*****************************************************************************/
static int
my_get_attrib(struct pcscd_context* context, int card, int attrid,
              char* attr, int attrlen, int result)
{
    struct call_test_info* cti;

    //printf("my_get_attrib: card %d result %d attrlen %d\n",
    //       card, result, attrlen);
    if (attrlen > 264)
    {
        attrlen = 264;
    }
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->get_attrib_test.callcount++;
    cti->get_attrib_test.in_card = card;
    cti->get_attrib_test.in_attrid = attrid;
    cti->get_attrib_test.in_attrlen = attrlen;
    attrlen = cti->get_attrib_test.out_attrlen;
    memcpy(attr, cti->get_attrib_test.out_attr, attrlen);
    result = cti->get_attrib_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_get_attrib_reply(context, card, attrid,
                                  attr, attrlen, result);
}

/*****************************************************************************/
static int
my_set_attrib(struct pcscd_context* context, int card, int attrid,
              const char* attr, int attrlen, int result)
{
    struct call_test_info* cti;

    //printf("my_set_attrib: card %d result %d attrlen %d\n",
    //       card, result, attrlen);
    if (attrlen > 264)
    {
        attrlen = 264;
    }
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->set_attrib_test.callcount++;
    cti->set_attrib_test.in_card = card;
    cti->set_attrib_test.in_attrid = attrid;
    cti->set_attrib_test.in_attrlen = attrlen;
    memcpy(cti->set_attrib_test.in_attr, attr, attrlen);
    result = cti->set_attrib_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_set_attrib_reply(context, card, attrid,
                                  attr, attrlen, result);
}

/*****************************************************************************/
static int
my_cmd_version(struct pcscd_context* context, int major, int minor, int result)
{
    struct call_test_info* cti;

    printf("my_cmd_version: major %d minor %d result %d\n",
           major, minor, result);
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->my_cmd_version_test.callcount++;
    cti->my_cmd_version_test.in_major = major;
    cti->my_cmd_version_test.in_minor = minor;
    if (cti->my_cmd_version_test.out_major != -1)
    {
        major = cti->my_cmd_version_test.out_major;
    }
    if (cti->my_cmd_version_test.out_minor != -1)
    {
        minor = cti->my_cmd_version_test.out_minor;
    }
    result = cti->my_cmd_version_test.out_result;
    pthread_mutex_unlock(&(cti->mutex));
    g_version_major = major;
    g_version_minor = minor;
    return pcscd_cmd_version_reply(context, major, minor, result);
}

/*****************************************************************************/
static int
my_cmd_get_readers_state(struct pcscd_context* context)
{
    struct pcsc_reader_state states[16];
    struct call_test_info* cti;

    //printf("my_cmd_get_readers_state:\n");
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->cmd_get_readers_state_test.callcount++;
    memcpy(states, cti->cmd_get_readers_state_test.states, sizeof(states));
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_cmd_get_readers_state_reply(context, states, 16);
}

/*****************************************************************************/
static int
my_cmd_wait_reader_state_change(struct pcscd_context* context,
                                int timeout, int result)
{
    struct call_test_info* cti;

    //printf("my_cmd_wait_reader_state_change:\n");
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->cmd_wait_reader_state_change_test.callcount++;
    pthread_mutex_unlock(&(cti->mutex));
    /* should only call my_cmd_get_readers_state if version is 4.4+ */
    if (g_version_major > 4 || (g_version_major > 3 && g_version_minor > 3))
    {
        return my_cmd_get_readers_state(context);
    }
    return LIBPCSCD_ERROR_NONE;;
}

/*****************************************************************************/
static int
my_cmd_stop_waiting_reader_state_change(struct pcscd_context* context,
                                        int timeout, int result)
{
    struct call_test_info* cti;

    //printf("my_cmd_stop_waiting_reader_state_change:\n");
    cti = (struct call_test_info*)(context->user[0]);
    pthread_mutex_lock(&(cti->mutex));
    cti->cmd_stop_waiting_reader_state_change_test.callcount++;
    pthread_mutex_unlock(&(cti->mutex));
    return pcscd_wait_reader_state_change_reply(context, timeout, result);
}

/*****************************************************************************/
static int
main_thread_loop(struct call_test_info* cti)
{
    fd_set rfds;
    int max_fd;
    int error;
    int sck;
    int num_bytes;
    struct timeval time;
    struct timeval* ptime;
    socklen_t sock_len;
    struct sockaddr_un s;
    char bytes[32];

    printf("main_thread_loop: sck %d\n", cti->sockets[0]);
    for (;;)
    {
        memset(&time, 0, sizeof(time));
        ptime = &time;
        FD_ZERO(&rfds);
        FD_SET(cti->listen_sck, &rfds);
        max_fd = cti->listen_sck;
        FD_SET(cti->sockets[0], &rfds);
        max_fd = LMAX(cti->sockets[0], max_fd);
        if (cti->got_con)
        {
            FD_SET(cti->sck, &rfds);
            max_fd = LMAX(cti->sck, max_fd);
        }
        error = select(max_fd + 1, &rfds, NULL, NULL, ptime);
        if (error > 0)
        {
            if (FD_ISSET(cti->listen_sck, &rfds))
            {
                printf("main_thread_loop: listen_sck set\n");
                sock_len = sizeof(s);
                sck = accept(cti->listen_sck,
                             (struct sockaddr*)&s, &sock_len);
                if (sck != -1)
                {
                    if (cti->got_con)
                    {
                        close(sck);
                    }
                    else
                    {
                        printf("main_thread_loop: got connection sck %d\n",
                               sck);
                        cti->got_con = 1;
                        cti->sck = sck;
                    }
                }
            }
            if (FD_ISSET(cti->sockets[0], &rfds))
            {
                printf("main_thread_loop: thread_sck set\n");
                break;
            }
            if (FD_ISSET(cti->sck, &rfds))
            {
                //printf("main_thread_loop: sck set\n");
                num_bytes = recv(cti->sck, bytes, sizeof(bytes), 0);
                //printf("main_thread_loop: num_bytes %d\n", num_bytes);
                if (num_bytes > 0)
                {
                    //hexdump(bytes, num_bytes);
                    error = pcscd_process_data_in(cti->context,
                                                  bytes, num_bytes);
                    if (error != LIBPCSCD_ERROR_NONE)
                    {
                        printf("main_thread_loop: pcscd_process_data_in "
                               "error %d\n", error);
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
        }
    }
    return 0;
}

/*****************************************************************************/
static int
pcsc_thread_wait(struct call_test_info* cti, int in_callcount,
                 volatile int* acallcount)
{
    int lcallcout;

    for (;;)
    {
        pthread_mutex_lock(&(cti->mutex));
        lcallcout = *acallcount;
        pthread_mutex_unlock(&(cti->mutex));
        if (lcallcout != in_callcount)
        {
            break;
        }
        usleep(1000);
    }
    return 0;
}

/*****************************************************************************/
static void*
pcsc_thread_loop(void* in)
{
    DWORD bytes;
    LONG rv;
    SCARDCONTEXT hcontext;
    DWORD dwscope;
    SCARD_READERSTATE cards[4];
    SCARDHANDLE card;
    DWORD proto;
    DWORD state;
    char readername[128];
    DWORD readername_len;
    BYTE attr[264];
    DWORD attr_len;
    SCARD_IO_REQUEST ior;
    SCARD_IO_REQUEST ior1;
    struct call_test_info* cti;
    int callcount;
    char readers[256];

    cti = (struct call_test_info*)in;
    printf("pcsc_thread_loop: sck %d pid %d\n", cti->sockets[1], getpid());

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->establish_context_test.callcount;
    cti->establish_context_test.in_dwscope = SCARD_SCOPE_USER;
    cti->establish_context_test.out_hcontext = 1;
    cti->establish_context_test.out_result = SCARD_S_SUCCESS;
    cti->my_cmd_version_test.out_major = -1;
    cti->my_cmd_version_test.out_minor = -1;
    pthread_mutex_unlock(&(cti->mutex));
    rv = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hcontext);
    printf("pcsc_thread_loop: SCardEstablishContext rv 0x%8.8x hcontext %d\n",
           (int)rv, (int)hcontext);
    pcsc_thread_wait(cti, callcount, &(cti->establish_context_test.callcount));
    if ((hcontext == 1) && (rv == SCARD_S_SUCCESS))
    {
        printf("pcsc_thread_loop: SCardEstablishContext - hcontext, rv pass\n");
    }
    else
    {
        printf("pcsc_thread_loop: SCardEstablishContext - hcontext, rv fail\n");
    }
    pthread_mutex_lock(&(cti->mutex));
    dwscope = cti->establish_context_test.in_dwscope;
    pthread_mutex_unlock(&(cti->mutex));
    if (dwscope == SCARD_SCOPE_USER)
    {
        printf("pcsc_thread_loop: SCardEstablishContext - dwscope pass\n");
    }
    else
    {
        printf("pcsc_thread_loop: SCardEstablishContext - dwscope fail %d\n", (int)dwscope);
    }

    rv = SCardIsValidContext(12);
    printf("pcsc_thread_loop: SCardIsValidContext rv 0x%8.8x\n", (int)rv);

    rv = SCardIsValidContext(hcontext);
    printf("pcsc_thread_loop: SCardIsValidContext rv 0x%8.8x\n", (int)rv);

    /* setup the fake readers */
    pthread_mutex_lock(&(cti->mutex));
    strncpy(cti->cmd_get_readers_state_test.states[0].readerName, "jay1", 127);
    cti->cmd_get_readers_state_test.states[0].eventCounter = 1;
    cti->cmd_get_readers_state_test.states[0].readerState = SCARD_PRESENT;
    strncpy(cti->cmd_get_readers_state_test.states[1].readerName, "jay2", 127);
    cti->cmd_get_readers_state_test.states[1].eventCounter = 1;
    cti->cmd_get_readers_state_test.states[1].readerState = SCARD_ABSENT;
    pthread_mutex_unlock(&(cti->mutex));
    bytes = 256;
    rv = SCardListReaders(hcontext, NULL, readers, &bytes);
    printf("pcsc_thread_loop: SCardListReaders rv 0x%8.8x bytes %d\n", (int)rv, (int)bytes);
    hexdump(readers, bytes);

    memset(cards, 0, sizeof(cards));
    cards[0].szReader = "jay1";
    cards[0].dwCurrentState = SCARD_STATE_UNAWARE;
    cards[1].szReader = "jay2";
    cards[1].dwCurrentState = SCARD_STATE_UNAWARE;
    cards[2].szReader = "\\\\?PnP?\\Notification";
    rv = SCardGetStatusChange(hcontext, 1000, cards, 3);
    printf("pcsc_thread_loop: SCardGetStatusChange rv 0x%8.8x\n", (int)rv);
#if 0
    memset(cards, 0, sizeof(cards));
    cards[0].szReader = "jay1";
    cards[0].dwCurrentState = SCARD_STATE_PRESENT;
    cards[1].szReader = "jay2";
    cards[1].dwCurrentState = SCARD_STATE_EMPTY;
    cards[2].szReader = "\\\\?PnP?\\Notification";
    rv = SCardGetStatusChange(hcontext, 1000, cards, 3);
    printf("pcsc_thread_loop: SCardGetStatusChange rv 0x%8.8x\n", (int)rv);
#endif
    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->connect_test.callcount;
    cti->connect_test.out_card = 1;
    cti->connect_test.out_activeprotocol = SCARD_PROTOCOL_T0;
    cti->connect_test.out_result = SCARD_S_SUCCESS;
    pthread_mutex_unlock(&(cti->mutex));
    rv = SCardConnect(hcontext, "jay", 0, 0, &card, &proto);
    printf("pcsc_thread_loop: SCardConnect rv 0x%8.8x card %d proto %d\n", (int)rv, (int)card, (int)proto);
    pcsc_thread_wait(cti, callcount, &(cti->connect_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->disconnect_test.callcount;
    cti->disconnect_test.out_result = SCARD_S_SUCCESS;
    pthread_mutex_unlock(&(cti->mutex));
    rv = SCardDisconnect(hcontext, card);
    printf("pcsc_thread_loop: SCardDisconnect rv 0x%8.8x\n", (int)rv);
    pcsc_thread_wait(cti, callcount, &(cti->disconnect_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->connect_test.callcount;
    cti->connect_test.out_card = 1;
    cti->connect_test.out_activeprotocol = SCARD_PROTOCOL_T0;
    cti->connect_test.out_result = SCARD_S_SUCCESS;
    pthread_mutex_unlock(&(cti->mutex));
    rv = SCardConnect(hcontext, "jay1", 0, 0, &card, &proto);
    printf("pcsc_thread_loop: SCardConnect rv 0x%8.8x card %d proto %d\n",
           (int)rv, (int)card, (int)proto);
    pcsc_thread_wait(cti, callcount, &(cti->connect_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->reconnect_test.callcount;
    cti->reconnect_test.out_activeprotocol = SCARD_PROTOCOL_T0;
    cti->reconnect_test.out_result = SCARD_S_SUCCESS;
    pthread_mutex_unlock(&(cti->mutex));
    rv = SCardReconnect(card, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &proto);
    printf("pcsc_thread_loop: SCardReconnect rv 0x%8.8x proto %d\n", (int)rv, (int)proto);
    pcsc_thread_wait(cti, callcount, &(cti->reconnect_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->begin_transaction_test.callcount;
    cti->begin_transaction_test.out_result = SCARD_S_SUCCESS;
    pthread_mutex_unlock(&(cti->mutex));
    rv = SCardBeginTransaction(card);
    printf("pcsc_thread_loop: SCardBeginTransaction rv 0x%8.8x\n", (int)rv);
    pcsc_thread_wait(cti, callcount, &(cti->begin_transaction_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->transmit_test.callcount;
    pthread_mutex_unlock(&(cti->mutex));
    memset(attr, 0, 128);
    ior.dwProtocol = 0;
    ior.cbPciLength = 0;
    ior1.dwProtocol = 0;
    ior1.cbPciLength = 0;
    attr_len = 128;
    rv = SCardTransmit(1, &ior, attr, attr_len, &ior1, attr, &attr_len);
    printf("pcsc_thread_loop: SCardTransmit rv 0x%8.8x\n", (int)rv);
    pcsc_thread_wait(cti, callcount, &(cti->transmit_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->end_transaction_test.callcount;
    cti->end_transaction_test.out_result = SCARD_S_SUCCESS;
    pthread_mutex_unlock(&(cti->mutex));
    rv = SCardEndTransaction(card, 0);
    printf("pcsc_thread_loop: SCardEndTransaction rv 0x%8.8x\n", (int)rv);
    pcsc_thread_wait(cti, callcount, &(cti->end_transaction_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->status_test.callcount;
    cti->status_test.out_result = SCARD_S_SUCCESS;
    pthread_mutex_unlock(&(cti->mutex));
    readername_len = 128;
    attr_len = 128;
    rv = SCardStatus(card, readername, &readername_len, &state, &proto,
                     attr, &attr_len);
    printf("pcsc_thread_loop: SCardStatus readername %s rv 0x%8.8x "
           "state 0x%8.8x proto %d attr_len %d\n",
           readername, (int)rv, (int)state, (int)proto, (int)attr_len);
    pcsc_thread_wait(cti, callcount, &(cti->status_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->control_test.callcount;
    cti->control_test.out_result = SCARD_S_SUCCESS;
    cti->control_test.out_recvdata = (char*)attr;
    pthread_mutex_unlock(&(cti->mutex));
    attr_len = 128;
    rv = SCardControl(card, 0, attr, attr_len, attr, attr_len, &attr_len);
    printf("pcsc_thread_loop: SCardControl rv 0x%8.8x\n", (int)rv);
    pcsc_thread_wait(cti, callcount, &(cti->control_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->set_attrib_test.callcount;
    pthread_mutex_unlock(&(cti->mutex));
    memset(attr, 0xff, 264);
    attr_len = 264;
    rv = SCardSetAttrib(card, 0, attr, attr_len);
    printf("pcsc_thread_loop: SCardSetAttrib rv 0x%8.8x\n", (int)rv);
    pcsc_thread_wait(cti, callcount, &(cti->set_attrib_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->get_attrib_test.callcount;
    pthread_mutex_unlock(&(cti->mutex));
    memset(attr, 0xff, 128);
    attr_len = 264;
    rv = SCardGetAttrib(card, 0xe, attr, &attr_len);
    printf("pcsc_thread_loop: SCardGetAttrib rv 0x%8.8x\n", (int)rv);
    pcsc_thread_wait(cti, callcount, &(cti->get_attrib_test.callcount));

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->disconnect_test.callcount;
    cti->disconnect_test.out_result = SCARD_S_SUCCESS;
    pthread_mutex_unlock(&(cti->mutex));
    rv = SCardDisconnect(hcontext, card);
    printf("pcsc_thread_loop: SCardDisconnect rv 0x%8.8x\n", (int)rv);
    pcsc_thread_wait(cti, callcount, &(cti->disconnect_test.callcount));

    rv = SCardCancel(hcontext);
    printf("pcsc_thread_loop: SCardCancel rv 0x%8.8x\n", (int)rv);

    pthread_mutex_lock(&(cti->mutex));
    callcount = cti->release_context_test.callcount;
    cti->release_context_test.out_result = SCARD_S_SUCCESS;
    pthread_mutex_unlock(&(cti->mutex));
    rv = SCardReleaseContext(hcontext);
    printf("pcsc_thread_loop: SCardReleaseContext rv 0x%8.8x\n", (int)rv);
    pcsc_thread_wait(cti, callcount, &(cti->release_context_test.callcount));

    close(cti->sockets[1]);
    return 0;
}

/*****************************************************************************/
static int
listening(struct call_test_info* cti)
{
    pthread_t thread;
    int rv;
    void* thread_in;

    printf("listening\n");
    setenv("PCSCLITE_CSOCK_NAME", LUDS_SCK_FILE, 1);
    rv = socketpair(AF_UNIX, SOCK_STREAM, 0, cti->sockets);
    if (rv == 0)
    {
        thread_in = (void*)(intptr_t)cti;
        rv = pthread_create(&thread, 0, pcsc_thread_loop, thread_in);
        if (rv == 0)
        {
            pthread_detach(thread);
            rv = main_thread_loop(cti);
        }
        else
        {
            close(cti->sockets[1]);
        }
        close(cti->sockets[0]);
    }
    return rv;
}

/*****************************************************************************/
static int
start_uds(struct call_test_info* cti)
{
    struct sockaddr_un s;
    int sck;
    size_t sz;

    sck = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (sck > -1)
    {
        unlink(LUDS_SCK_FILE);
        sz = sizeof(s);
        memset(&s, 0, sz);
        s.sun_family = AF_UNIX;
        sz = sizeof(s.sun_path);
        strncpy(s.sun_path, LUDS_SCK_FILE, sz);
        s.sun_path[sz - 1] = 0;
        sz = sizeof(s);
        if (bind(sck, (struct sockaddr*)&s, sz) == 0)
        {
            if (listen(sck, 2) == 0)
            {
                cti->listen_sck = sck;
                listening(cti);
            }
            unlink(LUDS_SCK_FILE);
        }
        close(sck);
    }
    return 0;
}

/*****************************************************************************/
int
main(int argc, char** argv)
{
    int error;
    struct pcscd_context* context;
    struct pcscd_settings settings;
    struct call_test_info cti;

    memset(&cti, 0, sizeof(cti));
    memset(&settings, 0, sizeof(settings));
    pthread_mutex_init(&(cti.mutex), NULL);
    error = pcscd_create_context(&settings, &context);
    if (error == LIBPCSCD_ERROR_NONE)
    {
        context->log_msg = my_log_msg;
        context->send_to_app = my_send_to_app;
        context->establish_context = my_establish_context;
        context->release_context = my_release_context;
        context->connect = my_connect;
        context->reconnect = my_reconnect;
        context->disconnect = my_disconnect;
        context->begin_transaction = my_begin_transaction;
        context->end_transaction = my_end_transaction;
        context->transmit = my_transmit;
        context->control = my_control;
        context->status = my_status;
        context->cancel = my_cancel;
        context->get_attrib = my_get_attrib;
        context->set_attrib = my_set_attrib;
        context->cmd_version = my_cmd_version;
        context->cmd_get_readers_state = my_cmd_get_readers_state;
        context->cmd_wait_reader_state_change = my_cmd_wait_reader_state_change;
        context->cmd_stop_waiting_reader_state_change = my_cmd_stop_waiting_reader_state_change;
        context->user[0] = &cti;
        cti.context = context;
        start_uds(&cti);
        pcscd_delete_context(context);
    }
    return 0;
}
