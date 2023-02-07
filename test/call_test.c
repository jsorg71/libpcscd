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
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libpcscd.h>

#include <winscard.h>

#define LUDS_SCK_FILE "/tmp/libpcscd.socket"
#define LMAX(_val1, _val2) (_val1) > (_val2) ? _val1 : _val2

static int g_version_major = 0;;
static int g_version_minor = 0;

struct call_test_info
{
    struct pcscd_context* context;
    int listen_sck;
    int sck;
    int thread_sck;
    int got_con;;
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
    //printf("my_establish_context: dwscope %d hcontext %d result %d\n",
    //       dwscope, hcontext, result);
    //return pcscd_establish_context_reply(context, dwscope, hcontext, result);
    return pcscd_establish_context_reply(context, dwscope, 1, result);
}

/*****************************************************************************/
static int
my_release_context(struct pcscd_context* context, int hcontext, int result)
{
    //printf("my_release_context: hcontext %d result %d\n", hcontext, result);
    return pcscd_release_context_reply(context, hcontext, result);
}

/*****************************************************************************/
static int
my_connect(struct pcscd_context* context, int hcontext,
           const char* reader, int sharemode,
           int preferredprotocols, int card, int activeprotocol, int result)
{
    //printf("my_connect: hcontext %d result %d\n", hcontext, result);
    return pcscd_connect_reply(context, hcontext, reader, sharemode,
                               preferredprotocols, 1,
                               activeprotocol, result);
}

/*****************************************************************************/
static int
my_reconnect(struct pcscd_context* context, int card,
             int sharemode, int preferredprotocols,
             int initialization, int activeprotocol, int result)
{
    //printf("my_reconnect: card %d result %d\n", card, result);
    return pcscd_reconnect_reply(context, card, sharemode,
                                 preferredprotocols, initialization,
                                 activeprotocol, result);
}

/*****************************************************************************/
static int
my_disconnect(struct pcscd_context* context, int card,
              int disposition, int result)
{
    //printf("my_disconnect: card %d result %d\n", card, result);
    return pcscd_disconnect_reply(context, card, disposition, result);
}

/*****************************************************************************/
static int
my_begin_transaction(struct pcscd_context* context,
                     int card, int result)
{
    //printf("my_begin_transaction: card %d result %d\n", card, result);
    return pcscd_begin_transaction_reply(context, card, result);
}

/*****************************************************************************/
static int
my_end_transaction(struct pcscd_context* context,
                   int card, int disposition, int result)
{
    //printf("my_end_transaction: card %d result %d\n", card, result);
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
    char* recvdata;
    int rv;

    //printf("my_transmit: card %d result %d send_bytes %d recv_bytes %d\n",
    //       card, result, sendbytes, recvbytes);
    recvdata = (char*)calloc(1, recvbytes);
    rv = pcscd_transmit_reply(context, card,
                              sendiorprotocol, sendiorpcilength,
                              sendbytes,
                              recviorprotocol, recviorpcilength,
                              recvbytes, result, recvdata);
    free(recvdata);
    return rv;
}

/*****************************************************************************/
static int
my_control(struct pcscd_context* context, int card, int controlcode,
           int sendbytes, int recvbytes, int bytesreturned,
           int result, const char* senddata)
{
    char* recvdata;
    int rv;

    //printf("my_control: card %d result %d\n", card, result);
    recvdata = (char*)calloc(1, recvbytes);
    bytesreturned = recvbytes;
    rv = pcscd_control_reply(context, card, controlcode,
                             sendbytes, recvbytes, bytesreturned,
                             result, recvdata);
    free(recvdata);
    return rv;
}

/*****************************************************************************/
static int
my_status(struct pcscd_context* context, int card, int result)
{
    //printf("my_status: card %d result %d\n", card, result);
    return pcscd_status_reply(context, card, result);
}

/*****************************************************************************/
static int
my_cancel(struct pcscd_context* context, int hcontext, int result)
{
    //printf("my_cancel: hcontext %d result %d\n", hcontext, result);
    return pcscd_cancel_reply(context, hcontext, result);
}

/*****************************************************************************/
static int
my_get_attrib(struct pcscd_context* context, int card, int attrid,
              const char* attr, int attrlen, int result)
{
    //printf("my_get_attrib: card %d result %d attrlen %d\n",
    //       card, result, attrlen);
    return pcscd_get_attrib_reply(context, card, attrid, attr, attrlen, 0);
}

/*****************************************************************************/
static int
my_set_attrib(struct pcscd_context* context, int card, int attrid,
              const char* attr, int attrlen, int result)
{
    //printf("my_set_attrib: card %d result %d attrlen %d\n",
    //       card, result, attrlen);
    return pcscd_set_attrib_reply(context, card, attrid, attr, attrlen, 0);
}

/*****************************************************************************/
static int
my_cmd_version(struct pcscd_context* context, int major, int minor, int result)
{
    printf("my_cmd_version: major %d minor %d result %d\n",
           major, minor, result);
    g_version_major = major;
    g_version_minor = minor;
    return pcscd_cmd_version_reply(context, major, minor, result);
}

/*****************************************************************************/
static int
my_cmd_get_readers_state(struct pcscd_context* context)
{
    struct pcsc_reader_state states[16];

    //printf("my_cmd_get_readers_state:\n");
    memset(states, 0, sizeof(states));
    return pcscd_cmd_get_readers_state_reply(context, states, 16);
}

/*****************************************************************************/
static int
my_cmd_wait_reader_state_change(struct pcscd_context* context,
                                int timeout, int result)
{
    //printf("my_cmd_wait_reader_state_change:\n");
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
    //printf("my_cmd_stop_waiting_reader_state_change:\n");
    return pcscd_wait_reader_state_change_reply(context, 0, 0);
    //return LIBPCSCD_ERROR_NONE;
    //return my_cmd_get_readers_state(context);
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

    printf("main_thread_loop: sck %d\n", cti->thread_sck);
    for (;;)
    {
        memset(&time, 0, sizeof(time));
        ptime = &time;
        FD_ZERO(&rfds);
        FD_SET(cti->listen_sck, &rfds);
        max_fd = cti->listen_sck;
        FD_SET(cti->thread_sck, &rfds);
        max_fd = LMAX(cti->thread_sck, max_fd);
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
            if (FD_ISSET(cti->thread_sck, &rfds))
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
static void*
pcsc_thread_loop(void* in)
{
    DWORD bytes;
    LONG rv;
    SCARDCONTEXT context;
    int sck;
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

    sck = (int)(intptr_t)in;
    printf("pcsc_thread_loop: sck %d pid %d\n", sck, getpid());

    rv = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &context);
    printf("pcsc_thread_loop: SCardEstablishContext rv 0x%8.8x context %d\n",
           (int)rv, (int)context);

    rv = SCardIsValidContext(context);
    printf("pcsc_thread_loop: SCardIsValidContext rv 0x%8.8x\n", (int)rv);

    rv = SCardListReaders(context, NULL, NULL, &bytes);
    printf("pcsc_thread_loop: SCardListReaders rv 0x%8.8x\n", (int)rv);
    memset(cards, 0, sizeof(cards));

    cards[0].szReader = "\\\\?PnP?\\Notification";
    rv = SCardGetStatusChange(context, 1000, cards, 1);
    printf("pcsc_thread_loop: SCardGetStatusChange rv 0x%8.8x\n", (int)rv);

    rv = SCardConnect(context, "jay", 0, 0, &card, &proto);
    printf("pcsc_thread_loop: SCardConnect rv 0x%8.8x card %d proto %d\n", (int)rv, (int)card, (int)proto);

    rv = SCardReconnect(context, card, 0, 0, &proto);
    printf("pcsc_thread_loop: SCardReconnect rv 0x%8.8x\n", (int)rv);

    rv = SCardBeginTransaction(card);
    printf("pcsc_thread_loop: SCardBeginTransaction rv 0x%8.8x\n", (int)rv);

    memset(attr, 0, 128);
    ior.dwProtocol = 0;
    ior.cbPciLength = 0;
    ior1.dwProtocol = 0;
    ior1.cbPciLength = 0;
    attr_len = 128;
    rv = SCardTransmit(1, &ior, attr, attr_len, &ior1, attr, &attr_len);
    printf("pcsc_thread_loop: SCardTransmit rv 0x%8.8x\n", (int)rv);

    rv = SCardEndTransaction(card, 0);
    printf("pcsc_thread_loop: SCardEndTransaction rv 0x%8.8x\n", (int)rv);

    readername_len = 128;
    attr_len = 128;
    rv = SCardStatus(card, readername, &readername_len, &state, &proto, attr, &attr_len);
    printf("pcsc_thread_loop: SCardStatus rv 0x%8.8x\n", (int)rv);

    attr_len = 128;
    rv = SCardControl(card, 0, attr, attr_len, attr, attr_len, &attr_len);
    printf("pcsc_thread_loop: SCardControl rv 0x%8.8x\n", (int)rv);

    memset(attr, 0xff, 264);
    attr_len = 264;
    rv = SCardSetAttrib(card, 0, attr, attr_len);
    printf("pcsc_thread_loop: SCardSetAttrib rv 0x%8.8x\n", (int)rv);

    memset(attr, 0xff, 128);
    attr_len = 264;
    rv = SCardGetAttrib(card, 0xe, attr, &attr_len);
    printf("pcsc_thread_loop: SCardGetAttrib rv 0x%8.8x\n", (int)rv);

    rv = SCardDisconnect(context, card);
    printf("pcsc_thread_loop: SCardDisconnect rv 0x%8.8x\n", (int)rv);

    rv = SCardCancel(context);
    printf("pcsc_thread_loop: SCardCancel rv 0x%8.8x\n", (int)rv);

    rv = SCardReleaseContext(context);
    printf("pcsc_thread_loop: SCardReleaseContext rv 0x%8.8x\n", (int)rv);

    close(sck);
    return 0;
}

/*****************************************************************************/
static int
listening(struct call_test_info* cti)
{
    pthread_t thread;
    int rv;
    int sockets[2];
    void* thread_in;

    printf("listening\n");
    setenv("PCSCLITE_CSOCK_NAME", LUDS_SCK_FILE, 1);
    rv = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    if (rv == 0)
    {
        thread_in = (void*)(intptr_t)sockets[1];
        rv = pthread_create(&thread, 0, pcsc_thread_loop, thread_in);
        if (rv == 0)
        {
            pthread_detach(thread);
            cti->thread_sck = sockets[0];
            rv = main_thread_loop(cti);
        }
        else
        {
            close(sockets[1]);
        }
        close(sockets[0]);
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
    error = pcscd_create_context(&settings, &context);
    if (error == LIBPCSCD_ERROR_NONE)
    {
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
