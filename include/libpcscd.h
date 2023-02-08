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

#ifndef _LIBPCSCD_H
#define _LIBPCSCD_H

#define LIBPCSCD_ERROR_NONE                 0
#define LIBPCSCD_ERROR_MEMORY               1
#define LIBPCSCD_ERROR_NEED_MORE            2
#define LIBPCSCD_ERROR_PARSE                3
#define LIBPCSCD_ERROR_SEND                 4
#define LIBPCSCD_ERROR_IMPL                 5
#define LIBPCSCD_ERROR_CODE                 6
#define LIBPCSCD_ERROR_MISSED               7
#define LIBPCSCD_ERROR_PARAM                8

#define LIBPCSCD_VERSION_MAJOR              0
#define LIBPCSCD_VERSION_MINOR              1

struct pcsc_reader_state
{
    char readerName[128];
    int eventCounter;
    int readerState;
    int readerSharing;
    char cardAtr[36];
    int cardAtrLength;
    int cardProtocol;
};

struct pcscd_settings
{
    int pad0;
};

struct pcscd_context
{
    int (*log_msg)(struct pcscd_context* context, int log_level,
                   const char* msg, ...);
    int (*send_to_app)(struct pcscd_context* context,
                       const void* data, int bytes);
    int (*establish_context)(struct pcscd_context* context,
                             int dwscope, int hcontext, int result);
    int (*release_context)(struct pcscd_context* context,
                           int hcontext, int result);
    int (*connect)(struct pcscd_context* context, int hcontext,
                   const char* reader, int sharemode,
                   int preferredprotocols, int card,
                   int activeprotocol, int result);
    int (*reconnect)(struct pcscd_context* context, int card,
                     int sharemode, int preferredprotocols,
                     int initialization, int activeprotocol, int result);
    int (*disconnect)(struct pcscd_context* context, int card,
                      int disposition, int result);
    int (*begin_transaction)(struct pcscd_context* context,
                             int card, int result);
    int (*end_transaction)(struct pcscd_context* context,
                           int card, int disposition, int result);
    int (*transmit)(struct pcscd_context* context, int card,
                    int send_ior_protocol, int send_ior_pcilength,
                    int send_bytes,
                    int recv_ior_protocol, int recv_ior_pcilength,
                    int recv_bytes, int result, const char* senddata);
    int (*control)(struct pcscd_context* context, int card, int controlcode,
                   int sendbytes, int recvbytes, int bytesreturned,
                   int result, const char* senddata);
    int (*status)(struct pcscd_context* context, int card, int result);
    int (*cancel)(struct pcscd_context* context, int hcontext, int result);
    int (*get_attrib)(struct pcscd_context* context, int card, int attrid,
                      const char* attr, int attrlen, int result);
    int (*set_attrib)(struct pcscd_context* context, int card, int attrid,
                      const char* attr, int attrlen, int result);
    int (*cmd_version)(struct pcscd_context* context,
                       int major, int minor, int result);
    int (*cmd_get_readers_state)(struct pcscd_context* context);
    int (*cmd_wait_reader_state_change)(struct pcscd_context* context,
                                        int timeout, int result);
    int (*cmd_stop_waiting_reader_state_change)(struct pcscd_context* context,
                                                int timeout, int result);
    void* user[16];
};

int
pcscd_create_context(struct pcscd_settings* settings,
                     struct pcscd_context** context);
int
pcscd_delete_context(struct pcscd_context* context);
int
pcscd_process_data_in(struct pcscd_context* context,
                      const void* data, int data_bytes);
int
pcscd_establish_context_reply(struct pcscd_context* context,
                              int dwscope, int hcontext, int result);
int
pcscd_release_context_reply(struct pcscd_context* context,
                            int hcontext, int result);
int
pcscd_connect_reply(struct pcscd_context* context, int hcontext,
                    const char* reader, int sharemode,
                    int preferredprotocols, int card,
                    int activeprotocol, int result);
int
pcscd_reconnect_reply(struct pcscd_context* context, int card,
                      int sharemode, int preferredprotocols,
                      int activeprotocol, int initialization, int result);
int
pcscd_disconnect_reply(struct pcscd_context* context, int card,
                       int disposition, int result);
int
pcscd_begin_transaction_reply(struct pcscd_context* context, int card,
                              int result);
int
pcscd_end_transaction_reply(struct pcscd_context* context, int card,
                            int disposition, int result);

int
pcscd_transmit_reply(struct pcscd_context* context, int card,
                     int sendiorprotocol, int sendiorpcilength,
                     int sendbytes,
                     int recviorprotocol, int recviorpcilength,
                     int recvbytes, int result, const char* recvdata);
int
pcscd_control_reply(struct pcscd_context* context, int card, int controlcode,
                    int sendbytes, int recvbytes, int bytesreturned,
                    int result, const char* recvdata);
int
pcscd_status_reply(struct pcscd_context* context, int card, int result);
int
pcscd_cancel_reply(struct pcscd_context* context, int hcontext, int result);
int
pcscd_get_attrib_reply(struct pcscd_context* context, int card, int attrid,
                       const char* attr, int attrlen, int result);
int
pcscd_set_attrib_reply(struct pcscd_context* context, int card, int attrid,
                       const char* attr, int attrlen, int result);
int
pcscd_cmd_version_reply(struct pcscd_context* context,
                        int major, int minor, int result);
int
pcscd_cmd_get_readers_state_reply(struct pcscd_context* context,
                                  struct pcsc_reader_state* states,
                                  int num_states);
int
pcscd_wait_reader_state_change_reply(struct pcscd_context* context,
                                     int timeout, int result);

#endif
