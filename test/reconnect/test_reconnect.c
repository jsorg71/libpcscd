
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winscard.h>

int
main(int argc, char** argv)
{
    LONG rv;
    SCARDCONTEXT hcontext;
    DWORD bytes;
    char readers[256];
    SCARDHANDLE card;
    DWORD proto;

    rv = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hcontext);
    printf("SCardEstablishContext: rv 0x%8.8x\n", (int)rv);

    bytes = 256;
    rv = SCardListReaders(hcontext, NULL, readers, &bytes);
    printf("SCardListReaders: rv 0x%8.8x %s\n", (int)rv, readers);

    rv = SCardConnect(hcontext, readers, SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &proto);
    printf("SCardConnect: rv 0x%8.8x\n", (int)rv);

    rv = SCardReconnect(card, SCARD_SHARE_SHARED,
                        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                        SCARD_LEAVE_CARD, &proto);
    printf("SCardReconnect: rv 0x%8.8x\n", (int)rv);

    rv = SCardDisconnect(card, SCARD_LEAVE_CARD);
    printf("SCardDisconnect: rv 0x%8.8x\n", (int)rv);

    rv = SCardReleaseContext(hcontext);
    printf("SCardReleaseContext: rv 0x%8.8x\n", (int)rv);
    return 0;
}