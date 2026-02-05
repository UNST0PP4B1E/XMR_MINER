#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <stdbool.h>
#include <WinSock2.h>
#include <windows.h>
#include <string.h>
#include <randomx.h>

SOCKET sock;

HANDLE hashingTh1;
HANDLE hashingTh2;
HANDLE hashingTh3;
HANDLE hashingTh4;
HANDLE hashingTh5;

randomx_flags flags = RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES;;
randomx_cache* globalCache;

char* strcmpTemp = 0;

int newblobupdate = 0;

int hashingToggle = 0;

char* id;

char* strblob;
size_t strblobSize = 0;
unsigned char* blob;

char* jobId;

char* strtarget;
unsigned char target[32] = {0};
int targetlen = 0;
uint8_t targetint[32] = { 0 };
char* target_id;

char* strseedHash;
unsigned char seedHash[32] = { 0 };

char* blockHash = NULL;


size_t major_version = 0;
int major_versionlen = 0;

size_t minor_version = 0;
int minor_versionlen = 0;

unsigned char timesptemp[100] = { 0 };
int timesptemplen = 0;

unsigned char hash[32] = { 0 };
uint8_t hashint[32] = { 0 };

unsigned int nonce = 0;

int othershitlen = 0;

unsigned char blobHeader[200] = { 0 };
int blobHeaderlen = 0;

unsigned char newhash[1000] = {0};


int compare_hash_target(uint8_t* hash, uint8_t* target, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (hash[i] < target[i]) return -1; // hash < target → valide
        if (hash[i] > target[i]) return 1;  // hash > target → invalide
    }
    return 0; // égal
}


void strhextobytearray(char* in, unsigned char* out)
{
    // for(int i=0;i<strlen(in);i++)
    // {
    //     printf(" in[%d] : %c\n", i, in[i]);
    // }

    size_t inSize = strlen(in);
    //printf("inSize : %d\n", inSize / 2);

    char hexnum[] = { '0','1','2','3','4','5','6','7','8','9', 'a', 'b', 'c', 'd', 'e', 'f' };
    unsigned int number1 = 0;
    unsigned int number2 = 0;
    unsigned int number3 = 0;
    int offset = 0;
    int swi = 0;
    int swi2 = 0;
    for (int i = 0; i < inSize; i++)
    {
        //printf("cara : %c\n", in[i]);
        for (int x = 0; x < strlen(hexnum); x++)
        {
            if (in[i] == hexnum[x])
            {
                if (swi == 1)
                {
                    number2 = x;
                    swi2 = 1;
                }
                else
                {
                    number1 = x;
                    swi = 1;

                }
            }
        }

        if (swi2 == 1)
        {
            number3 = (number1 * 16) + number2;
            //printf("number3 : %d = number2 : %d * number1 : %d\n", number3, number2, number1);

            out[offset] = (unsigned char)number3;
            //printf("out[offset : %d] : %x\n", offset, out[offset]);
            // printf("number3 : %x\n", number3);


            number1 = 0;
            number2 = 0;
            number3 = 0;

            offset++;
            swi = 0;

        }
        swi2 = 0;
    }


    offset = 0;
}

void hashing(LPVOID nonce)
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    //printf("targeteint : %u\n", targetint);
    //printf("hashint : %u\n", hashint);

    //printf("\n///////////////////////////////Hashing Thread Created///////////////////////\n");


    randomx_vm* myMachine = randomx_create_vm(flags, globalCache, NULL);

    printf("\n///////////////////////////////Hashing Thread ACTIVATE///////////////////////\n");
    //printf("nonce : %d\n", nonce);
    unsigned int start_nonce = (unsigned int)(uintptr_t)nonce;

    blobHeaderlen = major_versionlen + minor_versionlen + timesptemplen + 36;

    //printf("blobHeader : ");
    //for (int i = 0; i < blobHeaderlen; i++)
    //{
    //    printf("%x", blobHeader[i]);
    //}
    //printf("\n");

    char headerhashed[RANDOMX_HASH_SIZE];

    int offset = major_versionlen;

    memset(blobHeader, major_version, major_versionlen);
           
    //printf("major_version : %x\n", major_version);

    memset(blobHeader + offset, minor_version, minor_versionlen);
    offset += minor_versionlen;
    //printf("minor_version : %x\n", minor_version);

    for (int i = 0; i < timesptemplen; i++)
    {
        memcpy(blobHeader + offset + i, timesptemp + i, 1);
    }
    offset += timesptemplen;
    //printf("timesptemp : ");
    //for (int i = 0; i < timesptemplen; i++)
    //{
    //    printf("%x", timesptemp[i]);
    //}
    //printf("\n");


    for (int i = 0; i < 32; i++)
    {
        memcpy(blobHeader + offset + i, hash + i, 1);
    }
    offset += 32;

    //printf("hash : ");
    //for (int i = 0; i < 32; i++)
    //{
    //    printf("%x", hash[i]);
    //}
    //printf("\n");

    //printf("\nblobHeaderlen : %d\n", blobHeaderlen);
    //printf("blobHeader : ");
    //for (int i = 0; i < blobHeaderlen; i++)
    //{
    //    printf("%x", blobHeader[i]);

    //}
    //printf("\n");


    while (1)
    {

        //printf("nonce number : %d\n", nonce);

        blobHeader[offset + 3] = (byte)start_nonce;
        blobHeader[offset + 2] = (byte)(start_nonce >> 8);
        blobHeader[offset + 1] = (byte)(start_nonce >> 0x10);
        blobHeader[offset] = (byte)(start_nonce >> 0x18);

        //printf("blobHeader : ");
        //for (int i = 0; i < blobHeaderlen; i++)
        //{
        //    printf("%x", blobHeader[i]);

        //}
        //printf("\n");
        randomx_calculate_hash(myMachine, blobHeader, blobHeaderlen, headerhashed);

        for (int i = 0; i < sizeof(headerhashed); i++)
        {
            newhash[i] = headerhashed[i];
        }
        //for (int i = 0; i < othershitlen; i++)
        //{
        //    newhash[blobHeaderlen + i] = blob[blobHeaderlen + i];
        //}
              
        //printf("NEWHASH : ");
        //for (int i = 0; i < 32; i++)
        //{
        //    printf("%x", newhash[i]);
        //}
        //printf("\n");
        for (int i = 0; i < 32; i++)
        {
            memcpy(&hashint[31 - i], &newhash[i], 1);
        }
        if (!compare_hash_target(hashint, targetint, 32))
        {
            printf("GOT SHARE\n");
            memcpy(newhash + sizeof(headerhashed), &blob[blobHeaderlen], othershitlen);

            char hashHex[65] = { 0 };
            for (int i = 0; i < 32; i++) {
                sprintf(hashHex + i * 2, "%02x", hash[i]);
            }

            char submintMSG[300] = { 0 };
            int isprintf = sprintf(submintMSG, "{\"id\":2,\"jsonrpc\":\"2.0\",\"method\":\"submit\",\"params\":{\"id\":\"%s\",\"job_id\":\"%s\",\"nonce\":\"%u\",\"result\":\"%\"}}\n", id, jobId, nonce, hashHex);
            printf("%s\n", submintMSG);
            memset(hashHex, '0', sizeof(hashHex));
            Sleep(1000);
            send(sock, submintMSG, sizeof submintMSG, 0);
        }
        if (start_nonce % 100 == 1)
        {
            printf("nonce : %d\n", start_nonce);
        }
        start_nonce += 1;
    }   
}

void cycle(SOCKET sock)
{

    char buffer[5000] = { 0 };
    int rv = 0;
    char wordbuffer[5000] = { 0 };
    int checkpoint = 0;
    int checkpoint2 = 0;
    char list[40][1000];
    int listindex = 0;
    int wordlens = checkpoint2 - checkpoint;
    while (1)
    {
        rv = recv(sock, buffer, sizeof(buffer), 0);
        printf("\nBUFFER : %s\n", buffer);
        for (int i = 0; i < strlen(buffer); i++)
        {
            if (buffer[i] == '\"')
            {
                if (!checkpoint)
                {
                    checkpoint = i + 1;
                }
                else
                {
                    checkpoint2 = i;
                    int wordlens = checkpoint2 - checkpoint;
                    strncpy(wordbuffer, buffer + checkpoint, wordlens);
                    wordbuffer[wordlens] = '\0';
                    strcpy(list[listindex], wordbuffer);
                                     
                    //printf("list : %s : %d\n", list[listindex], listindex);

                    listindex++;

                    checkpoint = 0;
                    checkpoint2 = 0;
                    memset(wordbuffer, '\0', sizeof(wordbuffer));
                }
            }
            strcmpTemp = strcmp(list[7], "job");
            if (strcmpTemp == NULL)
            {
                id = list[6];
                strblob = list[9];

                jobId = list[11];
                strtarget = list[13];
                strseedHash = list[18];
                blockHash = list[20];

                newblobupdate = 1;
                //printf("newblocbupdate : %d\n", newblobupdate);

            }
            //if (strcmp(list[3], "job") == 0 && newblobupdate == 0)
            //{
            //    id = list[12];
            //    strblob = list[6];
            //    jobId = list[8];
            //    strtarget = list[10];
            //    strseedHash = list[15];

            //    newblobupdate++;
            //}
        
        }
        strcmpTemp = strcmp(list[3], "job");
        if (strcmpTemp == 0 && newblobupdate == 1)
        {            
            printf("\nNEW JOB V2\n");      
            
            DWORD susThr = TerminateThread(hashingTh1, NULL);


            /*TerminateThread(hashingTh2, NULL);
            TerminateThread(hashingTh3, NULL);
            TerminateThread(hashingTh4, NULL);
            TerminateThread(hashingTh5, NULL);*/

            CloseHandle(hashingTh1);

            /*CloseHandle(hashingTh2);
            CloseHandle(hashingTh3);
            CloseHandle(hashingTh4);
            CloseHandle(hashingTh5);*/
            //if (susThr == 0)
            //{
            //    printf("ERROR CANT TERMINATE HASHING THREAD\n");
            //}
            //else {
            //    printf("\n///////////////////////////////Hashing Thread TERMINATE///////////////////////\n");
            //}

            memset(&seedHash, '0', sizeof(seedHash));
            memset(&target, '0', sizeof(target));
            memset(&timesptemp, '0', sizeof(timesptemp));
            memset(&newhash, '0', sizeof(newhash));
            free(blob);

            id = list[12];
            strblob = list[6];
            jobId = list[8];
            strtarget = list[10];
            strseedHash = list[15];

            hashingTh1 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)0, 0, NULL);
            //hashingTh2 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)1000000, 0, NULL);
            //hashingTh3 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)2000000, 0, NULL);
            //hashingTh4 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)3000000, 0, NULL);
            //hashingTh5 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)4000000, 0, NULL);

        }
        //else
        //{
        //    printf("Error :  strcmp(list[3], job) == 0 && newblobupdate == 1\n");
        //    printf("newblocbupdate : %d\n", newblobupdate);
        //    printf("list[3] : %s\n", list[3]);
        //}

        strblobSize = strlen(strblob) / 2;
        blob = (unsigned char*)malloc(strblobSize);

        targetlen = strlen(strtarget) / 2;

        //printf("//////////////////strHexBlob//////////////////////");
        strhextobytearray(strblob, blob);


        //printf("//////////////////strHexTarget//////////////////////");
        strhextobytearray(strtarget, target);

        targetint[28] = target[0];
        targetint[29] = target[1];
        targetint[30] = target[2];
        targetint[31] = target[3];

        //printf("targein :");
        //for (int i = 0; i < sizeof(targetint); i++)
        //{
        //    printf("%x", targetint[i]);
        //}
        //printf("\n");
        

        //printf("//////////////////strHexseedHash//////////////////////");
        strhextobytearray(strseedHash, seedHash);
        //printf("seedhash : ");
        //for (int i = 0; i < sizeof(seedHash); i++)
        //{
        //    printf("%x", seedHash[i]);
        //}
        //printf('\n');
        //printf("//////////////////Varint blob//////////////////////");

        int offset = 0;
        int varintlen = 1;

        for (int i = 0; i < strblobSize; i++)
        {
            //printf("\nin[%d] : %x", i, blob[i]);
            if ((blob[i] & 0x80) == 0 && offset == 0)
            {
                memcpy(&major_version, &blob[i], varintlen);
                major_versionlen = varintlen;
                //printf("\nGOT major_version : %x : varintlen : %d", major_version, varintlen);
                offset++;
                varintlen = 1;
            }
            else if ((blob[i] & 0x80) == 0 && offset == 1)
            {
                memcpy(&minor_version, &blob[i], varintlen);
                minor_versionlen = varintlen;
                //printf("\nGOT minor_version : %x : varintlen : %d", minor_version, varintlen);
                offset++;
                varintlen = 1;
            }
            else if ((blob[i] & 0x80) == 0 && offset == 2)
            {
                timesptemplen = varintlen;
                memset(&timesptemp, '0', sizeof(timesptemp));
                for (int i = 0; i < timesptemplen; i++)
                {
                    timesptemp[i] = (unsigned char)blob[i + 2];
                }
        

                //printf("\nGOT timesptemp :");
  /*              for (int i = 0; i < timesptemplen; i++)
                {
                    printf("%x", timesptemp[i]);
                }
                printf("\n");*/

                offset++;
                varintlen = 1;

                othershitlen = strblobSize - (i + 37);
                //printf("\nothershitlen : %d\n", othershitlen);


                memcpy(&hash, &blob[i + 1], sizeof(hash));
          
        
                //printf("\ni+33 : %d", i + 33);
                memcpy(&nonce, &blob[i + 33], sizeof(int));
                //printf("\n i+37 : %d", i + 37);
            }
            else
            {
                varintlen++;
            }
        }
        varintlen = 1;
        offset = 0;
        globalCache = randomx_alloc_cache(flags);
        randomx_init_cache(globalCache, seedHash, sizeof seedHash);

        if (hashingToggle == 0)
        {
            hashingToggle++;
            hashingTh1 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)0, 0, NULL);
            //hashingTh2 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)1000000, 0, NULL);
            //hashingTh3 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)2000000, 0, NULL);
            //hashingTh4 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)3000000, 0, NULL);
            //hashingTh5 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hashing, (LPVOID)(uintptr_t)4000000, 0, NULL);
        }


        listindex = 0;
        memset(list, '\0', sizeof(list));
        memset(buffer, '\0', sizeof(buffer));

    }
}



int main()
{

    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    int poolPort = 3333;

    char walletID[] = "41kJDoFe4gvCaAMYNth4RhZ97TvGgYgYxdHD8uyyFn5RdwHq3q1PDSqRYjKHWQXwTi2oerU5X2ubK3UCVVfTywzp1TgHMGd";
    char worker = 'x';

    char loginMSG[300] = { 0 };
    int isprintf = sprintf(loginMSG, "{\"id\":1,\"method\":\"login\",\"params\":{\"login\":\"%s.%c\",\"pass\":\"x\",\"agent\":\"MonMiner/0.1\",\"algo\":[\"rx/0\"]}}\n", walletID, worker);


    WSADATA WSAData;
    SOCKADDR_IN addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("141.94.96.144"); // supportXMR.com
    addr.sin_port = htons(poolPort);

    int iWSAStartup = WSAStartup(MAKEWORD(2, 2), &WSAData);
    if (iWSAStartup)
    {
        printf("Error WSAStartup : %d \n", iWSAStartup);
    }
    else {
        printf("[+]   WSAStartup OK \n");
    }
    Sleep(1000);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        printf("Error socket : %d \n", WSAGetLastError());
    }
    else {
        printf("[+]   socket OK \n");
    }

    int iconnect = connect(sock, (SOCKADDR*)&addr, sizeof(addr));
    if (iconnect == SOCKET_ERROR)
    {
        printf("Error connect : %d \n", WSAGetLastError());
    }
    else {
        printf("[+]   connect OK \n");
    }

    int isubscribe = send(sock, loginMSG, sizeof(loginMSG), 0);
    if (isubscribe == SOCKET_ERROR)
    {
        printf("Error isubscribe : %d \n", WSAGetLastError());
    }
    else {
        printf("[+]   loginMSG OK : %s \n", loginMSG);
    }

    cycle(sock);

    Sleep(100000);
    return 0;
}