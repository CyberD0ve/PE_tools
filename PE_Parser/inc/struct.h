#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <psapi.h>
#include <errno.h>


typedef struct SECTION{
    char* data;
    struct SECTION* next;
} SECTION;

typedef struct SECTIONS_LIST{
    SECTION* first;
} SECTIONS_LIST;

typedef struct PE{
    IMAGE_DOS_HEADER* DOS_header;
    IMAGE_NT_HEADERS* NT_headers;

    SECTIONS_LIST* sections_list;
} PE;