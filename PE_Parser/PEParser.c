#include <stdlib.h>
#include <unistd.h>

#include "inc/struct.h"


void __load_headers(PE* pe, unsigned char* data){
    //Get DOS Header
    pe->DOS_header= (IMAGE_DOS_HEADER*)data;

    //Jump to PE Header
    pe->NT_headers = (IMAGE_NT_HEADERS*)(((char*)pe->DOS_header) + pe->DOS_header->e_lfanew);

}

void __load_sections(PE* pe, unsigned char* data){
    pe->DOS_header= (IMAGE_DOS_HEADER*)data;
    pe->NT_headers = (IMAGE_NT_HEADERS*)(((char*)pe->DOS_header) + pe->DOS_header->e_lfanew);
    printf("[+] PE has %X sections\n", pe->NT_headers->FileHeader.NumberOfSections);
    //for (int i = 0; i < pe->NT_headers->FileHeader.NumberOfSections; i++) {
    //    printf("Found %s section at 0x%08X\n", sections[i].Name, sections[i].VirtualAddress);
    //}
}

int __get_size_from_file(FILE* f){
    fseek(f, 0L, SEEK_END);
    int data_size = ftell(f);
    fseek(f, 0L, SEEK_SET);
    return data_size;
}

unsigned char* __allocate_data_from_file(FILE* f){
    int data_size;
    unsigned char *data = NULL;
    long int res = ftell(f);
    if(f != NULL){
        data_size = __get_size_from_file(f);
        if(data_size!=0){
            data = (unsigned char*)malloc((data_size)*sizeof(char));
        }
    }
    return data;
}

void __init_data(unsigned char* data){
    for(int i = 0; i<_msize(data); i++){
        data[i]=0;
    }
}

unsigned char* PE_GetDataFromFile(char* filename){
    FILE* f = fopen(filename, "r");
    unsigned char* data = __allocate_data_from_file(f);
    if(data!=NULL){
        fread(data, 1, _msize(data), f);
    }
    return data; 
}

void PE_print(PE* pe){
    printf("----[  PE  ]----\n");
    printf("--[DOS Header]--\n");
    printf("Magic Number     : 0x%X\n", pe->DOS_header->e_magic);
    printf("Checksum         : 0x%X\n", pe->DOS_header->e_cs);
    printf("NT Header offset : 0x%X\n", pe->DOS_header->e_lfanew);

    printf("--[NT Header]--\n");
    printf("Signature : 0x%4d\n", pe->NT_headers->Signature);
    printf("Magic : 0x%04X\n", pe->NT_headers->OptionalHeader.Magic);
    printf("Image Base : 0x%016X\n", pe->NT_headers->OptionalHeader.ImageBase);
    printf("Number of sections: %d\n", pe->NT_headers->FileHeader.NumberOfSections);
}

PE* PE_Parse(unsigned char* data){
    // Allocate memory for PE parsing
    PE* pe = malloc(sizeof(PE));
    
    //TODO : Verify if file is PE

    //Retrieve headers from PE data
    __load_headers(pe, data);
    
    //Retrieve section from PE data
    __load_sections(pe, data);

    return pe;
}