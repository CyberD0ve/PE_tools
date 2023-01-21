#include <stdio.h>
#include "inc/PEParser.h"

#define LOG 1

#ifdef LOG
    #define LOG_INFO(...) printf("[*] "__VA_ARGS__)
    #define LOG_WARN(...) printf("[@] "__VA_ARGS__)
    #define LOG_ERROR(...) printf("[!] "__VA_ARGS__)
#else
    #define LOG_INFO(...) do {} while (0)
    #define LOG_WARN(...) do {} while (0)
    #define LOG_ERROR(...) do {} while (0)
#endif

int main(int argc, char** argv){
    if(argc<2){
        LOG_ERROR("[!] Usage : ./peparser /path/to/PE\n");
    }

    unsigned char* data = NULL;
    LOG_INFO("Reading %s\n", argv[1]);
    

    data = PE_GetDataFromFile(argv[1]);
    if(data!=NULL){
        PE* pe = PE_Parse(data);
        PE_print(pe);
    }else{
        LOG_ERROR("Can't read data from file\n");
    }
}