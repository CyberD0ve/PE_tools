#!/bin/bash

# Compile Object Files
x86_64-w64-mingw32-gcc PEParser.c -c -o ./bin/PEParser.o
x86_64-w64-mingw32-gcc main.c -c -o ./bin/main.o

# Compile Binary Output
x86_64-w64-mingw32-gcc ./bin/PEParser.o ./bin/main.o -o PEParser

# Cleaning
rm ./bin/*.o