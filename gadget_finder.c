//
//  gadget_finder.c
//  
//
//  Created by Billy Ellis on 26/10/2017.
//
//  This code scans ARM binaries for ROP gadgets useful for exploit developers

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

char path[256];

// well this doesn't work as I thought it would D:
void removeSpaces(char* source)
{
    char* i = source;
    char* j = source;
    while(*j != 0)
    {
        *i = *j++;
        if(*i != ' ' || *i != '\t')
            i++;
    }
    *i = 0;
}

// at the moment this function is only used to grep the arm instruction for storage in the db
char * systemCallToGrepInstruction(int c1, int c2, int c3, int c4)
{
    FILE *fp;
    char cmd[200];
    char output[1035];
    char armInst[32];
    
    /* Open the command for reading. */
    snprintf(cmd, sizeof(cmd), "objdump -D %s | grep '%x %x %x %x' | tr -s ' ' ' ' | cut -d' ' -f6 -f7 -f8 -f9", path, c1, c2, c3, c4);
    printf("system call -> %s\n", cmd);
    
    fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command: %s\n", cmd);
        exit(1);
    }
    
    /* Read the output a line at a time - output it. */
    while (fgets(output, sizeof(output)-1, fp) != NULL) {
        printf("SysOut: %s\n", output);
        sprintf(armInst, output);
        // this should be the line of the instruction
    }
    
    // this small chunk just removes the new line from the objdump data line. That's all
    int i;
    for(i = 0;; i++) {
        if(armInst[i] == '\n') {
            armInst[i] = '\0';
            break;
        }
    }
    
    /* close */
    pclose(fp);
    
    return armInst;
}

//this function checks bytes to see if they match common ARM instruction encodings
//only some instruction encodings are stored here, feel free to add others :)
// EDIT: This now reads from a instruction database txt file that's in the dir
//       If the address doesn't exist, then it will be added automatically upon finding
//       TODO: Somehow find the instruction name that is with it to also write into the column
//             We could objdump -D the binary that was parsed, and grep the instruction only for the found addr?
char * checkInstruction(int c1, int c2, int c3, int c4){
    // ------- start of my stuff -------
    FILE *fp;
    char * returnData = "Fin";
    char row[100];
    int instructionFound = 0;
    
    fp = fopen("instructionDB.txt", "r");
    if (fp == NULL) {
        return "instructionDB.txt not found... make sure it's with the finder";
    }
    
    while (fgets(row, sizeof(row), fp) != NULL) {
        char *token, *str, *tofree;
        char * foundChunks[5]; // instruction string | c1 | c2 | c3 | c4
        tofree = str = strdup(row);
        int i = 0;
        while ((token = strsep(&str, "|"))) {
            foundChunks[i] = token;
            i++;
        }
        
        if (strtol(foundChunks[1], NULL, 0) == c1 && strtol(foundChunks[2], NULL, 0) == c2 && strtol(foundChunks[3], NULL, 0) == c3 && strtol(foundChunks[4], NULL, 0) == c4) {
            returnData = foundChunks[0];
            instructionFound = 1;
        }
        free(tofree);
    }
    fclose(fp);
    
    if (instructionFound == 1) {
        return returnData;
    } else {
        char newLine[100];
        
        // this is going to look horrible, but it will probably be easy to clean up
        char hexValues[32];
        sprintf(hexValues, "0x%x|0x%x|0x%x|0x%x", c1, c2, c3, c4);
        
        // Note: bit dirty, but I wanted the hex letters to be caps (not the x's)
        char *letterPtr;
        for (letterPtr = hexValues; *letterPtr != '\0'; letterPtr++){
            if (*letterPtr != 'x')
                *letterPtr = toupper(*letterPtr);
        }
        
        // Note: Could be a cleaner way to do this? But I wouldn't know in C :/
        char *armInst = systemCallToGrepInstruction(c1, c2, c3, c4);
        //removeSpaces(armInst);
        
        sprintf(newLine, "%s|%s\n", armInst, hexValues);
        //printf(newLine);
        
        // just need to append this newline to the file and happy days!
        fp = fopen("instructionDB.txt", "a");
        fprintf(fp, "\n%s", newLine);
        fclose(fp);
        
        return "UNKNOWN INSTRUCTION (above), need to set up automatic adding to DB.. WIP";
    }
    
    // ------- end of my stuff --------
    
    // check for 07 D0 A0 E1 / mov sp, r7
    /*
    if (c1 == 0x07 && c2 == 0xD0 && c3 == 0xA0 && c4 == 0xE1){
        return "mov sp, r7";
    }
    // check for 00 00 81 E5 / str r0, [r1]
    if (c1 == 0x00 && c2 == 0x00 && c3 == 0x81 && c4 == 0xE5){
        return "str r0, [r1]";
    }
    // check for 80 80 BD E8 / pop {r7, pc}
    if (c1 == 0x80 && c2 == 0x80 && c3 == 0xBD && c4 == 0xE8){
        return "pop {r7, pc}";
    }
    // check for 03 80 BD E8 / pop {r0, r1, pc}
    if (c1 == 0x03 && c2 == 0x80 && c3 == 0xBD && c4 == 0xE8){
        return "pop {r0, r1, pc}";
    }
    // check for 01 80 BD E8 / pop {r0, pc}
    if (c1 == 0x01 && c2 == 0x80 && c3 == 0xBD && c4 == 0xE8) {
        return "pop {r0, pc}";
    }
    */
}

int main(){
    // we'll assume the binaries we'll be scanning are small, and therefore shouldn't require anymore than 99999 bytes to store their contents
    unsigned char hex[99999] = "";
    unsigned char c;
    char *instruction;
    size_t bytes = 0;
    int i = 0;
    
    printf("Welcome to @bellis1000's ROP Gadget Finder!\nEnter path to ARM binary:\n");
    scanf("%s",path);
    
    FILE *f = fopen(path,"r");
   
    fread(&hex, 1, 99999, f);
   
    printf("Searching binary for gadgets...\n\n");
    
    // search for 80 80 BD E8 / pop {r7, pc}
    // this is the common "return" instruction in the 32-bit ARM instruction set
    
    while (i < 99999){
        // if pop {r7, pc} is found...
        if (hex[i] == 0x80 && hex[i+1] == 0x80 && hex[i+2] == 0xBD && hex[i+3] == 0xE8){
            // search backwards 4 bytes for previous instruction
            instruction = checkInstruction(hex[i-4],hex[i-3],hex[i-2],hex[i-1]);
            
            printf("%s\n",instruction);
            // calculation of the address is very broken
            // the '16384' is a number I've found that works for ARM binaries compiled by me using clang
            // does not work for all binaries, need to figure this out
            printf("pop {r7, pc} found at address \x1B[32m0x%x\n\n\x1B[0m",(i+16384)-0x4);
        }
        i++;
    }
    
    i = 0;
    
    // search for 1E FF 2F E1  / bx lr
    // this is another "return" instruction in the 32-bit ARM instruction set
    
    while (i < 99999){
        if (hex[i] == 0x1E && hex[i+1] == 0xFF && hex[i+2] == 0x2F && hex[i+3] == 0xE1){
            // search backwards 4 bytes for previous instruction
            instruction = checkInstruction(hex[i-4],hex[i-3],hex[i-2],hex[i-1]);
            
            printf("%s\n",instruction);
            // calculation of the address is very broken
            // the '16384' is a number I've found that works for ARM binaries compiled by me using clang
            // does not work for all binaries, need to figure this out
            printf("bx lr found at address \x1B[32m0x%x\n\n\x1B[0m",(i+16384)-0x4);
        }
        i++;
    }
    
    return 0;
}
