#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <elf.h>
#include <string.h>

#define ElfW(type) Elf64_ ## type

typedef struct {
    uint32_t ei_mag;
    uint8_t ei_class;
    uint8_t ei_data;
    uint8_t ei_version;
    uint8_t ei_osabi;
    uint8_t ei_abiversion;
    uint64_t ei_pad;
} e_ident;

int main() {
    FILE *fp;
    e_ident ident;
    Elf64_Ehdr headers;
    Elf64_Phdr pheaders;
    char name[] = "elf-executable";

    memset(&headers, 0, sizeof(headers));
    memset(&pheaders, 0, sizeof(pheaders));

    ident.ei_mag = 0x464C457F;  //ELF magic [0x7f, 0x45, 0x4c, 0x46]
    ident.ei_class = 0x02;      //Object file class. In this case 64-bit object file
    ident.ei_data = 0x01;       //Endianness. Current value is LE
    ident.ei_version = 0x01;    //ELF header version.
    ident.ei_osabi = 0x03;      //OS ABI. 0x03 for GNU/Linux
    ident.ei_abiversion = 0x00; //ABI version
    ident.ei_pad = 0x00;        //Padding

    memcpy(headers.e_ident, &ident, 0x10);

    if(memcmp(headers.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "e_ident is not elf format! exiting...\n");
        exit(1);
    }

    //Program
    unsigned char program[] = {
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,   //mov $0x1, %rax
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,   //mov $0x1, %rdi
        0x48, 0xC7, 0xC6, 0xA2, 0x10, 0x00, 0x00,   //mov $0x10a2, %rsi
        0x48, 0xC7, 0xC2, 0x0D, 0x00, 0x00, 0x00,   //mov $0xd, %rdx
        0x0F, 0x05,                                 //syscall
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,   //mov $0x3c, %rax
        0x48, 0x31, 0xff,                           //xor %rdi, %rdi
        0x0F, 0x05,                                 //syscall
        //ASCII text [hello world!\n]
        0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 
        0x6F, 0x72, 0x6C, 0x64, 0x21, 0x0A
    };

    //Elf headers
    headers.e_type = 0x02;      //Executable
    headers.e_machine = 0x3E;   //AMD64
    headers.e_version = 0x01;
    headers.e_entry = 0x00;     //Entry point is virtual address of first instruction
    headers.e_phoff = 0x40;     //Offset to first program header
    headers.e_shoff = 0x00;
    headers.e_flags = 0x00;
    headers.e_ehsize = 0x40;    //Size of Elf64_Ehdr
    headers.e_phentsize = 0x38; //Size of program header
    headers.e_phnum = 0x01;     //Count of program headers
    headers.e_shentsize = 0x00;
    headers.e_shnum = 0x00;
    headers.e_shstrndx = 0x00;

    //Program headers
    pheaders.p_type = 0x01;     //Loadable segment
    pheaders.p_flags = 0x05;    //0x04(read) + 0x01(exec) = 0x05(r-x)
    pheaders.p_offset = 0x00;   //Segment offset [location in file]
    pheaders.p_vaddr = 0x1000;  //Virtual address of segment
    pheaders.p_paddr = 0x00;    //Physical address. Program will run under OS, so
                                //this is not matter
    pheaders.p_filesz = headers.e_ehsize + headers.e_phnum * headers.e_phentsize +
        sizeof(program);        //Size of segment in file
    pheaders.p_memsz = pheaders.p_filesz; //Size of segment in memory
    pheaders.p_align = 0x00;    //Default align is 0x1000(4096)

    //Entry point
    headers.e_entry = pheaders.p_vaddr + headers.e_ehsize + headers.e_phnum *
        headers.e_phentsize;

    printf("opening file...\n");

    fp = fopen(name, "wb");
    if(fp != NULL) {
        fwrite(&headers, 1, sizeof(headers), fp);

        if(headers.e_phoff >= headers.e_ehsize &&
                headers.e_phnum > 0x00){
            fseek(fp, headers.e_phoff, SEEK_SET);
            fwrite(&pheaders, 1, sizeof(pheaders), fp);
            fwrite(program, 1, sizeof(program), fp);
        }

        fclose(fp);
    }

    chmod(name, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);

    exit(0);
}
