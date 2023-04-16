#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <elf.h>
#include <string.h>

#define ElfW(type) Elf64_ ## type
#define POFFSET 0x1000
#define DOFFSET 0x2000
#define VADDR 0x2000
#define PAGESIZE 0x1000

typedef struct {
    uint32_t ei_mag;
    uint8_t ei_class;
    uint8_t ei_data;
    uint8_t ei_version;
    uint8_t ei_osabi;
    uint8_t ei_abiversion;
    uint8_t ei_pad[7];
} e_ident;

typedef struct {
    uint64_t offset;
    unsigned char *data;
    size_t size;
} table;

int main() {
    FILE *fp;
    char name[] = "elf-executable";

    //Program
        unsigned char program[] = {
            0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,   //mov $0x1, %rax
            0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,   //mov $0x1, %rdi
            0x48, 0xC7, 0xC6, 0x00, 0x30, 0x00, 0x00,   //mov $0x10a2, %rsi
            0x48, 0xC7, 0xC2, 0x0D, 0x00, 0x00, 0x00,   //mov $0xd, %rdx
            0x0F, 0x05,                                 //syscall
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,   //mov $0x3c, %rax
            0x48, 0x31, 0xff,                           //xor %rdi, %rdi
            0x0F, 0x05                                  //syscall
        };
    //Program

    //Data
        unsigned char data[] = "hello world!\n";
    //Data

    //e_ident part of ELF header
        e_ident ident;
        memset(&ident, 0, sizeof(ident));
        ident.ei_mag = 0x464C457F;  //ELF magic [0x7f, 0x45, 0x4c, 0x46]
        ident.ei_class = 0x02;      //Object file class. In this case 64-bit object file
        ident.ei_data = 0x01;       //Endianness. Current value is LE
        ident.ei_version = 0x01;    //ELF header version.
        ident.ei_osabi = 0x03;      //OS ABI. 0x03 for GNU/Linux
        ident.ei_abiversion = 0x00; //ABI version
    //e_ident

    //Elf header
        Elf64_Ehdr header;
        memset(&header, 0, sizeof(header));

        memcpy(header.e_ident, &ident, 0x10);
        if(memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) {
            fprintf(stderr, "e_ident is not elf format! exiting...\n");
            exit(1);
        }

        header.e_type = 0x02;      //Executable
        header.e_machine = 0x3E;   //AMD64
        header.e_version = 0x01;
        header.e_entry = 0x00;     //Entry point is virtual address of first instruction
        header.e_phoff = 0x40;     //Offset to first program header
        header.e_shoff = 0x00;     //Offset to first section header
        header.e_flags = 0x00;
        header.e_ehsize = 0x40;    //Size of Elf64_Ehdr
        header.e_phentsize = 0x38; //Size of program header
        header.e_phnum = 0x03;     //Count of program headers
        header.e_shentsize = 0x40; //Size of section header
        header.e_shnum = 0x06;     //Count of section headers
        header.e_shstrndx = 0x05;  //Index of section header table entry that contains section names
    //Elf header

    //Program headers
        Elf64_Phdr pheaders[header.e_phnum];
        memset(pheaders, 0, sizeof(pheaders));

        //Program header 0
            pheaders[0].p_type = 0x01;
            pheaders[0].p_flags = 0x04;
            pheaders[0].p_vaddr = VADDR-PAGESIZE;
            pheaders[0].p_filesz = header.e_ehsize + header.e_phnum * header.e_phentsize;
            pheaders[0].p_memsz = pheaders[0].p_filesz;
            pheaders[0].p_align = PAGESIZE;
        //Program header 0

        //Program header 1 - .text segment
            pheaders[1].p_type = 0x01;                  //Loadable segment
            pheaders[1].p_flags = 0x05;                 //0x04(read) + 0x01(exec) = 0x05(r-x)
            pheaders[1].p_offset = POFFSET;             //Program segment offset
            pheaders[1].p_vaddr = VADDR;                //Virtual address of segment
            pheaders[1].p_paddr = 0x00;                 //Physical address. Program will run under OS, so
                                                        //this is not matter
            pheaders[1].p_filesz = sizeof(program);     //Size of segment in file
            pheaders[1].p_memsz = pheaders[1].p_filesz; //Size of segment in memory
            pheaders[1].p_align = PAGESIZE;             //Default align is 0x1000(4096)
        //Program header 1

        //Program header 2 - .rodata segment
            pheaders[2].p_type = 0x01;
            pheaders[2].p_flags = 0x04;
            pheaders[2].p_offset = DOFFSET;
            pheaders[2].p_vaddr = VADDR+PAGESIZE;
            pheaders[2].p_filesz = sizeof(data);
            pheaders[2].p_memsz = pheaders[2].p_filesz;
            pheaders[2].p_align = PAGESIZE;
        //Program header 2
    //Program headers

    //Section headers
        header.e_shoff = pheaders[header.e_phnum-1].p_offset +
            pheaders[header.e_phnum-1].p_filesz;
        Elf64_Shdr sheaders[header.e_shnum];
        memset(sheaders, 0, sizeof(sheaders));

        //String table linked to symtab (.strtab)
            table symtab_names_table;
            unsigned char symtab_names[] = "\x00msg\x00_start";
            symtab_names_table.offset = header.e_shoff;
            symtab_names_table.data = symtab_names;
            symtab_names_table.size = sizeof(symtab_names);
            header.e_shoff += symtab_names_table.size;
        //String table linked to symtab

        //Section headers string table (.shstrtab)
            table section_names_table;
            unsigned char section_names[] = "\x00.symtab\x00.strtab\x00.shstrtab\x00.text\x00.rodata\x00";
            section_names_table.offset = header.e_shoff;
            section_names_table.data = section_names;
            section_names_table.size = sizeof(section_names);
            header.e_shoff += section_names_table.size;
        //Section headers string table

        //Section header 0
        //  NULL
        //Section header 0

        //Section header 1 - .text section
            sheaders[1].sh_name = 0x1B;                     //Offset in .shstrtab table
            sheaders[1].sh_type = 0x01;                     //PROGBITS - Program data
            sheaders[1].sh_flags = 0x6;                     //Section flags 0x02(Alloc) + 0x04(Executable) = 0x06(AX)
            sheaders[1].sh_addr = pheaders[1].p_vaddr;      //Virtual address of segment
            sheaders[1].sh_offset = pheaders[1].p_offset;   //Offset to .text section
            sheaders[1].sh_size = pheaders[1].p_memsz;      //Size of section
        //Section header 1

        //Section header 2 - .data section
            sheaders[2].sh_name = 0x21;
            sheaders[2].sh_type = 0x01;
            sheaders[2].sh_flags = 0x02;
            sheaders[2].sh_addr = pheaders[2].p_vaddr;
            sheaders[2].sh_offset = pheaders[2].p_offset;
            sheaders[2].sh_size = pheaders[2].p_memsz;
        //Section header 2

        //Section header 3 - (.symtab)
            sheaders[3].sh_name = 0x01;
            sheaders[3].sh_type = 0x02;
            sheaders[3].sh_offset = symtab_names_table.offset;
            sheaders[3].sh_size = 0x30;
            sheaders[3].sh_link = 0x04;                 //Index of section header
            //that points to linking section. In this case linking section is .strtab.
            //This table contains names of symtab entries
            sheaders[3].sh_entsize = 0x18;              //Entry size in .symtab
            sheaders[3].sh_info = sheaders[3].sh_size / //
                sheaders[3].sh_entsize;                 //Number of entries

            //Symbol table
                Elf64_Sym symtab[sheaders[3].sh_info];
                memset(symtab, 0, sizeof(symtab));
                //msg entry
                    symtab[0].st_name = 0x01;
                    symtab[0].st_value = sheaders[2].sh_addr;
                    symtab[0].st_shndx = 0x02;
                    symtab[0].st_size = sheaders[2].sh_size;
                //msg entry

                //_start entry
                    symtab[1].st_name = 0x05;                   //Offset in .strtab
                    symtab[1].st_value = sheaders[1].sh_addr;   //Value is virtual address
                    //In this case value is entry point address
                    symtab[1].st_shndx = 0x01;                  //Index of section contains that symbol
                    //In this case index is .text section index
                    symtab[1].st_size = sheaders[1].sh_size;    //Size of .text section
                //_start entry
            //Symbol table

            symtab_names_table.offset += sheaders[3].sh_size;
            section_names_table.offset += sheaders[3].sh_size;
            header.e_shoff += sheaders[3].sh_size;
        //Section header 3

        //Section header 4 - (.strtab)
            sheaders[4].sh_name = 0x09;
            sheaders[4].sh_type = 0x03;
            sheaders[4].sh_offset = symtab_names_table.offset;
            sheaders[4].sh_size = symtab_names_table.size;
        //Section header 4

        //Section header 5 - (.shstrtab)
            sheaders[5].sh_name = 0x11;
            sheaders[5].sh_type = 0x03;
            sheaders[5].sh_offset = section_names_table.offset;
            sheaders[5].sh_size = section_names_table.size;
        //Section header 5
    //Section headers

    //Entry point
    header.e_entry = pheaders[1].p_vaddr;

    printf("opening file...\n");

    fp = fopen(name, "wb");
    if(fp != NULL) {
        fwrite(&header, 1, sizeof(header), fp);

        if(header.e_phnum > 0x00){
            fseek(fp, header.e_phoff, SEEK_SET);
            fwrite(&pheaders, 1, sizeof(pheaders[0])*header.e_phnum, fp);
        }

        fseek(fp, POFFSET, SEEK_SET);
        fwrite(program, 1, sizeof(program), fp);

        fseek(fp, DOFFSET, SEEK_SET);
        fwrite(data, 1, sizeof(data), fp);

        if(sheaders[3].sh_size){
            fseek(fp, sheaders[3].sh_offset, SEEK_SET);
            fwrite(symtab, 1, sheaders[3].sh_size, fp);
        }

        if(symtab_names_table.size){
            fseek(fp, symtab_names_table.offset, SEEK_SET);
            fwrite(symtab_names_table.data, 1, symtab_names_table.size, fp);
        }

        if(section_names_table.size){
            fseek(fp, section_names_table.offset, SEEK_SET);
            fwrite(section_names_table.data, 1, section_names_table.size, fp);
        }

        if(header.e_shnum > 0x00){
            fwrite(sheaders, 1, sizeof(sheaders), fp);
        }

        fclose(fp);
    }

    chmod(name, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);

    exit(0);
}
