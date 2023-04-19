#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <elf.h>
#include <string.h>

#define ElfW(type) Elf64_ ## type
#define __ELFCLASS ELFCLASS64
#define __EFLAGS 0
#define __EHSIZE 64
#define __EPHENTSIZE 56
#define __ESHENTSIZE 64

#define POFFSET 0x1000
#define DOFFSET 0x2000
#define VADDR 0x2000
#define PAGESIZE 0x1000

typedef struct {
    uint64_t offset;
    unsigned char *data;
    size_t size;
} table;

int Ehdr(Elf64_Ehdr *e_header) {
    memset(e_header, 0, __EHSIZE);
    //Elf header
        //e_ident
            unsigned char e_ident[EI_NIDENT];
            memset(e_ident, 0, EI_NIDENT);

            e_ident[EI_MAG0] = ELFMAG0;         //ELF magic [0x7f, 0x45, 0x4c, 0x46]
            e_ident[EI_MAG1] = ELFMAG1;
            e_ident[EI_MAG2] = ELFMAG2;
            e_ident[EI_MAG3] = ELFMAG3;
            e_ident[EI_CLASS] = __ELFCLASS;     //Object file class. In this case 64-bit object file
            e_ident[EI_DATA] = ELFDATA2LSB;     //Endianness. Current value is LE
            e_ident[EI_VERSION] = EV_CURRENT;   //ELF header version.
            e_ident[EI_OSABI] = ELFOSABI_LINUX; //OS ABI. 0x03 for GNU/Linux
            //ABI version
            //Padding
        //e_ident

        memcpy(e_header->e_ident, &e_ident, EI_NIDENT);
        e_header->e_type = ET_EXEC;             //Executable
        e_header->e_machine = EM_X86_64;        //AMD64
        e_header->e_version = EV_CURRENT;
        e_header->e_flags = __EFLAGS;
        e_header->e_ehsize = __EHSIZE;          //Size of Elf64_Ehdr
        e_header->e_phentsize = __EPHENTSIZE;   //Size of program header
        e_header->e_shentsize = __ESHENTSIZE;   //Size of section header
    //Elf e_header

    return 0;
}

int Phdr_exec(Elf64_Phdr *p_header, Elf64_Shdr *s_header, Elf64_Word sh_name) {
    memset(p_header, 0, __EPHENTSIZE);

    p_header->p_type = PT_LOAD;             //Loadable segment
    p_header->p_flags = PF_R|PF_X;          //0x04(read) + 0x01(exec) = 0x05(r-x)
    p_header->p_offset = POFFSET;           //Program segment offset
    p_header->p_vaddr = VADDR;              //Virtual address of segment
    p_header->p_paddr = 0x00;               //Physical address. Program will run under OS, so
                                            //this is not matter
    p_header->p_filesz = __EPHENTSIZE;      //Size of segment in file
    p_header->p_memsz = p_header->p_filesz; //Size of segment in memory
    p_header->p_align = PAGESIZE;           //Default align is 0x1000(4096)

    if(s_header) {
        s_header->sh_name = sh_name;                //Offset in .shstrtab table
        s_header->sh_type = SHT_PROGBITS;           //PROGBITS - Program data
        s_header->sh_flags = SHF_ALLOC|SHF_EXECINSTR; //Section flags 0x02(Alloc) + 0x04(Executable) = 0x06(AX)
        s_header->sh_addr = p_header->p_vaddr;      //Virtual address of segment
        s_header->sh_offset = p_header->p_offset;   //Offset to .text section
        s_header->sh_size = p_header->p_memsz;      //Size of section
    }

    return 0;
}

int Phdr_data(Elf64_Phdr *p_header, size_t datasize, Elf64_Shdr *s_header, Elf64_Word sh_name) {
    memset(p_header, 0, __EPHENTSIZE);

    p_header->p_type = PT_LOAD;
    p_header->p_flags = PF_R;
    p_header->p_offset = DOFFSET;
    p_header->p_vaddr = VADDR+PAGESIZE;
    p_header->p_filesz = datasize;
    p_header->p_memsz = p_header->p_filesz;
    p_header->p_align = PAGESIZE;

    if(s_header) {
        s_header->sh_name = sh_name;
        s_header->sh_type = SHT_PROGBITS;
        s_header->sh_flags = SHF_ALLOC;
        s_header->sh_addr = p_header->p_vaddr;
        s_header->sh_offset = p_header->p_offset;
        s_header->sh_size = p_header->p_memsz;
    }

    return 0;
}

table *shstrtab_ptr(Elf64_Shdr *s_header, Elf64_Off *e_shoff, void *section_names, size_t size) {
    //Section headers string table (.shstrtab)
        table *section_names_table = malloc(sizeof(table));
        section_names_table->offset = *e_shoff;
        section_names_table->data = section_names;
        section_names_table->size = size;
        *e_shoff += section_names_table->size;
    //Section headers string table

    s_header->sh_name = 0x01;
    s_header->sh_type = SHT_STRTAB;
    s_header->sh_offset = section_names_table->offset;
    s_header->sh_size = section_names_table->size;

    return section_names_table;
}

table *strtab_ptr(Elf64_Shdr *s_header, Elf64_Off *e_shoff, const Elf64_Word name, void *symtab_names, size_t size) {
    //String table linked to symtab (.strtab)
        table *symtab_names_table = malloc(sizeof(table));
        symtab_names_table->offset = *e_shoff;
        symtab_names_table->data = symtab_names;
        symtab_names_table->size = size;
        *e_shoff += symtab_names_table->size;
    //String table linked to symtab

    s_header->sh_name = name;
    s_header->sh_type = SHT_STRTAB;
    s_header->sh_offset = symtab_names_table->offset;
    s_header->sh_size = symtab_names_table->size;

    return symtab_names_table;
}

Elf64_Sym *symtab_ptr(Elf64_Shdr *s_header, Elf64_Off *e_shoff, const Elf64_Word link, const Elf64_Word name, const size_t size, const Elf64_Word *fmt, ...) {
    s_header->sh_name = name;
    s_header->sh_type = SHT_SYMTAB;
    s_header->sh_offset = *e_shoff;
    s_header->sh_link = link;               //Index of section header
    //that points to linking section. In this case linking section is .strtab.
    //This table contains names of symtab entries
    s_header->sh_entsize = 0x18;            //Entry size in .symtab
    s_header->sh_size = size * s_header->sh_entsize;
    s_header->sh_info = s_header->sh_size / //
        s_header->sh_entsize;               //Number of entries
    *e_shoff += s_header->sh_size;

    //Symbol table
        Elf64_Sym *symtab = malloc(sizeof(Elf64_Sym)*s_header->sh_info);
        memset(symtab, 0, sizeof(*symtab));

        va_list args;
        va_start(args, fmt);

            for(int i = 0; i < size; i++) {
                Elf64_Shdr *shdr = va_arg(args, Elf64_Shdr*);
                symtab[i].st_name = fmt[i];
                symtab[i].st_value = shdr->sh_addr;
                symtab[i].st_shndx = 0x01;
                symtab[i].st_size = shdr->sh_size;
            }

        va_end(args);

        return  symtab;
}

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

    //Data
    unsigned char data[] = "hello world!\n";

    //Elf header
    Elf64_Ehdr header;
    Ehdr(&header);

    //Program headers
    header.e_phoff = header.e_ehsize;       //Offset to first program header
    header.e_phnum = 0x02;                  //Count of program headers

    Elf64_Phdr pheaders[header.e_phnum];
    memset(pheaders, 0, sizeof(pheaders));

    //Section headers
        header.e_shnum = 0x06;  //Count of section headers
        header.e_shoff = DOFFSET + sizeof(data);

        Elf64_Shdr sheaders[header.e_shnum];
        memset(sheaders, 0, sizeof(sheaders));

        //Section header 0 is null

        //Section header 1 - .text section
        Phdr_exec(&pheaders[0], &sheaders[1], 0x1B);    //.text segment

        //Section header 2 - .data section
        Phdr_data(&pheaders[1], sizeof(data), &sheaders[2], 0x21); //.data segment

        //Section header 3 - (.shstrtab)
        header.e_shstrndx = 0x03;   //Index of section header table entry that contains section names
        unsigned char section_names[] = "\x00.shstrtab\x00.symtab\x00.strtab\x00.text\x00.rodata\x00";
        table *section_names_table = shstrtab_ptr(&sheaders[3], &header.e_shoff, section_names, sizeof(section_names));

        //Section header 4 - (.strtab)
        unsigned char symtab_names[] = "\x00msg\x00_start";
        table *symtab_names_table = strtab_ptr(&sheaders[4], &header.e_shoff, 0x13, symtab_names, sizeof(symtab_names));

        //Section header 5 - (.symtab)
        uint8_t symtabndx = 5;
        Elf64_Sym *symtab = symtab_ptr(&sheaders[5], &header.e_shoff, 0x04, 0x0B, 2, (const Elf64_Word[2]){0x01, 0x05}, &sheaders[2], &sheaders[1]);

    //Section headers

    //Entry point
    header.e_entry = pheaders[0].p_vaddr;

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

        if(symtab->st_size){
            fseek(fp, sheaders[symtabndx].sh_offset, SEEK_SET);
            fwrite(symtab, 1, sheaders[symtabndx].sh_size, fp);
        }

        if(symtab_names_table->size){
            fseek(fp, symtab_names_table->offset, SEEK_SET);
            fwrite(symtab_names_table->data, 1, symtab_names_table->size, fp);
        }

        if(section_names_table->size){
            fseek(fp, section_names_table->offset, SEEK_SET);
            fwrite(section_names_table->data, 1, section_names_table->size, fp);
        }

        if(header.e_shnum > 0x00){
            fseek(fp, header.e_shoff, SEEK_SET);
            fwrite(sheaders, 1, sizeof(sheaders), fp);
        }

        fclose(fp);
    }

    chmod(name, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);

    exit(0);
}
