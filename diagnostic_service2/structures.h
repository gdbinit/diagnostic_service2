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
 * structures.h
 * All kind of shared structures
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

#ifndef __diagnostic_service2__structures__
#define __diagnostic_service2__structures__

#include <sys/types.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

struct kernel_info
{
    const uint8_t *linkedit_buf;          // pointer to __LINKEDIT area in kernel mapped buffer
    mach_vm_address_t text_vmaddr;
    uint64_t text_section_fileoff;
    uint64_t linkedit_fileoff;
    uint64_t linkedit_size;
    uint64_t kaslr_slide;
    mach_vm_address_t hib_vmaddr;
    uint64_t hib_size;
    mach_vm_address_t modinit_addr;
    uint64_t modinit_size;
    uint32_t symboltable_fileoff;
    uint32_t symboltable_nr_symbols;
    uint32_t stringtable_fileoff;
    uint32_t stringtable_size;
    uint32_t cmds_size;
};

typedef int32_t	sy_call_t(struct proc *, void *, int *);
typedef void	sy_munge_t(const void *, void *);

/* Mavericks sysent structure is something like this */
struct sysent_mavericks {
    sy_call_t   *sy_call;
    sy_munge_t  *sy_arg_munge32;
    sy_munge_t  *sy_arg_munge64;
    int32_t     sy_return_type;
    int16_t     sy_narg;
    uint16_t    sy_arg_bytes;
};

/* Yosemite sysent structure is something like this */
struct sysent_yosemite {
    sy_call_t   *sy_call;
    sy_munge_t  *sy_arg_munge64;
    int32_t     sy_return_type;
    int16_t     sy_narg;
    uint16_t    sy_arg_bytes;
};

struct rk_info
{
    mach_vm_address_t kernel_phys_addr;
    mach_vm_address_t rk_entrypoint;
    mach_vm_address_t rk_phys_addr;
    mach_vm_address_t rk_virt_addr;
    mach_vm_address_t sysent_phys_addr;
    mach_vm_address_t nosys_addr;
    mach_vm_address_t shellcode_phys_addr;
    mach_vm_address_t shellcode_virt_addr;
    uint32_t rootkit_size;
};

#endif
