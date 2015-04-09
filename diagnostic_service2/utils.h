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
 * utils.h
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

#ifndef __diagnostic_service2__utils__
#define __diagnostic_service2__utils__

#include <CoreFoundation/CoreFoundation.h>
#import <IOKit/IOKitLib.h>
#include <sys/types.h>
#include <mach/mach.h>
#include "structures.h"

void get_kaslr_slide(size_t *size, uint64_t *slide);
int get_kernel_version(void);

kern_return_t map_kernel_buffer(uint8_t **kernel_buffer, size_t *kernel_size);
int unmap_kernel_buffer(uint8_t *kernel_buffer, size_t kernel_size);

kern_return_t find_kernel_bruteforce(uint8_t *kernel_buf, struct kernel_info *kinfo, mach_vm_address_t *kernel_addr);
kern_return_t find_kernel_smart(uint8_t *kernel_buf, struct kernel_info *kinfo, mach_vm_address_t *kernel_addr);
kern_return_t find_kernel_sysent(uint8_t *kernel_buf, struct kernel_info *kinfo, struct rk_info *rk_info);

kern_return_t readkmem(uint64_t address, uint64_t length, void *buffer);
kern_return_t writekmem(UInt64 address, UInt64 length, void *data);
kern_return_t zerokmem(uint64_t address, uint64_t length);

kern_return_t service_available(void);

#endif
