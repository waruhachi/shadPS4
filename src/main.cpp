// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <fmt/core.h>
#include "common/memory_patcher.h"
#include "emulator.h"

#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
void set_thread_affinity();

int main(int argc, char* argv[]) {
    set_thread_affinity();
    task_set_exception_ports(
                             mach_task_self(),
                             EXC_MASK_BAD_ACCESS,
                             MACH_PORT_NULL,//m_exception_port,
                             EXCEPTION_DEFAULT,
                             0);
    if (argc == 1) {
        fmt::print("Usage: {} <elf or eboot.bin path>\n", argv[0]);
        return -1;
    }

    for (int i = 0; i < argc; i++) {
        std::string curArg = argv[i];
        if (curArg == "-p") {
            std::string patchFile = argv[i + 1];
            MemoryPatcher::patchFile = patchFile;
        }
    }

    Core::Emulator emulator;
    emulator.Run(argv[1]);

    return 0;
}

#include <pthread.h>
#import <mach/thread_act.h>

void set_thread_affinity() {
    thread_affinity_policy_data_t policyData1 = { 1 };
    thread_policy_set(pthread_mach_thread_np(pthread_self()), THREAD_AFFINITY_POLICY, (thread_policy_t)&policyData1, 1);
}