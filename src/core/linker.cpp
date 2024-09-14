// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/alignment.h"
#include "common/arch.h"
#include "common/assert.h"
#include "common/config.h"
#include "common/logging/log.h"
#include "common/path_util.h"
#include "common/string_util.h"
#include "common/thread.h"
#include "core/aerolib/aerolib.h"
#include "core/aerolib/stubs.h"
#include "core/cpu_patches.h"
#include "core/libraries/kernel/memory_management.h"
#include "core/libraries/kernel/thread_management.h"
#include "core/linker.h"
#include "core/memory.h"
#include "core/tls.h"
#include "core/virtual_memory.h"

#include <unordered_map>
#include <unistd.h>
#include <fcntl.h>

void set_thread_affinity();

extern "C" {
    #include "x64emu.h"
    #include "x64run.h"
    #include "box64context.h"
    #include "regs.h"
    #include "externals/box64/src/emu/x64emu_private.h"


box64context_t *my_context = NULL;
    int box64_dynarec_test = 0;
    int box64_log = 2; //2 is debug; //LOG_NONE;
    int box64_dynarec_log = 0;

    int box64_ignoreint3 = 0;
    int box64_is32bits = 0;
    int box64_wine = 0;
    int box64_rdtsc = 0;
    int box64_rdtsc_1ghz = 0;
    uint8_t box64_rdtsc_shift = 0;
    int box64_sse_flushto0 = 0;
    int box64_x87_no80bits = 0;
    int box64_sync_rounding = 0;
    int box64_shaext = 1;
    int box64_sse42 = 1;
    int box64_avx = 1;
    int box64_avx2 = 1;
    int cycle_log = 0;
    int box64_mapclean = 0;
    int box64_dynarec = 1;
    uintptr_t box64_pagesize = 16 * 1024;

    int box64_dynarec_dump = 0;
    int box64_dynarec_forced = 0;
    int box64_dynarec_bigblock = 1;
    int box64_dynarec_forward = 128;
    int box64_dynarec_strongmem = 0;
    int box64_dynarec_x87double = 0;
    int box64_dynarec_div0 = 0;
    int box64_dynarec_fastnan = 1;
    int box64_dynarec_fastround = 1;
    int box64_dynarec_safeflags = 1;
    int box64_dynarec_callret = 0;
    int box64_dynarec_bleeding_edge = 1;
    int box64_dynarec_tbb = 1;
    int box64_dynarec_wait = 1;
    int box64_dynarec_missing = 0;
    int box64_dynarec_aligned_atomics = 0;
    uintptr_t box64_nodynarec_start = 0;
    uintptr_t box64_nodynarec_end = 0;
    uintptr_t box64_dynarec_test_start = 0;
    uintptr_t box64_dynarec_test_end = 0;

    int arm64_asimd = 1;
    int arm64_aes = 1;
    int arm64_pmull = 1;
    int arm64_crc32 = 1;
    int arm64_atomics = 1;
    int arm64_sha1 = 1;
    int arm64_sha2 = 1;
    int arm64_uscat = 1;
    int arm64_flagm = 1;
    int arm64_flagm2 = 1;
    int arm64_frintts = 1;
    int arm64_afp = 1;
    int arm64_rndr = 1;

    uint32_t default_gs = 0x53;
    uint32_t default_fs = 0x53;
    int box64_maxcpu = 0;
    void emit_signal(x64emu_t* emu, int sig, void* addr, int code) {
        for(;;) {
            printf("Signal %d at %p with code %d\n", sig, addr, code);
        }
    }
    void emit_div0(x64emu_t* emu, void* addr, int code) {
        for(;;) {
            printf("Divide by 0 at %p with code %d\n", addr, code);
        }
    }
    void emit_interruption(x64emu_t* emu, int num, void* addr) {
        if (num == 19) {
            using HLEFunc = PS4_SYSV_ABI uint64_t (*)(
                uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                double, double, double, double, double, double, double, double);

            auto return_addr = *(uint64_t*)(emu->regs[_RSP].q[0]);
            HLEFunc hleFunc;
            memcpy(&hleFunc, (uint8_t*)addr + 1, 8);
            asm volatile(
                "mov x0, %4\n"
                "mov x1, %5\n"
                "mov x2, %6\n"
                "mov x3, %7\n"
                "mov x4, %8\n"
                "mov x5, %9\n"
                "mov x6, %19\n"
                "mov x7, %20\n"

                "mov v0.16b, %10.16b\n"
                "mov v1.16b, %11.16b\n"
                "mov v2.16b, %12.16b\n"
                "mov v3.16b, %13.16b\n"
                "mov v4.16b, %14.16b\n"
                "mov v5.16b, %15.16b\n"
                "mov v6.16b, %16.16b\n"
                "mov v7.16b, %17.16b\n"
                "sub sp, sp, #16\n"
                "str %w21, [sp, #8]\n"
                "blr %18\n"
                "add sp, sp, #16\n"
                "mov %0, x0\n"
                "mov %1, x1\n"
                "mov %2.16b, v0.16b\n"
                "mov %3.16b, v1.16b\n"
                : "=r"(emu->regs[_RAX].q[0]), "=r"(emu->regs[_RDX].q[0]), "=w"(emu->xmm[0].u128), "=w"(emu->xmm[1].u128)
                : "r"(emu->regs[_RDI].q[0]), "r"(emu->regs[_RSI].q[0]), "r"(emu->regs[_RDX].q[0]), "r"(emu->regs[_RCX].q[0]),
                  "r"(emu->regs[_R8].q[0]), "r"(emu->regs[_R9].q[0]),  "w"(emu->xmm[0].u128), "w"(emu->xmm[1].u128), "w"(emu->xmm[2].u128),
                  "w"(emu->xmm[3].u128), "w"(emu->xmm[4].u128), "w"(emu->xmm[5].u128), "w"(emu->xmm[6].u128),
                  "w"(emu->xmm[7].u128), "r"(hleFunc), "r"(*(uint64_t*)(emu->regs[_RSP].q[0]+8)), "r"(*(uint64_t*)(emu->regs[_RSP].q[0]+16)),
                  "r"(*(uint64_t*)(emu->regs[_RSP].q[0]+24))
                : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",  // Clobber volatile general-purpose registers
                    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
                    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",  // Clobber volatile SIMD registers
                    "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", 
                    "memory", "cc"  // Clobber memory and condition codes
            );
            *(uint64_t*)(emu->regs[_RSP].q[0]) = return_addr;
            // emu->regs[_RAX].q[0] = hleFunc(
            //     emu->regs[_RDI].q[0],
            //     emu->regs[_RSI].q[0],
            //     emu->regs[_RDX].q[0],
            //     emu->regs[_RCX].q[0],
            //     emu->regs[_R8].q[0],
            //     emu->regs[_R9].q[0],

            //     emu->xmm[0].d[0],
            //     emu->xmm[1].d[0],
            //     emu->xmm[2].d[0],
            //     emu->xmm[3].d[0],

            //     emu->xmm[4].d[0],
            //     emu->xmm[5].d[0],
            //     emu->xmm[6].d[0],
            //     emu->xmm[7].d[0]
            // );
        } else if (num == 20) {
            emu->quit = 1;
         } else if (num == 21) {
            u64 next;
            memcpy(&next, (uint8_t*)addr, 8);
            LOG_INFO(Core_Linker, "Called: {} @{:x} RDI: {}", ((char*)addr + 8), next, emu->regs[_RDI].q[0]);
            emu->ip.q[0] = next;
        } else {
            for(;;) {
                printf("Interruption %d at %p\n", num, addr);
            }
        }
    }
    
    void x64Syscall(x64emu_t *emu) {
        for(;;) {
            printf("Syscall\n");
        }
    }
    void x86Syscall(x64emu_t *emu) {
        for(;;) {
            printf("Syscall\n");
        }
    }

    void printf_ftrace(const char* fmt, ...)
    {

        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);

        va_end(args);
    }
    int printFunctionAddr(uintptr_t nextaddr, const char* text) {
        printf("Function address %p with text %s\n", (void*)nextaddr, text);
        return 0;
    }
    void PltResolver64(x64emu_t* emu) {
        for(;;) {
            printf("PltResolver64\n");
        }
    }

    int isRetX87Wrapper(uint64_t fun) {
        return 0;
    }
    int isSimpleWrapper(uint64_t fun) {
        return 0;
    }

    int isAddrInPrereserve(uintptr_t addr) {
        return 0;
    }

    void* FindElfAddress(box64context_t *context, uintptr_t addr)
    {
        
        return NULL;
    }

    const char* GetNativeName(void* p)
    {
        return "NativeName";
    }

    void* GetSegmentBase(uint32_t desc)
    {
        printf("GetSegmentBase %d\n", desc);
        return Core::GetTcbBase();
    }

    uint64_t RunFunctionWithEmu(x64emu_t *emu, int QuitOnLongJump, uintptr_t fnc, int nargs, ...) {
        for(;;) {
            printf("RunFunctionWithEmu\n");
        }
    }

    const char* SymName64(void *h, void* sym) {
        return "SymName64";
    }
}

namespace Core {

using ExitFunc = PS4_SYSV_ABI void (*)();

static PS4_SYSV_ABI void ProgramExitFunc() {
    fmt::print("exit function called\n");
}


box64context_t *my_context;
thread_local x64emu_t *emu;

static void RunMainEntry(VAddr addr, EntryParams* params, ExitFunc exit_func) {
#ifdef ARCH_X86_64
    // reinterpret_cast<entry_func_t>(addr)(params, exit_func); // can't be used, stack has to have
    // a specific layout
    asm volatile("andq $-16, %%rsp\n" // Align to 16 bytes
                 "subq $8, %%rsp\n"   // videoout_basic expects the stack to be misaligned

                 // Kernel also pushes some more things here during process init
                 // at least: environment, auxv, possibly other things

                 "pushq 8(%1)\n" // copy EntryParams to top of stack like the kernel does
                 "pushq 0(%1)\n" // OpenOrbis expects to find it there

                 "movq %1, %%rdi\n" // also pass params and exit func
                 "movq %2, %%rsi\n" // as before

                 "jmp *%0\n" // can't use call here, as that would mangle the prepared stack.
                             // there's no coming back
                 :
                 : "r"(addr), "r"(params), "r"(exit_func)
                 : "rax", "rsi", "rdi");
#else

    uint64_t rsp = GetRSP(emu);

    rsp = rsp & ~16;
    rsp -= 8;

    rsp = rsp - 8;
    *(void**)rsp = params->argv;

    rsp = rsp - 8;
    *(u64*)rsp = params->argc;

    uint64_t rdi = (u64)params;
    uint64_t rsi = (u64)exit_func;

    SetRIP(emu, addr);
    SetRSP(emu, rsp);
    SetRDI(emu, rdi);
    SetRSI(emu, rsi);
    emu->quit = 0;

    set_thread_affinity();
    Run(emu, 0);

    UNIMPLEMENTED_MSG("Missing RunMainEntry() implementation for target CPU architecture.");
#endif
}

void* RunThreadEntry(u64 thread, void* arg) {
    emu = NewX64Emu(my_context, 0, (uintptr_t)0, 0, 0);

    auto* linker = Common::Singleton<Core::Linker>::Instance();

    thread_set_emu(emu);

    auto rsp = (uint8_t*)malloc(2 * 1024 * 1024) + 2 * 1024 * 1024;
    SetRSP(emu, (u64)rsp);

    linker->InitTlsForThread(false);

    uint8_t code[2];
    code[0] = 0xCD;
    code[1] = 0x14;
    rsp -= 8;
    *(uint8_t**)rsp = code;
    SetRIP(emu, thread);
    SetRSP(emu, (u64)rsp);
    SetRDI(emu, (u64)arg);

    emu->quit = 0;

    set_thread_affinity();
    Run(emu, 0);

    auto rv = emu->regs[_RAX].q[0];
    // no need here, freed automatically by thread_set_emu cleanup
    // FreeX64Emu(&emu);

    return (void*)rv;
}

Linker::Linker() : memory{Memory::Instance()} {}

Linker::~Linker() = default;

void Linker::Execute() {
    if (Config::debugDump()) {
        DebugDump();
    }

    // Calculate static TLS size.
    for (const auto& module : m_modules) {
        static_tls_size += module->tls.image_size;
        module->tls.offset = static_tls_size;
    }

    // Relocate all modules
    for (const auto& m : m_modules) {
        Relocate(m.get());
    }

    // Configure used flexible memory size.
    if (const auto* proc_param = GetProcParam()) {
        if (proc_param->size >=
            offsetof(OrbisProcParam, mem_param) + sizeof(OrbisKernelMemParam*)) {
            if (const auto* mem_param = proc_param->mem_param) {
                if (mem_param->size >=
                    offsetof(OrbisKernelMemParam, flexible_memory_size) + sizeof(u64*)) {
                    if (const auto* flexible_size = mem_param->flexible_memory_size) {
                        memory->SetupMemoryRegions(*flexible_size);
                    }
                }
            }
        }
    }

    // Init primary thread.
    Common::SetCurrentThreadName("GAME_MainThread");
#ifdef ARCH_X86_64
    InitializeThreadPatchStack();
#endif
    Libraries::Kernel::pthreadInitSelfMainThread();
    InitTlsForThread(true);

    my_context = NewBox64Context(0);
    emu = NewX64Emu(my_context, 0, (uintptr_t)0, 0, 0);

    thread_set_emu(emu);

    uintptr_t stack_top = 8 * 1024 * 1024 + (uintptr_t)malloc(8 * 1024 * 1024);

    // Start shared library modules
    for (auto& m : m_modules) {
        if (m->IsSharedLib()) {
            // m->Start(0, nullptr, nullptr);
            LOG_INFO(Core_Linker, "Starting shared library module {}", m->name);
            const VAddr addr = m->dynamic_info.init_virtual_addr + m->GetBaseAddress();
            uint8_t* code = (uint8_t*)malloc(2);
            code[0] = 0xCD;
            code[1] = 0x14;
            uint64_t rsp = stack_top;
            rsp &= ~16;
            rsp -= 8;
            *(uint8_t**)rsp = code;

            SetRIP(emu, addr);
            SetRSP(emu, rsp);
            SetRDI(emu, 0);
            SetRSI(emu, 0);
            SetRDX(emu, 0);

            emu->quit = 0;
            set_thread_affinity();
            Run(emu, 0);
        }
    }

    // Start main module.
    EntryParams p{};
    p.argc = 1;
    p.argv[0] = "eboot.bin";

    for (auto& m : m_modules) {
        if (!m->IsSharedLib()) {
            LOG_INFO(Core_Linker, "Starting main library module {}", m->name);
            SetRSP(emu, stack_top);
            RunMainEntry(m->GetEntryAddress(), &p, ProgramExitFunc);
        }
    }

    SetTcbBase(nullptr);
}

s32 Linker::LoadModule(const std::filesystem::path& elf_name, bool is_dynamic) {
    std::scoped_lock lk{mutex};

    if (!std::filesystem::exists(elf_name)) {
        LOG_ERROR(Core_Linker, "Provided file {} does not exist", elf_name.string());
        return -1;
    }

    auto module = std::make_unique<Module>(memory, elf_name, max_tls_index);
    if (!module->IsValid()) {
        LOG_ERROR(Core_Linker, "Provided file {} is not valid ELF file", elf_name.string());
        return -1;
    }

    num_static_modules += !is_dynamic;
    m_modules.emplace_back(std::move(module));
    return m_modules.size() - 1;
}

Module* Linker::FindByAddress(VAddr address) {
    for (auto& module : m_modules) {
        const VAddr base = module->GetBaseAddress();
        if (address >= base && address < base + module->aligned_base_size) {
            return module.get();
        }
    }
    return nullptr;
}

void Linker::Relocate(Module* module) {
    module->ForEachRelocation([&](elf_relocation* rel, u32 i, bool isJmpRel) {
        const u32 bit_idx =
            (isJmpRel ? module->dynamic_info.relocation_table_size / sizeof(elf_relocation) : 0) +
            i;
        if (module->TestRelaBit(bit_idx)) {
            return;
        }
        auto type = rel->GetType();
        auto symbol = rel->GetSymbol();
        auto addend = rel->rel_addend;
        auto* symbol_table = module->dynamic_info.symbol_table;
        auto* namesTlb = module->dynamic_info.str_table;

        const VAddr rel_base_virtual_addr = module->GetBaseAddress();
        const VAddr rel_virtual_addr = rel_base_virtual_addr + rel->rel_offset;
        bool rel_is_resolved = false;
        u64 rel_value = 0;
        Loader::SymbolType rel_sym_type = Loader::SymbolType::Unknown;
        std::string rel_name;

        switch (type) {
        case R_X86_64_RELATIVE:
            rel_value = rel_base_virtual_addr + addend;
            rel_is_resolved = true;
            module->SetRelaBit(bit_idx);
            break;
        case R_X86_64_DTPMOD64:
            rel_value = static_cast<u64>(module->tls.modid);
            rel_is_resolved = true;
            rel_sym_type = Loader::SymbolType::Tls;
            module->SetRelaBit(bit_idx);
            break;
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            addend = 0;
        case R_X86_64_64: {
            auto sym = symbol_table[symbol];
            auto sym_bind = sym.GetBind();
            auto sym_type = sym.GetType();
            auto sym_visibility = sym.GetVisibility();
            u64 symbol_virtual_addr = 0;
            Loader::SymbolRecord symrec{};
            switch (sym_type) {
            case STT_FUN:
                rel_sym_type = Loader::SymbolType::Function;
                break;
            case STT_OBJECT:
                rel_sym_type = Loader::SymbolType::Object;
                break;
            case STT_NOTYPE:
                rel_sym_type = Loader::SymbolType::NoType;
                break;
            default:
                ASSERT_MSG(0, "unknown symbol type {}", sym_type);
            }

            if (sym_visibility != 0) {
                LOG_INFO(Core_Linker, "symbol visibility !=0");
            }

            switch (sym_bind) {
            case STB_LOCAL:
                symbol_virtual_addr = rel_base_virtual_addr + sym.st_value;
                module->SetRelaBit(bit_idx);
                break;
            case STB_GLOBAL:
            case STB_WEAK: {
                rel_name = namesTlb + sym.st_name;
                if (Resolve(rel_name, rel_sym_type, module, &symrec)) {
                    // Only set the rela bit if the symbol was actually resolved and not stubbed.
                    module->SetRelaBit(bit_idx);
                }
                symbol_virtual_addr = symrec.virtual_address;
                break;
            }
            default:
                ASSERT_MSG(0, "unknown bind type {}", sym_bind);
            }
            rel_is_resolved = (symbol_virtual_addr != 0);
            rel_value = (rel_is_resolved ? symbol_virtual_addr + addend : 0);
            rel_name = symrec.name;
            break;
        }
        default:
            LOG_INFO(Core_Linker, "UNK type {:#010x} rel symbol : {:#010x}", type, symbol);
        }

        if (rel_is_resolved) {
            VirtualMemory::memory_patch(rel_virtual_addr, rel_value);
        } else {
            LOG_INFO(Core_Linker, "function not patched! {}", rel_name);
        }
    });
}

const Module* Linker::FindExportedModule(const ModuleInfo& module, const LibraryInfo& library) {
    const auto it = std::ranges::find_if(m_modules, [&](const auto& m) {
        return std::ranges::contains(m->GetExportLibs(), library) &&
               std::ranges::contains(m->GetExportModules(), module);
    });
    return it == m_modules.end() ? nullptr : it->get();
}

bool Linker::Resolve(const std::string& name, Loader::SymbolType sym_type, Module* m,
                     Loader::SymbolRecord* return_info) {
    const auto ids = Common::SplitString(name, '#');
    if (ids.size() != 3) {
        return_info->virtual_address = 0;
        return_info->name = name;
        LOG_ERROR(Core_Linker, "Not Resolved {}", name);
        return false;
    }

    const LibraryInfo* library = m->FindLibrary(ids[1]);
    const ModuleInfo* module = m->FindModule(ids[2]);
    ASSERT_MSG(library && module, "Unable to find library and module");

    Loader::SymbolResolver sr{};
    sr.name = ids.at(0);
    sr.library = library->name;
    sr.library_version = library->version;
    sr.module = module->name;
    sr.module_version_major = module->version_major;
    sr.module_version_minor = module->version_minor;
    sr.type = sym_type;

    const auto* record = m_hle_symbols.FindSymbol(sr);

    if (record) {
        *return_info = *record;

        return true;
    }

    if (!record) {
        // Check if it an export function
        const auto* p = FindExportedModule(*module, *library);
        if (p && p->export_sym.GetSize() > 0) {
            record = p->export_sym.FindSymbol(sr);
        }
    }
    if (record) {
        *return_info = *record;

#if 0 // Set to 1 to log all symbol calls
        const auto aeronid = AeroLib::FindByNid(sr.name.c_str());
        if (aeronid) {
            uint8_t* stub = (uint8_t*)malloc(2 + 8 + strlen(aeronid->name) + 1);
            stub[0] = 0xCD;
            stub[1] = 0x15;
            memcpy(&stub[2], &return_info->virtual_address, 8);
            strcpy((char*)&stub[10], aeronid->name);
            return_info->virtual_address = (uint64_t)stub;
        }
#endif
        return true;
    }

    const auto aeronid = AeroLib::FindByNid(sr.name.c_str());
    if (aeronid) {
        return_info->name = aeronid->name;
        return_info->virtual_address = AeroLib::GetStub(aeronid->nid);
    } else {
        return_info->virtual_address = AeroLib::GetStub(sr.name.c_str());
        return_info->name = "Unknown !!!";
    }
    LOG_ERROR(Core_Linker, "Linker: Stub resolved {} as {} (lib: {}, mod: {})", sr.name,
              return_info->name, library->name, module->name);
    return false;
}

void* heap_api_malloc(Core::HeapAPI* heap_api, size_t size) {
    static uint8_t code[2];
    code[0] = 0xCD;
    code[1] = 0x14;

    uint64_t rsp = GetRSP(emu);
    rsp -= 8;
    *(uint8_t**)rsp = code;

    SetRIP(emu, (u64)heap_api->heap_malloc);
    SetRSP(emu, rsp);
    SetRDI(emu, size);

    set_thread_affinity();
    Run(emu, 0);

    return (void*)emu->regs[_RAX].q[0];
}

void* Linker::TlsGetAddr(u64 module_index, u64 offset) {
    std::scoped_lock lk{mutex};

    DtvEntry* dtv_table = GetTcbBase()->tcb_dtv;
    if (dtv_table[0].counter != dtv_generation_counter) {
        // Generation counter changed, a dynamic module was either loaded or unloaded.
        const u32 old_num_dtvs = dtv_table[1].counter;
        ASSERT_MSG(max_tls_index > old_num_dtvs, "Module unloading unsupported");
        // Module was loaded, increase DTV table size.
        DtvEntry* new_dtv_table = new DtvEntry[max_tls_index + 2];
        std::memcpy(new_dtv_table + 2, dtv_table + 2, old_num_dtvs * sizeof(DtvEntry));
        new_dtv_table[0].counter = dtv_generation_counter;
        new_dtv_table[1].counter = max_tls_index;
        delete[] dtv_table;

        // Update TCB pointer.
        GetTcbBase()->tcb_dtv = new_dtv_table;
        dtv_table = new_dtv_table;
    }

    u8* addr = dtv_table[module_index + 1].pointer;
    if (!addr) {
        // Module was just loaded by above code. Allocate TLS block for it.
        Module* module = m_modules[module_index - 1].get();
        const u32 init_image_size = module->tls.init_image_size;
        // TODO: Determine if Windows will crash from this
        u8* dest = reinterpret_cast<u8*>(heap_api_malloc(heap_api, module->tls.image_size));
        const u8* src = reinterpret_cast<const u8*>(module->tls.image_virtual_addr);
        std::memcpy(dest, src, init_image_size);
        std::memset(dest + init_image_size, 0, module->tls.image_size - init_image_size);
        dtv_table[module_index + 1].pointer = dest;
        addr = dest;
    }
    return addr + offset;
}

void Linker::InitTlsForThread(bool is_primary) {
    static constexpr size_t TcbSize = 0x40;
    static constexpr size_t TlsAllocAlign = 0x20;
    const size_t total_tls_size = Common::AlignUp(static_tls_size, TlsAllocAlign) + TcbSize;

    // If sceKernelMapNamedFlexibleMemory is being called from libkernel and addr = 0
    // it automatically places mappings in system reserved area instead of managed.
    static constexpr VAddr KernelAllocBase = 0x880000000ULL;

    // The kernel module has a few different paths for TLS allocation.
    // For SDK < 1.7 it allocates both main and secondary thread blocks using libc mspace/malloc.
    // In games compiled with newer SDK, the main thread gets mapped from flexible memory,
    // with addr = 0, so system managed area. Here we will only implement the latter.
    void* addr_out{reinterpret_cast<void*>(KernelAllocBase)};
    if (is_primary) {
        const size_t tls_aligned = Common::AlignUp(total_tls_size, 16_KB);
        const int ret = Libraries::Kernel::sceKernelMapNamedFlexibleMemory(
            &addr_out, tls_aligned, 3, 0, "SceKernelPrimaryTcbTls");
        ASSERT_MSG(ret == 0, "Unable to allocate TLS+TCB for the primary thread");
    } else {
        if (heap_api) {
#ifndef WIN32
            addr_out = heap_api_malloc(heap_api, total_tls_size);
        } else {
            addr_out = std::malloc(total_tls_size);
#else
            // TODO: Windows tls malloc replacement, refer to rtld_tls_block_malloc
            LOG_ERROR(Core_Linker, "TLS user malloc called, using std::malloc");
            addr_out = std::malloc(total_tls_size);
            if (!addr_out) {
                auto pth_id = pthread_self();
                auto handle = pthread_gethandle(pth_id);
                ASSERT_MSG(addr_out,
                           "Cannot allocate TLS block defined for handle=%x, index=%d size=%d",
                           handle, pth_id, total_tls_size);
            }
#endif
        }
    }

    // Initialize allocated memory and allocate DTV table.
    const u32 num_dtvs = max_tls_index;
    std::memset(addr_out, 0, total_tls_size);
    DtvEntry* dtv_table = new DtvEntry[num_dtvs + 2];

    // Initialize thread control block
    u8* addr = reinterpret_cast<u8*>(addr_out);
    Tcb* tcb = reinterpret_cast<Tcb*>(addr + static_tls_size);
    tcb->tcb_self = tcb;
    tcb->tcb_dtv = dtv_table;

    // Dtv[0] is the generation counter. libkernel puts their number into dtv[1] (why?)
    dtv_table[0].counter = dtv_generation_counter;
    dtv_table[1].counter = num_dtvs;

    // Copy init images to TLS thread blocks and map them to DTV slots.
    for (u32 i = 0; i < num_static_modules; i++) {
        auto* module = m_modules[i].get();
        if (module->tls.image_size == 0) {
            continue;
        }
        u8* dest = reinterpret_cast<u8*>(addr + static_tls_size - module->tls.offset);
        const u8* src = reinterpret_cast<const u8*>(module->tls.image_virtual_addr);
        std::memcpy(dest, src, module->tls.init_image_size);
        tcb->tcb_dtv[module->tls.modid + 1].pointer = dest;
    }

    // Set pointer to FS base
    SetTcbBase(tcb);
}

void Linker::DebugDump() {
    const auto& log_dir = Common::FS::GetUserPath(Common::FS::PathType::LogDir);
    const std::filesystem::path debug(log_dir / "debugdump");
    std::filesystem::create_directory(debug);
    for (const auto& m : m_modules) {
        // TODO make a folder with game id for being more unique?
        const std::filesystem::path filepath(debug / m.get()->file.stem());
        std::filesystem::create_directory(filepath);
        m.get()->import_sym.DebugDump(filepath / "imports.txt");
        m.get()->export_sym.DebugDump(filepath / "exports.txt");
        if (m.get()->elf.IsSelfFile()) {
            m.get()->elf.SelfHeaderDebugDump(filepath / "selfHeader.txt");
            m.get()->elf.SelfSegHeaderDebugDump(filepath / "selfSegHeaders.txt");
        }
        m.get()->elf.ElfHeaderDebugDump(filepath / "elfHeader.txt");
        m.get()->elf.PHeaderDebugDump(filepath / "elfPHeaders.txt");
    }
}

} // namespace Core
