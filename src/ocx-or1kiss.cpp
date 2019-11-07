/******************************************************************************
 * Copyright (C) 2019 Synopsys, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 ******************************************************************************/

#include <ocx/ocx.h>

#include <or1kiss.h>
#include <climits>
#include <cstdlib>

#define INFO(...)                                                             \
    do {                                                                      \
        fprintf(stderr, "%s:%d ", __FILE__, __LINE__);                        \
        fprintf(stderr, __VA_ARGS__);                                         \
        fprintf(stderr, "\n");                                                \
    } while (0)


#define ERROR(...)                                                            \
    do {                                                                      \
        INFO(__VA_ARGS__);                                                    \
        abort();                                                              \
    } while (0)

#define ERROR_ON(cond, ...)                                                   \
    do {                                                                      \
        if (cond) {                                                           \
            ERROR(__VA_ARGS__);                                               \
        }                                                                     \
    } while (0)

#define UNUSED_PARAMETER(p) ((void)p)

#define OPENRISC_PAGE_SIZE 8192

class core_or : public ocx::core, or1kiss::env
{
public:
    typedef ocx::u8  u8;
    typedef ocx::u32 u32;
    typedef ocx::u64 u64;

private:
    ocx::env&    m_env;
    or1kiss::or1k   m_or;
    u32             m_pending_breakpoint;
    bool            m_stop_requested;

public:
    core_or(ocx::env &env);
    ~core_or();

    // or1kiss::env overrides
    or1kiss::response transact(const or1kiss::request& req) override;

    // ocx overrides
    const char* arch() override;
    const char* arch_gdb() override;
    const char* arch_family() override;

    const char* provider() override;

    u64 step(u64 num_insn) override;
    void stop() override;
    u64 insn_count() override;

    void reset() override;
    void interrupt(u64 irq, bool set) override;
    void notified(u64 eventid) override;

    u64 page_size() override;
    bool virt_to_phys(u64 paddr, u64& vaddr) override;

    void set_id(u64 procid, u64 coreid) override;

    u64 pc_regid() override;
    u64 sp_regid() override;
    u64 num_regs() override;

    size_t reg_size(u64 regid) override;
    const char* reg_name(u64 regid) override;

    bool read_reg(u64 regid, void *buf) override;
    bool write_reg(u64 regid, const void *buf) override;

    bool add_breakpoint(u64 addr) override;
    bool remove_breakpoint(u64 addr) override;

    bool add_watchpoint(u64 addr, u64 size, bool iswr) override;
    bool remove_watchpoint(u64 addr, u64 size, bool iswr) override;
    bool trace_basic_blocks(bool on) override;

    void handle_syscall(int callno, void *arg) override;

    u64 disassemble(const void *src, size_t srcsz, char *buf, size_t bufsz) override;

    void invalidate_page_ptrs() override;
    void invalidate_page_ptr(u64 page_addr) override;

private:
    inline bool is_breakpoint_pending() const;
    void suspend_current_breakpoint(u32 pc);
    void activate_pending_breakpoint();

    // helpers
    static inline or1kiss::response convert_response(ocx::response resp);
};

core_or::core_or(ocx::env& env) :
    or1kiss::env(or1kiss::ENDIAN_LITTLE),
    m_env(env),
    m_or(this),
    m_pending_breakpoint(~0u),
    m_stop_requested(false)
{
}

core_or::~core_or() {
}

or1kiss::response core_or::transact(const or1kiss::request& req) {
    ocx::transaction tx = {
        .addr = req.addr,
        .size = req.size,
        .data = (u8 *)req.data,
        .is_read = req.is_read(),
        .is_user = !req.is_supervisor(),
        .is_secure = false,
        .is_insn = !req.is_dmem(),
        .is_excl = req.is_exclusive(),
        .is_lock = false,
        .is_port = false,
        .is_debug = req.is_debug()
    };

    return convert_response(m_env.transport(tx));
}

const char* core_or::arch() {
    return "openrisc";
}

const char* core_or::arch_gdb() {
    return "openrisc";
}

const char* core_or::arch_family() {
    return "openrisc";
}

const char* core_or::provider() {
    return "or1kiss - " __DATE__;
}

void core_or::handle_syscall(int callno, void *arg) {
    switch(callno) {
    default:
        ERROR("unknown syscall id (%d)", callno);
        break;
    }
}

inline bool core_or::is_breakpoint_pending() const {
    return m_pending_breakpoint != ~0u;
}

void core_or::suspend_current_breakpoint(u32 pc) {
    ERROR_ON(is_breakpoint_pending(), "breakpoint already pending");
    m_pending_breakpoint = pc;
    m_or.remove_breakpoint(pc);
}

void core_or::activate_pending_breakpoint() {
    ERROR_ON(!is_breakpoint_pending(), "no breakpoint pending");
    m_or.insert_breakpoint(m_pending_breakpoint);
    m_pending_breakpoint = ~0u;
}

core_or::u64 core_or::step(u64 num_insn) {

    using namespace or1kiss;

    ERROR_ON(num_insn > UINT_MAX, "num_insn %llu out of bounds", num_insn);
    u32 target_cycles = (u32)num_insn;
    u32 executed_cycles = 0;
    u32 cycles;
    u32 pc;
    step_result ret;

    while (!m_stop_requested && executed_cycles < target_cycles) {
        if (!is_breakpoint_pending()) {
            // no pending breakpoint - run freely
            cycles = target_cycles - executed_cycles;
            ret = m_or.step(cycles);
        } else {
            cycles = 1;
            ret = m_or.step(cycles);
            activate_pending_breakpoint();
        }

        executed_cycles += cycles;

        switch (ret) {
        case STEP_OK:
            break;
        case STEP_BREAKPOINT:
            pc = m_or.get_spr(SPR_NPC);
            suspend_current_breakpoint(pc);
            if (m_env.handle_breakpoint(pc))
                return executed_cycles;
            break;
        case STEP_WATCHPOINT:
            // no location information - generic notification
            if (m_env.handle_watchpoint(~0ull, 0, 0, false))
                return executed_cycles;
            break;
        case STEP_EXIT:
            INFO("xcore_or1kiss software exit request");
            exit(0);
            break;
        default:
            ERROR("unexpected step_result (%d)", ret);
        }
    }

    return executed_cycles;
}

void core_or::stop() {
    m_stop_requested = true;
}

core_or::u64 core_or::insn_count() {
    return m_or.get_num_instructions();
}

void core_or::reset() {
    // do nothing
}

void core_or::interrupt(u64 irq, bool set) {
    ERROR_ON(irq >= INT_MAX, "irq (%llu) out of bounds", irq);
    m_or.interrupt((int)irq, set);
}

void core_or::notified(u64 eventid) {
    ERROR("unexpected notification from environment (%llu)", eventid);
}

core_or::u64 core_or::page_size() {
    return OPENRISC_PAGE_SIZE;
}

bool core_or::virt_to_phys(u64 vaddr, u64& paddr) {
    if (!m_or.is_dmmu_active() && !m_or.is_immu_active()) {
        paddr = vaddr;
        return true;
    }

    or1kiss::request req;
    req.set_imem();
    req.set_read();
    req.set_debug();
    req.addr = vaddr;

    if (m_or.get_dmmu()->translate(req) == or1kiss::MMU_OKAY) {
        paddr = req.addr;
        return true;
    }

    if (m_or.get_immu()->translate(req) == or1kiss::MMU_OKAY) {
        paddr = req.addr;
        return true;
    }

    return false;
}

void core_or::invalidate_page_ptr(u64 page_addr) {
    ERROR_ON(page_addr > UINT_MAX, "page_addr (%llu) out of bounds", page_addr);
    if (get_data_ptr((u32)page_addr) != nullptr)
        set_data_ptr(nullptr);
    if (get_insn_ptr((u32)page_addr) != nullptr)
        set_insn_ptr(nullptr);
}

void core_or::invalidate_page_ptrs() {
    set_data_ptr(nullptr);
    set_insn_ptr(nullptr);
}

void core_or::set_id(u64 procid, u64 cpuid) {
    u64 id = 8 * procid + cpuid;
    ERROR_ON(id > UINT_MAX, "core id (%llu) out of bounds", id);
    m_or.set_core_id((u32)id);
}

core_or::u64 core_or::num_regs() {
    return 35; // 32 GPR + PPC + NPC + SR
}

bool core_or::read_reg(u64 regid, void* buf) {
    ERROR_ON(regid >= num_regs(), "register index %llu out of bounds", regid);
    u32 val = 0;
    switch (regid) {
    case 32: val = m_or.get_spr(or1kiss::SPR_PPC, true); break;
    case 33: val = m_or.get_spr(or1kiss::SPR_NPC, true); break;
    case 34: val = m_or.get_spr(or1kiss::SPR_SR, true); break;
    default: val = m_or.GPR[regid]; break;
    }

    *(u32*)buf = val;
    return true;
}

bool core_or::write_reg(u64 regid, const void *buf) {
    ERROR_ON(regid >= num_regs(), "register index %llu out of bounds", regid);

    u32 val = *(u32*)buf;
    switch (regid) {
    case 32: m_or.set_spr(or1kiss::SPR_PPC, val, true); break;
    case 33: m_or.set_spr(or1kiss::SPR_NPC, val, true); break;
    case 34: m_or.set_spr(or1kiss::SPR_SR, val, true); break;
    default: m_or.GPR[regid] = val; break;
    }

    return true;
}

size_t core_or::reg_size(u64 reg) {
    return sizeof(m_or.GPR[0]);
}

core_or::u64 core_or::pc_regid() {
    return 33;
}

core_or::u64 core_or::sp_regid() {
    return 1;
}

const char* core_or::reg_name(u64 regid) {
    ERROR_ON(regid >= num_regs(), "register index %llu out of bounds", regid);
    switch (regid) {
    case  0: return "R0";   case  1: return "R1";
    case  2: return "R2";   case  3: return "R3";
    case  4: return "R4";   case  5: return "R5";
    case  6: return "R6";   case  7: return "R7";
    case  8: return "R8";   case  9: return "R9";
    case 10: return "R10";  case 11: return "R11";
    case 12: return "R12";  case 13: return "R13";
    case 14: return "R14";  case 15: return "R15";
    case 16: return "R16";  case 17: return "R17";
    case 18: return "R18";  case 19: return "R19";
    case 20: return "R20";  case 21: return "R21";
    case 22: return "R22";  case 23: return "R23";
    case 24: return "R24";  case 25: return "R25";
    case 26: return "R26";  case 27: return "R27";
    case 28: return "R28";  case 29: return "R29";
    case 30: return "R30";  case 31: return "R31";
    case 32: return "PPC";  case 33: return "NPC";
    case 34: return "SR";
    default:
        ERROR("unexpected register index (%llu)", regid);
    }

    return "<ERROR>";
}

bool core_or::add_breakpoint(u64 addr) {
    ERROR_ON(addr > UINT32_MAX, "breakpoint address %llu out of bounds", addr);
    m_or.insert_breakpoint((u32)addr);
    return true;
}

bool core_or::remove_breakpoint(u64 addr) {
    ERROR_ON(addr > UINT32_MAX, "breakpoint address %llu out of bounds", addr);
    m_or.remove_breakpoint(addr);
    return true;
}

bool core_or::add_watchpoint(u64 addr, u64 size, bool iswr) {
    ERROR_ON(addr > UINT32_MAX, "watchpoint address %llu out of bounds", addr);
    ERROR_ON(size > UINT32_MAX, "watchpoint size %llu out of bounds", size);
    if (iswr) {
        m_or.insert_watchpoint_w((u32)addr, (u32)size);
    } else {
        m_or.insert_watchpoint_r((u32)addr, (u32)size);
    }

    return true;
}

bool core_or::remove_watchpoint(u64 addr, u64 size, bool iswr) {
    if (iswr) {
        m_or.remove_watchpoint_w(addr, size);
    } else {
        m_or.remove_watchpoint_r(addr, size);
    }

    return true;
}

bool core_or::trace_basic_blocks(bool on) {
    return false;
}

core_or::u64 core_or::disassemble(const void *src, size_t srcsz,
                                  char *buf, size_t bufsz) {

    if (srcsz >= 4) {
        std::ostringstream os;
        or1kiss::disassemble(os, *(u32*)src);
        strncpy(buf, os.str().c_str(), bufsz);
        return 4;
    } else {
        return 0;
    }
}

inline or1kiss::response core_or::convert_response(ocx::response resp) {
    switch (resp) {
    case ocx::RESP_OK:
        return or1kiss::RESP_SUCCESS;

    case ocx::RESP_FAILED:
    case ocx::RESP_NOT_EXCLUSIVE:
    case ocx::RESP_COMMAND_ERROR:
    case ocx::RESP_ADDRESS_ERROR:
        return or1kiss::RESP_FAILED;

    default:
        ERROR("unexpected response (%d)", resp);
        return or1kiss::RESP_ERROR;
    }
}

namespace ocx {

    core* create_instance(u64 api_version, env& e, const char* variant) {
        UNUSED_PARAMETER(variant);
        if (api_version != OCX_API_VERSION) {
            INFO("OCX_API_VERSION mismatch: requested %llu - "
                 "expected %llu", api_version, OCX_API_VERSION);
            return nullptr;
        }
        return new core_or(e);
    }

    void delete_instance(core* c) {
        core_or *p = dynamic_cast<core_or*>(c);
        ERROR_ON(p == nullptr, "calling delete_instance with foreign core");
        delete p    ;
    }
}

