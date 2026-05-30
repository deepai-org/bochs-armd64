/////////////////////////////////////////////////////////////////////////
// $Id$
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2025  The Bochs Project
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA B 02110-1301 USA
//
/////////////////////////////////////////////////////////////////////////

#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#include "cpuid.h"
#define LOG_THIS BX_CPU_THIS_PTR

#if BX_SUPPORT_SVM
#include "svm.h"
#endif

#include "pc_system.h"
#include "gui/gui.h"

#include "bx_debug/debug.h"

#include "decoder/ia_opcodes.h"
#include "softfloat3e/include/softfloat.h"

enum {
  BX_POLY_MODE_X86 = 0,
  BX_POLY_MODE_RAW_AARCH64 = 3,
  BX_POLY_MODE_RAW_RISCV = 4
};

enum {
  BX_POLY_FRONTEND_X86 = 0,
  BX_POLY_FRONTEND_AARCH64 = 1,
  BX_POLY_FRONTEND_RISCV = 2
};

enum {
  BX_POLY_TRAP_NONE = 0,
  BX_POLY_TRAP_SYSCALL = 1,
  BX_POLY_TRAP_BREAK = 2,
  BX_POLY_TRAP_IMPORT = 3,
  BX_POLY_TRAP_ILLEGAL = 4
};

struct bx_poly_trap_packet {
  Bit32u reason;
  Bit32u mode;
  Bit32u number;
  Bit32u selector;
  bx_address pc;
  bx_address next_pc;
  Bit64u args[8];
};

struct bx_poly_trap_saved_regs {
  bool valid;
  Bit32u mode;
  Bit64u rax;
  Bit64u rbx;
  Bit64u rdi;
  Bit64u rsi;
  Bit64u rdx;
  Bit64u rcx;
  Bit64u r8;
  Bit64u r9;
  Bit64u r10;
  Bit64u r11;
  Bit64u r12;
  Bit64u rsp;
  Bit64u xmm_lo[8];
  Bit64u xmm_hi[8];
  bool aarch64_state_valid;
  Bit64u aarch64_x[32];
  bool aarch64_x_valid[32];
  Bit64u aarch64_fp[32];
  Bit64u aarch64_fp_hi[32];
  Bit32u aarch64_nzcv;
  bool riscv_state_valid;
  Bit64u riscv_x[32];
  bool riscv_x_valid[32];
  Bit64u riscv_fp[32];
  Bit64u riscv_fp_hi[32];
  Bit32u riscv_fflags;
  Bit32u riscv_frm;
};

static void bx_poly_clear_trap_saved_regs(bx_poly_trap_saved_regs *regs)
{
  regs->valid = false;
  regs->mode = BX_POLY_MODE_X86;
  regs->rax = 0;
  regs->rbx = 0;
  regs->rdi = 0;
  regs->rsi = 0;
  regs->rdx = 0;
  regs->rcx = 0;
  regs->r8 = 0;
  regs->r9 = 0;
  regs->r10 = 0;
  regs->r11 = 0;
  regs->r12 = 0;
  regs->rsp = 0;
  for (unsigned n = 0; n < 8; n++) {
    regs->xmm_lo[n] = 0;
    regs->xmm_hi[n] = 0;
  }
  regs->aarch64_state_valid = false;
  regs->riscv_state_valid = false;
  regs->aarch64_nzcv = 0;
  regs->riscv_fflags = 0;
  regs->riscv_frm = 0;
  for (unsigned n = 0; n < 32; n++) {
    regs->aarch64_x[n] = 0;
    regs->aarch64_x_valid[n] = false;
    regs->aarch64_fp[n] = 0;
    regs->aarch64_fp_hi[n] = 0;
    regs->riscv_x[n] = 0;
    regs->riscv_x_valid[n] = false;
    regs->riscv_fp[n] = 0;
    regs->riscv_fp_hi[n] = 0;
  }
}

static inline Bit32u BX_POLY_AARCH64_CTRL(Bit32u subop)
{
  return 0xd503201fU | ((subop & 0x7fU) << 5);
}

static inline Bit32u BX_POLY_RISCV_CTRL(Bit32u subop)
{
  return 0x0000700bU | ((subop & 0x7fU) << 25);
}

static const Bit32u BX_POLY_AARCH64_CTRL_SUBOP_CALL_SIG_IMM_BASE = 0x60;
static const Bit32u BX_POLY_AARCH64_CTRL_X86_ESCAPE = BX_POLY_AARCH64_CTRL(0x70);
static const Bit32u BX_POLY_AARCH64_CTRL_RISCV_SWITCH = BX_POLY_AARCH64_CTRL(0x71);
static const Bit32u BX_POLY_AARCH64_CTRL_RISCV_CALL = BX_POLY_AARCH64_CTRL(0x72);
static const Bit32u BX_POLY_AARCH64_CTRL_RISCV_CALL_COMPACT_U32_F32 = BX_POLY_AARCH64_CTRL(0x73);
static const Bit32u BX_POLY_AARCH64_CTRL_RISCV_CALL_COMPACT_F32_U32 = BX_POLY_AARCH64_CTRL(0x74);
static const Bit32u BX_POLY_AARCH64_CTRL_RISCV_CALL_FP64_STACK = BX_POLY_AARCH64_CTRL(0x75);
static const Bit32u BX_POLY_AARCH64_CTRL_TRAP_RETURN = BX_POLY_AARCH64_CTRL(0x76);
static const Bit32u BX_POLY_AARCH64_CTRL_RISCV_CALL_VEC128_U32 = BX_POLY_AARCH64_CTRL(0x77);
static const Bit32u BX_POLY_AARCH64_CTRL_SWITCH_MODE = BX_POLY_AARCH64_CTRL(0x78);
static const Bit32u BX_POLY_AARCH64_CTRL_CALL_MODE = BX_POLY_AARCH64_CTRL(0x79);
static const Bit32u BX_POLY_AARCH64_CTRL_CALL_SIG_MODE = BX_POLY_AARCH64_CTRL(0x7a);
static const Bit32u BX_POLY_AARCH64_CTRL_LANDING = BX_POLY_AARCH64_CTRL(0x7b);
static const Bit32u BX_POLY_AARCH64_CTRL_ABI_SIGNATURE_SET = BX_POLY_AARCH64_CTRL(0x7c);
static const Bit32u BX_POLY_AARCH64_CTRL_ABI_SIGNATURE_GET = BX_POLY_AARCH64_CTRL(0x7d);
static const Bit32u BX_POLY_AARCH64_CTRL_LANDING_POLICY_SET = BX_POLY_AARCH64_CTRL(0x7e);
static const Bit32u BX_POLY_AARCH64_CTRL_LANDING_POLICY_GET = BX_POLY_AARCH64_CTRL(0x7f);
static const Bit32u BX_POLY_AARCH64_CTRL_TRAP_VECTOR_SET = BX_POLY_AARCH64_CTRL(0x68);
static const Bit32u BX_POLY_AARCH64_CTRL_TRAP_VECTOR_GET = BX_POLY_AARCH64_CTRL(0x69);
static const Bit32u BX_POLY_AARCH64_CTRL_TRAP_VECTOR_MODE_SET = BX_POLY_AARCH64_CTRL(0x6a);
static const Bit32u BX_POLY_AARCH64_CTRL_TRAP_VECTOR_MODE_GET = BX_POLY_AARCH64_CTRL(0x6b);
static const Bit32u BX_POLY_AARCH64_CTRL_MONITOR_PACKET_SET = BX_POLY_AARCH64_CTRL(0x6c);
static const Bit32u BX_POLY_AARCH64_CTRL_MONITOR_PACKET_GET = BX_POLY_AARCH64_CTRL(0x6d);
static const Bit32u BX_POLY_RISCV_CTRL_SUBOP_CALL_SIG_IMM_BASE = 16;
static const Bit32u BX_POLY_RISCV_CTRL_X86_ESCAPE = BX_POLY_RISCV_CTRL(0);
static const Bit32u BX_POLY_RISCV_CTRL_AARCH64_SWITCH = BX_POLY_RISCV_CTRL(1);
static const Bit32u BX_POLY_RISCV_CTRL_AARCH64_CALL = BX_POLY_RISCV_CTRL(2);
static const Bit32u BX_POLY_RISCV_CTRL_AARCH64_CALL_COMPACT_U32_F32 = BX_POLY_RISCV_CTRL(3);
static const Bit32u BX_POLY_RISCV_CTRL_AARCH64_CALL_COMPACT_F32_U32 = BX_POLY_RISCV_CTRL(4);
static const Bit32u BX_POLY_RISCV_CTRL_AARCH64_CALL_FP64_STACK = BX_POLY_RISCV_CTRL(5);
static const Bit32u BX_POLY_RISCV_CTRL_TRAP_RETURN = BX_POLY_RISCV_CTRL(6);
static const Bit32u BX_POLY_RISCV_CTRL_AARCH64_CALL_VEC128_U32 = BX_POLY_RISCV_CTRL(7);
static const Bit32u BX_POLY_RISCV_CTRL_SWITCH_MODE = BX_POLY_RISCV_CTRL(8);
static const Bit32u BX_POLY_RISCV_CTRL_CALL_MODE = BX_POLY_RISCV_CTRL(9);
static const Bit32u BX_POLY_RISCV_CTRL_CALL_SIG_MODE = BX_POLY_RISCV_CTRL(10);
static const Bit32u BX_POLY_RISCV_CTRL_LANDING = BX_POLY_RISCV_CTRL(11);
static const Bit32u BX_POLY_RISCV_CTRL_ABI_SIGNATURE_SET = BX_POLY_RISCV_CTRL(12);
static const Bit32u BX_POLY_RISCV_CTRL_ABI_SIGNATURE_GET = BX_POLY_RISCV_CTRL(13);
static const Bit32u BX_POLY_RISCV_CTRL_TRAP_VECTOR_SET = BX_POLY_RISCV_CTRL(24);
static const Bit32u BX_POLY_RISCV_CTRL_TRAP_VECTOR_GET = BX_POLY_RISCV_CTRL(25);
static const Bit32u BX_POLY_RISCV_CTRL_TRAP_VECTOR_MODE_SET = BX_POLY_RISCV_CTRL(26);
static const Bit32u BX_POLY_RISCV_CTRL_TRAP_VECTOR_MODE_GET = BX_POLY_RISCV_CTRL(27);
static const Bit32u BX_POLY_RISCV_CTRL_MONITOR_PACKET_SET = BX_POLY_RISCV_CTRL(28);
static const Bit32u BX_POLY_RISCV_CTRL_MONITOR_PACKET_GET = BX_POLY_RISCV_CTRL(29);
static const Bit32u BX_POLY_RISCV_CTRL_LANDING_POLICY_SET = BX_POLY_RISCV_CTRL(30);
static const Bit32u BX_POLY_RISCV_CTRL_LANDING_POLICY_GET = BX_POLY_RISCV_CTRL(31);
static const Bit32u BX_POLY_CPUID_BASE = 0x40000000;
static const Bit32u BX_POLY_CPUID_MAX = 0x40000009;
static const Bit32u BX_POLY_CPUID_FEATURE_RAW_AARCH64 = (1U << 0);
static const Bit32u BX_POLY_CPUID_FEATURE_RAW_RISCV = (1U << 1);
static const Bit32u BX_POLY_CPUID_FEATURE_NEUTRAL_SWITCH = (1U << 2);
static const Bit32u BX_POLY_CPUID_FEATURE_NATIVE_RET = (1U << 3);
static const Bit32u BX_POLY_CPUID_FEATURE_PCALL_SYSV = (1U << 4);
static const Bit32u BX_POLY_CPUID_FEATURE_PCALL_SRET = (1U << 5);
static const Bit32u BX_POLY_CPUID_FEATURE_FP_BRIDGE = (1U << 6);
static const Bit32u BX_POLY_CPUID_FEATURE_TRAP_RECORDS = (1U << 7);
static const Bit32u BX_POLY_CPUID_FEATURE_USER_RETURN_RESTORE = (1U << 8);
static const Bit32u BX_POLY_CPUID_FEATURE_X86_TSO = (1U << 9);
static const Bit32u BX_POLY_CPUID_FEATURE_THREAD_BANKS = (1U << 10);
static const Bit32u BX_POLY_CPUID_FEATURE_GENERIC_FRONTEND_IDS = (1U << 11);
static const Bit32u BX_POLY_CPUID_FEATURE_X86_POLY_OPCODES = (1U << 12);
static const Bit32u BX_POLY_CPUID_FEATURE_FPAIR32_RET = (1U << 13);
static const Bit32u BX_POLY_CPUID_FEATURE_FPAIR32_ARG = (1U << 14);
static const Bit32u BX_POLY_CPUID_FEATURE_HETERO_U64_F64 = (1U << 15);
static const Bit32u BX_POLY_CPUID_FEATURE_HETERO_F64_U64 = (1U << 16);
static const Bit32u BX_POLY_CPUID_FEATURE_HETERO_U64_F32 = (1U << 17);
static const Bit32u BX_POLY_CPUID_FEATURE_HETERO_F32_U64 = (1U << 18);
static const Bit32u BX_POLY_CPUID_FEATURE_COMPACT_U32_F32 = (1U << 19);
static const Bit32u BX_POLY_CPUID_FEATURE_COMPACT_F32_U32 = (1U << 20);
static const Bit32u BX_POLY_CPUID_FEATURE_NEUTRAL_COMPACT = (1U << 21);
static const Bit32u BX_POLY_CPUID_FEATURE_X86_IMPORT_DESCRIPTORS = (1U << 22);
static const Bit32u BX_POLY_CPUID_FEATURE_FP64_STACK_ARGS = (1U << 23);
static const Bit32u BX_POLY_CPUID_FEATURE_NEUTRAL_FP64_STACK = (1U << 24);
static const Bit32u BX_POLY_CPUID_FEATURE_TRAP_VECTOR = (1U << 25);
static const Bit32u BX_POLY_CPUID_FEATURE_STATE_KEY = (1U << 26);
static const Bit32u BX_POLY_CPUID_FEATURE_VEC128_BRIDGE = (1U << 27);
static const Bit32u BX_POLY_CPUID_FEATURE_AARCH64_HFA64_RET = (1U << 28);
static const Bit32u BX_POLY_CPUID_FEATURE_AARCH64_HFA32_RET = (1U << 29);
static const Bit32u BX_POLY_CPUID_FEATURE_AARCH64_HFA_ARGS = (1U << 30);
static const Bit32u BX_POLY_CPUID_FEATURE_FOREIGN_PCALL_SIG_IMM = (1U << 31);
static const Bit32u BX_POLY_CPUID_STATE_OVERLAP_GPRS = (1U << 0);
static const Bit32u BX_POLY_CPUID_STATE_SYNTHETIC_BANKS = (1U << 1);
static const Bit32u BX_POLY_CPUID_STATE_KEY_CR3 = (1U << 2);
static const Bit32u BX_POLY_CPUID_STATE_KEY_FSBASE = (1U << 3);
static const Bit32u BX_POLY_CPUID_STATE_KEY_STACK_REGION = (1U << 4);
static const Bit32u BX_POLY_CPUID_STATE_USER_RETURN_RESTORE = (1U << 5);
static const Bit32u BX_POLY_CPUID_STATE_X86_TSO = (1U << 6);
static const Bit32u BX_POLY_CPUID_STATE_XSAVE_VISIBLE = (1U << 7);
static const Bit32u BX_POLY_CPUID_STATE_KEY_EXPLICIT = (1U << 8);
static const Bit32u BX_POLY_CPUID_STATE_TRANSITION_FRAME_32 = (1U << 9);
static const Bit32u BX_POLY_CPUID_STATE_EXPLICIT_SAVE_RESTORE = (1U << 10);
static const Bit32u BX_POLY_CPUID_STATE_XSAVE_ARCH_CONTRACT = (1U << 11);
static const Bit32u BX_POLY_CPUID_STATE_IMPORT_RETURN_XSAVE = (1U << 12);
static const Bit32u BX_POLY_CPUID_STATE_ABI_SIGNATURE_XSAVE = (1U << 13);
static const Bit32u BX_POLY_CPUID_STATE_MONITOR_PACKET_XSAVE = (1U << 14);
static const Bit32u BX_POLY_CPUID_STATE_CROSS_RETURN_XSAVE = (1U << 15);
static const Bit32u BX_POLY_CPUID_STATE_FRONTEND_TLS_XSAVE = (1U << 16);
static const Bit32u BX_POLY_CPUID_STATE_LANDING_POLICY_XSAVE = (1U << 17);
static const Bit32u BX_POLY_STATE_XSAVE_MAGIC = 0x31594c50; // "PLY1"
static const Bit32u BX_POLY_STATE_XSAVE_COMPONENT_ARCH = 20;
static const Bit32u BX_POLY_STATE_XSAVE_BYTES_ARCH = 4096;
static const Bit32u BX_POLY_STATE_XSAVE_ALIGN_ARCH = 64;
static const Bit32u BX_POLY_STATE_XSAVE_LAYOUT_VERSION = 8;
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_XCR0_USER = (1U << 0);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_OSXSAVE_REQUIRED = (1U << 1);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_INTERRUPT_RESUME = (1U << 2);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_TRAP_STATE = (1U << 3);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_NO_HIDDEN_BANKS = (1U << 4);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_IMPORT_RETURN = (1U << 5);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_ABI_SIGNATURES = (1U << 6);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_MONITOR_PACKET = (1U << 7);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_CROSS_RETURN = (1U << 8);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_FRONTEND_TLS = (1U << 9);
static const Bit32u BX_POLY_STATE_XSAVE_FLAG_LANDING_POLICY = (1U << 10);
static const Bit32u BX_POLY_STATE_XSAVE_HEADER_OFFSET = 0x000;
static const Bit32u BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET = 0x040;
static const Bit32u BX_POLY_STATE_XSAVE_TRAP_ARGS_OFFSET = 0x080;
static const Bit32u BX_POLY_STATE_XSAVE_TRANSITION_OFFSET = 0x0c0;
static const Bit32u BX_POLY_STATE_XSAVE_AARCH64_GPR_OFFSET = 0x100;
static const Bit32u BX_POLY_STATE_XSAVE_AARCH64_FP_OFFSET = 0x200;
static const Bit32u BX_POLY_STATE_XSAVE_AARCH64_STATUS_OFFSET = 0x400;
static const Bit32u BX_POLY_STATE_XSAVE_RISCV_GPR_OFFSET = 0x480;
static const Bit32u BX_POLY_STATE_XSAVE_RISCV_FP_OFFSET = 0x580;
static const Bit32u BX_POLY_STATE_XSAVE_RISCV_STATUS_OFFSET = 0x780;
static const Bit32u BX_POLY_STATE_XSAVE_IMPORT_RETURN_OFFSET = 0x800;
static const Bit32u BX_POLY_STATE_XSAVE_IMPORT_RETURN_DEPTH_OFFSET =
  BX_POLY_STATE_XSAVE_IMPORT_RETURN_OFFSET + 8;
static const Bit32u BX_POLY_STATE_XSAVE_IMPORT_RETURN_FRAMES_OFFSET =
  BX_POLY_STATE_XSAVE_IMPORT_RETURN_OFFSET + 16;
static const Bit32u BX_POLY_STATE_XSAVE_IMPORT_RETURN_FRAME_BYTES = 0x80;
static const Bit32u BX_POLY_STATE_XSAVE_ABI_SIGNATURE_OFFSET = 0xd00;
static const Bit32u BX_POLY_STATE_XSAVE_ABI_SIGNATURE_COUNT_OFFSET =
  BX_POLY_STATE_XSAVE_ABI_SIGNATURE_OFFSET;
static const Bit32u BX_POLY_STATE_XSAVE_ABI_SIGNATURE_SLOTS_OFFSET =
  BX_POLY_STATE_XSAVE_ABI_SIGNATURE_OFFSET + 16;
static const Bit32u BX_POLY_STATE_XSAVE_ABI_SIGNATURE_BYTES = 0x80;
static const Bit32u BX_POLY_STATE_XSAVE_CROSS_RETURN_OFFSET = 0xd80;
static const Bit32u BX_POLY_STATE_XSAVE_CROSS_RETURN_DEPTH_OFFSET =
  BX_POLY_STATE_XSAVE_CROSS_RETURN_OFFSET + 8;
static const Bit32u BX_POLY_STATE_XSAVE_CROSS_RETURN_FRAMES_OFFSET =
  BX_POLY_STATE_XSAVE_CROSS_RETURN_OFFSET + 16;
static const Bit32u BX_POLY_STATE_XSAVE_CROSS_RETURN_FRAME_BYTES = 0x20;
static const Bit32u BX_POLY_STATE_XSAVE_FRONTEND_TLS_OFFSET = 0xea0;
static const Bit32u BX_POLY_STATE_XSAVE_FRONTEND_TLS_BYTES = 0x40;
static const Bit32u BX_POLY_STATE_XSAVE_LANDING_POLICY_OFFSET = 0xee0;
static const Bit32u BX_POLY_STATE_XSAVE_LANDING_POLICY_BYTES = 0x40;
static const Bit32u BX_POLY_TRAP_PACKET_LAYOUT_VERSION = 2;
static const Bit32u BX_POLY_TRAP_PACKET_HEADER_BYTES = 64;
static const Bit32u BX_POLY_TRAP_PACKET_ARG_COUNT = 8;
static const Bit32u BX_POLY_TRAP_PACKET_FLAG_VECTOR_DELIVERY = (1U << 0);
static const Bit32u BX_POLY_TRAP_PACKET_FLAG_NO_VECTOR_X86_EXCEPTIONS = (1U << 1);
static const Bit32u BX_POLY_TRAP_PACKET_FLAG_TRAP_RETURN_RESTORE = (1U << 2);
static const Bit32u BX_POLY_TRAP_PACKET_FLAG_ALL_FRONTEND_HANDLERS = (1U << 3);
static const Bit32u BX_POLY_TRAP_PACKET_FLAG_STATUS_OPS = (1U << 4);
static const Bit32u BX_POLY_TRAP_PACKET_FLAG_MONITOR_MEMORY = (1U << 5);
static const Bit32u BX_POLY_INTERRUPT_ABI_VERSION = 1;
static const Bit32u BX_POLY_INTERRUPT_FLAG_RAW_CPL3_ONLY = (1U << 0);
static const Bit32u BX_POLY_INTERRUPT_FLAG_STANDARD_X86_ENTRY = (1U << 1);
static const Bit32u BX_POLY_INTERRUPT_FLAG_STATE_COMPONENT_SAVE = (1U << 2);
static const Bit32u BX_POLY_INTERRUPT_FLAG_PRECISE_FOREIGN_PC = (1U << 3);
static const Bit32u BX_POLY_INTERRUPT_FLAG_EVENT_CHECK_BETWEEN_INSNS = (1U << 4);
static const Bit32u BX_POLY_INTERRUPT_RETURN_IRET64 = (1U << 0);
static const Bit32u BX_POLY_INTERRUPT_RETURN_SYSRET = (1U << 1);
static const Bit32u BX_POLY_INTERRUPT_RETURN_SYSEXIT = (1U << 2);
static const Bit32u BX_POLY_INTERRUPT_RETURN_SIGNAL = (1U << 3);
static const Bit32u BX_POLY_MEMORY_ABI_VERSION = 1;
static const Bit32u BX_POLY_MEMORY_MODEL_X86_TSO = 1;
static const Bit32u BX_POLY_MEMORY_FLAG_SHARED_X86_MEMORY = (1U << 0);
static const Bit32u BX_POLY_MEMORY_FLAG_AARCH64_BARRIERS_NOOP = (1U << 1);
static const Bit32u BX_POLY_MEMORY_FLAG_RISCV_FENCES_NOOP = (1U << 2);
static const Bit32u BX_POLY_MEMORY_FLAG_ATOMICS_COHERENT = (1U << 3);
static const Bit32u BX_POLY_MEMORY_FLAG_NO_WEAK_REORDERING = (1U << 4);
static const Bit32u BX_POLY_TRANSITION_ABI_VERSION = 1;
static const Bit32u BX_POLY_TRANSITION_FLAG_DECODED_X86_OPCODES = (1U << 0);
static const Bit32u BX_POLY_TRANSITION_FLAG_NATIVE_RAW_ESCAPES = (1U << 1);
static const Bit32u BX_POLY_TRANSITION_FLAG_PIPELINE_FLUSH = (1U << 2);
static const Bit32u BX_POLY_TRANSITION_FLAG_BLOCK_BOUNDARY = (1U << 3);
static const Bit32u BX_POLY_TRANSITION_FLAG_PRECISE_NEXT_PC = (1U << 4);
static const Bit32u BX_POLY_TRANSITION_FLAG_FIXED_RAW_WIDTH = (1U << 5);
static const Bit32u BX_POLY_TRANSITION_FLAG_NEUTRAL_FOREIGN = (1U << 6);
static const Bit32u BX_POLY_TRANSITION_FLAG_NATIVE_RETURN_COOKIE = (1U << 7);
static const Bit32u BX_POLY_TRANSITION_FLAG_TRAP_RETURN = (1U << 8);
static const Bit32u BX_POLY_TRANSITION_FLAG_INTERRUPTED_RAW = (1U << 9);
static const Bit32u BX_POLY_TRANSITION_FLAG_LANDING_PADS = (1U << 10);
static const Bit32u BX_POLY_TRANSITION_FLAG_LANDING_POLICY = (1U << 11);
static const Bit64u BX_POLY_LANDING_POLICY_REQUIRE_SWITCH = (1ULL << 0);
static const Bit64u BX_POLY_LANDING_POLICY_REQUIRE_CALL = (1ULL << 1);
static const Bit64u BX_POLY_LANDING_POLICY_SUPPORTED =
  BX_POLY_LANDING_POLICY_REQUIRE_SWITCH |
  BX_POLY_LANDING_POLICY_REQUIRE_CALL;
static const Bit32u BX_POLY_TRANSITION_AARCH64_ALIGN = 4;
static const Bit32u BX_POLY_TRANSITION_RISCV_ALIGN = 2;
static const Bit32u BX_POLY_ABI_BRIDGE_ABI_VERSION = 1;
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_X86_SYSV_TO_AAPCS64 = (1U << 0);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_X86_SYSV_TO_RISCV = (1U << 1);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_SRET = (1U << 2);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_SCALAR_FP = (1U << 3);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_FOCUSED_AGGREGATES = (1U << 4);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_FP64_STACK = (1U << 5);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_TLS_BASE = (1U << 7);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_USER_DESCRIPTORS = (1U << 8);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_NO_CPU_HELPER_FALLBACK = (1U << 9);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_ORDINARY_X86_RET = (1U << 10);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_VEC128 = (1U << 11);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_REGISTER_SIGNATURES = (1U << 12);
static const Bit32u BX_POLY_ABI_BRIDGE_FLAG_NATIVE_I128_SIGNATURES = (1U << 13);
static const Bit32u BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT = 8;
static const Bit32u BX_POLY_ABI_BRIDGE_FP_ARG_COUNT = 8;
static const Bit32u BX_POLY_ABI_BRIDGE_STACK_ALIGN = 16;
static const Bit32u BX_POLY_ABI_SIGNATURE_SLOT_COUNT = 8;
static const Bit32u BX_POLY_ABI_SIGNATURE_SLOT_EXCHANGE = 0;
static const Bit32u BX_POLY_ABI_SIGNATURE_SLOT_X86_SYSV_REGS = 1;
static const Bit32u BX_POLY_ABI_SIGNATURE_SLOT_X86_SYSV_REGS_I128 = 2;
static const Bit32u BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS = 3;
static const Bit32u BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS_I128 = 4;
static const Bit32u BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS_VEC128_U32 = 5;
static const Bit32u BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE = 0;
// Kind 1 is reserved for the removed stack-capable SysV signature. Real
// signature slots are register-only; memory-side ABI work belongs in thunks.
static const Bit32u BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV = 1;
static const Bit32u BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS = 2;
static const Bit32u BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS_I128 = 3;
static const Bit32u BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS = 4;
static const Bit32u BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_I128 = 5;
static const Bit32u BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_VEC128_U32 = 6;
static const Bit32u BX_POLY_X86_CTRL_PCALL_SIG_IMM_MODE = 0x2e;
static const Bit32u BX_POLY_X86_CTRL_LANDING_POLICY_SET = 0x6d;
static const Bit32u BX_POLY_X86_CTRL_LANDING_POLICY_GET = 0x6e;

static bool bx_poly_aarch64_ctrl_slot(Bit32u insn, Bit32u base_subop,
    Bit32u *slot)
{
  if ((insn & ~(0x7fU << 5)) != 0xd503201fU)
    return false;
  Bit32u subop = (insn >> 5) & 0x7fU;
  if (subop < base_subop ||
      subop >= base_subop + BX_POLY_ABI_SIGNATURE_SLOT_COUNT)
    return false;
  *slot = subop - base_subop;
  return true;
}

static bool bx_poly_riscv_ctrl_slot(Bit32u insn, Bit32u base_subop,
    Bit32u *slot)
{
  if ((insn & 0x01ffffffU) != 0x0000700bU)
    return false;
  Bit32u subop = (insn >> 25) & 0x7fU;
  if (subop < base_subop ||
      subop >= base_subop + BX_POLY_ABI_SIGNATURE_SLOT_COUNT)
    return false;
  *slot = subop - base_subop;
  return true;
}

static const Bit64u BX_POLY_RETURN_COOKIE = BX_CONST64(0xfffffffffffff000);
static const Bit64u BX_POLY_CROSS_RETURN_COOKIE = BX_CONST64(0xffffffffffffd000);
static const Bit64u BX_POLY_IMPORT_CALL_BASE = BX_CONST64(0xffffffffffffe000);
static const Bit64u BX_POLY_IMPORT_CALL_STRIDE = BX_CONST64(0x10);
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_STACK_ARGS = BX_CONST64(1) << 0;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_I128 = BX_CONST64(1) << 1;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FP128 = BX_CONST64(1) << 2;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_STACK_FROM_MEMORY = BX_CONST64(1) << 3;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_STACK_FROM_GPR0 = BX_CONST64(1) << 4;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FPAIR64 = BX_CONST64(1) << 5;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FPAIR32 = BX_CONST64(1) << 6;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_VEC128 = BX_CONST64(1) << 7;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_VEC128_FROM_GPR_PAIRS = BX_CONST64(1) << 8;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_AARCH64_SRET_X8 = BX_CONST64(1) << 9;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FP64 = BX_CONST64(1) << 10;
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FP32 = BX_CONST64(1) << 11;
static const Bit32u BX_POLY_IMPORT_CALL_COUNT = 233;
static const Bit64u BX_POLY_DIRECT_X86_IMPORT_ID = BX_CONST64(0xffffffffffffffff);
static const Bit32u BX_POLY_IMPORT_X86_STACK_ARG_QWORDS_MAX = 8;
// Keep suspended x86 helper frames and active foreign frames from colliding
// when libc helpers use deep stack frames beneath the x86 return cookie.
static const Bit64u BX_POLY_FOREIGN_STACK_GAP = BX_CONST64(0x4000);
static const Bit32u BX_POLY_FOREIGN_STACK_ARG_QWORDS = 8;

enum {
  BX_POLY_RETURN_KIND_DEFAULT = 0,
  BX_POLY_RETURN_KIND_FPAIR32 = 1,
  BX_POLY_RETURN_KIND_HETERO_U64_F64 = 2,
  BX_POLY_RETURN_KIND_HETERO_F64_U64 = 3,
  BX_POLY_RETURN_KIND_HETERO_U64_F32 = 4,
  BX_POLY_RETURN_KIND_HETERO_F32_U64 = 5,
  BX_POLY_RETURN_KIND_COMPACT_U32_F32 = 6,
  BX_POLY_RETURN_KIND_COMPACT_F32_U32 = 7,
  BX_POLY_RETURN_KIND_VEC128_U32 = 8,
  BX_POLY_RETURN_KIND_AARCH64_HFA3_F64 = 9,
  BX_POLY_RETURN_KIND_AARCH64_HFA4_F64 = 10,
  BX_POLY_RETURN_KIND_AARCH64_HFA3_F32 = 11,
  BX_POLY_RETURN_KIND_AARCH64_HFA4_F32 = 12
};

enum {
  BX_POLY_ARG_KIND_DEFAULT = 0,
  BX_POLY_ARG_KIND_FPAIR32 = 1,
  BX_POLY_ARG_KIND_HETERO_U64_F64 = 2,
  BX_POLY_ARG_KIND_HETERO_F64_U64 = 3,
  BX_POLY_ARG_KIND_HETERO_U64_F32 = 4,
  BX_POLY_ARG_KIND_HETERO_F32_U64 = 5,
  BX_POLY_ARG_KIND_COMPACT_U32_F32 = 6,
  BX_POLY_ARG_KIND_COMPACT_F32_U32 = 7,
  BX_POLY_ARG_KIND_FP64_STACK = 8,
  BX_POLY_ARG_KIND_VEC128_U32 = 9,
  BX_POLY_ARG_KIND_AARCH64_HFA3_F64 = 10,
  BX_POLY_ARG_KIND_AARCH64_HFA4_F64 = 11,
  BX_POLY_ARG_KIND_AARCH64_HFA3_F32 = 12,
  BX_POLY_ARG_KIND_AARCH64_HFA4_F32 = 13
};

enum {
  BX_POLY_CROSS_BRIDGE_DEFAULT = 0,
  BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 = 1,
  BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32 = 2,
  BX_POLY_CROSS_BRIDGE_FP64_STACK = 3,
  BX_POLY_CROSS_BRIDGE_VEC128_U32 = 4
};

enum {
  BX_POLY_IMPORT_FUNC_ADD = 0,
  BX_POLY_IMPORT_FUNC_MUL = 1,
  BX_POLY_IMPORT_FUNC_RESERVED_LEGACY_X86_ADD = 2,
  BX_POLY_IMPORT_FUNC_FP64_ADD = 3,
  BX_POLY_IMPORT_FUNC_AARCH64_LDADD8_ACQ_REL = 4,
  BX_POLY_IMPORT_FUNC_AARCH64_SWP8_ACQ_REL = 5,
  BX_POLY_IMPORT_FUNC_AARCH64_LDSET4_RELAX = 6,
  BX_POLY_IMPORT_FUNC_AARCH64_CAS8_ACQ_REL = 7,
  BX_POLY_IMPORT_FUNC_STRLEN = 8,
  BX_POLY_IMPORT_FUNC_MEMCPY = 9,
  BX_POLY_IMPORT_FUNC_MEMSET = 10,
  BX_POLY_IMPORT_FUNC_MEMCMP = 11,
  BX_POLY_IMPORT_FUNC_AARCH64_TLSDESC = 12,
  BX_POLY_IMPORT_FUNC_RISCV_TLS_GET_ADDR = 13,
  BX_POLY_IMPORT_FUNC_FP32_ADD = 14,
  BX_POLY_IMPORT_FUNC_MEMMOVE = 15,
  BX_POLY_IMPORT_FUNC_STRCMP = 16,
  BX_POLY_IMPORT_FUNC_STRNCMP = 17,
  BX_POLY_IMPORT_FUNC_MEMCHR = 18,
  BX_POLY_IMPORT_FUNC_STRCHR = 19,
  BX_POLY_IMPORT_FUNC_STRRCHR = 20,
  BX_POLY_IMPORT_FUNC_STRSTR = 21,
  BX_POLY_IMPORT_FUNC_STRCPY = 22,
  BX_POLY_IMPORT_FUNC_STRNCPY = 23,
  BX_POLY_IMPORT_FUNC_STRNLEN = 24,
  BX_POLY_IMPORT_FUNC_STRCAT = 25,
  BX_POLY_IMPORT_FUNC_STRNCAT = 26,
  BX_POLY_IMPORT_FUNC_STRSPN = 27,
  BX_POLY_IMPORT_FUNC_STRCSPN = 28,
  BX_POLY_IMPORT_FUNC_STRPBRK = 29,
  BX_POLY_IMPORT_FUNC_STPCPY = 30,
  BX_POLY_IMPORT_FUNC_STPNCPY = 31,
  BX_POLY_IMPORT_FUNC_MEMPCPY = 32,
  BX_POLY_IMPORT_FUNC_RAWMEMCHR = 33,
  BX_POLY_IMPORT_FUNC_STRCHRNUL = 34,
  BX_POLY_IMPORT_FUNC_BCMP = 35,
  BX_POLY_IMPORT_FUNC_BCOPY = 36,
  BX_POLY_IMPORT_FUNC_BZERO = 37,
  BX_POLY_IMPORT_FUNC_MEMRCHR = 38,
  BX_POLY_IMPORT_FUNC_MEMMEM = 39,
  BX_POLY_IMPORT_FUNC_STRCASECMP = 40,
  BX_POLY_IMPORT_FUNC_STRNCASECMP = 41,
  BX_POLY_IMPORT_FUNC_STRCASESTR = 42,
  BX_POLY_IMPORT_FUNC_AARCH64_CAS4_ACQ_REL = 43,
  BX_POLY_IMPORT_FUNC_AARCH64_LDADD4_ACQ_REL = 44,
  BX_POLY_IMPORT_FUNC_AARCH64_SWP4_ACQ_REL = 45,
  BX_POLY_IMPORT_FUNC_AARCH64_LDCLR8_ACQ_REL = 46,
  BX_POLY_IMPORT_FUNC_AARCH64_LDEOR8_ACQ_REL = 47,
  BX_POLY_IMPORT_FUNC_AARCH64_LDCLR4_ACQ_REL = 48,
  BX_POLY_IMPORT_FUNC_AARCH64_LDEOR4_ACQ_REL = 49,
  BX_POLY_IMPORT_FUNC_AARCH64_LDSET8_ACQ_REL = 50,
  BX_POLY_IMPORT_FUNC_AARCH64_LDSET4_ACQ_REL = 51,
  BX_POLY_IMPORT_FUNC_AARCH64_LDADD2_ACQ_REL = 52,
  BX_POLY_IMPORT_FUNC_AARCH64_LDADD1_ACQ_REL = 53,
  BX_POLY_IMPORT_FUNC_AARCH64_SWP2_ACQ_REL = 54,
  BX_POLY_IMPORT_FUNC_AARCH64_SWP1_ACQ_REL = 55,
  BX_POLY_IMPORT_FUNC_AARCH64_LDCLR2_ACQ_REL = 56,
  BX_POLY_IMPORT_FUNC_AARCH64_LDCLR1_ACQ_REL = 57,
  BX_POLY_IMPORT_FUNC_AARCH64_LDEOR2_ACQ_REL = 58,
  BX_POLY_IMPORT_FUNC_AARCH64_LDEOR1_ACQ_REL = 59,
  BX_POLY_IMPORT_FUNC_AARCH64_LDSET2_ACQ_REL = 60,
  BX_POLY_IMPORT_FUNC_AARCH64_LDSET1_ACQ_REL = 61,
  BX_POLY_IMPORT_FUNC_AARCH64_CAS2_ACQ_REL = 62,
  BX_POLY_IMPORT_FUNC_AARCH64_CAS1_ACQ_REL = 63,
  BX_POLY_IMPORT_FUNC_ATOMIC_COMPARE_EXCHANGE_16 = 64,
  BX_POLY_IMPORT_FUNC_ATOMIC_LOAD_16 = 65,
  BX_POLY_IMPORT_FUNC_ATOMIC_STORE_16 = 66,
  BX_POLY_IMPORT_FUNC_UDIVTI3 = 67,
  BX_POLY_IMPORT_FUNC_UMODTI3 = 68,
  BX_POLY_IMPORT_FUNC_DIVTI3 = 69,
  BX_POLY_IMPORT_FUNC_MODTI3 = 70,
  BX_POLY_IMPORT_FUNC_FIXDFTI = 71,
  BX_POLY_IMPORT_FUNC_FIXUNSDFTI = 72,
  BX_POLY_IMPORT_FUNC_FLOATTIDF = 73,
  BX_POLY_IMPORT_FUNC_FLOATUNTIDF = 74,
  BX_POLY_IMPORT_FUNC_FIXSFTI = 75,
  BX_POLY_IMPORT_FUNC_FIXUNSSFTI = 76,
  BX_POLY_IMPORT_FUNC_FLOATTISF = 77,
  BX_POLY_IMPORT_FUNC_FLOATUNTISF = 78,
  BX_POLY_IMPORT_FUNC_CLZDI2 = 79,
  BX_POLY_IMPORT_FUNC_CTZDI2 = 80,
  BX_POLY_IMPORT_FUNC_PARITYDI2 = 81,
  BX_POLY_IMPORT_FUNC_POPCOUNTDI2 = 82,
  BX_POLY_IMPORT_FUNC_ADDTF3 = 83,
  BX_POLY_IMPORT_FUNC_SUBTF3 = 84,
  BX_POLY_IMPORT_FUNC_MULTF3 = 85,
  BX_POLY_IMPORT_FUNC_DIVTF3 = 86,
  BX_POLY_IMPORT_FUNC_FLOATUNDITF = 87,
  BX_POLY_IMPORT_FUNC_FIXUNSTFDI = 88,
  BX_POLY_IMPORT_FUNC_FLOATDITF = 89,
  BX_POLY_IMPORT_FUNC_FLOATSITF = 90,
  BX_POLY_IMPORT_FUNC_FIXTFDI = 91,
  BX_POLY_IMPORT_FUNC_EQTF2 = 92,
  BX_POLY_IMPORT_FUNC_LTTF2 = 93,
  BX_POLY_IMPORT_FUNC_LETF2 = 94,
  BX_POLY_IMPORT_FUNC_GTTF2 = 95,
  BX_POLY_IMPORT_FUNC_GETF2 = 96,
  BX_POLY_IMPORT_FUNC_EXTENDSFTF2 = 97,
  BX_POLY_IMPORT_FUNC_EXTENDDFTF2 = 98,
  BX_POLY_IMPORT_FUNC_TRUNCTFSF2 = 99,
  BX_POLY_IMPORT_FUNC_TRUNCTFDF2 = 100,
  BX_POLY_IMPORT_FUNC_NETF2 = 101,
  BX_POLY_IMPORT_FUNC_UNORDTF2 = 102,
  BX_POLY_IMPORT_FUNC_FLOATUNSITF = 103,
  BX_POLY_IMPORT_FUNC_FIXTFSI = 104,
  BX_POLY_IMPORT_FUNC_FIXUNSTFSI = 105,
  BX_POLY_IMPORT_FUNC_X86_SLOT0 = 106,
  BX_POLY_IMPORT_FUNC_X86_SLOT1 = 107,
  BX_POLY_IMPORT_FUNC_X86_SLOT2 = 108,
  BX_POLY_IMPORT_FUNC_X86_SLOT3 = 109,
  BX_POLY_IMPORT_FUNC_X86_SLOT4 = 110,
  BX_POLY_IMPORT_FUNC_X86_SLOT5 = 111,
  BX_POLY_IMPORT_FUNC_X86_SLOT6 = 112,
  BX_POLY_IMPORT_FUNC_X86_SLOT7 = 113,
  BX_POLY_IMPORT_FUNC_STACK_CHK_FAIL = 114,
  BX_POLY_IMPORT_FUNC_ERRNO_LOCATION = 115,
  BX_POLY_IMPORT_FUNC_GETAUXVAL = 116,
  BX_POLY_IMPORT_FUNC_GETPAGESIZE = 117,
  BX_POLY_IMPORT_FUNC_SYSCONF = 118,
  BX_POLY_IMPORT_FUNC_GETENV = 119,
  BX_POLY_IMPORT_FUNC_SECURE_GETENV = 120,
  BX_POLY_IMPORT_FUNC_MALLOC = 121,
  BX_POLY_IMPORT_FUNC_CALLOC = 122,
  BX_POLY_IMPORT_FUNC_REALLOC = 123,
  BX_POLY_IMPORT_FUNC_FREE = 124,
  BX_POLY_IMPORT_FUNC_STRDUP = 125,
  BX_POLY_IMPORT_FUNC_STRNDUP = 126,
  BX_POLY_IMPORT_FUNC_POSIX_MEMALIGN = 127,
  BX_POLY_IMPORT_FUNC_ALIGNED_ALLOC = 128,
  BX_POLY_IMPORT_FUNC_MEMALIGN = 129,
  BX_POLY_IMPORT_FUNC_ATEXIT = 130,
  BX_POLY_IMPORT_FUNC_CXA_ATEXIT = 131,
  BX_POLY_IMPORT_FUNC_CXA_FINALIZE = 132,
  BX_POLY_IMPORT_FUNC_GETPID = 133,
  BX_POLY_IMPORT_FUNC_GETPPID = 134,
  BX_POLY_IMPORT_FUNC_GETUID = 135,
  BX_POLY_IMPORT_FUNC_GETEUID = 136,
  BX_POLY_IMPORT_FUNC_GETGID = 137,
  BX_POLY_IMPORT_FUNC_GETEGID = 138,
  BX_POLY_IMPORT_FUNC_GETTID = 139,
  BX_POLY_IMPORT_FUNC_PUTS = 140,
  BX_POLY_IMPORT_FUNC_CXA_GUARD_ACQUIRE = 141,
  BX_POLY_IMPORT_FUNC_CXA_GUARD_RELEASE = 142,
  BX_POLY_IMPORT_FUNC_CXA_GUARD_ABORT = 143,
  BX_POLY_IMPORT_FUNC_X86_SUM10 = 144,
  BX_POLY_IMPORT_FUNC_X86_FP64_SUM10 = 145,
  BX_POLY_IMPORT_FUNC_X86_FPAIR64 = 146,
  BX_POLY_IMPORT_FUNC_X86_FPAIR32 = 147,
  BX_POLY_IMPORT_FUNC_X86_VEC128_U32 = 148,
  BX_POLY_IMPORT_FUNC_X86_SRET_U64 = 149,
  BX_POLY_IMPORT_FUNC_X86_SRET_U64_STACK = 150,
  BX_POLY_IMPORT_FUNC_X86_SRET_U64_STACK10 = 151,
  BX_POLY_IMPORT_FUNC_X86_SUM14 = 152,
  BX_POLY_IMPORT_FUNC_X86_ALIGN14 = 153,
  BX_POLY_IMPORT_FUNC_X86_I128 = 154,
  BX_POLY_IMPORT_FUNC_QSORT = 155,
  BX_POLY_IMPORT_FUNC_BSEARCH = 156,
  BX_POLY_IMPORT_FUNC_QSORT_R = 157,
  BX_POLY_IMPORT_FUNC_PTHREAD_ONCE = 158,
  BX_POLY_IMPORT_FUNC_PTHREAD_KEY_CREATE = 159,
  BX_POLY_IMPORT_FUNC_PTHREAD_KEY_DELETE = 160,
  BX_POLY_IMPORT_FUNC_PTHREAD_GETSPECIFIC = 161,
  BX_POLY_IMPORT_FUNC_PTHREAD_SETSPECIFIC = 162,
  BX_POLY_IMPORT_FUNC_PTHREAD_MUTEX_INIT = 163,
  BX_POLY_IMPORT_FUNC_PTHREAD_MUTEX_DESTROY = 164,
  BX_POLY_IMPORT_FUNC_PTHREAD_MUTEX_LOCK = 165,
  BX_POLY_IMPORT_FUNC_PTHREAD_MUTEX_TRYLOCK = 166,
  BX_POLY_IMPORT_FUNC_PTHREAD_MUTEX_UNLOCK = 167,
  BX_POLY_IMPORT_FUNC_PTHREAD_SELF = 168,
  BX_POLY_IMPORT_FUNC_PTHREAD_EQUAL = 169,
  BX_POLY_IMPORT_FUNC_PTHREAD_RWLOCK_INIT = 170,
  BX_POLY_IMPORT_FUNC_PTHREAD_RWLOCK_DESTROY = 171,
  BX_POLY_IMPORT_FUNC_PTHREAD_RWLOCK_RDLOCK = 172,
  BX_POLY_IMPORT_FUNC_PTHREAD_RWLOCK_TRYRDLOCK = 173,
  BX_POLY_IMPORT_FUNC_PTHREAD_RWLOCK_WRLOCK = 174,
  BX_POLY_IMPORT_FUNC_PTHREAD_RWLOCK_TRYWRLOCK = 175,
  BX_POLY_IMPORT_FUNC_PTHREAD_RWLOCK_UNLOCK = 176,
  BX_POLY_IMPORT_FUNC_PTHREAD_MUTEXATTR_INIT = 177,
  BX_POLY_IMPORT_FUNC_PTHREAD_MUTEXATTR_DESTROY = 178,
  BX_POLY_IMPORT_FUNC_PTHREAD_MUTEXATTR_SETTYPE = 179,
  BX_POLY_IMPORT_FUNC_PTHREAD_MUTEXATTR_GETTYPE = 180,
  BX_POLY_IMPORT_FUNC_PTHREAD_SPIN_INIT = 181,
  BX_POLY_IMPORT_FUNC_PTHREAD_SPIN_DESTROY = 182,
  BX_POLY_IMPORT_FUNC_PTHREAD_SPIN_LOCK = 183,
  BX_POLY_IMPORT_FUNC_PTHREAD_SPIN_TRYLOCK = 184,
  BX_POLY_IMPORT_FUNC_PTHREAD_SPIN_UNLOCK = 185,
  BX_POLY_IMPORT_FUNC_PTHREAD_COND_INIT = 186,
  BX_POLY_IMPORT_FUNC_PTHREAD_COND_DESTROY = 187,
  BX_POLY_IMPORT_FUNC_PTHREAD_COND_SIGNAL = 188,
  BX_POLY_IMPORT_FUNC_PTHREAD_COND_BROADCAST = 189,
  BX_POLY_IMPORT_FUNC_CLOCK_GETTIME = 190,
  BX_POLY_IMPORT_FUNC_CLOCK_GETRES = 191,
  BX_POLY_IMPORT_FUNC_TIME = 192,
  BX_POLY_IMPORT_FUNC_GETTIMEOFDAY = 193,
  BX_POLY_IMPORT_FUNC_CLOCK = 194,
  BX_POLY_IMPORT_FUNC_ATOI = 195,
  BX_POLY_IMPORT_FUNC_STRTOL = 196,
  BX_POLY_IMPORT_FUNC_STRTOUL = 197,
  BX_POLY_IMPORT_FUNC_STRTOLL = 198,
  BX_POLY_IMPORT_FUNC_STRTOULL = 199,
  BX_POLY_IMPORT_FUNC_SNPRINTF = 200,
  BX_POLY_IMPORT_FUNC_STRTOD = 201,
  BX_POLY_IMPORT_FUNC_STRTOF = 202,
  BX_POLY_IMPORT_FUNC_FABSF = 203,
  BX_POLY_IMPORT_FUNC_FABS = 204,
  BX_POLY_IMPORT_FUNC_SQRTF = 205,
  BX_POLY_IMPORT_FUNC_SQRT = 206,
  BX_POLY_IMPORT_FUNC_FLOORF = 207,
  BX_POLY_IMPORT_FUNC_FLOOR = 208,
  BX_POLY_IMPORT_FUNC_CEILF = 209,
  BX_POLY_IMPORT_FUNC_CEIL = 210,
  BX_POLY_IMPORT_FUNC_ISALNUM = 211,
  BX_POLY_IMPORT_FUNC_ISALPHA = 212,
  BX_POLY_IMPORT_FUNC_ISDIGIT = 213,
  BX_POLY_IMPORT_FUNC_ISLOWER = 214,
  BX_POLY_IMPORT_FUNC_ISSPACE = 215,
  BX_POLY_IMPORT_FUNC_ISUPPER = 216,
  BX_POLY_IMPORT_FUNC_ISXDIGIT = 217,
  BX_POLY_IMPORT_FUNC_ISBLANK = 218,
  BX_POLY_IMPORT_FUNC_ISCNTRL = 219,
  BX_POLY_IMPORT_FUNC_ISGRAPH = 220,
  BX_POLY_IMPORT_FUNC_ISPRINT = 221,
  BX_POLY_IMPORT_FUNC_ISPUNCT = 222,
  BX_POLY_IMPORT_FUNC_TOLOWER = 223,
  BX_POLY_IMPORT_FUNC_TOUPPER = 224,
  BX_POLY_IMPORT_FUNC_ABS = 225,
  BX_POLY_IMPORT_FUNC_LABS = 226,
  BX_POLY_IMPORT_FUNC_LLABS = 227,
  BX_POLY_IMPORT_FUNC_ATOL = 228,
  BX_POLY_IMPORT_FUNC_ATOLL = 229,
  BX_POLY_IMPORT_FUNC_FFS = 230,
  BX_POLY_IMPORT_FUNC_FFSL = 231,
  BX_POLY_IMPORT_FUNC_FFSLL = 232
};

static inline bool bx_poly_import_delivers_trap(Bit64u import_id)
{
  return import_id < BX_POLY_IMPORT_CALL_COUNT;
}

static Bit64u bx_poly_aarch64_size_mask(Bit32u size)
{
  return size == 8 ? BX_CONST64(0xffffffffffffffff) :
    ((BX_CONST64(1) << (size * 8)) - 1);
}

static const unsigned BX_POLY_REG_STATE_SLOTS = 64;
static const unsigned BX_POLY_RETURN_COOKIE_DEPTH = 8;
static const unsigned BX_POLY_CROSS_RETURN_DEPTH = 8;
static const unsigned BX_POLY_IMPORT_RETURN_DEPTH = 8;
static const unsigned BX_POLY_TRANSITION_FRAME_BYTES = 32;

struct bx_poly_cross_return_frame_t {
  bx_address return_rip;
  bx_address return_rsp;
  Bit32u caller_mode;
  Bit32u callee_mode;
  Bit32u bridge_kind;
  Bit32u flags;
};

typedef char bx_poly_cross_return_frame_must_be_32_bytes[
  sizeof(bx_poly_cross_return_frame_t) == BX_POLY_TRANSITION_FRAME_BYTES ? 1 : -1];

struct bx_poly_import_x86_return_frame_t {
  Bit32u mode;
  bx_address rip;
  bx_address rsp;
  Bit64u import_id;
  Bit64u return_flags;
  bool alias_valid;
  Bit64u alias[6];
};

struct bx_poly_return_cookie_frame_t {
  Bit32u mode;
  bx_address rip;
  bx_address rsp;
  bool sret;
  bx_address sret_ptr;
  Bit32u kind;
};

struct bx_poly_abi_signature_slot_t {
  Bit32u kind;
};

static void bx_poly_reset_abi_signature_slots(
    bx_poly_abi_signature_slot_t *slots)
{
  slots[0].kind = BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE;
  for (unsigned n = 1; n < BX_POLY_ABI_SIGNATURE_SLOT_COUNT; n++)
    slots[n].kind = BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE;
  slots[BX_POLY_ABI_SIGNATURE_SLOT_X86_SYSV_REGS].kind =
    BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS;
  slots[BX_POLY_ABI_SIGNATURE_SLOT_X86_SYSV_REGS_I128].kind =
    BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS_I128;
  slots[BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS].kind =
    BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS;
  slots[BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS_I128].kind =
    BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_I128;
  slots[BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS_VEC128_U32].kind =
    BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_VEC128_U32;
}

static Bit32u bx_poly_current_mode = BX_POLY_MODE_X86;
static bx_address bx_poly_raw_owner_cr3 = 0;
static bx_address bx_poly_raw_owner_fsbase = 0;
static bx_address bx_poly_raw_owner_stack_key = 0;
static Bit64u bx_poly_mode_switch_count = 0;
static Bit64u bx_poly_foreign_insn_count = 0;
static Bit64u bx_poly_foreign_syscall_count = 0;
static Bit64u bx_poly_foreign_break_count = 0;
static Bit32u bx_poly_last_syscall_mode = BX_POLY_MODE_X86;
static Bit32u bx_poly_last_syscall_number = 0;
static Bit32u bx_poly_last_break_mode = BX_POLY_MODE_X86;
static Bit32u bx_poly_last_break_number = 0;
static bx_poly_trap_packet bx_poly_last_trap = {
  BX_POLY_TRAP_NONE,
  BX_POLY_MODE_X86,
  0,
  0,
  0,
  0,
  { 0, 0, 0, 0, 0, 0 }
};
static bx_poly_trap_saved_regs bx_poly_trap_saved_regs = {
  false,
  BX_POLY_MODE_X86
};
static bool bx_poly_return_cookie_valid = false;
static Bit32u bx_poly_return_cookie_mode = BX_POLY_MODE_X86;
static bx_address bx_poly_return_cookie_rip = 0;
static bx_address bx_poly_return_cookie_rsp = 0;
static bool bx_poly_return_cookie_sret = false;
static bx_address bx_poly_return_cookie_sret_ptr = 0;
static Bit32u bx_poly_return_cookie_kind = BX_POLY_RETURN_KIND_DEFAULT;
static bx_poly_return_cookie_frame_t
  bx_poly_return_cookie_stack[BX_POLY_RETURN_COOKIE_DEPTH];
static unsigned bx_poly_return_cookie_top = 0;
static bx_poly_abi_signature_slot_t bx_poly_abi_signature_slots[
  BX_POLY_ABI_SIGNATURE_SLOT_COUNT] = {
  { BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE },
  { BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS },
  { BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS_I128 },
  { BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS },
  { BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_I128 },
  { BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_VEC128_U32 },
  { BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE },
  { BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE }
};
static bx_poly_cross_return_frame_t bx_poly_cross_return_stack[BX_POLY_CROSS_RETURN_DEPTH];
static unsigned bx_poly_cross_return_top = 0;
static bx_poly_import_x86_return_frame_t
  bx_poly_import_x86_return_stack[BX_POLY_IMPORT_RETURN_DEPTH];
static unsigned bx_poly_import_x86_return_top = 0;
static bool bx_poly_interrupted_raw_valid = false;
static Bit32u bx_poly_interrupted_raw_mode = BX_POLY_MODE_X86;
static bx_address bx_poly_interrupted_raw_rip = 0;
static bx_address bx_poly_aarch64_tls_base = 0;
static bx_address bx_poly_riscv_tls_base = 0;
static Bit64u bx_poly_landing_policy_flags = 0;
static bx_address bx_poly_trap_vector = 0;
static Bit32u bx_poly_trap_vector_mode = BX_POLY_MODE_X86;
static Bit64u bx_poly_aarch64_x[32];
static bool bx_poly_aarch64_x_valid[32];
static Bit64u bx_poly_aarch64_fp[32];
static Bit64u bx_poly_aarch64_fp_hi[32];
static Bit32u bx_poly_aarch64_nzcv = 0;
static bool bx_poly_aarch64_reservation_valid = false;
static bx_address bx_poly_aarch64_reservation_addr = 0;
static Bit32u bx_poly_aarch64_reservation_size = 0;
static Bit64u bx_poly_riscv_x[32];
static bool bx_poly_riscv_x_valid[32];
static Bit64u bx_poly_riscv_fp[32];
static Bit64u bx_poly_riscv_fp_hi[32];
static Bit32u bx_poly_riscv_fflags = 0;
static Bit32u bx_poly_riscv_frm = 0;
static bool bx_poly_riscv_reservation_valid = false;
static bx_address bx_poly_riscv_reservation_addr = 0;
static Bit32u bx_poly_riscv_reservation_size = 0;
static bx_address bx_poly_monitor_packet_addr = 0;

struct bx_poly_reg_state_t {
  bool valid;
  bx_address cr3;
  bx_address fsbase;
  bx_address stack_key;
  Bit64u age;
  Bit32u current_mode;
  bool return_cookie_valid;
  Bit32u return_cookie_mode;
  bx_address return_cookie_rip;
  bx_address return_cookie_rsp;
  bool return_cookie_sret;
  bx_address return_cookie_sret_ptr;
  Bit32u return_cookie_kind;
  bx_poly_return_cookie_frame_t
    return_cookie_stack[BX_POLY_RETURN_COOKIE_DEPTH];
  unsigned return_cookie_top;
  bx_poly_cross_return_frame_t cross_return_stack[BX_POLY_CROSS_RETURN_DEPTH];
  unsigned cross_return_top;
  bx_poly_import_x86_return_frame_t
    import_x86_return_stack[BX_POLY_IMPORT_RETURN_DEPTH];
  unsigned import_x86_return_top;
  bx_poly_abi_signature_slot_t abi_signature_slots[
    BX_POLY_ABI_SIGNATURE_SLOT_COUNT];
  bool interrupted_raw_valid;
  Bit32u interrupted_raw_mode;
  bx_address interrupted_raw_rip;
  bx_address aarch64_tls_base;
  bx_address riscv_tls_base;
  Bit64u landing_policy_flags;
  bx_address trap_vector;
  Bit32u trap_vector_mode;
  bx_address monitor_packet_addr;
  Bit32u last_syscall_mode;
  Bit32u last_syscall_number;
  Bit32u last_break_mode;
  Bit32u last_break_number;
  bx_poly_trap_packet last_trap;
  struct bx_poly_trap_saved_regs trap_saved_regs;
  Bit64u aarch64_x[32];
  bool aarch64_x_valid[32];
  Bit64u aarch64_fp[32];
  Bit64u aarch64_fp_hi[32];
  Bit32u aarch64_nzcv;
  bool aarch64_reservation_valid;
  bx_address aarch64_reservation_addr;
  Bit32u aarch64_reservation_size;
  Bit64u riscv_x[32];
  bool riscv_x_valid[32];
  Bit64u riscv_fp[32];
  Bit64u riscv_fp_hi[32];
  Bit32u riscv_fflags;
  Bit32u riscv_frm;
  bool riscv_reservation_valid;
  bx_address riscv_reservation_addr;
  Bit32u riscv_reservation_size;
};

struct bx_poly_thread_key_state_t {
  bool valid;
  bx_address cr3;
  bx_address fsbase;
  bx_address stack_key;
  Bit64u age;
};

static bx_address bx_poly_tls_base_for_mode(Bit32u mode)
{
  if (mode == BX_POLY_MODE_RAW_AARCH64)
    return bx_poly_aarch64_tls_base;
  if (mode == BX_POLY_MODE_RAW_RISCV)
    return bx_poly_riscv_tls_base;
  return 0;
}

static void bx_poly_set_tls_base_for_mode(Bit32u mode, bx_address value)
{
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    bx_poly_aarch64_tls_base = value;
    return;
  }
  if (mode == BX_POLY_MODE_RAW_RISCV) {
    bx_poly_riscv_tls_base = value;
    bx_poly_riscv_x[4] = value;
    bx_poly_riscv_x_valid[4] = true;
  }
}

static void bx_poly_set_runtime_tls_base(bx_address value)
{
  // ABI PCALL enters a loaded mixed-frontend program. The runtime's TLS block
  // is shared by that program's AArch64 and RISC-V objects; per-frontend
  // offsets are resolved by the loader before execution reaches hardware.
  bx_poly_set_tls_base_for_mode(BX_POLY_MODE_RAW_AARCH64, value);
  bx_poly_set_tls_base_for_mode(BX_POLY_MODE_RAW_RISCV, value);
}

static void bx_poly_capture_tls_base_for_mode(Bit32u mode)
{
  if (mode == BX_POLY_MODE_RAW_RISCV && bx_poly_riscv_x_valid[4])
    bx_poly_riscv_tls_base = bx_poly_riscv_x[4];
}

static void bx_poly_prepare_tls_for_mode(Bit32u mode)
{
  if (mode == BX_POLY_MODE_RAW_RISCV) {
    bx_poly_riscv_x[4] = bx_poly_riscv_tls_base;
    bx_poly_riscv_x_valid[4] = true;
  }
}

static bool bx_poly_valid_landing_policy(Bit64u policy)
{
  return (policy & ~BX_POLY_LANDING_POLICY_SUPPORTED) == 0;
}

bool BX_CPU_C::bx_poly_target_has_landing_pad(unsigned seg, bx_address target,
  Bit32u mode)
{
  if (mode == BX_POLY_MODE_X86) {
    return read_virtual_byte(seg, target) == 0x0f &&
      read_virtual_byte(seg, target + 1) == 0x3a &&
      read_virtual_byte(seg, target + 2) == 0xfc &&
      read_virtual_byte(seg, target + 3) == 0x05;
  }

  Bit32u marker = read_virtual_dword(seg, target);
  if (mode == BX_POLY_MODE_RAW_AARCH64)
    return marker == BX_POLY_AARCH64_CTRL_LANDING;
  if (mode == BX_POLY_MODE_RAW_RISCV)
    return marker == BX_POLY_RISCV_CTRL_LANDING;
  return false;
}

bool BX_CPU_C::bx_poly_require_landing_target(unsigned seg, bx_address target,
  Bit32u mode, Bit64u policy_bit, const char *op_name)
{
  if ((bx_poly_landing_policy_flags & policy_bit) == 0)
    return true;
  if (bx_poly_target_has_landing_pad(seg, target, mode))
    return true;

  BX_INFO(("poly_landing: reject %s mode=%u target=%llx policy=%llx",
    op_name, mode, (unsigned long long) target,
    (unsigned long long) bx_poly_landing_policy_flags));
  return false;
}

static bx_poly_reg_state_t bx_poly_reg_states[BX_POLY_REG_STATE_SLOTS];
static bx_poly_thread_key_state_t
  bx_poly_thread_key_states[BX_POLY_REG_STATE_SLOTS];
static bool bx_poly_loaded_reg_state_valid = false;
static bx_address bx_poly_loaded_reg_state_cr3 = 0;
static bx_address bx_poly_loaded_reg_state_fsbase = 0;
static bx_address bx_poly_loaded_reg_state_stack_key = 0;
static Bit64u bx_poly_reg_state_age = 1;

static double bx_poly_fp64_from_bits(Bit64u bits)
{
  union {
    Bit64u bits;
    double value;
  } fp;
  fp.bits = bits;
  return fp.value;
}

static Bit64u bx_poly_fp64_to_bits(double value)
{
  union {
    Bit64u bits;
    double value;
  } fp;
  fp.value = value;
  return fp.bits;
}

static float bx_poly_fp32_from_bits(Bit32u bits)
{
  union {
    Bit32u bits;
    float value;
  } fp;
  fp.bits = bits;
  return fp.value;
}

static Bit32u bx_poly_fp32_to_bits(float value)
{
  union {
    Bit32u bits;
    float value;
  } fp;
  fp.value = value;
  return fp.bits;
}

static Bit64u bx_poly_aarch64_expand_fp64_imm(Bit32u imm8)
{
  Bit64u sign = (Bit64u) (imm8 >> 7) << 63;
  Bit64u exp_bit = (imm8 >> 6) & 1;
  Bit64u exponent = ((exp_bit ^ 1) << 10) |
    (exp_bit ? 0x3fc : 0) | ((imm8 >> 4) & 0x3);
  Bit64u fraction = (Bit64u) (imm8 & 0xf) << 48;
  return sign | (exponent << 52) | fraction;
}

static Bit32u bx_poly_aarch64_expand_fp32_imm(Bit32u imm8)
{
  Bit32u sign = (imm8 >> 7) << 31;
  Bit32u exp_bit = (imm8 >> 6) & 1;
  Bit32u exponent = ((exp_bit ^ 1) << 7) |
    (exp_bit ? 0x7c : 0) | ((imm8 >> 4) & 0x3);
  Bit32u fraction = (imm8 & 0xf) << 19;
  return sign | (exponent << 23) | fraction;
}

static Bit32u bx_poly_riscv_softfloat_rounding_mode(Bit32u rm)
{
  if (rm == 7)
    rm = bx_poly_riscv_frm & 0x7;
  switch (rm) {
  case 0:
    return softfloat_round_near_even;
  case 1:
    return softfloat_round_to_zero;
  case 2:
    return softfloat_round_min;
  case 3:
    return softfloat_round_max;
  case 4:
    return softfloat_round_near_maxMag;
  default:
    return 0xff;
  }
}

static softfloat_status_t bx_poly_softfloat_status()
{
  softfloat_status_t status = {};
  Bit32u rm = (bx_poly_current_mode == BX_POLY_MODE_RAW_RISCV) ?
    bx_poly_riscv_softfloat_rounding_mode(7) : softfloat_round_near_even;
  status.softfloat_roundingMode = (rm == 0xff) ? softfloat_round_near_even : rm;
  status.softfloat_exceptionMasks = softfloat_all_exceptions_mask;
  status.extF80_roundingPrecision = 80;
  return status;
}

static Bit32u bx_poly_riscv_read_fp_csr(Bit32u csr)
{
  switch (csr) {
  case 0x001:
    return bx_poly_riscv_fflags & 0x1f;
  case 0x002:
    return bx_poly_riscv_frm & 0x7;
  case 0x003:
    return ((bx_poly_riscv_frm & 0x7) << 5) |
      (bx_poly_riscv_fflags & 0x1f);
  default:
    return 0;
  }
}

static bool bx_poly_riscv_write_fp_csr(Bit32u csr, Bit32u value)
{
  switch (csr) {
  case 0x001:
    bx_poly_riscv_fflags = value & 0x1f;
    return true;
  case 0x002:
    bx_poly_riscv_frm = value & 0x7;
    return true;
  case 0x003:
    bx_poly_riscv_fflags = value & 0x1f;
    bx_poly_riscv_frm = (value >> 5) & 0x7;
    return true;
  default:
    return false;
  }
}

static void bx_poly_riscv_accumulate_softfloat_fflags(
  const softfloat_status_t *status)
{
  int flags = softfloat_getExceptionFlags(status);
  if (flags & softfloat_flag_inexact)
    bx_poly_riscv_fflags |= 0x01;
  if (flags & softfloat_flag_underflow)
    bx_poly_riscv_fflags |= 0x02;
  if (flags & softfloat_flag_overflow)
    bx_poly_riscv_fflags |= 0x04;
  if (flags & softfloat_flag_divbyzero)
    bx_poly_riscv_fflags |= 0x08;
  if (flags & softfloat_flag_invalid)
    bx_poly_riscv_fflags |= 0x10;
}

static Bit64u bx_poly_fp64_to_uint64_rtz(double value)
{
  if (!(value > 0.0))
    return 0;
  if (value >= 18446744073709551616.0)
    return BX_CONST64(0xffffffffffffffff);
  return (Bit64u) value;
}

static Bit64u bx_poly_fp64_to_int64_rtz(double value)
{
  if (value != value)
    return 0;
  if (value >= 9223372036854775808.0)
    return (Bit64u) BX_MAX_BIT64S;
  if (value <= -9223372036854775808.0)
    return (Bit64u) BX_MIN_BIT64S;
  return (Bit64u) (Bit64s) value;
}

static Bit32u bx_poly_fp64_to_uint32_rtz(double value)
{
  if (!(value > 0.0))
    return 0;
  if (value >= 4294967296.0)
    return 0xffffffff;
  return (Bit32u) value;
}

static Bit64u bx_poly_fp64_to_int32_rtz(double value)
{
  if (value != value)
    return 0;
  if (value >= 2147483648.0)
    return (Bit64u) (Bit64s) (Bit32s) 0x7fffffff;
  if (value <= -2147483648.0)
    return (Bit64u) (Bit64s) (Bit32s) 0x80000000;
  return (Bit64u) (Bit64s) (Bit32s) value;
}

static Bit32u bx_poly_count_ones64(Bit64u value)
{
  Bit32u count = 0;
  while (value != 0) {
    count += (Bit32u) (value & 1);
    value >>= 1;
  }
  return count;
}

static Bit64u bx_poly_riscv_fclass32(Bit32u bits)
{
  Bit32u sign = bits >> 31;
  Bit32u exp = (bits >> 23) & 0xff;
  Bit32u frac = bits & 0x7fffff;
  if (exp == 0xff) {
    if (frac == 0)
      return sign ? 0x1 : 0x80;
    return (frac & 0x400000) ? 0x200 : 0x100;
  }
  if (exp == 0) {
    if (frac == 0)
      return sign ? 0x8 : 0x10;
    return sign ? 0x4 : 0x20;
  }
  return sign ? 0x2 : 0x40;
}

static Bit64u bx_poly_riscv_fclass64(Bit64u bits)
{
  Bit32u sign = (Bit32u) (bits >> 63);
  Bit64u exp = (bits >> 52) & 0x7ff;
  Bit64u frac = bits & BX_CONST64(0x000fffffffffffff);
  if (exp == 0x7ff) {
    if (frac == 0)
      return sign ? 0x1 : 0x80;
    return (frac & BX_CONST64(0x0008000000000000)) ? 0x200 : 0x100;
  }
  if (exp == 0) {
    if (frac == 0)
      return sign ? 0x8 : 0x10;
    return sign ? 0x4 : 0x20;
  }
  return sign ? 0x2 : 0x40;
}

static void bx_poly_aarch64_set_fp64_compare_nzcv(Bit64u left_bits,
  Bit64u right_bits, bool signal_all_nans)
{
  softfloat_status_t status = bx_poly_softfloat_status();
  int relation = f64_compare(left_bits, right_bits, !signal_all_nans, &status);
  if (relation == softfloat_relation_unordered)
    bx_poly_aarch64_nzcv = 0x3;
  else if (relation == softfloat_relation_less)
    bx_poly_aarch64_nzcv = 0x8;
  else if (relation == softfloat_relation_greater)
    bx_poly_aarch64_nzcv = 0x2;
  else
    bx_poly_aarch64_nzcv = 0x6;
}

static void bx_poly_aarch64_set_fp32_compare_nzcv(Bit32u left_bits,
  Bit32u right_bits, bool signal_all_nans)
{
  softfloat_status_t status = bx_poly_softfloat_status();
  int relation = f32_compare(left_bits, right_bits, !signal_all_nans, &status);
  if (relation == softfloat_relation_unordered)
    bx_poly_aarch64_nzcv = 0x3;
  else if (relation == softfloat_relation_less)
    bx_poly_aarch64_nzcv = 0x8;
  else if (relation == softfloat_relation_greater)
    bx_poly_aarch64_nzcv = 0x2;
  else
    bx_poly_aarch64_nzcv = 0x6;
}

static Bit64s bx_poly_sign_extend(Bit32u value, unsigned bits)
{
  Bit64s extended = value & ((BX_CONST64(1) << bits) - 1);
  if (extended & (BX_CONST64(1) << (bits - 1)))
    extended -= BX_CONST64(1) << bits;
  return extended;
}

static Bit64u bx_poly_low_mask(unsigned bits)
{
  return bits >= 64 ? ~BX_CONST64(0) : ((BX_CONST64(1) << bits) - 1);
}

static Bit64u bx_poly_get_vector_element(Bit64u lo, Bit64u hi,
    Bit32u element_bits, Bit32u lane)
{
  Bit32u bit_offset = lane * element_bits;
  Bit64u source = bit_offset < 64 ? lo : hi;
  return (source >> (bit_offset & 63)) & bx_poly_low_mask(element_bits);
}

static void bx_poly_set_vector_element(Bit64u *lo, Bit64u *hi,
    Bit32u element_bits, Bit32u lane, Bit64u value)
{
  Bit32u bit_offset = lane * element_bits;
  Bit64u *target = bit_offset < 64 ? lo : hi;
  Bit32u shift = bit_offset & 63;
  Bit64u mask = bx_poly_low_mask(element_bits) << shift;
  *target = (*target & ~mask) |
    ((value & bx_poly_low_mask(element_bits)) << shift);
}

static Bit64s bx_poly_sign_extend64(Bit64u value, unsigned bits)
{
  Bit64u mask = bx_poly_low_mask(bits);
  Bit64u sign = BX_CONST64(1) << (bits - 1);
  value &= mask;
  return (Bit64s) ((value ^ sign) - sign);
}

static Bit64u bx_poly_reverse_bits(Bit64u value, unsigned bits)
{
  Bit64u result = 0;
  for (unsigned i = 0; i < bits; i++) {
    if (value & (BX_CONST64(1) << i))
      result |= BX_CONST64(1) << (bits - 1 - i);
  }
  return result;
}

static Bit64u bx_poly_reverse_bytes_in_lanes(Bit64u value, unsigned bits,
  unsigned lane_bits)
{
  Bit64u result = 0;
  for (unsigned lane = 0; lane < bits; lane += lane_bits) {
    for (unsigned byte = 0; byte < lane_bits; byte += 8) {
      Bit64u b = (value >> (lane + byte)) & 0xff;
      result |= b << (lane + lane_bits - 8 - byte);
    }
  }
  return result;
}

static Bit64u bx_poly_count_leading_zeroes(Bit64u value, unsigned bits)
{
  value &= bx_poly_low_mask(bits);
  Bit64u count = 0;
  for (int bit = (int) bits - 1; bit >= 0; bit--) {
    if (value & (BX_CONST64(1) << bit))
      break;
    count++;
  }
  return count;
}

static Bit64u bx_poly_count_trailing_zeroes(Bit64u value, unsigned bits)
{
  value &= bx_poly_low_mask(bits);
  Bit64u count = 0;
  for (unsigned bit = 0; bit < bits; bit++) {
    if (value & (BX_CONST64(1) << bit))
      break;
    count++;
  }
  return count;
}

static Bit64u bx_poly_rotate_left(Bit64u value, unsigned bits, Bit32u amount)
{
  Bit64u mask = bx_poly_low_mask(bits);
  amount &= bits - 1;
  value &= mask;
  if (amount == 0)
    return value;
  return ((value << amount) | (value >> (bits - amount))) & mask;
}

static Bit64u bx_poly_rotate_right(Bit64u value, unsigned bits, Bit32u amount)
{
  Bit64u mask = bx_poly_low_mask(bits);
  amount &= bits - 1;
  value &= mask;
  if (amount == 0)
    return value;
  return ((value >> amount) | (value << (bits - amount))) & mask;
}

static Bit64u bx_poly_or_combine_bytes(Bit64u value)
{
  Bit64u result = 0;
  for (unsigned byte = 0; byte < 8; byte++) {
    if (((value >> (byte * 8)) & 0xff) != 0)
      result |= BX_CONST64(0xff) << (byte * 8);
  }
  return result;
}

static Bit64u bx_poly_count_leading_sign_bits(Bit64u value, unsigned bits)
{
  value &= bx_poly_low_mask(bits);
  bool sign = (value & (BX_CONST64(1) << (bits - 1))) != 0;
  Bit64u count = 0;
  for (int bit = (int) bits - 2; bit >= 0; bit--) {
    bool current = (value & (BX_CONST64(1) << bit)) != 0;
    if (current != sign)
      break;
    count++;
  }
  return count;
}

static Bit64s bx_poly_marker_offset(Bit64s guest_offset)
{
  return (guest_offset / 4) * 8;
}

static Bit32u bx_poly_riscv_creg(Bit32u reg)
{
  return 8 + (reg & 0x7);
}

static Bit64s bx_poly_riscv_ci_imm(Bit16u insn)
{
  Bit32u imm = (((Bit32u) insn >> 2) & 0x1f) | ((((Bit32u) insn >> 12) & 0x1) << 5);
  return bx_poly_sign_extend(imm, 6);
}

static Bit64s bx_poly_riscv_cj_imm(Bit16u insn)
{
  Bit32u imm =
    ((((Bit32u) insn >> 12) & 0x1) << 11) |
    ((((Bit32u) insn >> 11) & 0x1) << 4) |
    ((((Bit32u) insn >> 9) & 0x3) << 8) |
    ((((Bit32u) insn >> 8) & 0x1) << 10) |
    ((((Bit32u) insn >> 7) & 0x1) << 6) |
    ((((Bit32u) insn >> 6) & 0x1) << 7) |
    ((((Bit32u) insn >> 3) & 0x7) << 1) |
    ((((Bit32u) insn >> 2) & 0x1) << 5);
  return bx_poly_sign_extend(imm, 12);
}

static Bit64s bx_poly_riscv_cb_imm(Bit16u insn)
{
  Bit32u imm =
    ((((Bit32u) insn >> 12) & 0x1) << 8) |
    ((((Bit32u) insn >> 10) & 0x3) << 3) |
    ((((Bit32u) insn >> 5) & 0x3) << 6) |
    ((((Bit32u) insn >> 3) & 0x3) << 1) |
    ((((Bit32u) insn >> 2) & 0x1) << 5);
  return bx_poly_sign_extend(imm, 9);
}

static Bit32u bx_poly_riscv_caddi4spn_imm(Bit16u insn)
{
  return ((((Bit32u) insn >> 7) & 0xf) << 6) |
    ((((Bit32u) insn >> 11) & 0x3) << 4) |
    ((((Bit32u) insn >> 5) & 0x1) << 3) |
    ((((Bit32u) insn >> 6) & 0x1) << 2);
}

static Bit64s bx_poly_riscv_caddi16sp_imm(Bit16u insn)
{
  Bit32u imm =
    ((((Bit32u) insn >> 12) & 0x1) << 9) |
    ((((Bit32u) insn >> 6) & 0x1) << 4) |
    ((((Bit32u) insn >> 5) & 0x1) << 6) |
    ((((Bit32u) insn >> 3) & 0x3) << 7) |
    ((((Bit32u) insn >> 2) & 0x1) << 5);
  return bx_poly_sign_extend(imm, 10);
}

static Bit32u bx_poly_riscv_cld_imm(Bit16u insn)
{
  return ((((Bit32u) insn >> 10) & 0x7) << 3) |
    ((((Bit32u) insn >> 5) & 0x3) << 6);
}

static Bit32u bx_poly_riscv_clw_imm(Bit16u insn)
{
  return ((((Bit32u) insn >> 10) & 0x7) << 3) |
    ((((Bit32u) insn >> 6) & 0x1) << 2) |
    ((((Bit32u) insn >> 5) & 0x1) << 6);
}

static Bit32u bx_poly_riscv_cldsp_imm(Bit16u insn)
{
  return ((((Bit32u) insn >> 12) & 0x1) << 5) |
    ((((Bit32u) insn >> 5) & 0x3) << 3) |
    ((((Bit32u) insn >> 2) & 0x7) << 6);
}

static Bit32u bx_poly_riscv_clwsp_imm(Bit16u insn)
{
  return ((((Bit32u) insn >> 12) & 0x1) << 5) |
    ((((Bit32u) insn >> 4) & 0x7) << 2) |
    ((((Bit32u) insn >> 2) & 0x3) << 6);
}

static Bit32u bx_poly_riscv_csdsp_imm(Bit16u insn)
{
  return ((((Bit32u) insn >> 10) & 0x7) << 3) |
    ((((Bit32u) insn >> 7) & 0x7) << 6);
}

static Bit32u bx_poly_riscv_cswsp_imm(Bit16u insn)
{
  return ((((Bit32u) insn >> 9) & 0xf) << 2) |
    ((((Bit32u) insn >> 7) & 0x3) << 6);
}

static Bit64u bx_poly_riscv_indirect_target(Bit64u target, bx_address pc)
{
  // The raw stream may start on an odd x86 byte lane. RISC-V C has IALIGN=2,
  // so JALR clears architectural bit 0 while preserving target bit 1.
  return (target & ~BX_CONST64(1)) | (pc & 0x1);
}

static bool bx_poly_valid_frontend_mode(Bit32u mode)
{
  return mode == BX_POLY_MODE_X86 ||
    mode == BX_POLY_MODE_RAW_AARCH64 ||
    mode == BX_POLY_MODE_RAW_RISCV;
}

static bool bx_poly_frontend_id_to_mode(Bit32u frontend_id, Bit32u *mode)
{
  switch (frontend_id) {
  case BX_POLY_FRONTEND_X86:
    *mode = BX_POLY_MODE_X86;
    return true;
  case BX_POLY_FRONTEND_AARCH64:
    *mode = BX_POLY_MODE_RAW_AARCH64;
    return true;
  case BX_POLY_FRONTEND_RISCV:
    *mode = BX_POLY_MODE_RAW_RISCV;
    return true;
  default:
    return false;
  }
}

static void bx_poly_record_architectural_trap(Bit32u reason, Bit32u mode, Bit32u number,
  Bit32u selector, bx_address pc, bx_address next_pc, Bit64u arg0, Bit64u arg1,
  Bit64u arg2, Bit64u arg3, Bit64u arg4, Bit64u arg5, Bit64u arg6, Bit64u arg7)
{
  bx_poly_last_trap.reason = reason;
  bx_poly_last_trap.mode = mode;
  bx_poly_last_trap.number = number;
  bx_poly_last_trap.selector = selector;
  bx_poly_last_trap.pc = pc;
  bx_poly_last_trap.next_pc = next_pc;
  bx_poly_last_trap.args[0] = arg0;
  bx_poly_last_trap.args[1] = arg1;
  bx_poly_last_trap.args[2] = arg2;
  bx_poly_last_trap.args[3] = arg3;
  bx_poly_last_trap.args[4] = arg4;
  bx_poly_last_trap.args[5] = arg5;
  bx_poly_last_trap.args[6] = arg6;
  bx_poly_last_trap.args[7] = arg7;
}

static void bx_poly_record_syscall_trap(Bit32u mode, Bit32u number, Bit32u selector,
  bx_address pc, bx_address next_pc, Bit64u arg0, Bit64u arg1, Bit64u arg2,
  Bit64u arg3, Bit64u arg4, Bit64u arg5, Bit64u arg6, Bit64u arg7)
{
  bx_poly_last_syscall_mode = mode;
  bx_poly_last_syscall_number = number;
  bx_poly_foreign_syscall_count++;
  bx_poly_record_architectural_trap(BX_POLY_TRAP_SYSCALL, mode, number, selector,
    pc, next_pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

static void bx_poly_record_break_trap(Bit32u mode, Bit32u number, Bit32u selector,
  bx_address pc, bx_address next_pc, Bit64u arg0, Bit64u arg1, Bit64u arg2,
  Bit64u arg3, Bit64u arg4, Bit64u arg5, Bit64u arg6, Bit64u arg7)
{
  bx_poly_last_break_mode = mode;
  bx_poly_last_break_number = number;
  bx_poly_foreign_break_count++;
  bx_poly_record_architectural_trap(BX_POLY_TRAP_BREAK, mode, number, selector,
    pc, next_pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

static void bx_poly_record_import_trap(Bit32u mode, Bit32u import_id,
  bx_address pc, bx_address next_pc, Bit64u arg0, Bit64u arg1, Bit64u arg2,
  Bit64u arg3, Bit64u arg4, Bit64u arg5, Bit64u arg6, Bit64u arg7)
{
  bx_poly_record_architectural_trap(BX_POLY_TRAP_IMPORT, mode, import_id, 0,
    pc, next_pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

static void bx_poly_record_illegal_trap(Bit32u mode, Bit32u insn,
  Bit32u insn_bytes, bx_address pc, bx_address next_pc)
{
  bx_poly_record_architectural_trap(BX_POLY_TRAP_ILLEGAL, mode, insn,
    insn_bytes, pc, next_pc, 0, 0, 0, 0, 0, 0, 0, 0);
}

static bool bx_poly_aarch64_shifted_reg(Bit64u value, Bit32u shift_type, Bit32u shift_amount, Bit64u *result)
{
  switch (shift_type) {
  case 0:
    *result = value << shift_amount;
    return true;
  case 1:
    *result = value >> shift_amount;
    return true;
  case 2:
    *result = (Bit64u) ((Bit64s) value >> shift_amount);
    return true;
  case 3:
    *result = shift_amount == 0 ? value :
      (value >> shift_amount) | (value << (64 - shift_amount));
    return true;
  default:
    return false;
  }
}

static bool bx_poly_aarch64_shifted_reg_width(Bit64u value, Bit32u shift_type,
  Bit32u shift_amount, unsigned bits, Bit64u *result)
{
  Bit64u mask = bits == 64 ? ~BX_CONST64(0) : ((BX_CONST64(1) << bits) - 1);
  value &= mask;
  if (bits == 32 && shift_amount > 31)
    return false;

  switch (shift_type) {
  case 0:
    *result = (value << shift_amount) & mask;
    return true;
  case 1:
    *result = value >> shift_amount;
    return true;
  case 2:
    if (bits == 32)
      *result = (Bit32u) ((Bit32s) (Bit32u) value >> shift_amount);
    else
      *result = (Bit64u) ((Bit64s) value >> shift_amount);
    *result &= mask;
    return true;
  case 3:
    *result = shift_amount == 0 ? (value & mask) :
      ((value >> shift_amount) | (value << (bits - shift_amount))) & mask;
    return true;
  default:
    return false;
  }
}

static bool bx_poly_aarch64_extended_reg(Bit64u value, Bit32u option,
  Bit32u amount, unsigned bits, Bit64u *result)
{
  if (amount > 4)
    return false;

  switch (option) {
  case 0:
    value = (Bit8u) value;
    break;
  case 1:
    value = (Bit16u) value;
    break;
  case 2:
    value = (Bit32u) value;
    break;
  case 3:
    value = bits == 32 ? (Bit32u) value : value;
    break;
  case 4:
    value = (Bit64u) (Bit64s) (Bit8s) (Bit8u) value;
    break;
  case 5:
    value = (Bit64u) (Bit64s) (Bit16s) (Bit16u) value;
    break;
  case 6:
    value = (Bit64u) (Bit64s) (Bit32s) (Bit32u) value;
    break;
  case 7:
    value = bits == 32 ?
      (Bit64u) (Bit64s) (Bit32s) (Bit32u) value : value;
    break;
  default:
    return false;
  }

  value <<= amount;
  *result = bits == 32 ? (Bit32u) value : value;
  return true;
}

static void bx_poly_aarch64_set_nzcv(Bit64u result, bool carry, bool overflow, unsigned bits)
{
  Bit64u sign_bit = BX_CONST64(1) << (bits - 1);
  Bit64u mask = bits == 64 ? ~BX_CONST64(0) : ((BX_CONST64(1) << bits) - 1);
  result &= mask;
  bx_poly_aarch64_nzcv = 0;
  if (result & sign_bit)
    bx_poly_aarch64_nzcv |= 0x8;
  if (result == 0)
    bx_poly_aarch64_nzcv |= 0x4;
  if (carry)
    bx_poly_aarch64_nzcv |= 0x2;
  if (overflow)
    bx_poly_aarch64_nzcv |= 0x1;
}

static Bit64u bx_poly_aarch64_addsub_flags(Bit64u left, Bit64u right, bool subtract, unsigned bits)
{
  Bit64u mask = bits == 64 ? ~BX_CONST64(0) : ((BX_CONST64(1) << bits) - 1);
  Bit64u sign_bit = BX_CONST64(1) << (bits - 1);
  left &= mask;
  right &= mask;
  Bit64u result = subtract ? (left - right) & mask : (left + right) & mask;
  bool carry = subtract ? left >= right :
    (bits == 64 ? result < left : ((left + right) >> bits) != 0);
  bool overflow = subtract ?
    (((left ^ right) & (left ^ result) & sign_bit) != 0) :
    (((~(left ^ right)) & (left ^ result) & sign_bit) != 0);
  bx_poly_aarch64_set_nzcv(result, carry, overflow, bits);
  return result;
}

static int bx_poly_highest_set_bit(Bit32u value)
{
  for (int n = 31; n >= 0; n--) {
    if (value & ((Bit32u) 1 << n))
      return n;
  }
  return -1;
}

static bool bx_poly_aarch64_decode_logical_imm(Bit32u n, Bit32u immr,
  Bit32u imms, unsigned bits, Bit64u *value)
{
  int len = bx_poly_highest_set_bit((n << 6) | ((~imms) & 0x3f));
  if (len < 1 || (1u << len) > bits)
    return false;

  Bit32u levels = ((Bit32u) 1 << len) - 1;
  Bit32u s = imms & levels;
  Bit32u r = immr & levels;
  if (s == levels)
    return false;

  unsigned esize = 1u << len;
  Bit64u emask = esize == 64 ? ~BX_CONST64(0) : ((BX_CONST64(1) << esize) - 1);
  Bit64u pattern = ((BX_CONST64(1) << (s + 1)) - 1) & emask;
  if (r != 0)
    pattern = ((pattern >> r) | (pattern << (esize - r))) & emask;

  Bit64u replicated = 0;
  for (unsigned offset = 0; offset < bits; offset += esize)
    replicated |= pattern << offset;
  *value = bits == 64 ? replicated : (Bit32u) replicated;
  return true;
}

static bool bx_poly_aarch64_condition_holds(Bit32u cond)
{
  bool n = (bx_poly_aarch64_nzcv & 0x8) != 0;
  bool z = (bx_poly_aarch64_nzcv & 0x4) != 0;
  bool c = (bx_poly_aarch64_nzcv & 0x2) != 0;
  bool v = (bx_poly_aarch64_nzcv & 0x1) != 0;

  switch (cond & 0xf) {
  case 0x0: return z;
  case 0x1: return !z;
  case 0x2: return c;
  case 0x3: return !c;
  case 0x4: return n;
  case 0x5: return !n;
  case 0x6: return v;
  case 0x7: return !v;
  case 0x8: return c && !z;
  case 0x9: return !c || z;
  case 0xa: return n == v;
  case 0xb: return n != v;
  case 0xc: return !z && n == v;
  case 0xd: return z || n != v;
  default: return true;
  }
}

static const char *bx_poly_aarch64_barrier_name(Bit32u insn)
{
  if ((insn & 0xfffff0ff) == 0xd503309f)
    return "dsb";
  if ((insn & 0xfffff0ff) == 0xd50330bf)
    return "dmb";
  if ((insn & 0xfffff0ff) == 0xd50330df)
    return "isb";
  return 0;
}

static const char *bx_poly_aarch64_hint_name(Bit32u insn)
{
  if ((insn & ~(0x7fU << 5)) != 0xd503201fU)
    return 0;

  Bit32u subop = (insn >> 5) & 0x7fU;
  if (subop >= BX_POLY_AARCH64_CTRL_SUBOP_CALL_SIG_IMM_BASE)
    return 0;

  switch (subop) {
  case 0x00: return "nop";
  case 0x01: return "yield";
  case 0x02: return "wfe";
  case 0x03: return "wfi";
  case 0x04: return "sev";
  case 0x05: return "sevl";
  case 0x22: return "bti";
  default: return "hint";
  }
}

static const char *bx_poly_riscv_fence_name(Bit32u insn)
{
  if ((insn & 0x0000707f) == 0x0000000f)
    return "fence";
  if ((insn & 0x0000707f) == 0x0000100f)
    return "fence.i";
  return 0;
}

static void bx_poly_reset_aarch64_regs()
{
  for (unsigned n = 0; n < 32; n++) {
    bx_poly_aarch64_x[n] = 0;
    bx_poly_aarch64_x_valid[n] = false;
    bx_poly_aarch64_fp[n] = 0;
    bx_poly_aarch64_fp_hi[n] = 0;
  }
  bx_poly_aarch64_nzcv = 0;
  bx_poly_aarch64_reservation_valid = false;
  bx_poly_aarch64_reservation_addr = 0;
  bx_poly_aarch64_reservation_size = 0;
}

static void bx_poly_reset_riscv_regs()
{
  for (unsigned n = 0; n < 32; n++) {
    bx_poly_riscv_x[n] = 0;
    bx_poly_riscv_x_valid[n] = false;
    bx_poly_riscv_fp[n] = 0;
    bx_poly_riscv_fp_hi[n] = 0;
  }
  bx_poly_riscv_fflags = 0;
  bx_poly_riscv_frm = 0;
}

static bx_address bx_poly_stack_key(bx_address rsp)
{
  return rsp & ~BX_CONST64(0x7fffff);
}

static bool bx_poly_is_stack_region_key(bx_address stack_key)
{
  return (stack_key & BX_CONST64(0x7fffff)) == 0;
}

static bx_address bx_poly_thread_selector_key(bx_address fsbase,
  bx_address rsp)
{
  // In userspace, CR3+FSBASE is the stable architectural thread identity.
  // Including RSP here fragments one pthread's hidden foreign register bank
  // across ordinary call frames. Keep the stack-region key only as a fallback
  // for code that has no TLS base.
  if (fsbase != 0)
    return 0;
  return bx_poly_stack_key(rsp);
}

static bool bx_poly_thread_key_matches(const bx_poly_thread_key_state_t *state,
  bx_address cr3, bx_address fsbase, bx_address stack_key)
{
  return state->valid && state->cr3 == cr3 && state->fsbase == fsbase &&
    state->stack_key == stack_key;
}

static unsigned bx_poly_find_or_alloc_thread_key_state(bx_address cr3,
  bx_address fsbase, bx_address stack_key)
{
  unsigned victim = 0;
  Bit64u oldest_age = ~BX_CONST64(0);

  for (unsigned n = 0; n < BX_POLY_REG_STATE_SLOTS; n++) {
    if (bx_poly_thread_key_matches(&bx_poly_thread_key_states[n], cr3,
          fsbase, stack_key))
      return n;
  }

  for (unsigned n = 0; n < BX_POLY_REG_STATE_SLOTS; n++) {
    if (!bx_poly_thread_key_states[n].valid) {
      victim = n;
      break;
    }
    if (bx_poly_thread_key_states[n].age < oldest_age) {
      oldest_age = bx_poly_thread_key_states[n].age;
      victim = n;
    }
  }

  bx_poly_thread_key_states[victim].valid = true;
  bx_poly_thread_key_states[victim].cr3 = cr3;
  bx_poly_thread_key_states[victim].fsbase = fsbase;
  bx_poly_thread_key_states[victim].stack_key = stack_key;
  bx_poly_thread_key_states[victim].age = bx_poly_reg_state_age++;
  return victim;
}

static bx_address bx_poly_current_state_key_for_thread(bx_address cr3,
  bx_address fsbase, bx_address rsp)
{
  bx_address stack_key = bx_poly_thread_selector_key(fsbase, rsp);
  unsigned slot = bx_poly_find_or_alloc_thread_key_state(cr3, fsbase,
    stack_key);
  bx_poly_thread_key_states[slot].age = bx_poly_reg_state_age++;
  return stack_key;
}

#define bx_poly_current_state_key(rsp) \
  bx_poly_current_state_key_for_thread(BX_CPU_THIS_PTR cr3, MSR_FSBASE, (rsp))

static bool bx_poly_key_matches(const bx_poly_reg_state_t *state,
  bx_address cr3, bx_address fsbase, bx_address stack_key)
{
  return state->valid && state->cr3 == cr3 && state->fsbase == fsbase &&
    state->stack_key == stack_key;
}

static bool bx_poly_is_raw_mode(Bit32u mode)
{
  return mode == BX_POLY_MODE_RAW_AARCH64 || mode == BX_POLY_MODE_RAW_RISCV;
}

static void bx_poly_clear_cross_return_stack(void)
{
  bx_poly_cross_return_top = 0;
}

static void bx_poly_reset_return_cookie_frame(
    bx_poly_return_cookie_frame_t *frame)
{
  frame->mode = BX_POLY_MODE_X86;
  frame->rip = 0;
  frame->rsp = 0;
  frame->sret = false;
  frame->sret_ptr = 0;
  frame->kind = BX_POLY_RETURN_KIND_DEFAULT;
}

static void bx_poly_clear_return_cookie(void)
{
  bx_poly_return_cookie_valid = false;
  bx_poly_return_cookie_mode = BX_POLY_MODE_X86;
  bx_poly_return_cookie_rip = 0;
  bx_poly_return_cookie_rsp = 0;
  bx_poly_return_cookie_sret = false;
  bx_poly_return_cookie_sret_ptr = 0;
  bx_poly_return_cookie_kind = BX_POLY_RETURN_KIND_DEFAULT;
}

static bool bx_poly_push_return_cookie(void)
{
  if (!bx_poly_return_cookie_valid)
    return true;
  if (bx_poly_return_cookie_top >= BX_POLY_RETURN_COOKIE_DEPTH)
    return false;

  bx_poly_return_cookie_frame_t *frame =
    &bx_poly_return_cookie_stack[bx_poly_return_cookie_top++];
  frame->mode = bx_poly_return_cookie_mode;
  frame->rip = bx_poly_return_cookie_rip;
  frame->rsp = bx_poly_return_cookie_rsp;
  frame->sret = bx_poly_return_cookie_sret;
  frame->sret_ptr = bx_poly_return_cookie_sret_ptr;
  frame->kind = bx_poly_return_cookie_kind;
  return true;
}

static void bx_poly_restore_previous_return_cookie(void)
{
  if (bx_poly_return_cookie_top == 0) {
    bx_poly_clear_return_cookie();
    return;
  }

  bx_poly_return_cookie_frame_t frame =
    bx_poly_return_cookie_stack[bx_poly_return_cookie_top - 1];
  bx_poly_return_cookie_top--;
  bx_poly_reset_return_cookie_frame(
    &bx_poly_return_cookie_stack[bx_poly_return_cookie_top]);
  bx_poly_return_cookie_valid = true;
  bx_poly_return_cookie_mode = frame.mode;
  bx_poly_return_cookie_rip = frame.rip;
  bx_poly_return_cookie_rsp = frame.rsp;
  bx_poly_return_cookie_sret = frame.sret;
  bx_poly_return_cookie_sret_ptr = frame.sret_ptr;
  bx_poly_return_cookie_kind = frame.kind;
}

static void bx_poly_clear_import_x86_return_stack(void)
{
  bx_poly_import_x86_return_top = 0;
}

static void bx_poly_reset_import_x86_return_frame(
    bx_poly_import_x86_return_frame_t *frame)
{
  frame->mode = BX_POLY_MODE_X86;
  frame->rip = 0;
  frame->rsp = 0;
  frame->import_id = 0;
  frame->return_flags = 0;
  frame->alias_valid = false;
  for (unsigned n = 0; n < 6; n++)
    frame->alias[n] = 0;
}

static void bx_poly_reset_current_xstate(void)
{
  bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_clear_return_cookie();
  bx_poly_return_cookie_top = 0;
  for (unsigned n = 0; n < BX_POLY_RETURN_COOKIE_DEPTH; n++)
    bx_poly_reset_return_cookie_frame(&bx_poly_return_cookie_stack[n]);
  bx_poly_clear_cross_return_stack();
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++) {
    bx_poly_cross_return_stack[n].caller_mode = BX_POLY_MODE_X86;
    bx_poly_cross_return_stack[n].callee_mode = BX_POLY_MODE_X86;
    bx_poly_cross_return_stack[n].bridge_kind = BX_POLY_CROSS_BRIDGE_DEFAULT;
    bx_poly_cross_return_stack[n].return_rip = 0;
    bx_poly_cross_return_stack[n].return_rsp = 0;
    bx_poly_cross_return_stack[n].flags = 0;
  }
  bx_poly_clear_import_x86_return_stack();
  for (unsigned n = 0; n < BX_POLY_IMPORT_RETURN_DEPTH; n++)
    bx_poly_reset_import_x86_return_frame(&bx_poly_import_x86_return_stack[n]);
  bx_poly_reset_abi_signature_slots(bx_poly_abi_signature_slots);
  bx_poly_interrupted_raw_valid = false;
  bx_poly_interrupted_raw_mode = BX_POLY_MODE_X86;
  bx_poly_interrupted_raw_rip = 0;
  bx_poly_aarch64_tls_base = 0;
  bx_poly_riscv_tls_base = 0;
  bx_poly_landing_policy_flags = 0;
  bx_poly_trap_vector = 0;
  bx_poly_trap_vector_mode = BX_POLY_MODE_X86;
  bx_poly_monitor_packet_addr = 0;
  bx_poly_last_syscall_mode = BX_POLY_MODE_X86;
  bx_poly_last_syscall_number = 0;
  bx_poly_last_break_mode = BX_POLY_MODE_X86;
  bx_poly_last_break_number = 0;
  bx_poly_last_trap.reason = BX_POLY_TRAP_NONE;
  bx_poly_last_trap.mode = BX_POLY_MODE_X86;
  bx_poly_last_trap.number = 0;
  bx_poly_last_trap.selector = 0;
  bx_poly_last_trap.pc = 0;
  bx_poly_last_trap.next_pc = 0;
  for (unsigned n = 0; n < 8; n++)
    bx_poly_last_trap.args[n] = 0;
  bx_poly_clear_trap_saved_regs(&bx_poly_trap_saved_regs);
  bx_poly_reset_aarch64_regs();
  bx_poly_reset_riscv_regs();
  bx_poly_riscv_reservation_valid = false;
  bx_poly_riscv_reservation_addr = 0;
  bx_poly_riscv_reservation_size = 0;
  for (unsigned n = 0; n < BX_POLY_REG_STATE_SLOTS; n++) {
    bx_poly_thread_key_states[n].valid = false;
    bx_poly_thread_key_states[n].cr3 = 0;
    bx_poly_thread_key_states[n].fsbase = 0;
    bx_poly_thread_key_states[n].stack_key = 0;
    bx_poly_thread_key_states[n].age = 0;
  }
}

static void bx_poly_update_raw_owner(bx_address cr3, bx_address fsbase,
  bx_address stack_key)
{
  if (bx_poly_is_raw_mode(bx_poly_current_mode)) {
    bx_poly_raw_owner_cr3 = cr3;
    bx_poly_raw_owner_fsbase = fsbase;
    bx_poly_raw_owner_stack_key = stack_key;
  }
  else {
    bx_poly_raw_owner_cr3 = 0;
    bx_poly_raw_owner_fsbase = 0;
    bx_poly_raw_owner_stack_key = 0;
  }
}

static unsigned bx_poly_find_or_alloc_reg_state(bx_address cr3,
  bx_address fsbase, bx_address stack_key)
{
  unsigned victim = 0;
  Bit64u oldest_age = ~BX_CONST64(0);
  bool inherited_trap_vector_valid = false;
  Bit64u inherited_trap_vector_age = 0;
  bx_address inherited_trap_vector = 0;
  Bit32u inherited_trap_vector_mode = BX_POLY_MODE_X86;
  bx_address inherited_monitor_packet_addr = 0;

  for (unsigned n = 0; n < BX_POLY_REG_STATE_SLOTS; n++) {
    if (bx_poly_key_matches(&bx_poly_reg_states[n], cr3, fsbase, stack_key))
      return n;
  }

  if (bx_poly_is_stack_region_key(stack_key)) {
    for (unsigned n = 0; n < BX_POLY_REG_STATE_SLOTS; n++) {
      if (!bx_poly_reg_states[n].valid ||
          bx_poly_reg_states[n].cr3 != cr3 ||
          bx_poly_reg_states[n].fsbase != fsbase ||
          !bx_poly_is_stack_region_key(bx_poly_reg_states[n].stack_key))
        continue;
      if (!inherited_trap_vector_valid ||
          bx_poly_reg_states[n].age >= inherited_trap_vector_age) {
        inherited_trap_vector_valid = true;
        inherited_trap_vector_age = bx_poly_reg_states[n].age;
        inherited_trap_vector = bx_poly_reg_states[n].trap_vector;
        inherited_trap_vector_mode = bx_poly_reg_states[n].trap_vector_mode;
        inherited_monitor_packet_addr =
          bx_poly_reg_states[n].monitor_packet_addr;
      }
    }
  }

  for (unsigned n = 0; n < BX_POLY_REG_STATE_SLOTS; n++) {
    if (!bx_poly_reg_states[n].valid) {
      victim = n;
      break;
    }
    if (bx_poly_reg_states[n].age < oldest_age) {
      oldest_age = bx_poly_reg_states[n].age;
      victim = n;
    }
  }

  bx_poly_reg_states[victim].valid = true;
  bx_poly_reg_states[victim].cr3 = cr3;
  bx_poly_reg_states[victim].fsbase = fsbase;
  bx_poly_reg_states[victim].stack_key = stack_key;
  bx_poly_reg_states[victim].age = bx_poly_reg_state_age++;
  bx_poly_reg_states[victim].current_mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].return_cookie_valid = false;
  bx_poly_reg_states[victim].return_cookie_mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].return_cookie_rip = 0;
  bx_poly_reg_states[victim].return_cookie_rsp = 0;
  bx_poly_reg_states[victim].return_cookie_sret = false;
  bx_poly_reg_states[victim].return_cookie_sret_ptr = 0;
  bx_poly_reg_states[victim].return_cookie_kind = BX_POLY_RETURN_KIND_DEFAULT;
  bx_poly_reg_states[victim].return_cookie_top = 0;
  bx_poly_reg_states[victim].cross_return_top = 0;
  bx_poly_reg_states[victim].import_x86_return_top = 0;
  bx_poly_reset_abi_signature_slots(
    bx_poly_reg_states[victim].abi_signature_slots);
  bx_poly_reg_states[victim].interrupted_raw_valid = false;
  bx_poly_reg_states[victim].interrupted_raw_mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].interrupted_raw_rip = 0;
  bx_poly_reg_states[victim].aarch64_tls_base = 0;
  bx_poly_reg_states[victim].riscv_tls_base = 0;
  bx_poly_reg_states[victim].landing_policy_flags = 0;
  bx_poly_reg_states[victim].trap_vector =
    inherited_trap_vector_valid ? inherited_trap_vector : 0;
  bx_poly_reg_states[victim].trap_vector_mode =
    inherited_trap_vector_valid ? inherited_trap_vector_mode : BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].monitor_packet_addr =
    inherited_trap_vector_valid ? inherited_monitor_packet_addr : 0;
  bx_poly_reg_states[victim].last_syscall_mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].last_syscall_number = 0;
  bx_poly_reg_states[victim].last_break_mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].last_break_number = 0;
  bx_poly_reg_states[victim].last_trap.reason = BX_POLY_TRAP_NONE;
  bx_poly_reg_states[victim].last_trap.mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].last_trap.number = 0;
  bx_poly_reg_states[victim].last_trap.selector = 0;
  bx_poly_reg_states[victim].last_trap.pc = 0;
  bx_poly_reg_states[victim].last_trap.next_pc = 0;
  for (unsigned n = 0; n < BX_POLY_TRAP_PACKET_ARG_COUNT; n++)
    bx_poly_reg_states[victim].last_trap.args[n] = 0;
  bx_poly_clear_trap_saved_regs(&bx_poly_reg_states[victim].trap_saved_regs);
  bx_poly_reg_states[victim].aarch64_nzcv = 0;
  bx_poly_reg_states[victim].aarch64_reservation_valid = false;
  bx_poly_reg_states[victim].aarch64_reservation_addr = 0;
  bx_poly_reg_states[victim].aarch64_reservation_size = 0;
  bx_poly_reg_states[victim].riscv_reservation_valid = false;
  bx_poly_reg_states[victim].riscv_reservation_addr = 0;
  bx_poly_reg_states[victim].riscv_reservation_size = 0;
  bx_poly_reg_states[victim].riscv_fflags = 0;
  bx_poly_reg_states[victim].riscv_frm = 0;
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++) {
    bx_poly_reg_states[victim].cross_return_stack[n].caller_mode = BX_POLY_MODE_X86;
    bx_poly_reg_states[victim].cross_return_stack[n].callee_mode = BX_POLY_MODE_X86;
    bx_poly_reg_states[victim].cross_return_stack[n].bridge_kind = BX_POLY_CROSS_BRIDGE_DEFAULT;
    bx_poly_reg_states[victim].cross_return_stack[n].return_rip = 0;
    bx_poly_reg_states[victim].cross_return_stack[n].return_rsp = 0;
    bx_poly_reg_states[victim].cross_return_stack[n].flags = 0;
  }
  for (unsigned n = 0; n < BX_POLY_RETURN_COOKIE_DEPTH; n++)
    bx_poly_reset_return_cookie_frame(
      &bx_poly_reg_states[victim].return_cookie_stack[n]);
  for (unsigned n = 0; n < BX_POLY_IMPORT_RETURN_DEPTH; n++)
    bx_poly_reset_import_x86_return_frame(
      &bx_poly_reg_states[victim].import_x86_return_stack[n]);
  for (unsigned n = 0; n < 32; n++) {
    bx_poly_reg_states[victim].aarch64_x[n] = 0;
    bx_poly_reg_states[victim].aarch64_x_valid[n] = false;
    bx_poly_reg_states[victim].aarch64_fp[n] = 0;
    bx_poly_reg_states[victim].aarch64_fp_hi[n] = 0;
    bx_poly_reg_states[victim].riscv_x[n] = 0;
    bx_poly_reg_states[victim].riscv_x_valid[n] = false;
    bx_poly_reg_states[victim].riscv_fp[n] = 0;
    bx_poly_reg_states[victim].riscv_fp_hi[n] = 0;
  }
  return victim;
}

static void bx_poly_propagate_trap_vector_state(bx_address cr3,
  bx_address fsbase, bx_address stack_key)
{
  if (!bx_poly_is_stack_region_key(stack_key))
    return;

  for (unsigned n = 0; n < BX_POLY_REG_STATE_SLOTS; n++) {
    if (!bx_poly_reg_states[n].valid ||
        bx_poly_reg_states[n].cr3 != cr3 ||
        bx_poly_reg_states[n].fsbase != fsbase ||
        !bx_poly_is_stack_region_key(bx_poly_reg_states[n].stack_key))
      continue;
    bx_poly_reg_states[n].trap_vector = bx_poly_trap_vector;
    bx_poly_reg_states[n].trap_vector_mode = bx_poly_trap_vector_mode;
    bx_poly_reg_states[n].monitor_packet_addr = bx_poly_monitor_packet_addr;
  }
}

static bool bx_poly_read_exchange_window(Bit32u lane, Bit64u *value);
static bool bx_poly_write_exchange_window(Bit32u lane, Bit64u value);

static void bx_poly_snapshot_aliased_state(Bit32u mode)
{
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    for (unsigned n = 0; n < BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT; n++) {
      Bit64u value = 0;
      if (bx_poly_read_exchange_window(n, &value)) {
        bx_poly_aarch64_x[n] = value;
        bx_poly_aarch64_x_valid[n] = true;
      }
    }
    for (unsigned n = 0; n < 8; n++) {
      bx_poly_aarch64_fp[n] = BX_READ_XMM_REG_LO_QWORD(n);
      bx_poly_aarch64_fp_hi[n] = BX_READ_XMM_REG_HI_QWORD(n);
    }
  }
  else if (mode == BX_POLY_MODE_RAW_RISCV) {
    bx_poly_riscv_x[2] = RSP;
    bx_poly_riscv_x_valid[2] = true;
    for (unsigned n = 0; n < BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT; n++) {
      Bit64u value = 0;
      if (bx_poly_read_exchange_window(n, &value)) {
        bx_poly_riscv_x[10 + n] = value;
        bx_poly_riscv_x_valid[10 + n] = true;
      }
    }
    for (unsigned n = 0; n < 8; n++) {
      bx_poly_riscv_fp[10 + n] = BX_READ_XMM_REG_LO_QWORD(n);
      bx_poly_riscv_fp_hi[10 + n] = BX_READ_XMM_REG_HI_QWORD(n);
    }
  }
}

static void bx_poly_restore_aliased_state(Bit32u mode)
{
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    for (unsigned n = 0; n < BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT; n++) {
      if (bx_poly_aarch64_x_valid[n])
        bx_poly_write_exchange_window(n, bx_poly_aarch64_x[n]);
    }
    for (unsigned n = 0; n < 8; n++) {
      BX_WRITE_XMM_REG_LO_QWORD(n, bx_poly_aarch64_fp[n]);
      BX_WRITE_XMM_REG_HI_QWORD(n, bx_poly_aarch64_fp_hi[n]);
    }
  }
  else if (mode == BX_POLY_MODE_RAW_RISCV) {
    if (bx_poly_riscv_x_valid[2])
      RSP = bx_poly_riscv_x[2];
    for (unsigned n = 0; n < BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT; n++) {
      if (bx_poly_riscv_x_valid[10 + n])
        bx_poly_write_exchange_window(n, bx_poly_riscv_x[10 + n]);
    }
    for (unsigned n = 0; n < 8; n++) {
      BX_WRITE_XMM_REG_LO_QWORD(n, bx_poly_riscv_fp[10 + n]);
      BX_WRITE_XMM_REG_HI_QWORD(n, bx_poly_riscv_fp_hi[10 + n]);
    }
  }
}

static void bx_poly_save_current_reg_state(bx_address cr3, bx_address fsbase,
  bx_address stack_key)
{
  bx_poly_capture_tls_base_for_mode(bx_poly_current_mode);
  bx_poly_snapshot_aliased_state(bx_poly_current_mode);

  unsigned slot = bx_poly_find_or_alloc_reg_state(cr3, fsbase, stack_key);
  bx_poly_reg_states[slot].age = bx_poly_reg_state_age++;
  bx_poly_reg_states[slot].current_mode = bx_poly_current_mode;
  bx_poly_reg_states[slot].return_cookie_valid = bx_poly_return_cookie_valid;
  bx_poly_reg_states[slot].return_cookie_mode = bx_poly_return_cookie_mode;
  bx_poly_reg_states[slot].return_cookie_rip = bx_poly_return_cookie_rip;
  bx_poly_reg_states[slot].return_cookie_rsp = bx_poly_return_cookie_rsp;
  bx_poly_reg_states[slot].return_cookie_sret = bx_poly_return_cookie_sret;
  bx_poly_reg_states[slot].return_cookie_sret_ptr = bx_poly_return_cookie_sret_ptr;
  bx_poly_reg_states[slot].return_cookie_kind = bx_poly_return_cookie_kind;
  bx_poly_reg_states[slot].return_cookie_top = bx_poly_return_cookie_top;
  bx_poly_reg_states[slot].cross_return_top = bx_poly_cross_return_top;
  bx_poly_reg_states[slot].import_x86_return_top =
    bx_poly_import_x86_return_top;
  for (unsigned n = 0; n < BX_POLY_ABI_SIGNATURE_SLOT_COUNT; n++)
    bx_poly_reg_states[slot].abi_signature_slots[n] =
      bx_poly_abi_signature_slots[n];
  bx_poly_reg_states[slot].interrupted_raw_valid = bx_poly_interrupted_raw_valid;
  bx_poly_reg_states[slot].interrupted_raw_mode = bx_poly_interrupted_raw_mode;
  bx_poly_reg_states[slot].interrupted_raw_rip = bx_poly_interrupted_raw_rip;
  bx_poly_reg_states[slot].aarch64_tls_base = bx_poly_aarch64_tls_base;
  bx_poly_reg_states[slot].riscv_tls_base = bx_poly_riscv_tls_base;
  bx_poly_reg_states[slot].landing_policy_flags =
    bx_poly_landing_policy_flags;
  bx_poly_reg_states[slot].trap_vector = bx_poly_trap_vector;
  bx_poly_reg_states[slot].trap_vector_mode = bx_poly_trap_vector_mode;
  bx_poly_reg_states[slot].monitor_packet_addr = bx_poly_monitor_packet_addr;
  bx_poly_reg_states[slot].last_syscall_mode = bx_poly_last_syscall_mode;
  bx_poly_reg_states[slot].last_syscall_number = bx_poly_last_syscall_number;
  bx_poly_reg_states[slot].last_break_mode = bx_poly_last_break_mode;
  bx_poly_reg_states[slot].last_break_number = bx_poly_last_break_number;
  bx_poly_reg_states[slot].last_trap = bx_poly_last_trap;
  bx_poly_reg_states[slot].trap_saved_regs = bx_poly_trap_saved_regs;
  bx_poly_reg_states[slot].aarch64_nzcv = bx_poly_aarch64_nzcv;
  bx_poly_reg_states[slot].aarch64_reservation_valid = bx_poly_aarch64_reservation_valid;
  bx_poly_reg_states[slot].aarch64_reservation_addr = bx_poly_aarch64_reservation_addr;
  bx_poly_reg_states[slot].aarch64_reservation_size = bx_poly_aarch64_reservation_size;
  bx_poly_reg_states[slot].riscv_reservation_valid = bx_poly_riscv_reservation_valid;
  bx_poly_reg_states[slot].riscv_reservation_addr = bx_poly_riscv_reservation_addr;
  bx_poly_reg_states[slot].riscv_reservation_size = bx_poly_riscv_reservation_size;
  bx_poly_reg_states[slot].riscv_fflags = bx_poly_riscv_fflags;
  bx_poly_reg_states[slot].riscv_frm = bx_poly_riscv_frm;
  for (unsigned n = 0; n < BX_POLY_RETURN_COOKIE_DEPTH; n++)
    bx_poly_reg_states[slot].return_cookie_stack[n] =
      bx_poly_return_cookie_stack[n];
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++)
    bx_poly_reg_states[slot].cross_return_stack[n] = bx_poly_cross_return_stack[n];
  for (unsigned n = 0; n < BX_POLY_IMPORT_RETURN_DEPTH; n++)
    bx_poly_reg_states[slot].import_x86_return_stack[n] =
      bx_poly_import_x86_return_stack[n];
  for (unsigned n = 0; n < 32; n++) {
    bx_poly_reg_states[slot].aarch64_x[n] = bx_poly_aarch64_x[n];
    bx_poly_reg_states[slot].aarch64_x_valid[n] = bx_poly_aarch64_x_valid[n];
    bx_poly_reg_states[slot].aarch64_fp[n] = bx_poly_aarch64_fp[n];
    bx_poly_reg_states[slot].aarch64_fp_hi[n] = bx_poly_aarch64_fp_hi[n];
    bx_poly_reg_states[slot].riscv_x[n] = bx_poly_riscv_x[n];
    bx_poly_reg_states[slot].riscv_x_valid[n] = bx_poly_riscv_x_valid[n];
    bx_poly_reg_states[slot].riscv_fp[n] = bx_poly_riscv_fp[n];
    bx_poly_reg_states[slot].riscv_fp_hi[n] = bx_poly_riscv_fp_hi[n];
  }
}

static void bx_poly_load_reg_state(bx_address cr3, bx_address fsbase,
  bx_address stack_key)
{
  unsigned slot = bx_poly_find_or_alloc_reg_state(cr3, fsbase, stack_key);
  bx_poly_reg_states[slot].age = bx_poly_reg_state_age++;
  bx_poly_current_mode = bx_poly_reg_states[slot].current_mode;
  bx_poly_return_cookie_valid = bx_poly_reg_states[slot].return_cookie_valid;
  bx_poly_return_cookie_mode = bx_poly_reg_states[slot].return_cookie_mode;
  bx_poly_return_cookie_rip = bx_poly_reg_states[slot].return_cookie_rip;
  bx_poly_return_cookie_rsp = bx_poly_reg_states[slot].return_cookie_rsp;
  bx_poly_return_cookie_sret = bx_poly_reg_states[slot].return_cookie_sret;
  bx_poly_return_cookie_sret_ptr = bx_poly_reg_states[slot].return_cookie_sret_ptr;
  bx_poly_return_cookie_kind = bx_poly_reg_states[slot].return_cookie_kind;
  bx_poly_return_cookie_top = bx_poly_reg_states[slot].return_cookie_top;
  bx_poly_cross_return_top = bx_poly_reg_states[slot].cross_return_top;
  bx_poly_import_x86_return_top =
    bx_poly_reg_states[slot].import_x86_return_top;
  for (unsigned n = 0; n < BX_POLY_ABI_SIGNATURE_SLOT_COUNT; n++)
    bx_poly_abi_signature_slots[n] =
      bx_poly_reg_states[slot].abi_signature_slots[n];
  bx_poly_interrupted_raw_valid = bx_poly_reg_states[slot].interrupted_raw_valid;
  bx_poly_interrupted_raw_mode = bx_poly_reg_states[slot].interrupted_raw_mode;
  bx_poly_interrupted_raw_rip = bx_poly_reg_states[slot].interrupted_raw_rip;
  if (bx_poly_interrupted_raw_valid)
    bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_aarch64_tls_base = bx_poly_reg_states[slot].aarch64_tls_base;
  bx_poly_riscv_tls_base = bx_poly_reg_states[slot].riscv_tls_base;
  bx_poly_landing_policy_flags =
    bx_poly_reg_states[slot].landing_policy_flags;
  bx_poly_trap_vector = bx_poly_reg_states[slot].trap_vector;
  bx_poly_trap_vector_mode = bx_poly_reg_states[slot].trap_vector_mode;
  bx_poly_monitor_packet_addr = bx_poly_reg_states[slot].monitor_packet_addr;
  bx_poly_last_syscall_mode = bx_poly_reg_states[slot].last_syscall_mode;
  bx_poly_last_syscall_number = bx_poly_reg_states[slot].last_syscall_number;
  bx_poly_last_break_mode = bx_poly_reg_states[slot].last_break_mode;
  bx_poly_last_break_number = bx_poly_reg_states[slot].last_break_number;
  bx_poly_last_trap = bx_poly_reg_states[slot].last_trap;
  bx_poly_trap_saved_regs = bx_poly_reg_states[slot].trap_saved_regs;
  bx_poly_aarch64_nzcv = bx_poly_reg_states[slot].aarch64_nzcv;
  bx_poly_aarch64_reservation_valid = bx_poly_reg_states[slot].aarch64_reservation_valid;
  bx_poly_aarch64_reservation_addr = bx_poly_reg_states[slot].aarch64_reservation_addr;
  bx_poly_aarch64_reservation_size = bx_poly_reg_states[slot].aarch64_reservation_size;
  bx_poly_riscv_reservation_valid = bx_poly_reg_states[slot].riscv_reservation_valid;
  bx_poly_riscv_reservation_addr = bx_poly_reg_states[slot].riscv_reservation_addr;
  bx_poly_riscv_reservation_size = bx_poly_reg_states[slot].riscv_reservation_size;
  bx_poly_riscv_fflags = bx_poly_reg_states[slot].riscv_fflags;
  bx_poly_riscv_frm = bx_poly_reg_states[slot].riscv_frm;
  for (unsigned n = 0; n < BX_POLY_RETURN_COOKIE_DEPTH; n++)
    bx_poly_return_cookie_stack[n] =
      bx_poly_reg_states[slot].return_cookie_stack[n];
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++)
    bx_poly_cross_return_stack[n] = bx_poly_reg_states[slot].cross_return_stack[n];
  for (unsigned n = 0; n < BX_POLY_IMPORT_RETURN_DEPTH; n++)
    bx_poly_import_x86_return_stack[n] =
      bx_poly_reg_states[slot].import_x86_return_stack[n];
  for (unsigned n = 0; n < 32; n++) {
    bx_poly_aarch64_x[n] = bx_poly_reg_states[slot].aarch64_x[n];
    bx_poly_aarch64_x_valid[n] = bx_poly_reg_states[slot].aarch64_x_valid[n];
    bx_poly_aarch64_fp[n] = bx_poly_reg_states[slot].aarch64_fp[n];
    bx_poly_aarch64_fp_hi[n] = bx_poly_reg_states[slot].aarch64_fp_hi[n];
    bx_poly_riscv_x[n] = bx_poly_reg_states[slot].riscv_x[n];
    bx_poly_riscv_x_valid[n] = bx_poly_reg_states[slot].riscv_x_valid[n];
    bx_poly_riscv_fp[n] = bx_poly_reg_states[slot].riscv_fp[n];
    bx_poly_riscv_fp_hi[n] = bx_poly_reg_states[slot].riscv_fp_hi[n];
  }
  bx_poly_prepare_tls_for_mode(bx_poly_current_mode);
  if (bx_poly_is_raw_mode(bx_poly_current_mode))
    bx_poly_restore_aliased_state(bx_poly_current_mode);
  bx_poly_update_raw_owner(cr3, fsbase, stack_key);
}

static void bx_poly_bind_reg_state(bx_address cr3, bx_address fsbase,
  bx_address stack_key)
{
  if (bx_poly_loaded_reg_state_valid &&
      bx_poly_loaded_reg_state_cr3 == cr3 &&
      bx_poly_loaded_reg_state_fsbase == fsbase &&
      bx_poly_loaded_reg_state_stack_key == stack_key)
    return;

  if (bx_poly_loaded_reg_state_valid)
    bx_poly_save_current_reg_state(bx_poly_loaded_reg_state_cr3,
      bx_poly_loaded_reg_state_fsbase, bx_poly_loaded_reg_state_stack_key);

  bx_poly_load_reg_state(cr3, fsbase, stack_key);
  bx_poly_loaded_reg_state_valid = true;
  bx_poly_loaded_reg_state_cr3 = cr3;
  bx_poly_loaded_reg_state_fsbase = fsbase;
  bx_poly_loaded_reg_state_stack_key = stack_key;
}

static void bx_poly_commit_reg_state(bx_address cr3, bx_address fsbase,
  bx_address stack_key)
{
  bx_poly_save_current_reg_state(cr3, fsbase, stack_key);
  bx_poly_loaded_reg_state_valid = true;
  bx_poly_loaded_reg_state_cr3 = cr3;
  bx_poly_loaded_reg_state_fsbase = fsbase;
  bx_poly_loaded_reg_state_stack_key = stack_key;
}

static Bit32u bx_poly_state_contract_flags(void)
{
  return BX_POLY_CPUID_STATE_OVERLAP_GPRS |
    BX_POLY_CPUID_STATE_USER_RETURN_RESTORE |
    BX_POLY_CPUID_STATE_X86_TSO |
    BX_POLY_CPUID_STATE_XSAVE_VISIBLE |
    BX_POLY_CPUID_STATE_TRANSITION_FRAME_32 |
    BX_POLY_CPUID_STATE_EXPLICIT_SAVE_RESTORE |
    BX_POLY_CPUID_STATE_XSAVE_ARCH_CONTRACT |
    BX_POLY_CPUID_STATE_IMPORT_RETURN_XSAVE |
    BX_POLY_CPUID_STATE_ABI_SIGNATURE_XSAVE |
    BX_POLY_CPUID_STATE_MONITOR_PACKET_XSAVE |
    BX_POLY_CPUID_STATE_CROSS_RETURN_XSAVE |
    BX_POLY_CPUID_STATE_FRONTEND_TLS_XSAVE |
    BX_POLY_CPUID_STATE_LANDING_POLICY_XSAVE;
}

static Bit32u bx_poly_xsave_arch_flags(void)
{
  return BX_POLY_STATE_XSAVE_FLAG_XCR0_USER |
    BX_POLY_STATE_XSAVE_FLAG_OSXSAVE_REQUIRED |
    BX_POLY_STATE_XSAVE_FLAG_INTERRUPT_RESUME |
    BX_POLY_STATE_XSAVE_FLAG_TRAP_STATE |
    BX_POLY_STATE_XSAVE_FLAG_NO_HIDDEN_BANKS |
    BX_POLY_STATE_XSAVE_FLAG_IMPORT_RETURN |
    BX_POLY_STATE_XSAVE_FLAG_ABI_SIGNATURES |
    BX_POLY_STATE_XSAVE_FLAG_MONITOR_PACKET |
    BX_POLY_STATE_XSAVE_FLAG_CROSS_RETURN |
    BX_POLY_STATE_XSAVE_FLAG_FRONTEND_TLS |
    BX_POLY_STATE_XSAVE_FLAG_LANDING_POLICY;
}

static Bit64u bx_poly_trap_packet_flags(void)
{
  if (bx_poly_last_trap.reason == BX_POLY_TRAP_NONE)
    return 0;
  Bit64u flags = BX_POLY_TRAP_PACKET_FLAG_STATUS_OPS;
  if (bx_poly_monitor_packet_addr != 0)
    flags |= BX_POLY_TRAP_PACKET_FLAG_MONITOR_MEMORY;
  return flags;
}

static bool bx_poly_valid_abi_signature_kind(Bit32u kind);

static bool bx_poly_read_exchange_window(Bit32u lane, Bit64u *value)
{
  switch (lane) {
  case 0: *value = RAX; return true;
  case 1: *value = RDX; return true;
  case 2: *value = RCX; return true;
  case 3: *value = RDI; return true;
  case 4: *value = RSI; return true;
  case 5: *value = R8; return true;
  case 6: *value = R9; return true;
  case 7: *value = R10; return true;
  default: return false;
  }
}

static bool bx_poly_write_exchange_window(Bit32u lane, Bit64u value)
{
  switch (lane) {
  case 0: RAX = value; return true;
  case 1: RDX = value; return true;
  case 2: RCX = value; return true;
  case 3: RDI = value; return true;
  case 4: RSI = value; return true;
  case 5: R8 = value; return true;
  case 6: R9 = value; return true;
  case 7: R10 = value; return true;
  default: return false;
  }
}

bool BX_CPU_C::read_poly_aarch64_reg(Bit32u reg, Bit64u *value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg < BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT)
    return bx_poly_read_exchange_window(reg, value);

  switch (reg) {
  case 31:
    *value = 0;
    return true;
  default:
    if (reg < 31) {
      *value = bx_poly_aarch64_x[reg];
      return true;
    }
    return false;
  }
}

bool BX_CPU_C::write_poly_aarch64_reg(Bit32u reg, Bit64u value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg < BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT) {
    if (!bx_poly_write_exchange_window(reg, value))
      return false;
    bx_poly_aarch64_x[reg] = value;
    bx_poly_aarch64_x_valid[reg] = true;
    return true;
  }

  switch (reg) {
  case 31:
    return true;
  default:
    if (reg < 31) {
      bx_poly_aarch64_x[reg] = value;
      bx_poly_aarch64_x_valid[reg] = true;
      return true;
    }
    return false;
  }
}

bool BX_CPU_C::read_poly_riscv_reg(Bit32u reg, Bit64u *value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg >= 10 && reg < 10 + BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT)
    return bx_poly_read_exchange_window(reg - 10, value);

  switch (reg) {
  case 0:
    *value = 0;
    return true;
  case 2:
    *value = RSP;
    return true;
  default:
    if (reg < 32) {
      *value = bx_poly_riscv_x[reg];
      return true;
    }
    return false;
  }
}

bool BX_CPU_C::write_poly_riscv_reg(Bit32u reg, Bit64u value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg >= 10 && reg < 10 + BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT) {
    if (!bx_poly_write_exchange_window(reg - 10, value))
      return false;
    bx_poly_riscv_x[reg] = value;
    bx_poly_riscv_x_valid[reg] = true;
    return true;
  }

  switch (reg) {
  case 0:
    return true;
  case 2:
    RSP = value;
    bx_poly_riscv_x[2] = value;
    bx_poly_riscv_x_valid[2] = true;
    return true;
  default:
    if (reg < 32) {
      bx_poly_riscv_x[reg] = value;
      bx_poly_riscv_x_valid[reg] = true;
      return true;
    }
    return false;
  }
}

bool BX_CPU_C::read_poly_aarch64_fp64_reg(Bit32u reg, Bit64u *value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg < 8) {
    *value = BX_READ_XMM_REG_LO_QWORD(reg);
    return true;
  }
  if (reg < 32) {
    *value = bx_poly_aarch64_fp[reg];
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_aarch64_fp64_reg(Bit32u reg, Bit64u value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg < 8) {
    BX_WRITE_XMM_REG_LO_QWORD(reg, value);
    bx_poly_aarch64_fp[reg] = value;
    return true;
  }
  if (reg < 32) {
    bx_poly_aarch64_fp[reg] = value;
    return true;
  }
  return false;
}

bool BX_CPU_C::read_poly_aarch64_fp128_reg(Bit32u reg, Bit64u *lo, Bit64u *hi)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg < 8) {
    *lo = BX_READ_XMM_REG_LO_QWORD(reg);
    *hi = BX_READ_XMM_REG_HI_QWORD(reg);
    return true;
  }
  if (reg < 32) {
    *lo = bx_poly_aarch64_fp[reg];
    *hi = bx_poly_aarch64_fp_hi[reg];
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_aarch64_fp128_reg(Bit32u reg, Bit64u lo, Bit64u hi)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg < 8) {
    BX_WRITE_XMM_REG_LO_QWORD(reg, lo);
    BX_WRITE_XMM_REG_HI_QWORD(reg, hi);
    bx_poly_aarch64_fp[reg] = lo;
    bx_poly_aarch64_fp_hi[reg] = hi;
    return true;
  }
  if (reg < 32) {
    bx_poly_aarch64_fp[reg] = lo;
    bx_poly_aarch64_fp_hi[reg] = hi;
    return true;
  }
  return false;
}

bool BX_CPU_C::read_poly_riscv_fp64_reg(Bit32u reg, Bit64u *value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg >= 10 && reg <= 17) {
    *value = BX_READ_XMM_REG_LO_QWORD(reg - 10);
    return true;
  }
  if (reg < 32) {
    *value = bx_poly_riscv_fp[reg];
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_riscv_fp64_reg(Bit32u reg, Bit64u value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg >= 10 && reg <= 17) {
    BX_WRITE_XMM_REG_LO_QWORD(reg - 10, value);
    bx_poly_riscv_fp[reg] = value;
    return true;
  }
  if (reg < 32) {
    bx_poly_riscv_fp[reg] = value;
    return true;
  }
  return false;
}

bool BX_CPU_C::read_poly_riscv_fp128_reg(Bit32u reg, Bit64u *lo, Bit64u *hi)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg >= 10 && reg <= 17) {
    unsigned xmm = reg - 10;
    *lo = BX_READ_XMM_REG_LO_QWORD(xmm);
    *hi = BX_READ_XMM_REG_HI_QWORD(xmm);
    return true;
  }
  if (reg < 32) {
    *lo = bx_poly_riscv_fp[reg];
    *hi = bx_poly_riscv_fp_hi[reg];
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_riscv_fp128_reg(Bit32u reg, Bit64u lo, Bit64u hi)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg >= 10 && reg <= 17) {
    unsigned xmm = reg - 10;
    BX_WRITE_XMM_REG_LO_QWORD(xmm, lo);
    BX_WRITE_XMM_REG_HI_QWORD(xmm, hi);
    bx_poly_riscv_fp[reg] = lo;
    bx_poly_riscv_fp_hi[reg] = hi;
    return true;
  }
  if (reg < 32) {
    bx_poly_riscv_fp[reg] = lo;
    bx_poly_riscv_fp_hi[reg] = hi;
    return true;
  }
  return false;
}

bool BX_CPU_C::read_poly_aarch64_fp32_reg(Bit32u reg, Bit32u *value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg < 8) {
    *value = BX_READ_XMM_REG_LO_DWORD(reg);
    return true;
  }
  if (reg < 32) {
    *value = (Bit32u) bx_poly_aarch64_fp[reg];
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_aarch64_fp32_reg(Bit32u reg, Bit32u value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg < 8) {
    BX_WRITE_XMM_REG_LO_DWORD(reg, value);
    bx_poly_aarch64_fp[reg] =
      (bx_poly_aarch64_fp[reg] & BX_CONST64(0xffffffff00000000)) | value;
    return true;
  }
  if (reg < 32) {
    bx_poly_aarch64_fp[reg] =
      (bx_poly_aarch64_fp[reg] & BX_CONST64(0xffffffff00000000)) | value;
    return true;
  }
  return false;
}

bool BX_CPU_C::read_poly_riscv_fp32_reg(Bit32u reg, Bit32u *value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg >= 10 && reg <= 17) {
    *value = BX_READ_XMM_REG_LO_DWORD(reg - 10);
    return true;
  }
  if (reg < 32) {
    *value = (Bit32u) bx_poly_riscv_fp[reg];
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_riscv_fp32_reg(Bit32u reg, Bit32u value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  if (reg >= 10 && reg <= 17) {
    BX_WRITE_XMM_REG_LO_DWORD(reg - 10, value);
    bx_poly_riscv_fp[reg] =
      (bx_poly_riscv_fp[reg] & BX_CONST64(0xffffffff00000000)) | value;
    return true;
  }
  if (reg < 32) {
    bx_poly_riscv_fp[reg] =
      (bx_poly_riscv_fp[reg] & BX_CONST64(0xffffffff00000000)) | value;
    return true;
  }
  return false;
}

bool BX_CPU_C::export_poly_xsave_state(unsigned seg, bx_address base)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  bx_poly_capture_tls_base_for_mode(bx_poly_current_mode);

  for (Bit32u offset = 0; offset < BX_POLY_STATE_XSAVE_BYTES_ARCH; offset += 8)
    write_virtual_qword(seg, base + offset, 0);

  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET,
    (Bit64u) BX_POLY_STATE_XSAVE_MAGIC |
    ((Bit64u) BX_POLY_STATE_XSAVE_LAYOUT_VERSION << 32) |
    (BX_CONST64(0x40) << 48));
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 8,
    (Bit64u) BX_POLY_STATE_XSAVE_BYTES_ARCH |
    ((Bit64u) bx_poly_current_mode << 32));
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 16,
    bx_poly_xsave_arch_flags());
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 24,
    RIP);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 32,
    bx_poly_tls_base_for_mode(bx_poly_current_mode));
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 40,
    bx_poly_trap_vector);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 48,
    bx_poly_trap_vector_mode);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 56,
    bx_poly_monitor_packet_addr);

  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET,
    (Bit64u) bx_poly_last_trap.reason |
    ((Bit64u) bx_poly_last_trap.mode << 32));
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET + 8,
    bx_poly_last_trap.number);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET + 16,
    bx_poly_last_trap.selector);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET + 24,
    bx_poly_last_trap.pc);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET + 32,
    bx_poly_last_trap.next_pc);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET + 40,
    bx_poly_trap_packet_flags());

  for (unsigned n = 0; n < BX_POLY_TRAP_PACKET_ARG_COUNT; n++)
    write_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_TRAP_ARGS_OFFSET + n * 8,
      bx_poly_last_trap.args[n]);

  if (bx_poly_interrupted_raw_valid) {
    write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET,
      bx_poly_interrupted_raw_rip);
    write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET + 8,
      (Bit64u) BX_POLY_MODE_X86 | ((Bit64u) bx_poly_interrupted_raw_mode << 32));
    write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET + 16,
      ((Bit64u) (Bit16u) BX_POLY_TRANSITION_FLAG_INTERRUPTED_RAW << 16));
    write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET + 24,
      0);
  }
  else if (bx_poly_cross_return_top != 0) {
    const bx_poly_cross_return_frame_t *frame =
      &bx_poly_cross_return_stack[bx_poly_cross_return_top - 1];
    write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET,
      frame->return_rip);
    write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET + 8,
      (Bit64u) frame->caller_mode | ((Bit64u) frame->callee_mode << 32));
    write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET + 16,
      (Bit64u) (Bit16u) frame->bridge_kind |
      ((Bit64u) (Bit16u) frame->flags << 16));
    write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET + 24,
      frame->return_rsp);
  }

  for (unsigned n = 0; n < 32; n++) {
    Bit64u value = 0;
    read_poly_aarch64_reg(n, &value);
    write_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_AARCH64_GPR_OFFSET + n * 8, value);
    Bit64u lo = 0, hi = 0;
    read_poly_aarch64_fp128_reg(n, &lo, &hi);
    write_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_AARCH64_FP_OFFSET + n * 16, lo);
    write_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_AARCH64_FP_OFFSET + n * 16 + 8, hi);

    read_poly_riscv_reg(n, &value);
    write_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_RISCV_GPR_OFFSET + n * 8, value);
    read_poly_riscv_fp128_reg(n, &lo, &hi);
    write_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_RISCV_FP_OFFSET + n * 16, lo);
    write_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_RISCV_FP_OFFSET + n * 16 + 8, hi);
  }

  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_AARCH64_STATUS_OFFSET,
    bx_poly_aarch64_nzcv);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_AARCH64_STATUS_OFFSET + 24,
    bx_poly_aarch64_reservation_addr);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_AARCH64_STATUS_OFFSET + 32,
    bx_poly_aarch64_reservation_size);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_RISCV_STATUS_OFFSET + 8,
    bx_poly_riscv_reservation_addr);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_RISCV_STATUS_OFFSET + 16,
    bx_poly_riscv_reservation_size);

  unsigned import_top = bx_poly_import_x86_return_top;
  if (import_top > BX_POLY_IMPORT_RETURN_DEPTH)
    import_top = BX_POLY_IMPORT_RETURN_DEPTH;
  write_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_IMPORT_RETURN_OFFSET, import_top);
  write_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_IMPORT_RETURN_DEPTH_OFFSET,
    BX_POLY_IMPORT_RETURN_DEPTH);
  for (unsigned n = 0; n < import_top; n++) {
    const bx_poly_import_x86_return_frame_t *frame =
      &bx_poly_import_x86_return_stack[n];
    bx_address frame_base =
      base + BX_POLY_STATE_XSAVE_IMPORT_RETURN_FRAMES_OFFSET +
      (bx_address) n * BX_POLY_STATE_XSAVE_IMPORT_RETURN_FRAME_BYTES;
    write_virtual_qword(seg, frame_base,
      (Bit64u) frame->mode | ((Bit64u) (frame->alias_valid ? 1 : 0) << 32));
    write_virtual_qword(seg, frame_base + 8, frame->rip);
    write_virtual_qword(seg, frame_base + 16, frame->rsp);
    write_virtual_qword(seg, frame_base + 24, frame->import_id);
    write_virtual_qword(seg, frame_base + 32,
      frame->return_flags);
    for (unsigned alias = 0; alias < 6; alias++)
      write_virtual_qword(seg, frame_base + 40 + alias * 8,
        frame->alias[alias]);
  }

  write_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_ABI_SIGNATURE_COUNT_OFFSET,
    BX_POLY_ABI_SIGNATURE_SLOT_COUNT);
  for (unsigned n = 0; n < BX_POLY_ABI_SIGNATURE_SLOT_COUNT; n++) {
    write_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_ABI_SIGNATURE_SLOTS_OFFSET + n * 8,
      bx_poly_abi_signature_slots[n].kind);
  }

  unsigned cross_top = bx_poly_cross_return_top;
  if (cross_top > BX_POLY_CROSS_RETURN_DEPTH)
    cross_top = BX_POLY_CROSS_RETURN_DEPTH;
  write_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_CROSS_RETURN_OFFSET, cross_top);
  write_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_CROSS_RETURN_DEPTH_OFFSET,
    BX_POLY_CROSS_RETURN_DEPTH);
  for (unsigned n = 0; n < cross_top; n++) {
    const bx_poly_cross_return_frame_t *frame =
      &bx_poly_cross_return_stack[n];
    bx_address frame_base =
      base + BX_POLY_STATE_XSAVE_CROSS_RETURN_FRAMES_OFFSET +
      (bx_address) n * BX_POLY_STATE_XSAVE_CROSS_RETURN_FRAME_BYTES;
    write_virtual_qword(seg, frame_base, frame->return_rip);
    write_virtual_qword(seg, frame_base + 8, frame->return_rsp);
    write_virtual_qword(seg, frame_base + 16,
      (Bit64u) frame->caller_mode | ((Bit64u) frame->callee_mode << 32));
    write_virtual_qword(seg, frame_base + 24,
      (Bit64u) (Bit16u) frame->bridge_kind |
      ((Bit64u) (Bit16u) frame->flags << 16));
  }

  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_FRONTEND_TLS_OFFSET,
    1);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_FRONTEND_TLS_OFFSET + 8,
    bx_poly_current_mode);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_FRONTEND_TLS_OFFSET + 16,
    bx_poly_aarch64_tls_base);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_FRONTEND_TLS_OFFSET + 24,
    bx_poly_riscv_tls_base);

  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_LANDING_POLICY_OFFSET,
    bx_poly_landing_policy_flags);
  write_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_LANDING_POLICY_OFFSET + 8,
    BX_POLY_LANDING_POLICY_SUPPORTED);

  return true;
}

bool BX_CPU_C::import_poly_xsave_state(unsigned seg, bx_address base)
{
  Bit64u header0 = read_virtual_qword(seg, base);
  Bit64u header1 = read_virtual_qword(seg, base + 8);
  Bit32u magic = (Bit32u) header0;
  Bit32u layout_version = (Bit32u) ((header0 >> 32) & 0xffff);
  Bit32u total_bytes = (Bit32u) header1;
  Bit32u saved_mode = (Bit32u) (header1 >> 32);
  if (magic != BX_POLY_STATE_XSAVE_MAGIC ||
      layout_version != BX_POLY_STATE_XSAVE_LAYOUT_VERSION ||
      total_bytes != BX_POLY_STATE_XSAVE_BYTES_ARCH ||
      !bx_poly_valid_frontend_mode(saved_mode)) {
    BX_INFO(("poly_state_import: reject magic=%08x version=%u bytes=%u mode=%u",
      magic, layout_version, total_bytes, saved_mode));
    return false;
  }

  Bit64u aarch64_gpr[32], aarch64_fp_lo[32], aarch64_fp_hi[32];
  Bit64u riscv_gpr[32], riscv_fp_lo[32], riscv_fp_hi[32];
  bx_poly_abi_signature_slot_t abi_signature_slots[
    BX_POLY_ABI_SIGNATURE_SLOT_COUNT];
  bx_poly_reset_abi_signature_slots(abi_signature_slots);
  bx_poly_cross_return_frame_t cross_return_frames[
    BX_POLY_CROSS_RETURN_DEPTH] = {};
  bx_poly_import_x86_return_frame_t
    import_return_frames[BX_POLY_IMPORT_RETURN_DEPTH] = {};
  Bit64u tls_active_mode = read_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_FRONTEND_TLS_OFFSET + 8);
  if (!bx_poly_valid_frontend_mode((Bit32u) tls_active_mode)) {
    BX_INFO(("poly_state_import: reject TLS active mode=%llu",
      (unsigned long long) tls_active_mode));
    return false;
  }
  bx_address imported_aarch64_tls_base =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_FRONTEND_TLS_OFFSET + 16);
  bx_address imported_riscv_tls_base =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_FRONTEND_TLS_OFFSET + 24);
  Bit64u imported_landing_policy = read_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_LANDING_POLICY_OFFSET);
  if (!bx_poly_valid_landing_policy(imported_landing_policy)) {
    BX_INFO(("poly_state_import: reject landing policy=%llx",
      (unsigned long long) imported_landing_policy));
    return false;
  }
  for (unsigned n = 0; n < 32; n++) {
    aarch64_gpr[n] = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_AARCH64_GPR_OFFSET + n * 8);
    aarch64_fp_lo[n] = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_AARCH64_FP_OFFSET + n * 16);
    aarch64_fp_hi[n] = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_AARCH64_FP_OFFSET + n * 16 + 8);
    riscv_gpr[n] = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_RISCV_GPR_OFFSET + n * 8);
    riscv_fp_lo[n] = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_RISCV_FP_OFFSET + n * 16);
    riscv_fp_hi[n] = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_RISCV_FP_OFFSET + n * 16 + 8);
  }
  riscv_gpr[4] = imported_riscv_tls_base;

  Bit64u import_top64 = read_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_IMPORT_RETURN_OFFSET);
  Bit64u import_depth = read_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_IMPORT_RETURN_DEPTH_OFFSET);
  if (import_top64 > import_depth ||
      import_depth > BX_POLY_IMPORT_RETURN_DEPTH) {
    BX_INFO(("poly_state_import: reject import return top=%llu depth=%llu",
      (unsigned long long) import_top64,
      (unsigned long long) import_depth));
    return false;
  }
  unsigned import_top = (unsigned) import_top64;
  for (unsigned n = 0; n < import_top; n++) {
    bx_address frame_base =
      base + BX_POLY_STATE_XSAVE_IMPORT_RETURN_FRAMES_OFFSET +
      (bx_address) n * BX_POLY_STATE_XSAVE_IMPORT_RETURN_FRAME_BYTES;
    Bit64u mode_alias = read_virtual_qword(seg, frame_base);
    bx_poly_import_x86_return_frame_t *frame = &import_return_frames[n];
    frame->mode = (Bit32u) mode_alias;
    frame->alias_valid = ((mode_alias >> 32) & 1) != 0;
    frame->rip = read_virtual_qword(seg, frame_base + 8);
    frame->rsp = read_virtual_qword(seg, frame_base + 16);
    frame->import_id = read_virtual_qword(seg, frame_base + 24);
    frame->return_flags =
      read_virtual_qword(seg, frame_base + 32);
    const bool direct_x86_frame =
      frame->import_id == BX_POLY_DIRECT_X86_IMPORT_ID;
    if (!bx_poly_is_raw_mode(frame->mode) ||
        (!direct_x86_frame && frame->import_id >= BX_POLY_IMPORT_CALL_COUNT)) {
      BX_INFO(("poly_state_import: reject import return frame %u mode=%u import=%llu",
        n, frame->mode, (unsigned long long) frame->import_id));
      return false;
    }
    for (unsigned alias = 0; alias < 6; alias++)
      frame->alias[alias] =
        read_virtual_qword(seg, frame_base + 40 + alias * 8);
  }

  Bit64u signature_slot_count = read_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_ABI_SIGNATURE_COUNT_OFFSET);
  if (signature_slot_count != BX_POLY_ABI_SIGNATURE_SLOT_COUNT) {
    BX_INFO(("poly_state_import: reject ABI signature slot count=%llu",
      (unsigned long long) signature_slot_count));
    return false;
  }
  for (unsigned n = 0; n < BX_POLY_ABI_SIGNATURE_SLOT_COUNT; n++) {
    Bit64u kind = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_ABI_SIGNATURE_SLOTS_OFFSET + n * 8);
    if (kind > 0xffffffff ||
        !bx_poly_valid_abi_signature_kind((Bit32u) kind)) {
      BX_INFO(("poly_state_import: reject ABI signature slot=%u kind=%llu",
        n, (unsigned long long) kind));
      return false;
    }
    abi_signature_slots[n].kind = (Bit32u) kind;
  }

  Bit64u cross_top64 = read_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_CROSS_RETURN_OFFSET);
  Bit64u cross_depth = read_virtual_qword(seg,
    base + BX_POLY_STATE_XSAVE_CROSS_RETURN_DEPTH_OFFSET);
  if (cross_top64 > cross_depth ||
      cross_depth != BX_POLY_CROSS_RETURN_DEPTH) {
    BX_INFO(("poly_state_import: reject cross return top=%llu depth=%llu",
      (unsigned long long) cross_top64,
      (unsigned long long) cross_depth));
    return false;
  }
  unsigned cross_top = (unsigned) cross_top64;
  for (unsigned n = 0; n < cross_top; n++) {
    bx_address frame_base =
      base + BX_POLY_STATE_XSAVE_CROSS_RETURN_FRAMES_OFFSET +
      (bx_address) n * BX_POLY_STATE_XSAVE_CROSS_RETURN_FRAME_BYTES;
    bx_poly_cross_return_frame_t *frame = &cross_return_frames[n];
    frame->return_rip = read_virtual_qword(seg, frame_base);
    frame->return_rsp = read_virtual_qword(seg, frame_base + 8);
    Bit64u modes = read_virtual_qword(seg, frame_base + 16);
    Bit64u abi_flags = read_virtual_qword(seg, frame_base + 24);
    frame->caller_mode = (Bit32u) modes;
    frame->callee_mode = (Bit32u) (modes >> 32);
    frame->bridge_kind = (Bit32u) (Bit16u) abi_flags;
    frame->flags = (Bit32u) ((abi_flags >> 16) & 0xffff);
    if (!bx_poly_valid_frontend_mode(frame->caller_mode) ||
        !bx_poly_valid_frontend_mode(frame->callee_mode) ||
        frame->bridge_kind > BX_POLY_CROSS_BRIDGE_VEC128_U32) {
      BX_INFO(("poly_state_import: reject cross return frame %u caller=%u callee=%u bridge=%u",
        n, frame->caller_mode, frame->callee_mode, frame->bridge_kind));
      return false;
    }
  }

  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_aarch64_tls_base = imported_aarch64_tls_base;
  bx_poly_riscv_tls_base = imported_riscv_tls_base;
  bx_poly_landing_policy_flags = imported_landing_policy;
  bx_poly_trap_vector =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 40);
  bx_poly_trap_vector_mode = (Bit32u)
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 48);
  if (!bx_poly_valid_frontend_mode(bx_poly_trap_vector_mode))
    bx_poly_trap_vector_mode = BX_POLY_MODE_X86;
  bx_poly_monitor_packet_addr =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_HEADER_OFFSET + 56);

  Bit64u trap0 =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET);
  bx_poly_last_trap.reason = (Bit32u) trap0;
  bx_poly_last_trap.mode = (Bit32u) (trap0 >> 32);
  bx_poly_last_trap.number = (Bit32u)
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET + 8);
  bx_poly_last_trap.selector = (Bit32u)
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET + 16);
  bx_poly_last_trap.pc =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET + 24);
  bx_poly_last_trap.next_pc =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRAP_PACKET_OFFSET + 32);
  for (unsigned n = 0; n < BX_POLY_TRAP_PACKET_ARG_COUNT; n++)
    bx_poly_last_trap.args[n] = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_TRAP_ARGS_OFFSET + n * 8);

  bx_poly_cross_return_top = 0;
  bx_poly_clear_import_x86_return_stack();
  bx_poly_interrupted_raw_valid = false;
  bx_poly_interrupted_raw_mode = BX_POLY_MODE_X86;
  bx_poly_interrupted_raw_rip = 0;
  Bit64u return_pc =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET);
  if (return_pc != 0) {
    Bit64u modes = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET + 8);
    Bit64u abi_flags = read_virtual_qword(seg,
      base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET + 16);
    Bit32u flags = (Bit32u) ((abi_flags >> 16) & 0xffff);
    Bit32u caller_mode = (Bit32u) modes;
    Bit32u target_mode = (Bit32u) (modes >> 32);
    if ((flags & BX_POLY_TRANSITION_FLAG_INTERRUPTED_RAW) != 0) {
      if (caller_mode == BX_POLY_MODE_X86 && bx_poly_is_raw_mode(target_mode)) {
        bx_poly_interrupted_raw_valid = true;
        bx_poly_interrupted_raw_mode = target_mode;
        bx_poly_interrupted_raw_rip = return_pc;
      }
    }
    else if (cross_top == 0) {
      bx_poly_cross_return_frame_t *frame = &bx_poly_cross_return_stack[0];
      frame->return_rip = return_pc;
      frame->return_rsp = read_virtual_qword(seg,
        base + BX_POLY_STATE_XSAVE_TRANSITION_OFFSET + 24);
      frame->caller_mode = caller_mode;
      frame->callee_mode = target_mode;
      frame->bridge_kind = (Bit32u) (Bit16u) abi_flags;
      frame->flags = flags;
      if (bx_poly_valid_frontend_mode(frame->caller_mode) &&
          bx_poly_valid_frontend_mode(frame->callee_mode))
        bx_poly_cross_return_top = 1;
    }
  }
  if (!bx_poly_interrupted_raw_valid && cross_top != 0) {
    bx_poly_cross_return_top = cross_top;
    for (unsigned n = 0; n < bx_poly_cross_return_top; n++)
      bx_poly_cross_return_stack[n] = cross_return_frames[n];
  }

  for (unsigned n = 0; n < 32; n++) {
    bx_poly_aarch64_x[n] = aarch64_gpr[n];
    bx_poly_aarch64_x_valid[n] = true;
    bx_poly_aarch64_fp[n] = aarch64_fp_lo[n];
    bx_poly_aarch64_fp_hi[n] = aarch64_fp_hi[n];
    bx_poly_riscv_x[n] = riscv_gpr[n];
    bx_poly_riscv_x_valid[n] = true;
    bx_poly_riscv_fp[n] = riscv_fp_lo[n];
    bx_poly_riscv_fp_hi[n] = riscv_fp_hi[n];
  }

  if (saved_mode == BX_POLY_MODE_RAW_RISCV) {
    RSP = riscv_gpr[2];
    RAX = riscv_gpr[10];
    RDX = riscv_gpr[11];
    RCX = riscv_gpr[12];
    RDI = riscv_gpr[13];
    RSI = riscv_gpr[14];
    R8 = riscv_gpr[15];
    R9 = riscv_gpr[16];
    R10 = riscv_gpr[17];
    for (unsigned n = 10; n <= 17; n++) {
      unsigned xmm = n - 10;
      BX_WRITE_XMM_REG_LO_QWORD(xmm, riscv_fp_lo[n]);
      BX_WRITE_XMM_REG_HI_QWORD(xmm, riscv_fp_hi[n]);
    }
  }
  else {
    RAX = aarch64_gpr[0];
    RDX = aarch64_gpr[1];
    RCX = aarch64_gpr[2];
    RDI = aarch64_gpr[3];
    RSI = aarch64_gpr[4];
    R8 = aarch64_gpr[5];
    R9 = aarch64_gpr[6];
    R10 = aarch64_gpr[7];
    for (unsigned n = 0; n < 8; n++) {
      BX_WRITE_XMM_REG_LO_QWORD(n, aarch64_fp_lo[n]);
      BX_WRITE_XMM_REG_HI_QWORD(n, aarch64_fp_hi[n]);
    }
    if (saved_mode == BX_POLY_MODE_X86)
      RSP = riscv_gpr[2];
  }

  bx_poly_aarch64_nzcv = (Bit32u)
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_AARCH64_STATUS_OFFSET);
  bx_poly_aarch64_reservation_addr =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_AARCH64_STATUS_OFFSET + 24);
  bx_poly_aarch64_reservation_size = (Bit32u)
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_AARCH64_STATUS_OFFSET + 32);
  bx_poly_aarch64_reservation_valid = bx_poly_aarch64_reservation_size != 0;
  bx_poly_riscv_reservation_addr =
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_RISCV_STATUS_OFFSET + 8);
  bx_poly_riscv_reservation_size = (Bit32u)
    read_virtual_qword(seg, base + BX_POLY_STATE_XSAVE_RISCV_STATUS_OFFSET + 16);
  bx_poly_riscv_reservation_valid = bx_poly_riscv_reservation_size != 0;

  bx_poly_import_x86_return_top = import_top;
  for (unsigned n = 0; n < bx_poly_import_x86_return_top; n++)
    bx_poly_import_x86_return_stack[n] = import_return_frames[n];
  for (unsigned n = 0; n < BX_POLY_ABI_SIGNATURE_SLOT_COUNT; n++)
    bx_poly_abi_signature_slots[n] = abi_signature_slots[n];

  return true;
}

bool BX_CPU_C::xsave_poly_state_xinuse(void)
{
  return BX_CPU_THIS_PTR poly_feature_enabled;
}

void BX_CPU_C::xsave_poly_state(bxInstruction_c *i, bx_address offset)
{
  export_poly_xsave_state(i->seg(), offset);
}

void BX_CPU_C::xrstor_poly_state(bxInstruction_c *i, bx_address offset)
{
  if (!import_poly_xsave_state(i->seg(), offset))
    exception(BX_GP_EXCEPTION, 0);
}

void BX_CPU_C::xrstor_init_poly_state(void)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  bx_poly_reset_current_xstate();
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
}

static bool bx_poly_valid_abi_signature_kind(Bit32u kind)
{
  return kind == BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS_I128 ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_I128 ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_VEC128_U32;
}

static bool bx_poly_register_only_abi_signature_kind(Bit32u kind)
{
  return kind == BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS_I128 ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_I128 ||
    kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_VEC128_U32;
}

static bool bx_poly_cross_bridge_for_abi_signature_kind(Bit32u kind,
  Bit32u *bridge_kind)
{
  if (!bx_poly_valid_abi_signature_kind(kind))
    return false;

  // Foreign-to-foreign signature calls are register-renaming only. AArch64 and
  // RISC-V integer ABI lanes already align as x0/a0 through x7/a7, so the
  // register-only signature kinds select the default cross bridge. The older
  // stack-capable SysV kind is intentionally rejected here; stack or aggregate
  // layout conversion belongs in loader/runtime thunks, not in PCALL.
  if (kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_VEC128_U32) {
    *bridge_kind = BX_POLY_CROSS_BRIDGE_VEC128_U32;
    return true;
  }

  if (bx_poly_register_only_abi_signature_kind(kind)) {
    *bridge_kind = BX_POLY_CROSS_BRIDGE_DEFAULT;
    return true;
  }

  return false;
}

bool BX_CPU_C::enter_poly_abi_call(Bit32u mode, bx_address target_rip,
  bx_address return_rip, bool sret_call, Bit32u return_kind, Bit32u arg_kind,
  Bit32u source_kind, bool copy_foreign_stack_args)
{
  if (!bx_poly_require_landing_target(BX_SEG_REG_CS, target_rip, mode,
        BX_POLY_LANDING_POLICY_REQUIRE_CALL, "x86-pcall"))
    return false;

  Bit64u args[8];
  Bit64u fp_args[8];
  Bit64u fp_args_hi[8];
  bool aarch64_hfa64_sret =
    return_kind == BX_POLY_RETURN_KIND_AARCH64_HFA3_F64 ||
    return_kind == BX_POLY_RETURN_KIND_AARCH64_HFA4_F64;
  bx_address sret_ptr = (sret_call || aarch64_hfa64_sret) ?
    (bx_address) RDI : 0;
  bx_address original_rsp = RSP;
  bx_address foreign_stack_anchor = RSP;
  if (bx_poly_import_x86_return_top != 0) {
    bx_poly_import_x86_return_frame_t *frame =
      &bx_poly_import_x86_return_stack[bx_poly_import_x86_return_top - 1];
    if (bx_poly_is_raw_mode(frame->mode) && frame->rsp != 0)
      foreign_stack_anchor = frame->rsp;
  }
  bx_address foreign_stack_rsp =
    (bx_address) ((foreign_stack_anchor - BX_POLY_FOREIGN_STACK_GAP) &
      ~BX_CONST64(0xf));
  bx_address stack_copy_base = arg_kind == BX_POLY_ARG_KIND_FP64_STACK ?
    original_rsp + 8 : original_rsp + 24;
  if (!bx_poly_valid_abi_signature_kind(source_kind)) {
    BX_INFO(("poly_ud: reject unknown ABI signature kind=%u", source_kind));
    return false;
  }

  if (sret_call) {
    args[0] = RSI;
    args[1] = RDX;
    args[2] = RCX;
    args[3] = R8;
    args[4] = R9;
    args[5] = read_virtual_qword(BX_SEG_REG_SS, RSP + 8);
    args[6] = read_virtual_qword(BX_SEG_REG_SS, RSP + 16);
    args[7] = read_virtual_qword(BX_SEG_REG_SS, RSP + 24);
    stack_copy_base = original_rsp +
      (mode == BX_POLY_MODE_RAW_AARCH64 ? 32 : 24);
  }
  else if (source_kind == BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE) {
    args[0] = RAX;
    args[1] = RDX;
    args[2] = RCX;
    args[3] = RDI;
    args[4] = RSI;
    args[5] = R8;
    args[6] = R9;
    args[7] = R10;
    // The exchange window already carries eight integer arguments. From an
    // x86 SysV caller, the first source stack slot after those eight logical
    // arguments is arg8, which lives at [rsp+24] because arg6 and arg7 are
    // also on the x86 stack but mapped into R9/R10 before PCALL.
    stack_copy_base = original_rsp + 24;
  }
  else if (source_kind == BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS ||
      source_kind == BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS_I128 ||
      source_kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS ||
      source_kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_I128) {
    args[0] = RDI;
    args[1] = RSI;
    args[2] = RDX;
    args[3] = RCX;
    args[4] = R8;
    args[5] = R9;
    args[6] = 0;
    args[7] = 0;
    stack_copy_base = original_rsp + 8;
  }
  else {
    args[0] = RDI;
    args[1] = RSI;
    args[2] = RDX;
    args[3] = RCX;
    args[4] = R8;
    args[5] = R9;
    args[6] = read_virtual_qword(BX_SEG_REG_SS, RSP + 8);
    args[7] = read_virtual_qword(BX_SEG_REG_SS, RSP + 16);
  }
  for (Bit32u n = 0; n < 8; n++) {
    fp_args[n] = BX_READ_XMM_REG_LO_QWORD(n);
    fp_args_hi[n] = BX_READ_XMM_REG_HI_QWORD(n);
  }

  if (copy_foreign_stack_args) {
    for (Bit32u n = 0; n < BX_POLY_FOREIGN_STACK_ARG_QWORDS; n++) {
      Bit64u value = read_virtual_qword(BX_SEG_REG_SS,
        stack_copy_base + n * 8);
      write_virtual_qword(BX_SEG_REG_SS, foreign_stack_rsp + n * 8, value);
    }
  }

  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  if (!bx_poly_push_return_cookie())
    return false;
  bx_poly_current_mode = mode;
  bx_poly_return_cookie_valid = true;
  bx_poly_return_cookie_mode = mode;
  bx_poly_return_cookie_rip = return_rip;
  bx_poly_return_cookie_rsp = original_rsp;
  bx_poly_return_cookie_sret = sret_call;
  bx_poly_return_cookie_sret_ptr = sret_ptr;
  bx_poly_return_cookie_kind = return_kind;
  bx_poly_set_runtime_tls_base((bx_address) R13);
  RSP = foreign_stack_rsp;

  bool mapped = false;
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    // PCALL is a frontend/ABI transition, not a reset of the target ISA.
    // Hardware would preserve the per-thread foreign register file and only
    // overwrite the registers named by the call ABI.
    mapped =
      write_poly_aarch64_reg(0, args[0]) &&
      write_poly_aarch64_reg(1, args[1]) &&
      write_poly_aarch64_reg(2, args[2]) &&
      write_poly_aarch64_reg(3, args[3]) &&
      write_poly_aarch64_reg(4, args[4]) &&
      write_poly_aarch64_reg(5, args[5]) &&
      write_poly_aarch64_reg(6, args[6]) &&
      write_poly_aarch64_reg(7, args[7]) &&
      (!sret_call || write_poly_aarch64_reg(8, sret_ptr)) &&
      write_poly_aarch64_reg(30, BX_POLY_RETURN_COOKIE);
    if (mapped && arg_kind == BX_POLY_ARG_KIND_FPAIR32) {
      Bit32u lo = (Bit32u) fp_args[0];
      Bit32u hi = (Bit32u) (fp_args[0] >> 32);
      mapped =
        write_poly_aarch64_fp32_reg(0, lo) &&
        write_poly_aarch64_fp32_reg(1, hi);
      for (Bit32u n = 1; mapped && n < 7; n++)
        mapped = write_poly_aarch64_fp64_reg(n + 1, fp_args[n]);
    }
    else if (mapped && arg_kind == BX_POLY_ARG_KIND_HETERO_U64_F64) {
      mapped =
        write_poly_aarch64_reg(1, fp_args[0]) &&
        write_poly_aarch64_reg(2, args[1]);
      for (Bit32u n = 2; mapped && n < 7; n++)
        mapped = write_poly_aarch64_reg(n + 1, args[n]);
    }
    else if (mapped && arg_kind == BX_POLY_ARG_KIND_HETERO_F64_U64) {
      mapped =
        write_poly_aarch64_reg(0, fp_args[0]) &&
        write_poly_aarch64_reg(1, args[0]) &&
        write_poly_aarch64_reg(2, args[1]);
      for (Bit32u n = 2; mapped && n < 7; n++)
        mapped = write_poly_aarch64_reg(n + 1, args[n]);
    }
    else if (mapped && arg_kind == BX_POLY_ARG_KIND_HETERO_U64_F32) {
      mapped =
        write_poly_aarch64_reg(1, (Bit32u) fp_args[0]) &&
        write_poly_aarch64_reg(2, args[1]);
      for (Bit32u n = 2; mapped && n < 7; n++)
        mapped = write_poly_aarch64_reg(n + 1, args[n]);
    }
    else if (mapped && arg_kind == BX_POLY_ARG_KIND_HETERO_F32_U64) {
      mapped =
        write_poly_aarch64_reg(0, (Bit32u) fp_args[0]) &&
        write_poly_aarch64_reg(1, args[0]) &&
        write_poly_aarch64_reg(2, args[1]);
      for (Bit32u n = 2; mapped && n < 7; n++)
        mapped = write_poly_aarch64_reg(n + 1, args[n]);
    }
    else if (mapped && arg_kind == BX_POLY_ARG_KIND_VEC128_U32) {
      mapped =
        write_poly_aarch64_fp128_reg(0, fp_args[0], fp_args_hi[0]) &&
        write_poly_aarch64_fp128_reg(1, fp_args[1], fp_args_hi[1]);
    }
    else if (mapped && (arg_kind == BX_POLY_ARG_KIND_AARCH64_HFA3_F64 ||
        arg_kind == BX_POLY_ARG_KIND_AARCH64_HFA4_F64)) {
      mapped =
        write_poly_aarch64_fp64_reg(0,
          read_virtual_qword(BX_SEG_REG_SS, original_rsp + 8)) &&
        write_poly_aarch64_fp64_reg(1,
          read_virtual_qword(BX_SEG_REG_SS, original_rsp + 16)) &&
        write_poly_aarch64_fp64_reg(2,
          read_virtual_qword(BX_SEG_REG_SS, original_rsp + 24));
      if (arg_kind == BX_POLY_ARG_KIND_AARCH64_HFA4_F64)
        mapped = mapped && write_poly_aarch64_fp64_reg(3,
          read_virtual_qword(BX_SEG_REG_SS, original_rsp + 32));
    }
    else if (mapped && (arg_kind == BX_POLY_ARG_KIND_AARCH64_HFA3_F32 ||
        arg_kind == BX_POLY_ARG_KIND_AARCH64_HFA4_F32)) {
      mapped =
        write_poly_aarch64_fp32_reg(0, (Bit32u) fp_args[0]) &&
        write_poly_aarch64_fp32_reg(1, (Bit32u) (fp_args[0] >> 32)) &&
        write_poly_aarch64_fp32_reg(2, (Bit32u) fp_args[1]);
      if (arg_kind == BX_POLY_ARG_KIND_AARCH64_HFA4_F32)
        mapped = mapped &&
          write_poly_aarch64_fp32_reg(3, (Bit32u) (fp_args[1] >> 32));
    }
  }
  else if (mode == BX_POLY_MODE_RAW_RISCV) {
    // Preserve synthetic registers not explicitly overwritten by the psABI
    // argument mapping, matching architectural register-file behavior.
    if (sret_call) {
      mapped =
        write_poly_riscv_reg(4, bx_poly_riscv_tls_base) &&
        write_poly_riscv_reg(10, sret_ptr) &&
        write_poly_riscv_reg(11, args[0]) &&
        write_poly_riscv_reg(12, args[1]) &&
        write_poly_riscv_reg(13, args[2]) &&
        write_poly_riscv_reg(14, args[3]) &&
        write_poly_riscv_reg(15, args[4]) &&
        write_poly_riscv_reg(16, args[5]) &&
        write_poly_riscv_reg(17, args[6]) &&
        write_poly_riscv_reg(1, BX_POLY_RETURN_COOKIE);
    }
    else {
      mapped =
        write_poly_riscv_reg(4, bx_poly_riscv_tls_base) &&
        write_poly_riscv_reg(10, args[0]) &&
        write_poly_riscv_reg(11, args[1]) &&
        write_poly_riscv_reg(12, args[2]) &&
        write_poly_riscv_reg(13, args[3]) &&
        write_poly_riscv_reg(14, args[4]) &&
        write_poly_riscv_reg(15, args[5]) &&
        write_poly_riscv_reg(16, args[6]) &&
        write_poly_riscv_reg(17, args[7]) &&
        write_poly_riscv_reg(1, BX_POLY_RETURN_COOKIE);
    }
    if (mapped && arg_kind == BX_POLY_ARG_KIND_FPAIR32) {
      Bit32u lo = (Bit32u) fp_args[0];
      Bit32u hi = (Bit32u) (fp_args[0] >> 32);
      mapped =
        write_poly_riscv_fp32_reg(10, lo) &&
        write_poly_riscv_fp32_reg(11, hi);
      for (Bit32u n = 1; mapped && n < 7; n++)
        mapped = write_poly_riscv_fp64_reg(10 + n + 1, fp_args[n]);
    }
    else if (mapped && arg_kind == BX_POLY_ARG_KIND_COMPACT_U32_F32) {
      Bit32u int_lane = (Bit32u) args[0];
      Bit32u fp_lane = (Bit32u) (args[0] >> 32);
      mapped =
        write_poly_riscv_reg(10, int_lane) &&
        write_poly_riscv_fp32_reg(10, fp_lane);
    }
    else if (mapped && arg_kind == BX_POLY_ARG_KIND_COMPACT_F32_U32) {
      Bit32u fp_lane = (Bit32u) args[0];
      Bit32u int_lane = (Bit32u) (args[0] >> 32);
      mapped =
        write_poly_riscv_reg(10, int_lane) &&
        write_poly_riscv_fp32_reg(10, fp_lane);
    }
    else if (mapped && arg_kind == BX_POLY_ARG_KIND_FP64_STACK) {
      // RISC-V psABI falls back to integer arg registers after fa0-fa7.
      for (Bit32u n = 0; mapped && n < 8; n++) {
        mapped = write_poly_riscv_reg(10 + n,
          read_virtual_qword(BX_SEG_REG_SS, original_rsp + 8 + n * 8));
      }
    }
    else if (mapped && arg_kind == BX_POLY_ARG_KIND_VEC128_U32) {
      mapped =
        write_poly_riscv_reg(10, fp_args[0]) &&
        write_poly_riscv_reg(11, fp_args_hi[0]) &&
        write_poly_riscv_reg(12, fp_args[1]) &&
        write_poly_riscv_reg(13, fp_args_hi[1]);
    }
  }
  else {
    mapped = false;
  }

  if (!mapped) {
    bx_poly_restore_previous_return_cookie();
    RSP = original_rsp;
    return false;
  }

  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  RIP = target_rip;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  BX_DEBUG(("poly_ud: pcall mode=%u target=%llx return=%llx sret=%u kind=%u arg=%u",
    mode, (unsigned long long) target_rip, (unsigned long long) return_rip,
    sret_call ? 1 : 0, return_kind, arg_kind));
  return true;
}

bool BX_CPU_C::enter_poly_abi_signature_call(Bit32u mode,
  bx_address target_rip, bx_address return_rip, bool sret_call,
  Bit32u return_kind, Bit32u arg_kind, Bit32u slot)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  if (slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT) {
    BX_INFO(("poly_ud: reject ABI signature slot=%u", slot));
    return false;
  }

  Bit32u source_kind = bx_poly_abi_signature_slots[slot].kind;
  if (!bx_poly_valid_abi_signature_kind(source_kind)) {
    BX_INFO(("poly_ud: reject ABI signature slot=%u kind=%u",
      slot, source_kind));
    return false;
  }
  if (source_kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_VEC128_U32 &&
      return_kind == BX_POLY_RETURN_KIND_DEFAULT &&
      arg_kind == BX_POLY_ARG_KIND_DEFAULT) {
    return_kind = BX_POLY_RETURN_KIND_VEC128_U32;
    arg_kind = BX_POLY_ARG_KIND_VEC128_U32;
  }

  BX_DEBUG(("poly_ud: pcall signature mode=%u slot=%u kind=%u target=%llx return=%llx",
    mode, slot, source_kind, (unsigned long long) target_rip,
    (unsigned long long) return_rip));
  // Signature-slot PCALL is the silicon-oriented fast path: it must only
  // switch frontend state and apply register aliases. Memory-side ABI work
  // stays in explicit loader/runtime thunks.
  return enter_poly_abi_call(mode, target_rip, return_rip, sret_call,
    return_kind, arg_kind, source_kind, false);
}

bool BX_CPU_C::return_poly_abi_call(Bit32u mode, bx_address target_rip)
{
  if (!bx_poly_return_cookie_valid ||
      bx_poly_return_cookie_mode != mode ||
      target_rip != (bx_address) BX_POLY_RETURN_COOKIE)
    return false;

  Bit64u second_result = 0;
  bool has_second_result = false;
  Bit64u hetero_f64_u64_fp_result = 0;
  Bit64u hetero_f64_u64_int_result = 0;
  bool has_hetero_f64_u64_result = false;
  Bit32u hetero_f32_result = 0;
  Bit64u hetero_f32_int_result = 0;
  bool has_hetero_f32_result = false;
  Bit64u compact_result = 0;
  bool has_compact_result = false;
  Bit32u fpair32_lo = 0, fpair32_hi = 0;
  bool has_fpair32_result = false;
  Bit64u vec128_lo = 0, vec128_hi = 0;
  bool has_vec128_result = false;
  Bit64u hfa64_result[4] = {};
  bool has_hfa64_result = false;
  Bit32u hfa32_result[4] = {};
  bool has_hfa32_result = false;
  bool sret_call = bx_poly_return_cookie_sret;
  bx_address sret_ptr = bx_poly_return_cookie_sret_ptr;
  bx_address return_rsp = bx_poly_return_cookie_rsp;
  bx_address return_rip = bx_poly_return_cookie_rip;
  Bit32u return_kind = bx_poly_return_cookie_kind;
  if (return_kind == BX_POLY_RETURN_KIND_FPAIR32) {
    if (mode == BX_POLY_MODE_RAW_AARCH64)
      has_fpair32_result =
        read_poly_aarch64_fp32_reg(0, &fpair32_lo) &&
        read_poly_aarch64_fp32_reg(1, &fpair32_hi);
    else if (mode == BX_POLY_MODE_RAW_RISCV)
      has_fpair32_result =
        read_poly_riscv_fp32_reg(10, &fpair32_lo) &&
        read_poly_riscv_fp32_reg(11, &fpair32_hi);
  }
  else if (return_kind == BX_POLY_RETURN_KIND_HETERO_U64_F64 &&
      mode == BX_POLY_MODE_RAW_AARCH64) {
    has_second_result = read_poly_aarch64_reg(1, &second_result);
  }
  else if (return_kind == BX_POLY_RETURN_KIND_HETERO_F64_U64 &&
      mode == BX_POLY_MODE_RAW_AARCH64) {
    has_hetero_f64_u64_result =
      read_poly_aarch64_reg(0, &hetero_f64_u64_fp_result) &&
      read_poly_aarch64_reg(1, &hetero_f64_u64_int_result);
  }
  else if (return_kind == BX_POLY_RETURN_KIND_HETERO_U64_F32 &&
      mode == BX_POLY_MODE_RAW_AARCH64) {
    has_hetero_f32_result =
      read_poly_aarch64_reg(0, &hetero_f32_int_result) &&
      read_poly_aarch64_reg(1, &second_result);
    hetero_f32_result = (Bit32u) second_result;
  }
  else if (return_kind == BX_POLY_RETURN_KIND_HETERO_F32_U64 &&
      mode == BX_POLY_MODE_RAW_AARCH64) {
    has_hetero_f32_result =
      read_poly_aarch64_reg(0, &second_result) &&
      read_poly_aarch64_reg(1, &hetero_f32_int_result);
    hetero_f32_result = (Bit32u) second_result;
  }
  else if (return_kind == BX_POLY_RETURN_KIND_COMPACT_U32_F32 &&
      mode == BX_POLY_MODE_RAW_RISCV) {
    Bit64u int_lane = 0;
    Bit32u fp_lane = 0;
    has_compact_result =
      read_poly_riscv_reg(10, &int_lane) &&
      read_poly_riscv_fp32_reg(10, &fp_lane);
    compact_result = ((Bit64u) fp_lane << 32) | (Bit32u) int_lane;
  }
  else if (return_kind == BX_POLY_RETURN_KIND_COMPACT_F32_U32 &&
      mode == BX_POLY_MODE_RAW_RISCV) {
    Bit64u int_lane = 0;
    Bit32u fp_lane = 0;
    has_compact_result =
      read_poly_riscv_reg(10, &int_lane) &&
      read_poly_riscv_fp32_reg(10, &fp_lane);
    compact_result = ((Bit64u) (Bit32u) int_lane << 32) | fp_lane;
  }
  else if (return_kind == BX_POLY_RETURN_KIND_VEC128_U32 &&
      mode == BX_POLY_MODE_RAW_AARCH64) {
    has_vec128_result = read_poly_aarch64_fp128_reg(0, &vec128_lo,
      &vec128_hi);
  }
  else if (return_kind == BX_POLY_RETURN_KIND_VEC128_U32 &&
      mode == BX_POLY_MODE_RAW_RISCV) {
    has_vec128_result =
      read_poly_riscv_reg(10, &vec128_lo) &&
      read_poly_riscv_reg(11, &vec128_hi);
  }
  else if ((return_kind == BX_POLY_RETURN_KIND_AARCH64_HFA3_F64 ||
      return_kind == BX_POLY_RETURN_KIND_AARCH64_HFA4_F64) &&
      mode == BX_POLY_MODE_RAW_AARCH64) {
    has_hfa64_result =
      read_poly_aarch64_fp64_reg(0, &hfa64_result[0]) &&
      read_poly_aarch64_fp64_reg(1, &hfa64_result[1]) &&
      read_poly_aarch64_fp64_reg(2, &hfa64_result[2]);
    if (return_kind == BX_POLY_RETURN_KIND_AARCH64_HFA4_F64)
      has_hfa64_result = has_hfa64_result &&
        read_poly_aarch64_fp64_reg(3, &hfa64_result[3]);
  }
  else if ((return_kind == BX_POLY_RETURN_KIND_AARCH64_HFA3_F32 ||
      return_kind == BX_POLY_RETURN_KIND_AARCH64_HFA4_F32) &&
      mode == BX_POLY_MODE_RAW_AARCH64) {
    has_hfa32_result =
      read_poly_aarch64_fp32_reg(0, &hfa32_result[0]) &&
      read_poly_aarch64_fp32_reg(1, &hfa32_result[1]) &&
      read_poly_aarch64_fp32_reg(2, &hfa32_result[2]);
    if (return_kind == BX_POLY_RETURN_KIND_AARCH64_HFA4_F32)
      has_hfa32_result = has_hfa32_result &&
        read_poly_aarch64_fp32_reg(3, &hfa32_result[3]);
  }
  else if (mode == BX_POLY_MODE_RAW_AARCH64)
    has_second_result = read_poly_aarch64_reg(1, &second_result);
  else if (mode == BX_POLY_MODE_RAW_RISCV)
    has_second_result = read_poly_riscv_reg(11, &second_result);

  bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_clear_cross_return_stack();
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  RSP = return_rsp;
  RIP = return_rip;
  if (sret_call)
    RAX = sret_ptr;
  else if (has_hfa64_result && sret_ptr != 0) {
    write_virtual_qword(BX_SEG_REG_DS, sret_ptr, hfa64_result[0]);
    write_virtual_qword(BX_SEG_REG_DS, sret_ptr + 8, hfa64_result[1]);
    write_virtual_qword(BX_SEG_REG_DS, sret_ptr + 16, hfa64_result[2]);
    if (return_kind == BX_POLY_RETURN_KIND_AARCH64_HFA4_F64)
      write_virtual_qword(BX_SEG_REG_DS, sret_ptr + 24, hfa64_result[3]);
    RAX = sret_ptr;
  }
  else if (has_fpair32_result) {
    BX_WRITE_XMM_REG_LO_QWORD(0,
      ((Bit64u) fpair32_hi << 32) | (Bit64u) fpair32_lo);
  }
  else if (has_hfa32_result) {
    BX_WRITE_XMM_REG_LO_QWORD(0,
      ((Bit64u) hfa32_result[1] << 32) | hfa32_result[0]);
    BX_WRITE_XMM_REG_LO_QWORD(1,
      ((Bit64u) hfa32_result[3] << 32) | hfa32_result[2]);
  }
  else if (return_kind == BX_POLY_RETURN_KIND_HETERO_U64_F64 &&
      has_second_result) {
    BX_WRITE_XMM_REG_LO_QWORD(0, second_result);
  }
  else if (has_hetero_f64_u64_result) {
    RAX = hetero_f64_u64_int_result;
    BX_WRITE_XMM_REG_LO_QWORD(0, hetero_f64_u64_fp_result);
  }
  else if (has_hetero_f32_result) {
    RAX = hetero_f32_int_result;
    BX_WRITE_XMM_REG_LO_DWORD(0, hetero_f32_result);
  }
  else if (has_compact_result)
    RAX = compact_result;
  else if (has_vec128_result) {
    BX_WRITE_XMM_REG_LO_QWORD(0, vec128_lo);
    BX_WRITE_XMM_REG_HI_QWORD(0, vec128_hi);
  }
  else if (has_second_result)
    RDX = second_result;
  bx_poly_restore_previous_return_cookie();
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  BX_DEBUG(("poly_raw: pcall return mode=%u rip=%llx", mode, (unsigned long long) RIP));
  return true;
}

bool BX_CPU_C::enter_poly_cross_call(Bit32u caller_mode, Bit32u callee_mode,
  bx_address target_rip, bx_address return_rip, Bit32u bridge_kind)
{
  if (bx_poly_cross_return_top >= BX_POLY_CROSS_RETURN_DEPTH)
    return false;
  if (!bx_poly_require_landing_target(BX_SEG_REG_CS, target_rip, callee_mode,
        BX_POLY_LANDING_POLICY_REQUIRE_CALL, "foreign-pcall"))
    return false;

  Bit64u args[8] = {};
  if (bridge_kind != BX_POLY_CROSS_BRIDGE_VEC128_U32) {
    for (Bit32u n = 0; n < 8; n++) {
      bool read_ok = false;
      if (caller_mode == BX_POLY_MODE_RAW_AARCH64)
        read_ok = read_poly_aarch64_reg(n, &args[n]);
      else if (caller_mode == BX_POLY_MODE_RAW_RISCV)
        read_ok = read_poly_riscv_reg(10 + n, &args[n]);
      if (!read_ok)
        return false;
    }
  }

  bool mapped = true;
  if (bridge_kind == BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 &&
      caller_mode == BX_POLY_MODE_RAW_AARCH64 &&
      callee_mode == BX_POLY_MODE_RAW_RISCV) {
    Bit32u int_lane = (Bit32u) args[0];
    Bit32u fp_lane = (Bit32u) (args[0] >> 32);
    mapped =
      write_poly_riscv_reg(10, int_lane) &&
      write_poly_riscv_fp32_reg(10, fp_lane);
    for (Bit32u n = 1; mapped && n < 8; n++)
      mapped = write_poly_riscv_reg(10 + n, args[n]);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32 &&
      caller_mode == BX_POLY_MODE_RAW_AARCH64 &&
      callee_mode == BX_POLY_MODE_RAW_RISCV) {
    Bit32u fp_lane = (Bit32u) args[0];
    Bit32u int_lane = (Bit32u) (args[0] >> 32);
    mapped =
      write_poly_riscv_reg(10, int_lane) &&
      write_poly_riscv_fp32_reg(10, fp_lane);
    for (Bit32u n = 1; mapped && n < 8; n++)
      mapped = write_poly_riscv_reg(10 + n, args[n]);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 &&
      caller_mode == BX_POLY_MODE_RAW_RISCV &&
      callee_mode == BX_POLY_MODE_RAW_AARCH64) {
    Bit64u int_lane = 0;
    Bit32u fp_lane = 0;
    mapped =
      read_poly_riscv_reg(10, &int_lane) &&
      read_poly_riscv_fp32_reg(10, &fp_lane) &&
      write_poly_aarch64_reg(0, ((Bit64u) fp_lane << 32) | (Bit32u) int_lane);
    for (Bit32u n = 1; mapped && n < 8; n++)
      mapped = write_poly_aarch64_reg(n, args[n]);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32 &&
      caller_mode == BX_POLY_MODE_RAW_RISCV &&
      callee_mode == BX_POLY_MODE_RAW_AARCH64) {
    Bit64u int_lane = 0;
    Bit32u fp_lane = 0;
    mapped =
      read_poly_riscv_reg(10, &int_lane) &&
      read_poly_riscv_fp32_reg(10, &fp_lane) &&
      write_poly_aarch64_reg(0, ((Bit64u) (Bit32u) int_lane << 32) | fp_lane);
    for (Bit32u n = 1; mapped && n < 8; n++)
      mapped = write_poly_aarch64_reg(n, args[n]);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_FP64_STACK &&
      caller_mode == BX_POLY_MODE_RAW_AARCH64 &&
      callee_mode == BX_POLY_MODE_RAW_RISCV) {
    // AAPCS64 places FP overflow arguments in stack slots; RV64 psABI uses a0-a7 here.
    for (Bit32u n = 0; mapped && n < 8; n++) {
      mapped = write_poly_riscv_reg(10 + n,
        read_virtual_qword(BX_SEG_REG_SS, RSP + n * 8));
    }
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_FP64_STACK &&
      caller_mode == BX_POLY_MODE_RAW_RISCV &&
      callee_mode == BX_POLY_MODE_RAW_AARCH64) {
    for (Bit32u n = 0; n < 8; n++)
      write_virtual_qword(BX_SEG_REG_SS, RSP + n * 8, args[n]);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_VEC128_U32 &&
      caller_mode == BX_POLY_MODE_RAW_AARCH64 &&
      callee_mode == BX_POLY_MODE_RAW_RISCV) {
    Bit64u v0_lo = 0, v0_hi = 0, v1_lo = 0, v1_hi = 0;
    mapped =
      read_poly_aarch64_fp128_reg(0, &v0_lo, &v0_hi) &&
      read_poly_aarch64_fp128_reg(1, &v1_lo, &v1_hi) &&
      write_poly_riscv_reg(10, v0_lo) &&
      write_poly_riscv_reg(11, v0_hi) &&
      write_poly_riscv_reg(12, v1_lo) &&
      write_poly_riscv_reg(13, v1_hi);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_VEC128_U32 &&
      caller_mode == BX_POLY_MODE_RAW_RISCV &&
      callee_mode == BX_POLY_MODE_RAW_AARCH64) {
    Bit64u v0_lo = 0, v0_hi = 0, v1_lo = 0, v1_hi = 0;
    mapped =
      read_poly_riscv_reg(10, &v0_lo) &&
      read_poly_riscv_reg(11, &v0_hi) &&
      read_poly_riscv_reg(12, &v1_lo) &&
      read_poly_riscv_reg(13, &v1_hi) &&
      write_poly_aarch64_fp128_reg(0, v0_lo, v0_hi) &&
      write_poly_aarch64_fp128_reg(1, v1_lo, v1_hi);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_DEFAULT) {
    for (Bit32u n = 0; mapped && n < 8; n++) {
      if (callee_mode == BX_POLY_MODE_RAW_AARCH64)
        mapped = write_poly_aarch64_reg(n, args[n]);
      else if (callee_mode == BX_POLY_MODE_RAW_RISCV)
        mapped = write_poly_riscv_reg(10 + n, args[n]);
      else
        mapped = false;
    }
  }
  else {
    mapped = false;
  }
  if (!mapped)
    return false;

  bool link_ok = false;
  if (callee_mode == BX_POLY_MODE_RAW_AARCH64)
    link_ok = write_poly_aarch64_reg(30, BX_POLY_CROSS_RETURN_COOKIE);
  else if (callee_mode == BX_POLY_MODE_RAW_RISCV)
    link_ok = write_poly_riscv_reg(1, BX_POLY_CROSS_RETURN_COOKIE);
  if (!link_ok)
    return false;

  bx_poly_cross_return_frame_t *frame =
    &bx_poly_cross_return_stack[bx_poly_cross_return_top++];
  frame->caller_mode = caller_mode;
  frame->callee_mode = callee_mode;
  frame->bridge_kind = bridge_kind;
  frame->return_rip = return_rip;
  frame->return_rsp = RSP;
  frame->flags = 0;
  bx_poly_capture_tls_base_for_mode(caller_mode);
  bx_poly_current_mode = callee_mode;
  bx_poly_prepare_tls_for_mode(callee_mode);
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  RIP = target_rip;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  BX_DEBUG(("poly_raw: cross call caller=%u callee=%u depth=%u target=%llx return=%llx bridge=%u",
    caller_mode, callee_mode, bx_poly_cross_return_top,
    (unsigned long long) target_rip, (unsigned long long) return_rip,
    bridge_kind));
  return true;
}

bool BX_CPU_C::return_poly_cross_call(Bit32u callee_mode, bx_address target_rip)
{
  if (bx_poly_cross_return_top == 0 ||
      target_rip != (bx_address) BX_POLY_CROSS_RETURN_COOKIE)
    return false;

  bx_poly_cross_return_frame_t *frame =
    &bx_poly_cross_return_stack[bx_poly_cross_return_top - 1];
  if (frame->callee_mode != callee_mode)
    return false;
  Bit32u bridge_kind = frame->bridge_kind;

  Bit64u args[8] = {};
  if (bridge_kind != BX_POLY_CROSS_BRIDGE_VEC128_U32) {
    for (Bit32u n = 0; n < 8; n++) {
      bool read_ok = false;
      if (callee_mode == BX_POLY_MODE_RAW_AARCH64)
        read_ok = read_poly_aarch64_reg(n, &args[n]);
      else if (callee_mode == BX_POLY_MODE_RAW_RISCV)
        read_ok = read_poly_riscv_reg(10 + n, &args[n]);
      if (!read_ok)
        return false;
    }
  }

  bool mapped = true;
  if (bridge_kind == BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 &&
      callee_mode == BX_POLY_MODE_RAW_RISCV &&
      frame->caller_mode == BX_POLY_MODE_RAW_AARCH64) {
    Bit64u int_lane = 0;
    Bit32u fp_lane = 0;
    mapped =
      read_poly_riscv_reg(10, &int_lane) &&
      read_poly_riscv_fp32_reg(10, &fp_lane) &&
      write_poly_aarch64_reg(0, ((Bit64u) fp_lane << 32) | (Bit32u) int_lane);
    for (Bit32u n = 1; mapped && n < 8; n++)
      mapped = write_poly_aarch64_reg(n, args[n]);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32 &&
      callee_mode == BX_POLY_MODE_RAW_RISCV &&
      frame->caller_mode == BX_POLY_MODE_RAW_AARCH64) {
    Bit64u int_lane = 0;
    Bit32u fp_lane = 0;
    mapped =
      read_poly_riscv_reg(10, &int_lane) &&
      read_poly_riscv_fp32_reg(10, &fp_lane) &&
      write_poly_aarch64_reg(0, ((Bit64u) (Bit32u) int_lane << 32) | fp_lane);
    for (Bit32u n = 1; mapped && n < 8; n++)
      mapped = write_poly_aarch64_reg(n, args[n]);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 &&
      callee_mode == BX_POLY_MODE_RAW_AARCH64 &&
      frame->caller_mode == BX_POLY_MODE_RAW_RISCV) {
    Bit32u int_lane = (Bit32u) args[0];
    Bit32u fp_lane = (Bit32u) (args[0] >> 32);
    mapped =
      write_poly_riscv_reg(10, int_lane) &&
      write_poly_riscv_fp32_reg(10, fp_lane);
    for (Bit32u n = 1; mapped && n < 8; n++)
      mapped = write_poly_riscv_reg(10 + n, args[n]);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32 &&
      callee_mode == BX_POLY_MODE_RAW_AARCH64 &&
      frame->caller_mode == BX_POLY_MODE_RAW_RISCV) {
    Bit32u fp_lane = (Bit32u) args[0];
    Bit32u int_lane = (Bit32u) (args[0] >> 32);
    mapped =
      write_poly_riscv_reg(10, int_lane) &&
      write_poly_riscv_fp32_reg(10, fp_lane);
    for (Bit32u n = 1; mapped && n < 8; n++)
      mapped = write_poly_riscv_reg(10 + n, args[n]);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_DEFAULT ||
      bridge_kind == BX_POLY_CROSS_BRIDGE_FP64_STACK) {
    for (Bit32u n = 0; mapped && n < 8; n++) {
      if (frame->caller_mode == BX_POLY_MODE_RAW_AARCH64)
        mapped = write_poly_aarch64_reg(n, args[n]);
      else if (frame->caller_mode == BX_POLY_MODE_RAW_RISCV)
        mapped = write_poly_riscv_reg(10 + n, args[n]);
      else
        mapped = false;
    }
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_VEC128_U32 &&
      callee_mode == BX_POLY_MODE_RAW_RISCV &&
      frame->caller_mode == BX_POLY_MODE_RAW_AARCH64) {
    Bit64u v0_lo = 0, v0_hi = 0;
    mapped =
      read_poly_riscv_reg(10, &v0_lo) &&
      read_poly_riscv_reg(11, &v0_hi) &&
      write_poly_aarch64_fp128_reg(0, v0_lo, v0_hi);
  }
  else if (bridge_kind == BX_POLY_CROSS_BRIDGE_VEC128_U32 &&
      callee_mode == BX_POLY_MODE_RAW_AARCH64 &&
      frame->caller_mode == BX_POLY_MODE_RAW_RISCV) {
    Bit64u v0_lo = 0, v0_hi = 0;
    mapped =
      read_poly_aarch64_fp128_reg(0, &v0_lo, &v0_hi) &&
      write_poly_riscv_reg(10, v0_lo) &&
      write_poly_riscv_reg(11, v0_hi);
  }
  else {
    mapped = false;
  }
  if (!mapped)
    return false;

  bx_poly_capture_tls_base_for_mode(callee_mode);
  bx_poly_current_mode = frame->caller_mode;
  bx_poly_prepare_tls_for_mode(frame->caller_mode);
  RIP = frame->return_rip;
  bx_poly_cross_return_top--;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  BX_DEBUG(("poly_raw: cross return callee=%u mode=%u depth=%u rip=%llx bridge=%u",
    callee_mode, bx_poly_current_mode, bx_poly_cross_return_top,
    (unsigned long long) RIP, bridge_kind));
  return true;
}

bool BX_CPU_C::return_poly_import_x86_call(void)
{
  if (bx_poly_import_x86_return_top == 0)
    return false;

  bx_poly_import_x86_return_frame_t frame =
    bx_poly_import_x86_return_stack[bx_poly_import_x86_return_top - 1];
  Bit32u return_mode = frame.mode;
  bx_address return_rip = frame.rip;
  bx_address return_rsp = frame.rsp;
  Bit64u import_id = frame.import_id;
  const Bit64u return_flags = frame.return_flags;
  const bool returns_i128 =
    (return_flags & BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_I128) != 0;
  const bool returns_fp128 =
    (return_flags & BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FP128) != 0;
  const bool returns_fp64 =
    (return_flags & BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FP64) != 0;
  const bool returns_fp32 =
    (return_flags & BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FP32) != 0;
  const bool returns_fpair64 =
    (return_flags & BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FPAIR64) != 0;
  const bool returns_fpair32 =
    (return_flags & BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_FPAIR32) != 0;
  const bool returns_vec128 =
    (return_flags & BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_VEC128) != 0;
  const Bit64u result_rax = RAX;
  const Bit64u result_rdx = RDX;
  const Bit64u result_xmm0_lo = BX_READ_XMM_REG_LO_QWORD(0);
  const Bit64u result_xmm0_hi = BX_READ_XMM_REG_HI_QWORD(0);
  const Bit64u result_xmm1_lo = BX_READ_XMM_REG_LO_QWORD(1);

  bx_poly_current_mode = return_mode;
  bx_poly_prepare_tls_for_mode(return_mode);
  RIP = return_rip;
  RSP = return_rsp;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  if (frame.alias_valid) {
    RDI = frame.alias[0];
    RSI = frame.alias[1];
    RDX = frame.alias[2];
    RCX = frame.alias[3];
    R8 = frame.alias[4];
    R9 = frame.alias[5];
  }

  bool mapped = false;
  if (return_mode == BX_POLY_MODE_RAW_AARCH64 && returns_vec128) {
    mapped = write_poly_aarch64_fp128_reg(0, result_xmm0_lo, result_xmm0_hi);
  }
  else if (return_mode == BX_POLY_MODE_RAW_AARCH64 && returns_fpair32) {
    mapped = write_poly_aarch64_fp32_reg(0, (Bit32u) result_xmm0_lo) &&
      write_poly_aarch64_fp32_reg(1, (Bit32u) (result_xmm0_lo >> 32));
  }
  else if (return_mode == BX_POLY_MODE_RAW_AARCH64 && returns_fpair64) {
    mapped = write_poly_aarch64_fp64_reg(0, result_xmm0_lo) &&
      write_poly_aarch64_fp64_reg(1, result_xmm1_lo);
  }
  else if (return_mode == BX_POLY_MODE_RAW_AARCH64 && returns_fp128) {
    mapped = write_poly_aarch64_fp128_reg(0, result_xmm0_lo, result_xmm0_hi);
  }
  else if (return_mode == BX_POLY_MODE_RAW_AARCH64 && returns_fp64) {
    mapped = write_poly_aarch64_fp64_reg(0, result_xmm0_lo);
  }
  else if (return_mode == BX_POLY_MODE_RAW_AARCH64 && returns_fp32) {
    mapped = write_poly_aarch64_fp32_reg(0, (Bit32u) result_xmm0_lo);
  }
  else if (return_mode == BX_POLY_MODE_RAW_AARCH64) {
    mapped = write_poly_aarch64_reg(0, result_rax);
    if (mapped && returns_i128)
      mapped = write_poly_aarch64_reg(1, result_rdx);
  }
  else if (return_mode == BX_POLY_MODE_RAW_RISCV && returns_vec128) {
    mapped = write_poly_riscv_reg(10, result_xmm0_lo) &&
      write_poly_riscv_reg(11, result_xmm0_hi);
  }
  else if (return_mode == BX_POLY_MODE_RAW_RISCV && returns_fpair32) {
    mapped = write_poly_riscv_fp32_reg(10, (Bit32u) result_xmm0_lo) &&
      write_poly_riscv_fp32_reg(11, (Bit32u) (result_xmm0_lo >> 32));
  }
  else if (return_mode == BX_POLY_MODE_RAW_RISCV && returns_fpair64) {
    mapped = write_poly_riscv_fp64_reg(10, result_xmm0_lo) &&
      write_poly_riscv_fp64_reg(11, result_xmm1_lo);
  }
  else if (return_mode == BX_POLY_MODE_RAW_RISCV && returns_fp128) {
    mapped = write_poly_riscv_reg(10, result_xmm0_lo) &&
      write_poly_riscv_reg(11, result_xmm0_hi);
  }
  else if (return_mode == BX_POLY_MODE_RAW_RISCV && returns_fp64) {
    mapped = write_poly_riscv_fp64_reg(10, result_xmm0_lo);
  }
  else if (return_mode == BX_POLY_MODE_RAW_RISCV && returns_fp32) {
    mapped = write_poly_riscv_fp32_reg(10, (Bit32u) result_xmm0_lo);
  }
  else if (return_mode == BX_POLY_MODE_RAW_RISCV) {
    mapped = write_poly_riscv_reg(10, result_rax);
    if (mapped && returns_i128)
      mapped = write_poly_riscv_reg(11, result_rdx);
  }
  else if (return_mode == BX_POLY_MODE_X86) {
    mapped = true;
  }

  if (!mapped)
    return false;

  bx_poly_import_x86_return_top--;
  bx_poly_reset_import_x86_return_frame(
    &bx_poly_import_x86_return_stack[bx_poly_import_x86_return_top]);
  if (return_poly_abi_call(return_mode, return_rip))
    return true;
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  if (import_id == BX_POLY_DIRECT_X86_IMPORT_ID) {
    BX_DEBUG(("poly_raw: direct x86 return mode=%u result=%llu high=%llu rip=%llx",
      bx_poly_current_mode, (unsigned long long) result_rax,
      (unsigned long long) result_rdx, (unsigned long long) RIP));
  }
  else {
    BX_DEBUG(("poly_raw: import x86 return mode=%u import=%u result=%llu high=%llu rip=%llx",
      bx_poly_current_mode, (unsigned) import_id,
      (unsigned long long) result_rax,
      (unsigned long long) result_rdx, (unsigned long long) RIP));
  }
  return true;
}

bool BX_CPU_C::handle_poly_x86_ret_cookie(bx_address target_rip)
{
  if (target_rip != (bx_address) BX_POLY_RETURN_COOKIE)
    return false;

  return return_poly_import_x86_call();
}

bool BX_CPU_C::enter_poly_x86_direct_call(Bit32u mode, bx_address target_rip,
  bx_address return_rip, Bit32u source_kind)
{
  if (target_rip >= (bx_address) BX_POLY_IMPORT_CALL_BASE)
    return false;
  if (!bx_poly_require_landing_target(BX_SEG_REG_CS, target_rip,
        BX_POLY_MODE_X86, BX_POLY_LANDING_POLICY_REQUIRE_CALL,
        "direct-x86-pcall"))
    return false;
  if (!bx_poly_valid_abi_signature_kind(source_kind)) {
    BX_INFO(("poly_raw: reject direct x86 call source kind=%u", source_kind));
    return false;
  }

  Bit64u args[8] = {};
  bool mapped = true;
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    for (Bit32u n = 0; mapped && n < 8; n++)
      mapped = read_poly_aarch64_reg(n, &args[n]);
  }
  else if (mode == BX_POLY_MODE_RAW_RISCV) {
    for (Bit32u n = 0; mapped && n < 8; n++)
      mapped = read_poly_riscv_reg(10 + n, &args[n]);
  }
  else if (mode == BX_POLY_MODE_X86) {
    if (source_kind == BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE) {
      args[0] = RAX;
      args[1] = RDX;
      args[2] = RCX;
      args[3] = RDI;
      args[4] = RSI;
      args[5] = R8;
      args[6] = R9;
      args[7] = R10;
    }
    else {
      args[0] = RDI;
      args[1] = RSI;
      args[2] = RDX;
      args[3] = RCX;
      args[4] = R8;
      args[5] = R9;
    }
  }
  else {
    mapped = false;
  }

  if (!mapped)
    return false;

  bx_address foreign_rsp = RSP;
  bx_address x86_stack_base = bx_poly_return_cookie_valid ?
    bx_poly_return_cookie_rsp : RSP;
  if (x86_stack_base < 24)
    return false;

  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(foreign_rsp));
  if (bx_poly_import_x86_return_top >= BX_POLY_IMPORT_RETURN_DEPTH)
    return false;

  bx_poly_import_x86_return_frame_t *frame =
    &bx_poly_import_x86_return_stack[bx_poly_import_x86_return_top++];
  frame->mode = mode;
  frame->rip = return_rip;
  frame->rsp = foreign_rsp;
  frame->import_id = BX_POLY_DIRECT_X86_IMPORT_ID;
  frame->return_flags =
    source_kind == BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS_I128 ||
    source_kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_I128 ?
      BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_I128 : 0;
  if (source_kind == BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_VEC128_U32)
    frame->return_flags |= BX_POLY_IMPORT_X86_DESCRIPTOR_RETURN_VEC128;
  frame->alias_valid = true;
  frame->alias[0] = RDI;
  frame->alias[1] = RSI;
  frame->alias[2] = RDX;
  frame->alias[3] = RCX;
  frame->alias[4] = R8;
  frame->alias[5] = R9;

  // User-space ABI thunks need the source stack for overflow arguments.
  // R11 is volatile in the x86_64 SysV ABI, so exposing it here does not add
  // callee-visible preserved state or descriptor parsing to the CPU path.
  R11 = foreign_rsp;

  if (source_kind == BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE) {
    RAX = args[0];
    RDX = args[1];
    RCX = args[2];
    RDI = args[3];
    RSI = args[4];
    R8 = args[5];
    R9 = args[6];
    R10 = args[7];
  }
  else {
    RDI = args[0];
    RSI = args[1];
    RDX = args[2];
    RCX = args[3];
    R8 = args[4];
    R9 = args[5];
  }

  bx_address x86_rsp = ((x86_stack_base - 16) & ~BX_CONST64(0xf)) + 8;
  if (x86_rsp + 8 > x86_stack_base)
    return false;
  write_virtual_qword(BX_SEG_REG_SS, x86_rsp,
    (Bit64u) BX_POLY_RETURN_COOKIE);

  BX_DEBUG(("poly_raw: direct x86 call mode=%u kind=%u target=%llx stack=%llx arg0=%llu arg1=%llu arg2=%llu arg3=%llu arg4=%llu arg5=%llu return=%llx",
    mode, source_kind, (unsigned long long) target_rip,
    (unsigned long long) x86_rsp,
    (unsigned long long) args[0], (unsigned long long) args[1],
    (unsigned long long) args[2], (unsigned long long) args[3],
    (unsigned long long) args[4], (unsigned long long) args[5],
    (unsigned long long) return_rip));

  bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  RIP = target_rip;
  RSP = x86_rsp;
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  return true;
}

void BX_CPU_C::poly_interrupt_enter(void)
{
  if (!BX_CPU_THIS_PTR poly_feature_enabled || CPL != 3)
    return;

  bx_address stack_key = bx_poly_current_state_key(RSP);
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
  if (!bx_poly_is_raw_mode(bx_poly_current_mode))
    return;

  bx_poly_interrupted_raw_valid = true;
  bx_poly_interrupted_raw_mode = bx_poly_current_mode;
  bx_poly_interrupted_raw_rip = RIP;
  bx_poly_save_current_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);

  bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
  bx_poly_loaded_reg_state_valid = false;
  BX_DEBUG(("poly_raw: interrupt enter mode=%u rip=%llx",
    bx_poly_interrupted_raw_mode, (unsigned long long) bx_poly_interrupted_raw_rip));
}

void BX_CPU_C::poly_restore_raw_return_to_user(const char *source)
{
  if (!BX_CPU_THIS_PTR poly_feature_enabled || CPL != 3)
    return;

  bx_address stack_key = bx_poly_current_state_key(RSP);
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
  if (!bx_poly_interrupted_raw_valid ||
      !bx_poly_is_raw_mode(bx_poly_interrupted_raw_mode) ||
      bx_poly_interrupted_raw_rip != RIP)
    return;

  bx_poly_current_mode = bx_poly_interrupted_raw_mode;
  bx_poly_interrupted_raw_valid = false;
  bx_poly_interrupted_raw_mode = BX_POLY_MODE_X86;
  bx_poly_interrupted_raw_rip = 0;
  bx_poly_restore_aliased_state(bx_poly_current_mode);
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  BX_DEBUG(("poly_raw: %s restore mode=%u rip=%llx",
    source, bx_poly_current_mode, (unsigned long long) RIP));
}

void BX_CPU_C::poly_iret_return_to_user(void)
{
  poly_restore_raw_return_to_user("iret");
}

void BX_CPU_C::poly_sysret_return_to_user(void)
{
  poly_restore_raw_return_to_user("sysret");
}

void BX_CPU_C::poly_sysexit_return_to_user(void)
{
  poly_restore_raw_return_to_user("sysexit");
}

bool BX_CPU_C::handle_poly_import_call(Bit32u mode, bx_address target_rip,
  bx_address return_rip)
{
  if (target_rip < (bx_address) BX_POLY_IMPORT_CALL_BASE)
    return false;

  Bit64u target_offset = (Bit64u) target_rip - BX_POLY_IMPORT_CALL_BASE;
  if ((target_offset % BX_POLY_IMPORT_CALL_STRIDE) != 0)
    return false;

  Bit32u import_id = (Bit32u) (target_offset / BX_POLY_IMPORT_CALL_STRIDE);
  if (import_id >= BX_POLY_IMPORT_CALL_COUNT)
    return false;

  Bit64u arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0;
  Bit64u arg6 = 0, arg7 = 0;
  bool mapped = false;
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    mapped = read_poly_aarch64_reg(0, &arg0) &&
      read_poly_aarch64_reg(1, &arg1) &&
      read_poly_aarch64_reg(2, &arg2) &&
      read_poly_aarch64_reg(3, &arg3) &&
      read_poly_aarch64_reg(4, &arg4) &&
      read_poly_aarch64_reg(5, &arg5);
  }
  else if (mode == BX_POLY_MODE_RAW_RISCV) {
    mapped = read_poly_riscv_reg(10, &arg0) &&
      read_poly_riscv_reg(11, &arg1) &&
      read_poly_riscv_reg(12, &arg2) &&
      read_poly_riscv_reg(13, &arg3) &&
      read_poly_riscv_reg(14, &arg4) &&
      read_poly_riscv_reg(15, &arg5);
  }

  if (!mapped)
    return false;

  if (bx_poly_import_delivers_trap(import_id)) {
    // Hardware/FPGA contract: reserved import calls are architectural exits.
    // The CPU records the import id and native ABI arguments; software decides
    // whether this is dynamic binding, libc policy, a generated thunk, or an
    // application fault. The transition path must not read user-memory
    // descriptors or rewrite stack layouts.
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_reg(6, &arg6) &&
        read_poly_aarch64_reg(7, &arg7);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_reg(16, &arg6) &&
        read_poly_riscv_reg(17, &arg7);
    }
    if (!mapped)
      return false;
    bx_poly_record_import_trap(mode, import_id, target_rip, return_rip,
      arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    BX_INFO(("poly_raw: import %u unresolved; delivering import trap",
      (unsigned) import_id));
    return deliver_poly_architectural_trap("foreign", "import", target_rip);
  }
  return false;
}

bool BX_CPU_C::poly_raw_mode_active(void)
{
  if (!BX_CPU_THIS_PTR poly_feature_enabled || CPL != 3)
    return false;

  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
  return bx_poly_is_raw_mode(bx_poly_current_mode);
}

bool BX_CPU_C::execute_poly_raw_aarch64(Bit32u insn, bx_address pc)
{
  bx_address next_rip = pc + 4;

  if (insn == 0xd503305f) {
    bx_poly_aarch64_reservation_valid = false;
    bx_poly_aarch64_reservation_addr = 0;
    bx_poly_aarch64_reservation_size = 0;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 clrex"));
    return true;
  }

  {
    const char *hint_name = bx_poly_aarch64_hint_name(insn);
    if (hint_name != 0) {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s as no-op", hint_name));
      return true;
    }
  }

  if ((insn & 0xffffffe0) == 0xd53bd040) {
    Bit32u rd = insn & 0x1f;
    if (!write_poly_aarch64_reg(rd, bx_poly_aarch64_tls_base))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 mrs x%u,tpidr_el0 value=%llx",
      rd, (unsigned long long) bx_poly_aarch64_tls_base));
    return true;
  }

  {
    const char *barrier_name = bx_poly_aarch64_barrier_name(insn);
    if (barrier_name != 0) {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s as x86-tso no-op", barrier_name));
      return true;
    }
  }

  if ((insn & 0xffefbc00) == 0x6e080400) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u dst_lane = (insn >> 20) & 1;
    Bit32u src_lane = (insn >> 14) & 1;
    Bit64u src_lo = 0, src_hi = 0, dst_lo = 0, dst_hi = 0;
    if (!read_poly_aarch64_fp128_reg(rn, &src_lo, &src_hi) ||
        !read_poly_aarch64_fp128_reg(rd, &dst_lo, &dst_hi))
      return false;
    Bit64u value = src_lane ? src_hi : src_lo;
    if (dst_lane)
      dst_hi = value;
    else
      dst_lo = value;
    if (!write_poly_aarch64_fp128_reg(rd, dst_lo, dst_hi))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 mov v%u.d[%u],v%u.d[%u]",
      rd, dst_lane, rn, src_lane));
    return true;
  }

  if ((insn & 0xffe08400) == 0x6e000400) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u dst_lane = ((insn >> 16) & 0x1f) >> 3;
    Bit32u src_lane = ((insn >> 11) & 0x0f) >> 2;
    if (dst_lane > 3 || src_lane > 3)
      return false;
    Bit64u src_lo = 0, src_hi = 0, dst_lo = 0, dst_hi = 0;
    if (!read_poly_aarch64_fp128_reg(rn, &src_lo, &src_hi) ||
        !read_poly_aarch64_fp128_reg(rd, &dst_lo, &dst_hi))
      return false;
    Bit64u src_qword = src_lane < 2 ? src_lo : src_hi;
    Bit32u value = (Bit32u) (src_qword >> ((src_lane & 1) * 32));
    Bit64u *dst_qword = dst_lane < 2 ? &dst_lo : &dst_hi;
    Bit32u shift = (dst_lane & 1) * 32;
    *dst_qword = (*dst_qword & ~(BX_CONST64(0xffffffff) << shift)) |
      ((Bit64u) value << shift);
    if (!write_poly_aarch64_fp128_reg(rd, dst_lo, dst_hi))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 mov v%u.s[%u],v%u.s[%u]",
      rd, dst_lane, rn, src_lane));
    return true;
  }

  if ((insn & 0xffe0fc00) == 0x4e000c00 ||
      (insn & 0xffe0fc00) == 0x0e000c00) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u imm5 = (insn >> 16) & 0x1f;
    bool q = (insn & 0x40000000) != 0;
    Bit32u element_bits = 0;
    Bit64u source = 0;
    Bit64u lo = 0, hi = 0;

    if (imm5 & 0x01)
      element_bits = 8;
    else if (imm5 & 0x02)
      element_bits = 16;
    else if (imm5 & 0x04)
      element_bits = 32;
    else if (imm5 & 0x08)
      element_bits = 64;
    else
      return false;

    if (!read_poly_aarch64_reg(rn, &source))
      return false;

    Bit64u value = source;
    if (element_bits < 64)
      value &= (BX_CONST64(1) << element_bits) - 1;

    Bit32u lanes = (q ? 128 : 64) / element_bits;
    for (Bit32u lane = 0; lane < lanes; lane++) {
      Bit32u bit_offset = lane * element_bits;
      Bit64u *qword = bit_offset < 64 ? &lo : &hi;
      Bit32u shift = bit_offset & 63;
      *qword |= value << shift;
    }

    if (!write_poly_aarch64_fp128_reg(rd, lo, hi))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 dup v%u.%u-bit,%c%u value=%llu",
      rd, element_bits, element_bits == 64 ? 'x' : 'w', rn,
      (unsigned long long) value));
    return true;
  }

  if ((insn & 0xffe0fc00) == 0x4e60d400) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit64u left_lo = 0, left_hi = 0, right_lo = 0, right_hi = 0;
    if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
        !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
      return false;
    Bit64u result_lo = bx_poly_fp64_to_bits(
      bx_poly_fp64_from_bits(left_lo) + bx_poly_fp64_from_bits(right_lo));
    Bit64u result_hi = bx_poly_fp64_to_bits(
      bx_poly_fp64_from_bits(left_hi) + bx_poly_fp64_from_bits(right_hi));
    if (!write_poly_aarch64_fp128_reg(rd, result_lo, result_hi))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 fadd v%u.2d,v%u.2d,v%u.2d",
      rd, rn, rm));
    return true;
  }

  if ((insn & ~(Bit32u)(0x1f | (0x1f << 5))) == 0x5ef1b800) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit64u lo = 0, hi = 0;
    if (!read_poly_aarch64_fp128_reg(rn, &lo, &hi))
      return false;
    if (!write_poly_aarch64_fp64_reg(rd, lo + hi))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 addp d%u,v%u.2d result=%llu",
      rd, rn, (unsigned long long) (lo + hi)));
    return true;
  }

  if ((insn & 0xbfe0fc00) == 0x0e003c00) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u imm5 = (insn >> 16) & 0x1f;
    Bit32u size = 0;
    if (imm5 & 0x01)
      size = 8;
    else if (imm5 & 0x02)
      size = 16;
    else if (imm5 & 0x04)
      size = 32;
    else if (imm5 & 0x08)
      size = 64;
    else
      return false;
    Bit32u lane = imm5 >> (size == 8 ? 1 : size == 16 ? 2 : size == 32 ? 3 : 4);
    if (lane >= 128 / size)
      return false;
    Bit64u lo = 0, hi = 0;
    if (!read_poly_aarch64_fp128_reg(rn, &lo, &hi))
      return false;
    Bit32u bit_offset = lane * size;
    Bit64u qword = bit_offset < 64 ? lo : hi;
    Bit32u qword_shift = bit_offset & 63;
    Bit64u value = qword >> qword_shift;
    if (size < 64)
      value &= (BX_CONST64(1) << size) - 1;
    if (!write_poly_aarch64_reg(rd, value))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 umov %c%u,v%u.%u[%u] value=%llu",
      size == 64 ? 'x' : 'w', rd, rn, size, lane,
      (unsigned long long) value));
    return true;
  }

  if ((insn & 0xbfe0fc00) == 0x0e20d400) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u lanes = (insn & 0x40000000) ? 4 : 2;
    Bit64u left_lo = 0, left_hi = 0, right_lo = 0, right_hi = 0;
    Bit64u result_lo = 0, result_hi = 0;
    softfloat_status_t status = bx_poly_softfloat_status();
    if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
        !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
      return false;
    for (Bit32u lane = 0; lane < lanes; lane++) {
      Bit64u left_qword = lane < 2 ? left_lo : left_hi;
      Bit64u right_qword = lane < 2 ? right_lo : right_hi;
      Bit32u shift = (lane & 1) * 32;
      Bit32u left = (Bit32u) (left_qword >> shift);
      Bit32u right = (Bit32u) (right_qword >> shift);
      Bit64u *result_qword = lane < 2 ? &result_lo : &result_hi;
      *result_qword |= (Bit64u) f32_add(left, right, &status) << shift;
    }
    if (!write_poly_aarch64_fp128_reg(rd, result_lo, result_hi))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 fadd v%u.%us,v%u.%us,v%u.%us",
      rd, lanes, rn, lanes, rm, lanes));
    return true;
  }

  if ((insn & 0x9ff80c00) == 0x0f000400) {
    Bit32u rd = insn & 0x1f;
    Bit32u imm8 = (((insn >> 16) & 0x7) << 5) | ((insn >> 5) & 0x1f);
    Bit32u cmode = (insn >> 12) & 0xf;
    bool q = (insn & 0x40000000) != 0;
    bool op = (insn & 0x20000000) != 0;
    Bit32u element_bits = 0;
    Bit64u element = 0;
    Bit64u lo = 0, hi = 0;
    const char *shape = 0;
    const char *op_name = "movi";
    bool read_dest = false;
    bool invert_element = false;
    bool or_dest = false;
    bool bic_dest = false;

    if (!op && cmode == 14) {
      element_bits = 8;
      element = imm8;
      shape = q ? "16b" : "8b";
    }
    else if (!op && (cmode == 8 || cmode == 10)) {
      element_bits = 16;
      element = (Bit64u) imm8 << ((cmode == 10) ? 8 : 0);
      shape = q ? "8h" : "4h";
    }
    else if (op && (cmode == 8 || cmode == 10)) {
      element_bits = 16;
      element = (Bit64u) imm8 << ((cmode == 10) ? 8 : 0);
      shape = q ? "8h" : "4h";
      invert_element = true;
      op_name = "mvni";
    }
    else if ((cmode == 9 || cmode == 11)) {
      element_bits = 16;
      element = (Bit64u) imm8 << ((cmode == 11) ? 8 : 0);
      shape = q ? "8h" : "4h";
      read_dest = true;
      if (op) {
        bic_dest = true;
        op_name = "bic";
      }
      else {
        or_dest = true;
        op_name = "orr";
      }
    }
    else if (!op && (cmode & 1) == 0 && cmode < 8) {
      element_bits = 32;
      element = (Bit64u) imm8 << (8 * (cmode >> 1));
      shape = q ? "4s" : "2s";
    }
    else if (op && (cmode & 1) == 0 && cmode < 8) {
      element_bits = 32;
      element = (Bit64u) imm8 << (8 * (cmode >> 1));
      shape = q ? "4s" : "2s";
      invert_element = true;
      op_name = "mvni";
    }
    else if ((cmode & 1) == 1 && cmode < 8) {
      element_bits = 32;
      element = (Bit64u) imm8 << (8 * (cmode >> 1));
      shape = q ? "4s" : "2s";
      read_dest = true;
      if (op) {
        bic_dest = true;
        op_name = "bic";
      }
      else {
        or_dest = true;
        op_name = "orr";
      }
    }
    else if (op && q && cmode == 14) {
      element_bits = 64;
      for (Bit32u n = 0; n < 8; n++) {
        if (imm8 & (1u << n))
          element |= BX_CONST64(0xff) << (n * 8);
      }
      shape = "2d";
    }
    else {
      return false;
    }

    Bit64u element_mask = bx_poly_low_mask(element_bits);
    if (invert_element)
      element = (~element) & element_mask;
    if (read_dest && !read_poly_aarch64_fp128_reg(rd, &lo, &hi))
      return false;

    Bit32u lanes = (q ? 128 : 64) / element_bits;
    for (Bit32u lane = 0; lane < lanes; lane++) {
      Bit32u bit_offset = lane * element_bits;
      Bit64u *qword = bit_offset < 64 ? &lo : &hi;
      Bit32u shift = bit_offset & 63;
      Bit64u shifted_element = element << shift;
      if (bic_dest)
        *qword &= ~shifted_element;
      else if (or_dest)
        *qword |= shifted_element;
      else
        *qword |= shifted_element;
    }
    if (!q)
      hi = 0;

    if (!write_poly_aarch64_fp128_reg(rd, lo, hi))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s v%u.%s,#%llx lo=%llu hi=%llu",
      op_name, rd, shape, (unsigned long long) element,
      (unsigned long long) lo, (unsigned long long) hi));
    return true;
  }

  if ((insn & 0xbffffc00) == 0x88dffc00 ||
      (insn & 0xbffffc00) == 0x889ffc00) {
    Bit32u rt = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    bool is_load = (insn & 0x00400000) != 0;
    Bit32u size = (insn & 0x40000000) != 0 ? 8 : 4;
    Bit64u base = 0;

    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;

    bx_address addr = (bx_address) base;
    if (is_load) {
      Bit64u value = size == 8 ?
        read_virtual_qword(BX_SEG_REG_DS, addr) :
        read_virtual_dword(BX_SEG_REG_DS, addr);
      if (!write_poly_aarch64_reg(rt, size == 8 ? value : (Bit32u) value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 ldar %c%u,[rn=%u] addr=%llx value=%llu",
        size == 8 ? 'x' : 'w', rt, rn, (unsigned long long) addr,
        (unsigned long long) value));
      return true;
    }

    Bit64u value = 0;
    if (!read_poly_aarch64_reg(rt, &value))
      return false;
    if (size == 8)
      write_virtual_qword(BX_SEG_REG_DS, addr, value);
    else
      write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) value);
    if (bx_poly_aarch64_reservation_valid &&
        bx_poly_aarch64_reservation_addr == addr &&
        bx_poly_aarch64_reservation_size == size)
      bx_poly_aarch64_reservation_valid = false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 stlr %c%u,[rn=%u] addr=%llx value=%llu",
      size == 8 ? 'x' : 'w', rt, rn, (unsigned long long) addr,
      (unsigned long long) value));
    return true;
  }

  if ((insn & 0x3fff7c00) == 0x085f7c00 ||
      (insn & 0x3fe07c00) == 0x08007c00) {
    Bit32u size_code = (insn >> 30) & 0x3;
    Bit32u rt = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rs = (insn >> 16) & 0x1f;
    bool is_load = ((insn >> 21) & 0x7) == 0x2;
    bool is_store = ((insn >> 21) & 0x7) == 0x0;
    bool acquire_release = (insn & 0x00008000) != 0;
    Bit32u size = 0;
    Bit64u base = 0;

    if (size_code == 0x0)
      size = 1;
    else if (size_code == 0x1)
      size = 2;
    else if (size_code == 0x2)
      size = 4;
    else
      size = 8;

    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;

    bx_address addr = (bx_address) base;
    if (is_load) {
      Bit64u value = 0;
      if (rs != 31)
        return false;
      if (size == 1)
        value = read_virtual_byte(BX_SEG_REG_DS, addr);
      else if (size == 2)
        value = read_virtual_word(BX_SEG_REG_DS, addr);
      else if (size == 4)
        value = read_virtual_dword(BX_SEG_REG_DS, addr);
      else
        value = read_virtual_qword(BX_SEG_REG_DS, addr);
      bx_poly_aarch64_reservation_valid = true;
      bx_poly_aarch64_reservation_addr = addr;
      bx_poly_aarch64_reservation_size = size;
      if (!write_poly_aarch64_reg(rt, size == 4 ? (Bit32u) value : value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s %c%u,[rn=%u] addr=%llx value=%llu",
        acquire_release ? "ldaxr" : "ldxr", size == 8 ? 'x' : 'w', rt, rn,
        (unsigned long long) addr, (unsigned long long) value));
      return true;
    }

    if (is_store) {
      Bit64u value = 0;
      bool success = bx_poly_aarch64_reservation_valid &&
        bx_poly_aarch64_reservation_addr == addr &&
        bx_poly_aarch64_reservation_size == size;
      if (!read_poly_aarch64_reg(rt, &value))
        return false;
      if (success) {
        if (size == 1)
          write_virtual_byte(BX_SEG_REG_DS, addr, (Bit8u) value);
        else if (size == 2)
          write_virtual_word(BX_SEG_REG_DS, addr, (Bit16u) value);
        else if (size == 4)
          write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) value);
        else
          write_virtual_qword(BX_SEG_REG_DS, addr, value);
      }
      bx_poly_aarch64_reservation_valid = false;
      bx_poly_aarch64_reservation_addr = 0;
      bx_poly_aarch64_reservation_size = 0;
      if (!write_poly_aarch64_reg(rs, success ? 0 : 1))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s w%u,%c%u,[rn=%u] addr=%llx %s",
        acquire_release ? "stlxr" : "stxr", rs, size == 8 ? 'x' : 'w', rt,
        rn, (unsigned long long) addr, success ? "success" : "fail"));
      return true;
    }
  }

  if ((insn & 0x3f200c00) == 0x38200000) {
    Bit32u size_code = (insn >> 30) & 0x3;
    Bit32u rs = (insn >> 16) & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rt = insn & 0x1f;
    Bit32u op = (insn >> 12) & 0xf;
    Bit32u size = 0;
    Bit64u base = 0;
    Bit64u source = 0;
    Bit64u old_value = 0;
    Bit64u new_value = 0;
    const char *op_name = 0;

    if (size_code == 0x0)
      size = 1;
    else if (size_code == 0x1)
      size = 2;
    else if (size_code == 0x2)
      size = 4;
    else
      size = 8;

    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;
    if (!read_poly_aarch64_reg(rs, &source))
      return false;

    bx_address addr = (bx_address) base;
    Bit64u mask = bx_poly_aarch64_size_mask(size);
    source &= mask;
    if (size == 1)
      old_value = read_virtual_byte(BX_SEG_REG_DS, addr);
    else if (size == 2)
      old_value = read_virtual_word(BX_SEG_REG_DS, addr);
    else if (size == 4)
      old_value = read_virtual_dword(BX_SEG_REG_DS, addr);
    else
      old_value = read_virtual_qword(BX_SEG_REG_DS, addr);

    switch (op) {
      case 0x0:
        op_name = "ldadd";
        new_value = (old_value + source) & mask;
        break;
      case 0x1:
        op_name = "ldclr";
        new_value = old_value & ~source & mask;
        break;
      case 0x2:
        op_name = "ldeor";
        new_value = (old_value ^ source) & mask;
        break;
      case 0x3:
        op_name = "ldset";
        new_value = (old_value | source) & mask;
        break;
      case 0x4: {
        op_name = "ldsmax";
        Bit32u bits = size * 8;
        Bit64s old_signed = (Bit64s) bx_poly_sign_extend(old_value, bits);
        Bit64s source_signed = (Bit64s) bx_poly_sign_extend(source, bits);
        new_value = old_signed > source_signed ? old_value : source;
        break;
      }
      case 0x5: {
        op_name = "ldsmin";
        Bit32u bits = size * 8;
        Bit64s old_signed = (Bit64s) bx_poly_sign_extend(old_value, bits);
        Bit64s source_signed = (Bit64s) bx_poly_sign_extend(source, bits);
        new_value = old_signed < source_signed ? old_value : source;
        break;
      }
      case 0x6:
        op_name = "ldumax";
        new_value = old_value > source ? old_value : source;
        break;
      case 0x7:
        op_name = "ldumin";
        new_value = old_value < source ? old_value : source;
        break;
      case 0x8:
        op_name = "swp";
        new_value = source;
        break;
      default:
        return false;
    }
    new_value &= mask;

    if (size == 1)
      write_virtual_byte(BX_SEG_REG_DS, addr, (Bit8u) new_value);
    else if (size == 2)
      write_virtual_word(BX_SEG_REG_DS, addr, (Bit16u) new_value);
    else if (size == 4)
      write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) new_value);
    else
      write_virtual_qword(BX_SEG_REG_DS, addr, new_value);

    if (bx_poly_aarch64_reservation_valid &&
        bx_poly_aarch64_reservation_addr == addr &&
        bx_poly_aarch64_reservation_size == size)
      bx_poly_aarch64_reservation_valid = false;
    if (!write_poly_aarch64_reg(rt, size == 4 ? (Bit32u) old_value : old_value))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 lse %s%c %c%u,%c%u,[rn=%u] addr=%llx old=%llu new=%llu",
      op_name, ((insn >> 23) & 0x3) == 0x3 ? 'a' : ' ',
      size == 8 ? 'x' : 'w', rs, size == 8 ? 'x' : 'w', rt, rn,
      (unsigned long long) addr, (unsigned long long) old_value,
      (unsigned long long) new_value));
    return true;
  }

  if ((insn & 0x3fa07c00) == 0x08a07c00) {
    Bit32u size_code = (insn >> 30) & 0x3;
    Bit32u rs = (insn >> 16) & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rt = insn & 0x1f;
    Bit32u size = 0;
    Bit64u base = 0;
    Bit64u expected = 0;
    Bit64u desired = 0;
    Bit64u old_value = 0;
    bool success = false;

    if (size_code == 0x0)
      size = 1;
    else if (size_code == 0x1)
      size = 2;
    else if (size_code == 0x2)
      size = 4;
    else
      size = 8;

    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;
    if (!read_poly_aarch64_reg(rs, &expected) ||
        !read_poly_aarch64_reg(rt, &desired))
      return false;

    bx_address addr = (bx_address) base;
    Bit64u mask = bx_poly_aarch64_size_mask(size);
    expected &= mask;
    desired &= mask;
    if (size == 1)
      old_value = read_virtual_byte(BX_SEG_REG_DS, addr);
    else if (size == 2)
      old_value = read_virtual_word(BX_SEG_REG_DS, addr);
    else if (size == 4)
      old_value = read_virtual_dword(BX_SEG_REG_DS, addr);
    else
      old_value = read_virtual_qword(BX_SEG_REG_DS, addr);

    success = old_value == expected;
    if (success) {
      if (size == 1)
        write_virtual_byte(BX_SEG_REG_DS, addr, (Bit8u) desired);
      else if (size == 2)
        write_virtual_word(BX_SEG_REG_DS, addr, (Bit16u) desired);
      else if (size == 4)
        write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) desired);
      else
        write_virtual_qword(BX_SEG_REG_DS, addr, desired);
    }

    if (bx_poly_aarch64_reservation_valid &&
        bx_poly_aarch64_reservation_addr == addr &&
        bx_poly_aarch64_reservation_size == size)
      bx_poly_aarch64_reservation_valid = false;
    if (!write_poly_aarch64_reg(rs, size == 4 ? (Bit32u) old_value : old_value))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 lse cas %c%u,%c%u,[rn=%u] addr=%llx old=%llu desired=%llu %s",
      size == 8 ? 'x' : 'w', rs, size == 8 ? 'x' : 'w', rt, rn,
      (unsigned long long) addr, (unsigned long long) old_value,
      (unsigned long long) desired, success ? "success" : "fail"));
    return true;
  }

  {
    Bit32u fp_fma_op = insn & 0xffe08000;
    if (fp_fma_op == 0x1f000000 || fp_fma_op == 0x1f400000 ||
        fp_fma_op == 0x1f008000 || fp_fma_op == 0x1f408000 ||
        fp_fma_op == 0x1f200000 || fp_fma_op == 0x1f600000 ||
        fp_fma_op == 0x1f208000 || fp_fma_op == 0x1f608000) {
      Bit32u rd = insn & 0x1f;
      Bit32u rn = (insn >> 5) & 0x1f;
      Bit32u ra = (insn >> 10) & 0x1f;
      Bit32u rm = (insn >> 16) & 0x1f;
      bool fp32_op = (insn & 0x00400000) == 0;
      const char *op_name = "fmadd";
      Bit32u op = 0;
      softfloat_status_t status = bx_poly_softfloat_status();

      switch (fp_fma_op & 0xffa08000) {
        case 0x1f000000:
          op_name = "fmadd";
          op = 0;
          break;
        case 0x1f008000:
          op_name = "fmsub";
          op = softfloat_muladd_negate_product;
          break;
        case 0x1f200000:
          op_name = "fnmadd";
          op = softfloat_muladd_negate_result;
          break;
        case 0x1f208000:
          op_name = "fnmsub";
          op = softfloat_muladd_negate_c;
          break;
      }

      if (fp32_op) {
        Bit32u product_left = 0, product_right = 0, addend = 0;
        if (!read_poly_aarch64_fp32_reg(rn, &product_left) ||
            !read_poly_aarch64_fp32_reg(rm, &product_right) ||
            !read_poly_aarch64_fp32_reg(ra, &addend))
          return false;
        if (!write_poly_aarch64_fp32_reg(rd,
              f32_mulAdd(product_left, product_right, addend, op, &status)))
          return false;
      }
      else {
        Bit64u product_left = 0, product_right = 0, addend = 0;
        if (!read_poly_aarch64_fp64_reg(rn, &product_left) ||
            !read_poly_aarch64_fp64_reg(rm, &product_right) ||
            !read_poly_aarch64_fp64_reg(ra, &addend))
          return false;
        if (!write_poly_aarch64_fp64_reg(rd,
              f64_mulAdd(product_left, product_right, addend, op, &status)))
          return false;
      }

      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s%s v%u, v%u, v%u, v%u",
        op_name, fp32_op ? ".s" : ".d", rd, rn, rm, ra));
      return true;
    }
  }

  {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit64u left_bits = 0;
    Bit64u right_bits = 0;
    Bit64u result_bits = 0;
    const char *op_name = 0;

    if ((insn & 0xffe0fc00) == 0x5ee08400 ||
        (insn & 0xffe0fc00) == 0x7ee08400) {
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      if ((insn & 0xffe0fc00) == 0x5ee08400) {
        op_name = "add.d";
        result_bits = left_bits + right_bits;
      }
      else {
        op_name = "sub.d";
        result_bits = left_bits - right_bits;
      }
      if (!write_poly_aarch64_fp64_reg(rd, result_bits))
        return false;
    }
    else if ((insn & 0xbfe0fc00) == 0x2e201c00) {
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      op_name = "eor.8b";
      result_bits = left_bits ^ right_bits;
      if (!write_poly_aarch64_fp64_reg(rd, result_bits))
        return false;
    }

    if (op_name != 0) {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s v%u,v%u,v%u result=%llu",
        op_name, rd, rn, rm, (unsigned long long) result_bits));
      return true;
    }
  }

  if ((insn & 0xfffffc00) == 0x0e205800 ||
      (insn & 0xfffffc00) == 0x0e31b800) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit64u source = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if (!read_poly_aarch64_fp64_reg(rn, &source))
      return false;

    if ((insn & 0xfffffc00) == 0x0e205800) {
      op_name = "cnt.8b";
      for (Bit32u n = 0; n < 8; n++) {
        Bit64u byte = (source >> (n * 8)) & 0xff;
        result |= (Bit64u) bx_poly_count_ones64(byte) << (n * 8);
      }
    }
    else {
      op_name = "addv.b";
      for (Bit32u n = 0; n < 8; n++)
        result += (source >> (n * 8)) & 0xff;
      result &= 0xff;
    }

    if (!write_poly_aarch64_fp64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s v%u,v%u result=%llu",
      op_name, rd, rn, (unsigned long long) result));
    return true;
  }

  {
    Bit32u simd_reduce_base =
      insn & ~(Bit32u)(0x1f | (0x1f << 5) | 0x40000000 |
        0x20000000 | 0x00c00000 | 0x00010000);
    const char *op_name = 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u size = (insn >> 22) & 0x3;
    bool q = (insn & 0x40000000) != 0;
    bool unsigned_compare = (insn & 0x20000000) != 0;
    bool minimum = (insn & 0x00010000) != 0;
    Bit32u element_bits = 8U << size;
    Bit32u lanes = (q ? 128 : 64) / element_bits;
    Bit64u lo = 0, hi = 0;
    Bit64u best_value = 0;

    if (simd_reduce_base == 0x0e30a800) {
      if (size > 2 || (size == 2 && !q))
        return false;
      if (minimum)
        op_name = unsigned_compare ? "uminv" : "sminv";
      else
        op_name = unsigned_compare ? "umaxv" : "smaxv";
    }

    if (op_name != 0) {
      if (!read_poly_aarch64_fp128_reg(rn, &lo, &hi))
        return false;

      for (Bit32u lane = 0; lane < lanes; lane++) {
        Bit64u value = bx_poly_get_vector_element(lo, hi, element_bits, lane);
        bool take = lane == 0;

        if (!take) {
          if (unsigned_compare) {
            take = minimum ? value < best_value : value > best_value;
          }
          else {
            Bit64s signed_value = bx_poly_sign_extend64(value, element_bits);
            Bit64s signed_best =
              bx_poly_sign_extend64(best_value, element_bits);
            take = minimum ? signed_value < signed_best :
              signed_value > signed_best;
          }
        }

        if (take)
          best_value = value;
      }

      if (!write_poly_aarch64_fp128_reg(rd,
          best_value & bx_poly_low_mask(element_bits), 0))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s %u-bit v%u,v%u result=%llu",
        op_name, element_bits, rd, rn, (unsigned long long) best_value));
      return true;
    }
  }

  {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u left32_bits = 0;
    Bit32u right32_bits = 0;
    Bit32u result32_bits = 0;
    Bit64u left_bits = 0;
    Bit64u right_bits = 0;
    Bit64u result_bits = 0;
    const char *op_name = 0;
    bool fp32_op = false;

    if ((insn & 0xffe0fc00) == 0x1e202800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fadd.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_add(left32_bits, right32_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e203800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fsub.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_sub(left32_bits, right32_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e200800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmul.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_mul(left32_bits, right32_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e201800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fdiv.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_div(left32_bits, right32_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e207800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fminnm.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_minmax(left32_bits, right32_bits, 0, 1, false,
        &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e206800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmaxnm.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_minmax(left32_bits, right32_bits, 1, 1, false,
        &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e205800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmin.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_minmax(left32_bits, right32_bits, 0, 1, true,
        &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e204800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmax.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_minmax(left32_bits, right32_bits, 1, 1, true,
        &status);
    }
    else if ((insn & 0xfffffc00) == 0x1e214000) {
      op_name = "fneg.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &result32_bits))
        return false;
      result32_bits ^= 0x80000000;
    }
    else if ((insn & 0xfffffc00) == 0x1e20c000) {
      op_name = "fabs.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &result32_bits))
        return false;
      result32_bits &= 0x7fffffff;
    }
    else if ((insn & 0xfffffc00) == 0x1e21c000) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fsqrt.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits))
        return false;
      result32_bits = f32_sqrt(left32_bits, &status);
    }
    else if ((insn & 0xffe01c00) == 0x1e201000) {
      op_name = "fmov.s.imm";
      fp32_op = true;
      result32_bits = bx_poly_aarch64_expand_fp32_imm((insn >> 13) & 0xff);
    }
    else if ((insn & 0xfffffc00) == 0x1e204000) {
      op_name = "fmov.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &result32_bits))
        return false;
    }
    else if ((insn & 0xfffffc00) == 0x1e624000) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fcvt.s.d";
      fp32_op = true;
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits))
        return false;
      result32_bits = f64_to_f32(left_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e602800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fadd.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_add(left_bits, right_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e603800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fsub.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_sub(left_bits, right_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e600800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmul.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_mul(left_bits, right_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e601800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fdiv.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_div(left_bits, right_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e607800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fminnm.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_minmax(left_bits, right_bits, 0, 1, false, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e606800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmaxnm.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_minmax(left_bits, right_bits, 1, 1, false, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e605800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmin.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_minmax(left_bits, right_bits, 0, 1, true, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e604800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmax.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_minmax(left_bits, right_bits, 1, 1, true, &status);
    }
    else if ((insn & 0xfffffc00) == 0x1e614000) {
      op_name = "fneg.d";
      if (!read_poly_aarch64_fp64_reg(rn, &result_bits))
        return false;
      result_bits ^= BX_CONST64(0x8000000000000000);
    }
    else if ((insn & 0xfffffc00) == 0x1e60c000) {
      op_name = "fabs.d";
      if (!read_poly_aarch64_fp64_reg(rn, &result_bits))
        return false;
      result_bits &= BX_CONST64(0x7fffffffffffffff);
    }
    else if ((insn & 0xfffffc00) == 0x1e61c000) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fsqrt.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits))
        return false;
      result_bits = f64_sqrt(left_bits, &status);
    }
    else if ((insn & 0xffe01c00) == 0x1e601000) {
      op_name = "fmov.d.imm";
      result_bits = bx_poly_aarch64_expand_fp64_imm((insn >> 13) & 0xff);
    }
    else if ((insn & 0xfffffc00) == 0x1e604000) {
      op_name = "fmov.d";
      if (!read_poly_aarch64_fp64_reg(rn, &result_bits))
        return false;
    }
    else if ((insn & 0xfffffc00) == 0x1e22c000) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fcvt.d.s";
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits))
        return false;
      result_bits = f32_to_f64(left32_bits, &status);
    }
    else if ((insn & 0xfffffc00) == 0x5e21d800 ||
             (insn & 0xfffffc00) == 0x7e21d800 ||
             (insn & 0xfffffc00) == 0x5e61d800 ||
             (insn & 0xfffffc00) == 0x7e61d800) {
      Bit32u op = insn & 0xfffffc00;
      bool is_unsigned = (op & 0x20000000) != 0;
      fp32_op = (op & 0x00400000) == 0;
      op_name = is_unsigned ? "ucvtf" : "scvtf";
      softfloat_status_t status = bx_poly_softfloat_status();

      if (fp32_op) {
        if (!read_poly_aarch64_fp32_reg(rn, &left32_bits))
          return false;
        result32_bits = is_unsigned ?
          ui32_to_f32(left32_bits, &status) :
          i32_to_f32((Bit32s) left32_bits, &status);
      }
      else {
        if (!read_poly_aarch64_fp64_reg(rn, &left_bits))
          return false;
        result_bits = is_unsigned ?
          ui64_to_f64(left_bits, &status) :
          i64_to_f64((Bit64s) left_bits, &status);
      }
    }
    else if ((insn & 0xfffffc00) == 0x5ea1b800 ||
             (insn & 0xfffffc00) == 0x7ea1b800 ||
             (insn & 0xfffffc00) == 0x5ee1b800 ||
             (insn & 0xfffffc00) == 0x7ee1b800) {
      Bit32u op = insn & 0xfffffc00;
      bool is_unsigned = (op & 0x20000000) != 0;
      fp32_op = (op & 0x00400000) == 0;
      op_name = is_unsigned ? "fcvtzu" : "fcvtzs";

      if (fp32_op) {
        if (!read_poly_aarch64_fp32_reg(rn, &left32_bits))
          return false;
        softfloat_status_t status = bx_poly_softfloat_status();
        result32_bits = is_unsigned ?
          f32_to_ui32_r_minMag(left32_bits, true, true, &status) :
          (Bit32u) f32_to_i32_r_minMag(left32_bits, true, true, &status);
      }
      else {
        if (!read_poly_aarch64_fp64_reg(rn, &left_bits))
          return false;
        softfloat_status_t status = bx_poly_softfloat_status();
        result_bits = is_unsigned ?
          f64_to_ui64_r_minMag(left_bits, true, true, &status) :
          (Bit64u) f64_to_i64_r_minMag(left_bits, true, true, &status);
      }
    }

    if (op_name != 0) {
      if (fp32_op) {
        if (!write_poly_aarch64_fp32_reg(rd, result32_bits))
          return false;
      }
      else if (!write_poly_aarch64_fp64_reg(rd, result_bits))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s v%u,v%u,v%u", op_name, rd, rn, rm));
      return true;
    }
  }

  if ((insn & 0xfffffc00) == 0x1e260000 ||
      (insn & 0xfffffc00) == 0x1e270000 ||
      (insn & 0xfffffc00) == 0x9e660000 ||
      (insn & 0xfffffc00) == 0x9e670000) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u op = insn & 0xfffffc00;
    bool fp_to_gpr = op == 0x1e260000 || op == 0x9e660000;
    bool fp64_op = op == 0x9e660000 || op == 0x9e670000;

    if (fp_to_gpr) {
      Bit64u result = 0;
      if (fp64_op) {
        if (!read_poly_aarch64_fp64_reg(rn, &result))
          return false;
      }
      else {
        Bit32u value = 0;
        if (!read_poly_aarch64_fp32_reg(rn, &value))
          return false;
        result = value;
      }
      if (!write_poly_aarch64_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 fmov %c%u,%c%u value=%llu",
        fp64_op ? 'x' : 'w', rd, fp64_op ? 'd' : 's', rn,
        (unsigned long long) result));
      return true;
    }

    Bit64u value = 0;
    if (!read_poly_aarch64_reg(rn, &value))
      return false;
    if (fp64_op) {
      if (!write_poly_aarch64_fp64_reg(rd, value))
        return false;
    }
    else if (!write_poly_aarch64_fp32_reg(rd, (Bit32u) value))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 fmov %c%u,%c%u value=%llu",
      fp64_op ? 'd' : 's', rd, fp64_op ? 'x' : 'w', rn,
      (unsigned long long) value));
    return true;
  }

  if ((insn & 0xff80fc00) == 0x7f000400) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u immh = (insn >> 19) & 0xf;
    Bit32u immb = (insn >> 16) & 0x7;
    Bit32u imm = (immh << 3) | immb;
    Bit32u shift = 128 - imm;
    Bit64u value = 0;
    Bit64u result = 0;

    if ((immh & 0x8) == 0 || shift == 0 || shift > 64)
      return false;
    if (!read_poly_aarch64_fp64_reg(rn, &value))
      return false;
    result = shift == 64 ? 0 : (value >> shift);
    if (!write_poly_aarch64_fp64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 ushr d%u,d%u,#%u result=%llu",
      rd, rn, shift, (unsigned long long) result));
    return true;
  }

  if ((insn & 0xfffffc00) == 0x1e220000 ||
      (insn & 0xfffffc00) == 0x1e230000 ||
      (insn & 0xfffffc00) == 0x1e620000 ||
      (insn & 0xfffffc00) == 0x1e630000 ||
      (insn & 0xfffffc00) == 0x9e220000 ||
      (insn & 0xfffffc00) == 0x9e230000 ||
      (insn & 0xfffffc00) == 0x9e620000 ||
      (insn & 0xfffffc00) == 0x9e630000) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u op = insn & 0xfffffc00;
    Bit64u value = 0;
    bool input_64 = (op & 0x80000000) != 0;
    bool output_double = (op & 0x00400000) != 0;
    bool is_unsigned = (op & 0x00010000) != 0;

    if (!read_poly_aarch64_reg(rn, &value))
      return false;
    softfloat_status_t status = bx_poly_softfloat_status();
    if (output_double) {
      Bit64u result_bits = is_unsigned ?
        (input_64 ? ui64_to_f64(value, &status) :
          ui32_to_f64((Bit32u) value)) :
        (input_64 ? i64_to_f64((Bit64s) value, &status) :
          i32_to_f64((Bit32s) (Bit32u) value));
      if (!write_poly_aarch64_fp64_reg(rd, result_bits))
        return false;
    }
    else {
      Bit32u result_bits = is_unsigned ?
        (input_64 ? ui64_to_f32(value, &status) :
          ui32_to_f32((Bit32u) value, &status)) :
        (input_64 ? i64_to_f32((Bit64s) value, &status) :
          i32_to_f32((Bit32s) (Bit32u) value, &status));
      if (!write_poly_aarch64_fp32_reg(rd, result_bits))
        return false;
    }
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %c%u,%c%u value=%llu",
      is_unsigned ? "ucvtf" : "scvtf",
      output_double ? 'd' : 's', rd, input_64 ? 'x' : 'w', rn,
      (unsigned long long) value));
    return true;
  }

  if ((insn & 0xffe0fc1f) == 0x1e202000 ||
      (insn & 0xffe0fc1f) == 0x1e202010 ||
      (insn & 0xffe0fc1f) == 0x1e602000 ||
      (insn & 0xffe0fc1f) == 0x1e602010) {
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    bool fp32_op = (insn & 0xffe0fc1f) == 0x1e202000 ||
      (insn & 0xffe0fc1f) == 0x1e202010;
    bool signal_all_nans = (insn & 0x10) != 0;

    if (fp32_op) {
      Bit32u left_bits = 0;
      Bit32u right_bits = 0;
      if (!read_poly_aarch64_fp32_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right_bits))
        return false;
      bx_poly_aarch64_set_fp32_compare_nzcv(left_bits, right_bits,
        signal_all_nans);
    }
    else {
      Bit64u left_bits = 0;
      Bit64u right_bits = 0;
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      bx_poly_aarch64_set_fp64_compare_nzcv(left_bits, right_bits,
        signal_all_nans);
    }

    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 fcmp%s v%u,v%u nzcv=%x",
      fp32_op ? ".s" : ".d", rn, rm, bx_poly_aarch64_nzcv));
    return true;
  }

  if ((insn & 0xfffffc00) == 0x1e380000 ||
      (insn & 0xfffffc00) == 0x1e390000 ||
      (insn & 0xfffffc00) == 0x1e780000 ||
      (insn & 0xfffffc00) == 0x1e790000 ||
      (insn & 0xfffffc00) == 0x9e380000 ||
      (insn & 0xfffffc00) == 0x9e390000 ||
      (insn & 0xfffffc00) == 0x9e780000 ||
      (insn & 0xfffffc00) == 0x9e790000) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u op = insn & 0xfffffc00;
    bool source_fp32 = op == 0x1e380000 || op == 0x1e390000 ||
      op == 0x9e380000 || op == 0x9e390000;
    bool is_signed = op == 0x1e380000 || op == 0x1e780000 ||
      op == 0x9e380000 || op == 0x9e780000;
    bool is_64 = op == 0x9e380000 || op == 0x9e390000 ||
      op == 0x9e780000 || op == 0x9e790000;
    Bit64u fp_bits = 0;
    Bit32u fp32_bits = 0;
    Bit64u result = 0;

    if (source_fp32) {
      if (!read_poly_aarch64_fp32_reg(rn, &fp32_bits))
        return false;
    }
    else if (!read_poly_aarch64_fp64_reg(rn, &fp_bits))
      return false;
    softfloat_status_t status = bx_poly_softfloat_status();
    if (source_fp32) {
      if (is_64)
        result = is_signed ?
          (Bit64u) f32_to_i64_r_minMag(fp32_bits, true, true, &status) :
          f32_to_ui64_r_minMag(fp32_bits, true, true, &status);
      else
        result = is_signed ?
          (Bit64u) (Bit32u) f32_to_i32_r_minMag(fp32_bits, true, true,
            &status) :
          f32_to_ui32_r_minMag(fp32_bits, true, true, &status);
    }
    else {
      if (is_64)
        result = is_signed ?
          (Bit64u) f64_to_i64_r_minMag(fp_bits, true, true, &status) :
          f64_to_ui64_r_minMag(fp_bits, true, true, &status);
      else
        result = is_signed ?
          (Bit64u) (Bit32u) f64_to_i32_r_minMag(fp_bits, true, true,
            &status) :
          f64_to_ui32_r_minMag(fp_bits, true, true, &status);
    }
    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%c%u result=%llu",
      is_signed ? "fcvtzs" : "fcvtzu", is_64 ? "x" : "w", rd,
      source_fp32 ? 's' : 'd', rn,
      (unsigned long long) result));
    return true;
  }

  if ((insn & 0xffe0fc1f) == 0x1e202008 ||
      (insn & 0xffe0fc1f) == 0x1e202018 ||
      (insn & 0xffe0fc1f) == 0x1e602008 ||
      (insn & 0xffe0fc1f) == 0x1e602018) {
    Bit32u rn = (insn >> 5) & 0x1f;
    bool fp32_op = (insn & 0xffe0fc1f) == 0x1e202008 ||
      (insn & 0xffe0fc1f) == 0x1e202018;
    bool signal_all_nans = (insn & 0x10) != 0;

    if (fp32_op) {
      Bit32u left_bits = 0;
      if (!read_poly_aarch64_fp32_reg(rn, &left_bits))
        return false;
      bx_poly_aarch64_set_fp32_compare_nzcv(left_bits, 0, signal_all_nans);
    }
    else {
      Bit64u left_bits = 0;
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits))
        return false;
      bx_poly_aarch64_set_fp64_compare_nzcv(left_bits, 0, signal_all_nans);
    }

    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 fcmp%s v%u,#0.0 nzcv=%x",
      fp32_op ? ".s" : ".d", rn, bx_poly_aarch64_nzcv));
    return true;
  }

  if ((insn & 0x9f000000) == 0x10000000) {
    Bit32u rd = insn & 0x1f;
    Bit32u immlo = (insn >> 29) & 0x3;
    Bit32u immhi = (insn >> 5) & 0x7ffff;
    Bit64s offset = bx_poly_sign_extend((immhi << 2) | immlo, 21);
    Bit64u result = (Bit64u) ((Bit64s) pc + offset);
    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 adr x%u,offset=%lld result=%llx", rd, (long long) offset, (unsigned long long) result));
    return true;
  }

  if ((insn & 0x9f000000) == 0x90000000) {
    Bit32u rd = insn & 0x1f;
    Bit32u immlo = (insn >> 29) & 0x3;
    Bit32u immhi = (insn >> 5) & 0x7ffff;
    Bit64s offset = bx_poly_sign_extend((immhi << 2) | immlo, 21) << 12;
    Bit64u page_base = ((Bit64u) pc) & ~((Bit64u) 0xfff);
    Bit64u result = (Bit64u) ((Bit64s) page_base + offset);
    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 adrp x%u,offset=%lld result=%llx", rd, (long long) offset, (unsigned long long) result));
    return true;
  }

  if ((insn & 0xff800000) == 0x12800000 ||
      (insn & 0xff800000) == 0x52800000 ||
      (insn & 0xff800000) == 0x72800000 ||
      (insn & 0xff800000) == 0x92800000 ||
      (insn & 0xff800000) == 0xd2800000 ||
      (insn & 0xff800000) == 0xf2800000) {
    bool sf = (insn & 0x80000000) != 0;
    Bit32u base = insn & 0xff800000;
    Bit32u imm16 = (insn >> 5) & 0xffff;
    Bit32u hw = (insn >> 21) & 0x3;
    if (!sf && hw >= 2)
      return false;
    Bit32u shift = hw * 16;
    Bit32u rd = insn & 0x1f;
    Bit64u valid_mask = sf ? BX_CONST64(0xffffffffffffffff) : BX_CONST64(0xffffffff);
    Bit64u value = (((Bit64u) imm16) << shift) & valid_mask;
    const char *op_name = "movz";

    if (base == 0x12800000 || base == 0x92800000) {
      value = (~value) & valid_mask;
      op_name = "movn";
    }
    else if (base == 0x72800000 || base == 0xf2800000) {
      Bit64u prev = 0;
      Bit64u mask = (((Bit64u) 0xffff) << shift) & valid_mask;
      if (!read_poly_aarch64_reg(rd, &prev))
        return false;
      value = ((prev & valid_mask) & ~mask) | value;
      op_name = "movk";
    }

    if (!write_poly_aarch64_reg(rd, value))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %c%u,#%u,lsl #%u result=%llu", op_name, sf ? 'x' : 'w', rd, imm16, shift, (unsigned long long) value));
    return true;
  }

  if ((insn & 0x1f800000) == 0x12000000) {
    bool sf = (insn & 0x80000000) != 0;
    Bit32u opc = (insn >> 29) & 0x3;
    Bit32u n = (insn >> 22) & 0x1;
    Bit32u immr = (insn >> 16) & 0x3f;
    Bit32u imms = (insn >> 10) & 0x3f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rd = insn & 0x1f;
    unsigned bits = sf ? 64 : 32;
    Bit64u left = 0;
    Bit64u imm = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if (!sf && n != 0)
      return false;
    if (!bx_poly_aarch64_decode_logical_imm(n, immr, imms, bits, &imm))
      return false;
    if (rn != 31 && !read_poly_aarch64_reg(rn, &left))
      return false;

    if (opc == 0) {
      op_name = "and";
      result = left & imm;
    }
    else if (opc == 1) {
      op_name = "orr";
      result = left | imm;
    }
    else if (opc == 2) {
      op_name = "eor";
      result = left ^ imm;
    }
    else {
      op_name = "ands";
      result = left & imm;
      bx_poly_aarch64_set_nzcv(result, false, false, bits);
    }

    if (rd != 31 && !write_poly_aarch64_reg(rd, sf ? result : (Bit32u) result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,#%llx result=%llu nzcv=%x",
      op_name, sf ? "x" : "w", rd, sf ? "x" : "w", rn,
      (unsigned long long) imm, (unsigned long long) result,
      bx_poly_aarch64_nzcv));
    return true;
  }

  if ((insn & 0x7f800000) == 0x53000000) {
    bool sf = (insn & 0x80000000) != 0;
    Bit32u n = (insn >> 22) & 0x1;
    Bit32u immr = (insn >> 16) & 0x3f;
    Bit32u imms = (insn >> 10) & 0x3f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rd = insn & 0x1f;
    unsigned bits = sf ? 64 : 32;
    Bit64u value = 0;
    Bit64u result = 0;
    const char *op_name = "ubfm";

    if ((sf && n == 0) || (!sf && (n != 0 || immr >= 32 || imms >= 32)))
      return false;
    if (!read_poly_aarch64_reg(rn, &value))
      return false;
    value &= bx_poly_low_mask(bits);

    if (immr <= imms) {
      result = (value >> immr) & bx_poly_low_mask(imms - immr + 1);
      if (immr == 0 && imms == 7)
        op_name = "uxtb";
      else if (immr == 0 && imms == 15)
        op_name = "uxth";
      else if (imms == bits - 1)
        op_name = "lsr";
      else
        op_name = "ubfx";
    }
    else {
      unsigned shift = bits - immr;
      result = (value & bx_poly_low_mask(imms + 1)) << shift;
      op_name = "lsl";
    }
    result &= bx_poly_low_mask(bits);

    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,immr=%u,imms=%u result=%llu",
      op_name, sf ? "x" : "w", rd, sf ? "x" : "w", rn, immr, imms,
      (unsigned long long) result));
    return true;
  }

  if ((insn & 0x7f800000) == 0x33000000) {
    bool sf = (insn & 0x80000000) != 0;
    Bit32u n = (insn >> 22) & 0x1;
    Bit32u immr = (insn >> 16) & 0x3f;
    Bit32u imms = (insn >> 10) & 0x3f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rd = insn & 0x1f;
    unsigned bits = sf ? 64 : 32;
    Bit64u source = 0;
    Bit64u dest = 0;
    Bit64u mask = 0;
    Bit64u result = 0;
    const char *op_name = "bfm";

    if ((sf && n == 0) || (!sf && (n != 0 || immr >= 32 || imms >= 32)))
      return false;
    if (!read_poly_aarch64_reg(rn, &source) ||
        !read_poly_aarch64_reg(rd, &dest))
      return false;
    source &= bx_poly_low_mask(bits);
    dest &= bx_poly_low_mask(bits);

    if (immr <= imms) {
      unsigned width = imms - immr + 1;
      mask = bx_poly_low_mask(width);
      result = (dest & ~mask) | ((source >> immr) & mask);
      op_name = "bfxil";
    }
    else {
      unsigned lsb = bits - immr;
      unsigned width = imms + 1;
      mask = bx_poly_low_mask(width) << lsb;
      result = (dest & ~mask) | ((source << lsb) & mask);
      op_name = "bfi";
    }
    result &= bx_poly_low_mask(bits);

    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,immr=%u,imms=%u result=%llu",
      op_name, sf ? "x" : "w", rd, sf ? "x" : "w", rn, immr, imms,
      (unsigned long long) result));
    return true;
  }

  if ((insn & 0x7f800000) == 0x13000000) {
    bool sf = (insn & 0x80000000) != 0;
    Bit32u n = (insn >> 22) & 0x1;
    Bit32u immr = (insn >> 16) & 0x3f;
    Bit32u imms = (insn >> 10) & 0x3f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rd = insn & 0x1f;
    unsigned bits = sf ? 64 : 32;
    Bit64u value = 0;
    Bit64u result = 0;
    const char *op_name = "sbfm";

    if ((sf && n == 0) || (!sf && (n != 0 || immr >= 32 || imms >= 32)))
      return false;
    if (!read_poly_aarch64_reg(rn, &value))
      return false;
    value &= bx_poly_low_mask(bits);

    if (immr <= imms) {
      unsigned width = imms - immr + 1;
      result = (Bit64u) bx_poly_sign_extend64(value >> immr, width);
      if (immr == 0 && imms == 7)
        op_name = "sxtb";
      else if (immr == 0 && imms == 15)
        op_name = "sxth";
      else if (immr == 0 && imms == 31)
        op_name = "sxtw";
      else if (imms == bits - 1)
        op_name = "asr";
      else
        op_name = "sbfx";
    }
    else {
      unsigned shift = bits - immr;
      unsigned width = imms + 1 + shift;
      result = (Bit64u) bx_poly_sign_extend64(
        (value & bx_poly_low_mask(imms + 1)) << shift, width);
      op_name = "sbfiz";
    }
    result &= bx_poly_low_mask(bits);

    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,immr=%u,imms=%u result=%llu",
      op_name, sf ? "x" : "w", rd, sf ? "x" : "w", rn, immr, imms,
      (unsigned long long) result));
    return true;
  }

  if ((insn & 0x7fffe000) == 0x5ac00000) {
    bool sf = (insn & 0x80000000) != 0;
    Bit32u op = (insn >> 10) & 0x3f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rd = insn & 0x1f;
    unsigned bits = sf ? 64 : 32;
    Bit64u value = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if (op > 5 || (!sf && op == 3))
      return false;
    if (!read_poly_aarch64_reg(rn, &value))
      return false;
    value &= bx_poly_low_mask(bits);

    switch (op) {
      case 0:
        op_name = "rbit";
        result = bx_poly_reverse_bits(value, bits);
        break;
      case 1:
        op_name = "rev16";
        result = bx_poly_reverse_bytes_in_lanes(value, bits, 16);
        break;
      case 2:
        op_name = sf ? "rev32" : "rev";
        result = bx_poly_reverse_bytes_in_lanes(value, bits, 32);
        break;
      case 3:
        op_name = "rev";
        result = bx_poly_reverse_bytes_in_lanes(value, bits, 64);
        break;
      case 4:
        op_name = "clz";
        result = bx_poly_count_leading_zeroes(value, bits);
        break;
      case 5:
        op_name = "cls";
        result = bx_poly_count_leading_sign_bits(value, bits);
        break;
    }

    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u result=%llu",
      op_name, sf ? "x" : "w", rd, sf ? "x" : "w", rn,
      (unsigned long long) result));
    return true;
  }

  if ((insn & 0x7fa00000) == 0x13800000) {
    bool sf = (insn & 0x80000000) != 0;
    bool n = (insn & 0x00400000) != 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u imm = (insn >> 10) & 0x3f;
    Bit32u rm = (insn >> 16) & 0x1f;
    unsigned bits = sf ? 64 : 32;
    Bit64u high = 0;
    Bit64u low = 0;
    Bit64u mask = bx_poly_low_mask(bits);
    Bit64u result = 0;

    if (n != sf || (!sf && imm >= 32))
      return false;
    if (!read_poly_aarch64_reg(rn, &high) ||
        !read_poly_aarch64_reg(rm, &low))
      return false;
    high &= mask;
    low &= mask;
    result = imm == 0 ? low :
      ((low >> imm) | (high << (bits - imm))) & mask;

    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,%s%u,#%u result=%llu",
      rn == rm ? "ror" : "extr", sf ? "x" : "w", rd,
      sf ? "x" : "w", rn, sf ? "x" : "w", rm, imm,
      (unsigned long long) result));
    return true;
  }

  if ((insn & 0x7f000000) == 0x31000000 ||
      (insn & 0x7f000000) == 0x71000000) {
    bool sf = (insn & 0x80000000) != 0;
    bool subtract = (insn & 0x40000000) != 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit64u base = 0;
    Bit64u imm = (insn >> 10) & 0xfff;
    unsigned bits = sf ? 64 : 32;
    if (insn & 0x00400000)
      imm <<= 12;
    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base)) {
      return false;
    }

    Bit64u result = bx_poly_aarch64_addsub_flags(base, imm, subtract, bits);
    if (rd != 31 && !write_poly_aarch64_reg(rd, sf ? result : (Bit32u) result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %ss %s%u,%s%u,#%llu nzcv=%x result=%llu",
      subtract ? "sub" : "add", sf ? "x" : "w", rd, sf ? "x" : "w", rn,
      (unsigned long long) imm, bx_poly_aarch64_nzcv, (unsigned long long) result));
    return true;
  }

  if ((insn & 0x3f000000) == 0x11000000) {
    bool sf = (insn & 0x80000000) != 0;
    bool subtract = (insn & 0x40000000) != 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit64u base = 0;
    Bit64u imm = (insn >> 10) & 0xfff;
    unsigned bits = sf ? 64 : 32;
    if (insn & 0x00400000)
      imm <<= 12;
    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base)) {
      return false;
    }
    base &= bx_poly_low_mask(bits);
    Bit64u result = (subtract ? base - imm : base + imm) & bx_poly_low_mask(bits);
    if (rd == 31)
      RSP = result;
    else if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,#%llu result=%llu",
      subtract ? "sub" : "add", sf ? "x" : "w", rd, sf ? "x" : "w", rn,
      (unsigned long long) imm, (unsigned long long) result));
    return true;
  }

  if ((insn & 0x1f200000) == 0x0b200000) {
    bool sf = (insn & 0x80000000) != 0;
    bool subtract = (insn & 0x40000000) != 0;
    bool set_flags = (insn & 0x20000000) != 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u option = (insn >> 13) & 0x7;
    Bit32u amount = (insn >> 10) & 0x7;
    unsigned bits = sf ? 64 : 32;
    Bit64u left = 0;
    Bit64u right = 0;
    Bit64u result = 0;

    if (rn == 31)
      left = RSP;
    else if (!read_poly_aarch64_reg(rn, &left))
      return false;
    if (!read_poly_aarch64_reg(rm, &right) ||
        !bx_poly_aarch64_extended_reg(right, option, amount, bits, &right))
      return false;

    if (set_flags)
      result = bx_poly_aarch64_addsub_flags(left, right, subtract, bits);
    else
      result = subtract ? left - right : left + right;
    if (!sf)
      result = (Bit32u) result;

    if (rd == 31) {
      if (!set_flags)
        RSP = result;
    }
    else if (!write_poly_aarch64_reg(rd, result))
      return false;

    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s%s %s%u,%s%u,%s%u,extend=%u,#%u result=%llu nzcv=%x",
      subtract ? "sub" : "add", set_flags ? "s" : "",
      sf ? "x" : "w", rd, sf ? "x" : "w", rn,
      sf ? "x" : "w", rm, option, amount,
      (unsigned long long) result, bx_poly_aarch64_nzcv));
    return true;
  }

  if ((insn & ~(Bit32u)(0x1f | (0x1f << 5) | (0x1f << 16))) == 0x4ea01c00) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit64u lo = 0, hi = 0;

    if (rn == rm) {
      if (!read_poly_aarch64_fp128_reg(rn, &lo, &hi) ||
          !write_poly_aarch64_fp128_reg(rd, lo, hi))
        return false;

      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 mov v%u.16b,v%u.16b", rd, rn));
      return true;
    }
  }

  if ((insn & ~(Bit32u)(0x1f | (0x1f << 5) | (0x1f << 16) |
      (0xf << 11) | 0x40000000)) == 0x2e000000) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u imm = (insn >> 11) & 0xf;
    bool q = (insn & 0x40000000) != 0;
    Bit32u bytes = q ? 16 : 8;
    Bit64u left_lo = 0, left_hi = 0, right_lo = 0, right_hi = 0;
    Bit64u result_lo = 0, result_hi = 0;

    if (!q && imm >= 8)
      return false;
    if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
        !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
      return false;

    for (Bit32u byte = 0; byte < bytes; byte++) {
      Bit32u source_byte = imm + byte;
      Bit64u source_qword = 0;
      if (source_byte < bytes) {
        source_qword = source_byte < 8 ? left_lo : left_hi;
      }
      else {
        source_byte -= bytes;
        source_qword = source_byte < 8 ? right_lo : right_hi;
      }
      Bit64u value = (source_qword >> ((source_byte & 7) * 8)) & 0xff;
      Bit64u *result_qword = byte < 8 ? &result_lo : &result_hi;
      *result_qword |= value << ((byte & 7) * 8);
    }

    if (!write_poly_aarch64_fp128_reg(rd, result_lo, result_hi))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 ext v%u.%ub,v%u,v%u,#%u lo=%llu hi=%llu",
      rd, bytes, rn, rm, imm, (unsigned long long) result_lo,
      (unsigned long long) result_hi));
    return true;
  }

  if ((insn & ~(Bit32u)(0x1f | (0x1f << 5) | (0x1f << 16) |
      (0x3 << 13) | 0x1000 | 0x40000000)) == 0x0e000000) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u table_regs = ((insn >> 13) & 0x3) + 1;
    bool tbx = (insn & 0x1000) != 0;
    bool q = (insn & 0x40000000) != 0;
    Bit32u result_bytes = q ? 16 : 8;
    Bit32u table_bytes = table_regs * 16;
    Bit64u index_lo = 0, index_hi = 0;
    Bit64u result_lo = 0, result_hi = 0;
    Bit64u table_lo[4] = { 0, 0, 0, 0 };
    Bit64u table_hi[4] = { 0, 0, 0, 0 };

    if (!read_poly_aarch64_fp128_reg(rm, &index_lo, &index_hi))
      return false;
    if (tbx && !read_poly_aarch64_fp128_reg(rd, &result_lo, &result_hi))
      return false;
    for (Bit32u reg = 0; reg < table_regs; reg++) {
      if (!read_poly_aarch64_fp128_reg((rn + reg) & 0x1f,
          &table_lo[reg], &table_hi[reg]))
        return false;
    }

    for (Bit32u byte = 0; byte < result_bytes; byte++) {
      Bit32u index = (Bit32u) bx_poly_get_vector_element(index_lo, index_hi,
        8, byte);
      Bit64u value = 0;

      if (index < table_bytes) {
        Bit32u table_reg = index >> 4;
        Bit32u table_byte = index & 0xf;
        value = bx_poly_get_vector_element(table_lo[table_reg],
          table_hi[table_reg], 8, table_byte);
        bx_poly_set_vector_element(&result_lo, &result_hi, 8, byte, value);
      }
      else if (!tbx) {
        Bit64u *target = byte < 8 ? &result_lo : &result_hi;
        *target &= ~(BX_CONST64(0xff) << ((byte & 7) * 8));
      }
    }

    if (!q)
      result_hi = 0;
    if (!write_poly_aarch64_fp128_reg(rd, result_lo, result_hi))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s v%u.%ub,{v%u-%u},v%u lo=%llu hi=%llu",
      tbx ? "tbx" : "tbl", rd, result_bytes, rn,
      (rn + table_regs - 1) & 0x1f, rm,
      (unsigned long long) result_lo, (unsigned long long) result_hi));
    return true;
  }

  {
    Bit32u simd_reverse_base =
      insn & ~(Bit32u)(0x1f | (0x1f << 5) | (0x3 << 22) | 0x40000000);
    const char *op_name = 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u size = (insn >> 22) & 0x3;
    bool q = (insn & 0x40000000) != 0;
    Bit32u total_bytes = q ? 16 : 8;
    Bit32u element_bytes = 1U << size;
    Bit32u group_bytes = 0;
    Bit64u source_lo = 0, source_hi = 0;
    Bit64u result_lo = 0, result_hi = 0;

    if (simd_reverse_base == 0x0e201800) {
      op_name = "rev16";
      group_bytes = 2;
      if (size != 0)
        op_name = 0;
    }
    else if (simd_reverse_base == 0x2e200800) {
      op_name = "rev32";
      group_bytes = 4;
      if (size > 1)
        op_name = 0;
    }
    else if (simd_reverse_base == 0x0e200800) {
      op_name = "rev64";
      group_bytes = 8;
      if (size > 2)
        op_name = 0;
    }

    if (op_name != 0) {
      if (!read_poly_aarch64_fp128_reg(rn, &source_lo, &source_hi))
        return false;

      for (Bit32u element = 0; element < total_bytes / element_bytes;
          element++) {
        Bit32u group_element_count = group_bytes / element_bytes;
        Bit32u group_start = (element / group_element_count) *
          group_element_count;
        Bit32u reverse_element = group_start + group_element_count - 1 -
          (element % group_element_count);
        Bit64u value = bx_poly_get_vector_element(source_lo, source_hi,
          element_bytes * 8, reverse_element);
        bx_poly_set_vector_element(&result_lo, &result_hi, element_bytes * 8,
          element, value);
      }

      if (!q)
        result_hi = 0;
      if (!write_poly_aarch64_fp128_reg(rd, result_lo, result_hi))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s v%u.%u-bit,v%u lo=%llu hi=%llu",
        op_name, rd, element_bytes * 8, rn,
        (unsigned long long) result_lo, (unsigned long long) result_hi));
      return true;
    }
  }

  {
    Bit32u simd_permute_base =
      insn & ~(Bit32u)(0x1f | (0x1f << 5) | (0x1f << 16) |
        (0x3 << 22) | 0x40000000);
    const char *op_name = 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u size = (insn >> 22) & 0x3;
    bool q = (insn & 0x40000000) != 0;
    Bit32u element_bits = 8U << size;
    Bit32u lanes = (q ? 128 : 64) / element_bits;
    Bit64u left_lo = 0, left_hi = 0, right_lo = 0, right_hi = 0;
    Bit64u result_lo = 0, result_hi = 0;

    if (simd_permute_base == 0x0e001800)
      op_name = "uzp1";
    else if (simd_permute_base == 0x0e005800)
      op_name = "uzp2";
    else if (simd_permute_base == 0x0e002800)
      op_name = "trn1";
    else if (simd_permute_base == 0x0e006800)
      op_name = "trn2";
    else if (simd_permute_base == 0x0e003800)
      op_name = "zip1";
    else if (simd_permute_base == 0x0e007800)
      op_name = "zip2";

    if (op_name != 0) {
      if (!q && size == 3)
        return false;
      if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
          !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
        return false;

      for (Bit32u lane = 0; lane < lanes; lane++) {
        bool from_right = false;
        Bit32u source_lane = 0;
        Bit64u value = 0;

        if (simd_permute_base == 0x0e001800 ||
            simd_permute_base == 0x0e005800) {
          Bit32u source_index = ((lane & (lanes / 2 - 1)) * 2) +
            (simd_permute_base == 0x0e005800 ? 1 : 0);
          from_right = lane >= lanes / 2;
          source_lane = source_index;
        }
        else if (simd_permute_base == 0x0e002800 ||
            simd_permute_base == 0x0e006800) {
          from_right = (lane & 1) != 0;
          source_lane = ((lane >> 1) * 2) +
            (simd_permute_base == 0x0e006800 ? 1 : 0);
        }
        else {
          Bit32u base_lane = simd_permute_base == 0x0e007800 ?
            lanes / 2 : 0;
          from_right = (lane & 1) != 0;
          source_lane = base_lane + (lane >> 1);
        }

        value = from_right ?
          bx_poly_get_vector_element(right_lo, right_hi, element_bits,
            source_lane) :
          bx_poly_get_vector_element(left_lo, left_hi, element_bits,
            source_lane);
        bx_poly_set_vector_element(&result_lo, &result_hi, element_bits,
          lane, value);
      }

      if (!write_poly_aarch64_fp128_reg(rd, result_lo, result_hi))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s v%u.%u-bit,v%u,v%u lo=%llu hi=%llu",
        op_name, rd, element_bits, rn, rm,
        (unsigned long long) result_lo, (unsigned long long) result_hi));
      return true;
    }
  }

  {
    Bit32u simd_logical_base =
      insn & ~(Bit32u)(0x1f | (0x1f << 5) | (0x1f << 16) | 0x40000000);
    const char *op_name = 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    bool q = (insn & 0x40000000) != 0;
    Bit64u left_lo = 0, left_hi = 0, right_lo = 0, right_hi = 0;
    Bit64u result_lo = 0, result_hi = 0;

    if (simd_logical_base == 0x0e201c00) {
      op_name = "and";
      if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
          !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
        return false;
      result_lo = left_lo & right_lo;
      result_hi = left_hi & right_hi;
    }
    else if (simd_logical_base == 0x0ea01c00) {
      op_name = "orr";
      if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
          !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
        return false;
      result_lo = left_lo | right_lo;
      result_hi = left_hi | right_hi;
    }
    else if (simd_logical_base == 0x2e201c00) {
      op_name = "eor";
      if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
          !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
        return false;
      result_lo = left_lo ^ right_lo;
      result_hi = left_hi ^ right_hi;
    }
    else if (simd_logical_base == 0x0e601c00) {
      op_name = "bic";
      if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
          !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
        return false;
      result_lo = left_lo & ~right_lo;
      result_hi = left_hi & ~right_hi;
    }
    else if (simd_logical_base == 0x0ee01c00) {
      op_name = "orn";
      if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
          !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
        return false;
      result_lo = left_lo | ~right_lo;
      result_hi = left_hi | ~right_hi;
    }

    if (op_name != 0) {
      if (!q)
        result_hi = 0;
      if (!write_poly_aarch64_fp128_reg(rd, result_lo, result_hi))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s v%u.%s,v%u,v%u lo=%llu hi=%llu",
        op_name, rd, q ? "16b" : "8b", rn, rm,
        (unsigned long long) result_lo, (unsigned long long) result_hi));
      return true;
    }
  }

  {
    Bit32u simd_compare_base =
      insn & ~(Bit32u)(0x1f | (0x1f << 5) | (0x1f << 16) | 0x40000000);
    Bit32u simd_compare_op = simd_compare_base & ~(Bit32u) 0x00c00000;
    const char *op_name = 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    bool q = (insn & 0x40000000) != 0;
    bool signed_greater = false;
    bool unsigned_greater = false;
    bool equal = false;
    bool test_bits = false;
    Bit32u element_bits = 8;
    Bit64u left_lo = 0, left_hi = 0, right_lo = 0, right_hi = 0;
    Bit64u result_lo = 0, result_hi = 0;

    if ((simd_compare_op & 0xdfffffff) == 0x0e203400) {
      op_name = (simd_compare_base & 0x20000000) ? "cmhi" : "cmgt";
      unsigned_greater = (simd_compare_base & 0x20000000) != 0;
      signed_greater = !unsigned_greater;
    }
    else if ((simd_compare_op & 0xdfffffff) == 0x0e208c00) {
      op_name = (simd_compare_base & 0x20000000) ? "cmeq" : "cmtst";
      equal = (simd_compare_base & 0x20000000) != 0;
      test_bits = !equal;
    }

    if (op_name != 0) {
      if ((simd_compare_base & 0x00c00000) == 0x00400000)
        element_bits = 16;
      else if ((simd_compare_base & 0x00c00000) == 0x00800000)
        element_bits = 32;
      else if ((simd_compare_base & 0x00c00000) == 0x00c00000)
        element_bits = 64;
      if (!q && element_bits == 64)
        return false;

      if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
          !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
        return false;

      Bit64u mask = bx_poly_low_mask(element_bits);
      Bit32u lanes = (q ? 128 : 64) / element_bits;
      for (Bit32u lane = 0; lane < lanes; lane++) {
        Bit32u bit_offset = lane * element_bits;
        Bit32u shift = bit_offset & 63;
        Bit64u left_qword = bit_offset < 64 ? left_lo : left_hi;
        Bit64u right_qword = bit_offset < 64 ? right_lo : right_hi;
        Bit64u left = (left_qword >> shift) & mask;
        Bit64u right = (right_qword >> shift) & mask;
        bool matched = false;

        if (equal)
          matched = left == right;
        else if (test_bits)
          matched = (left & right) != 0;
        else if (unsigned_greater)
          matched = left > right;
        else if (signed_greater)
          matched = bx_poly_sign_extend64(left, element_bits) >
            bx_poly_sign_extend64(right, element_bits);

        if (matched) {
          Bit64u *result_qword = bit_offset < 64 ? &result_lo : &result_hi;
          *result_qword |= mask << shift;
        }
      }

      if (!write_poly_aarch64_fp128_reg(rd, result_lo, result_hi))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s v%u.%u-bit,v%u,v%u lo=%llu hi=%llu",
        op_name, rd, element_bits, rn, rm,
        (unsigned long long) result_lo, (unsigned long long) result_hi));
      return true;
    }
  }

  Bit32u simd_add_base =
    insn & ~(Bit32u)(0x1f | (0x1f << 5) | (0x1f << 16) | 0x40000000);
  if (simd_add_base == 0x0e208400 || simd_add_base == 0x0e608400 ||
      simd_add_base == 0x0ea08400 || simd_add_base == 0x0ee08400 ||
      simd_add_base == 0x2e208400 || simd_add_base == 0x2e608400 ||
      simd_add_base == 0x2ea08400 || simd_add_base == 0x2ee08400) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    bool q = (insn & 0x40000000) != 0;
    bool subtract = (simd_add_base & 0x20000000) != 0;
    Bit32u element_bits = 8;
    Bit32u total_bits = q ? 128 : 64;
    Bit64u left_lo = 0, left_hi = 0, right_lo = 0, right_hi = 0;
    Bit64u result_lo = 0, result_hi = 0;

    if ((simd_add_base & 0xdfffffff) == 0x0e608400)
      element_bits = 16;
    else if ((simd_add_base & 0xdfffffff) == 0x0ea08400)
      element_bits = 32;
    else if ((simd_add_base & 0xdfffffff) == 0x0ee08400)
      element_bits = 64;
    if (!q && element_bits == 64)
      return false;

    if (!read_poly_aarch64_fp128_reg(rn, &left_lo, &left_hi) ||
        !read_poly_aarch64_fp128_reg(rm, &right_lo, &right_hi))
      return false;

    Bit64u mask = bx_poly_low_mask(element_bits);
    Bit32u lanes = total_bits / element_bits;
    for (Bit32u lane = 0; lane < lanes; lane++) {
      Bit32u bit_offset = lane * element_bits;
      Bit32u shift = bit_offset & 63;
      Bit64u left_qword = bit_offset < 64 ? left_lo : left_hi;
      Bit64u right_qword = bit_offset < 64 ? right_lo : right_hi;
      Bit64u left = (left_qword >> shift) & mask;
      Bit64u right = (right_qword >> shift) & mask;
      Bit64u value = (subtract ? left - right : left + right) & mask;
      Bit64u *result_qword = bit_offset < 64 ? &result_lo : &result_hi;
      *result_qword |= value << shift;
    }

    if (!write_poly_aarch64_fp128_reg(rd, result_lo, result_hi))
      return false;

    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s v%u.%u-bit,v%u,v%u lo=%llu hi=%llu",
      subtract ? "sub" : "add", rd, element_bits, rn, rm,
      (unsigned long long) result_lo, (unsigned long long) result_hi));
    return true;
  }

  if ((insn & 0xffe00c00) == 0x1e200c00 ||
      (insn & 0xffe00c00) == 0x1e600c00) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u cond = (insn >> 12) & 0xf;
    Bit32u rm = (insn >> 16) & 0x1f;
    bool fp32_op = (insn & 0x00400000) == 0;
    bool take_left = bx_poly_aarch64_condition_holds(cond);

    if (fp32_op) {
      Bit32u left_bits = 0;
      Bit32u right_bits = 0;
      if (!read_poly_aarch64_fp32_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right_bits))
        return false;
      if (!write_poly_aarch64_fp32_reg(rd, take_left ? left_bits : right_bits))
        return false;
    }
    else {
      Bit64u left_bits = 0;
      Bit64u right_bits = 0;
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      if (!write_poly_aarch64_fp64_reg(rd, take_left ? left_bits : right_bits))
        return false;
    }

    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 fcsel%s v%u,v%u,v%u,cond=%u %s",
      fp32_op ? ".s" : ".d", rd, rn, rm, cond, take_left ? "left" : "right"));
    return true;
  }

  {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u shift_type = (insn >> 22) & 0x3;
    Bit32u shift_amount = (insn >> 10) & 0x3f;
    bool sf = (insn & 0x80000000) != 0;
    bool subtract = (insn & 0x40000000) != 0;
    Bit64u left = 0;
    Bit64u right = 0;
    unsigned bits = sf ? 64 : 32;

    if ((insn & 0x7f200000) == 0x2b000000 ||
        (insn & 0x7f200000) == 0x6b000000) {
      if (shift_type == 3)
        return false;
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg_width(right, shift_type, shift_amount, bits, &right))
        return false;
      Bit64u result = bx_poly_aarch64_addsub_flags(left, right, subtract, bits);
      if (rd != 31 && !write_poly_aarch64_reg(rd, sf ? result : (Bit32u) result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %ss %s%u,%s%u,%s%u,shift=%u,#%u nzcv=%x result=%llu",
        subtract ? "sub" : "add", sf ? "x" : "w", rd, sf ? "x" : "w", rn,
        sf ? "x" : "w", rm, shift_type, shift_amount, bx_poly_aarch64_nzcv,
        (unsigned long long) result));
      return true;
    }
  }

  if ((insn & 0x3fe00800) == 0x1a800000) {
    bool sf = (insn & 0x80000000) != 0;
    bool invert = (insn & 0x40000000) != 0;
    bool increment = (insn & 0x00000400) != 0;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u cond = (insn >> 12) & 0xf;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rd = insn & 0x1f;
    Bit64u mask = sf ? ~BX_CONST64(0) : 0xffffffff;
    Bit64u left = 0;
    Bit64u right = 0;
    if (!read_poly_aarch64_reg(rn, &left) ||
        !read_poly_aarch64_reg(rm, &right))
      return false;
    left &= mask;
    right &= mask;
    Bit64u result = right;
    if (invert)
      result = ~result;
    if (increment)
      result++;
    result = bx_poly_aarch64_condition_holds(cond) ? left : result;
    result &= mask;
    if (!sf)
      result = (Bit32u) result;
    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    const char *op_name = increment ? (invert ? "csneg" : "csinc") :
      (invert ? "csinv" : "csel");
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,%s%u,cond=%u result=%llu",
      op_name,
      sf ? "x" : "w", rd, sf ? "x" : "w", rn, sf ? "x" : "w", rm,
      cond, (unsigned long long) result));
    return true;
  }

  if ((insn & 0x1fe0fc00) == 0x1a000000) {
    bool sf = (insn & 0x80000000) != 0;
    bool subtract = (insn & 0x40000000) != 0;
    bool set_flags = (insn & 0x20000000) != 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    unsigned bits = sf ? 64 : 32;
    Bit64u mask = bx_poly_low_mask(bits);
    Bit64u sign_bit = BX_CONST64(1) << (bits - 1);
    Bit64u carry_in = (bx_poly_aarch64_nzcv & 0x2) ? 1 : 0;
    Bit64u left = 0;
    Bit64u right = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if (!read_poly_aarch64_reg(rn, &left) ||
        !read_poly_aarch64_reg(rm, &right))
      return false;
    left &= mask;
    right &= mask;

    if (subtract) {
      Bit64u borrow = carry_in ? 0 : 1;
      Bit64u subtrahend = (right + borrow) & mask;
      result = (left - subtrahend) & mask;
      if (set_flags) {
        bool carry = borrow ? left > right : left >= right;
        bool overflow =
          (((left ^ subtrahend) & (left ^ result) & sign_bit) != 0);
        bx_poly_aarch64_set_nzcv(result, carry, overflow, bits);
      }
      op_name = set_flags ? "sbcs" : "sbc";
    }
    else {
      unsigned __int128 sum =
        (unsigned __int128) left + right + carry_in;
      Bit64u addend = (right + carry_in) & mask;
      result = (Bit64u) sum & mask;
      if (set_flags) {
        bool carry = (sum >> bits) != 0;
        bool overflow =
          (((~(left ^ addend)) & (left ^ result) & sign_bit) != 0);
        bx_poly_aarch64_set_nzcv(result, carry, overflow, bits);
      }
      op_name = set_flags ? "adcs" : "adc";
    }

    if (rd != 31 && !write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,%s%u carry_in=%llu result=%llu nzcv=%x",
      op_name, sf ? "x" : "w", rd, sf ? "x" : "w", rn,
      sf ? "x" : "w", rm, (unsigned long long) carry_in,
      (unsigned long long) result, bx_poly_aarch64_nzcv));
    return true;
  }

  if ((insn & 0x7fe0f000) == 0x1ac02000) {
    bool sf = (insn & 0x80000000) != 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u shift_type = (insn >> 10) & 0x3;
    Bit32u rm = (insn >> 16) & 0x1f;
    unsigned bits = sf ? 64 : 32;
    Bit64u mask = bx_poly_low_mask(bits);
    Bit64u value = 0;
    Bit64u shift = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if (!read_poly_aarch64_reg(rn, &value) ||
        !read_poly_aarch64_reg(rm, &shift))
      return false;
    value &= mask;
    shift &= bits - 1;

    switch (shift_type) {
      case 0:
        op_name = "lsl";
        result = (value << shift) & mask;
        break;
      case 1:
        op_name = "lsr";
        result = value >> shift;
        break;
      case 2:
        op_name = "asr";
        result = bits == 32 ?
          (Bit32u) ((Bit32s) (Bit32u) value >> shift) :
          (Bit64u) ((Bit64s) value >> shift);
        break;
      case 3:
        op_name = "ror";
        result = shift == 0 ? value :
          ((value >> shift) | (value << (bits - shift))) & mask;
        break;
    }

    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,%s%u result=%llu",
      op_name, sf ? "x" : "w", rd, sf ? "x" : "w", rn,
      sf ? "x" : "w", rm, (unsigned long long) result));
    return true;
  }

  if ((insn & 0x1f000000) == 0x0a000000) {
    bool sf = (insn & 0x80000000) != 0;
    Bit32u opc = (insn >> 29) & 0x3;
    bool invert = (insn & 0x00200000) != 0;
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u shift_type = (insn >> 22) & 0x3;
    Bit32u shift_amount = (insn >> 10) & 0x3f;
    unsigned bits = sf ? 64 : 32;
    Bit64u mask = bx_poly_low_mask(bits);
    Bit64u left = 0;
    Bit64u right = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if (!read_poly_aarch64_reg(rn, &left) ||
        !read_poly_aarch64_reg(rm, &right))
      return false;
    if (!bx_poly_aarch64_shifted_reg_width(right, shift_type,
          shift_amount, bits, &right))
      return false;
    left &= mask;
    right &= mask;
    if (invert)
      right = (~right) & mask;

    switch (opc) {
      case 0:
        op_name = invert ? "bic" : "and";
        result = left & right;
        break;
      case 1:
        op_name = invert ? "orn" : "orr";
        result = left | right;
        break;
      case 2:
        op_name = invert ? "eon" : "eor";
        result = left ^ right;
        break;
      case 3:
        op_name = invert ? "bics" : "ands";
        result = left & right;
        bx_poly_aarch64_set_nzcv(result, false, false, bits);
        break;
    }
    result &= mask;

    if (rd != 31 && !write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,%s%u,shift=%u,#%u result=%llu nzcv=%x",
      op_name, sf ? "x" : "w", rd, sf ? "x" : "w", rn,
      sf ? "x" : "w", rm, shift_type, shift_amount,
      (unsigned long long) result, bx_poly_aarch64_nzcv));
    return true;
  }

  {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u shift_type = (insn >> 22) & 0x3;
    Bit32u shift_amount = (insn >> 10) & 0x3f;
    bool sf = (insn & 0x80000000) != 0;
    unsigned bits = sf ? 64 : 32;
    Bit64u left = 0;
    Bit64u right = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if ((insn & 0x7f200000) == 0x0b000000) {
      if (shift_type == 3)
        return false;
      op_name = "add";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg_width(right, shift_type, shift_amount, bits, &right))
        return false;
      result = left + right;
    }
    else if ((insn & 0x7f200000) == 0x4b000000) {
      if (shift_type == 3)
        return false;
      op_name = "sub";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg_width(right, shift_type, shift_amount, bits, &right))
        return false;
      result = left - right;
    }
    else if ((insn & 0x7fe0fc00) == 0x1b007c00) {
      op_name = "mul";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      result = left * right;
    }
    else if ((insn & 0x7fe08000) == 0x1b000000 ||
             (insn & 0x7fe08000) == 0x1b008000) {
      Bit32u ra = (insn >> 10) & 0x1f;
      bool subtract_product = (insn & 0x00008000) != 0;
      Bit64u addend = 0;
      op_name = subtract_product ? "msub" : "madd";
      if (!read_poly_aarch64_reg(rn, &left) ||
          !read_poly_aarch64_reg(rm, &right))
        return false;
      if (ra != 31 && !read_poly_aarch64_reg(ra, &addend))
        return false;
      left &= bx_poly_low_mask(bits);
      right &= bx_poly_low_mask(bits);
      addend &= bx_poly_low_mask(bits);
      result = subtract_product ? addend - (left * right) :
        addend + (left * right);
    }
    else if ((insn & 0xffe0fc00) == 0x9b407c00 ||
             (insn & 0xffe0fc00) == 0x9bc07c00) {
      bool is_unsigned = (insn & 0x00800000) != 0;
      op_name = is_unsigned ? "umulh" : "smulh";
      if (!read_poly_aarch64_reg(rn, &left) ||
          !read_poly_aarch64_reg(rm, &right))
        return false;
      if (is_unsigned)
        result = (Bit64u) (((unsigned __int128) left * right) >> 64);
      else
        result = (Bit64u) (((unsigned __int128)
          ((__int128) (Bit64s) left * (__int128) (Bit64s) right)) >> 64);
    }
    else if ((insn & 0x7fe0fc00) == 0x1ac00800 ||
             (insn & 0x7fe0fc00) == 0x1ac00c00) {
      bool signed_divide = (insn & 0x00000400) != 0;
      op_name = signed_divide ? "sdiv" : "udiv";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      left &= bx_poly_low_mask(bits);
      right &= bx_poly_low_mask(bits);
      if (right == 0) {
        result = 0;
      }
      else if (signed_divide) {
        Bit64u sign_bit = BX_CONST64(1) << (bits - 1);
        if (left == sign_bit && right == bx_poly_low_mask(bits)) {
          result = left;
        }
        else {
          Bit64s signed_left = bx_poly_sign_extend64(left, bits);
          Bit64s signed_right = bx_poly_sign_extend64(right, bits);
          result = (Bit64u) (signed_left / signed_right);
        }
      }
      else {
        result = left / right;
      }
    }
    else if ((insn & 0x7f200000) == 0x4a000000) {
      op_name = "eor";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg_width(right, shift_type, shift_amount, bits, &right))
        return false;
      result = left ^ right;
    }
    else if ((insn & 0x7f200000) == 0x0a000000) {
      op_name = "and";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg_width(right, shift_type, shift_amount, bits, &right))
        return false;
      result = left & right;
    }
    else if ((insn & 0x7f200000) == 0x2a000000) {
      op_name = "orr";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg_width(right, shift_type, shift_amount, bits, &right))
        return false;
      result = left | right;
    }

    if (op_name != 0) {
      result &= bx_poly_low_mask(bits);
      if (!write_poly_aarch64_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,%s%u,%s%u,shift=%u,#%u result=%llu",
        op_name, sf ? "x" : "w", rd, sf ? "x" : "w", rn,
        sf ? "x" : "w", rm, shift_type, shift_amount,
        (unsigned long long) result));
      return true;
    }
  }

  if ((insn & 0x3fe00c10) == 0x3a400000 ||
      (insn & 0x3fe00c10) == 0x3a400800) {
    bool sf = (insn & 0x80000000) != 0;
    bool subtract = (insn & 0x40000000) != 0;
    bool immediate = (insn & 0x00000800) != 0;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u cond = (insn >> 12) & 0xf;
    Bit32u nzcv = insn & 0xf;
    unsigned bits = sf ? 64 : 32;
    Bit64u left = 0;
    Bit64u right = 0;

    if (!bx_poly_aarch64_condition_holds(cond)) {
      bx_poly_aarch64_nzcv = nzcv;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s%s cond=%u false nzcv=%x",
        subtract ? "ccmp" : "ccmn", immediate ? "-imm" : "-reg",
        cond, bx_poly_aarch64_nzcv));
      return true;
    }

    if (!read_poly_aarch64_reg(rn, &left))
      return false;
    if (immediate) {
      right = (insn >> 16) & 0x1f;
    }
    else {
      Bit32u rm = (insn >> 16) & 0x1f;
      if (!read_poly_aarch64_reg(rm, &right))
        return false;
    }

    bx_poly_aarch64_addsub_flags(left, right, subtract, bits);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s%s %s%u,%llu,#%x,cond=%u nzcv=%x",
      subtract ? "ccmp" : "ccmn", immediate ? "-imm" : "-reg",
      sf ? "x" : "w", rn, (unsigned long long) right, nzcv, cond,
      bx_poly_aarch64_nzcv));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_X86_ESCAPE) {
    bx_poly_current_mode = BX_POLY_MODE_X86;
    bx_poly_clear_cross_return_stack();
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 polyctrl escape to x86"));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_TRAP_RETURN) {
    BX_DEBUG(("poly_raw: aarch64 polyctrl trap return"));
    return return_poly_architectural_trap();
  }

  if (insn == BX_POLY_AARCH64_CTRL_LANDING) {
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 landing pad"));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_TRAP_VECTOR_SET) {
    Bit64u vector = 0;
    if (!read_poly_aarch64_reg(0, &vector))
      return false;
    bx_poly_trap_vector = (bx_address) vector;
    bx_address stack_key = bx_poly_current_state_key(RSP);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
    bx_poly_propagate_trap_vector_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      stack_key);
    write_poly_aarch64_reg(0, 0);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 trap vector set value=%llx",
      (unsigned long long) vector));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_TRAP_VECTOR_GET) {
    write_poly_aarch64_reg(0, bx_poly_trap_vector);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 trap vector get value=%llx",
      (unsigned long long) bx_poly_trap_vector));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_TRAP_VECTOR_MODE_SET) {
    Bit64u mode = 0;
    if (!read_poly_aarch64_reg(0, &mode))
      return false;
    if (!bx_poly_valid_frontend_mode((Bit32u) mode)) {
      write_poly_aarch64_reg(0, (Bit64u) (Bit64s) -22);
      RIP = next_rip;
      return true;
    }
    bx_poly_trap_vector_mode = (Bit32u) mode;
    bx_address stack_key = bx_poly_current_state_key(RSP);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
    bx_poly_propagate_trap_vector_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      stack_key);
    write_poly_aarch64_reg(0, 0);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 trap vector mode set value=%u",
      bx_poly_trap_vector_mode));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_TRAP_VECTOR_MODE_GET) {
    write_poly_aarch64_reg(0, bx_poly_trap_vector_mode);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 trap vector mode get value=%u",
      bx_poly_trap_vector_mode));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_MONITOR_PACKET_SET) {
    Bit64u packet = 0;
    if (!read_poly_aarch64_reg(0, &packet))
      return false;
    bx_poly_monitor_packet_addr = (bx_address) packet;
    bx_address stack_key = bx_poly_current_state_key(RSP);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
    bx_poly_propagate_trap_vector_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      stack_key);
    write_poly_aarch64_reg(0, 0);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 monitor packet set value=%llx",
      (unsigned long long) packet));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_MONITOR_PACKET_GET) {
    write_poly_aarch64_reg(0, bx_poly_monitor_packet_addr);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 monitor packet get value=%llx",
      (unsigned long long) bx_poly_monitor_packet_addr));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_ABI_SIGNATURE_SET) {
    Bit64u slot = 0;
    Bit64u kind = 0;
    if (!read_poly_aarch64_reg(0, &slot) ||
        !read_poly_aarch64_reg(1, &kind))
      return false;
    if (slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT ||
        !bx_poly_valid_abi_signature_kind((Bit32u) kind)) {
      write_poly_aarch64_reg(0, (Bit64u) (Bit64s) -22);
      RIP = next_rip;
      return true;
    }
    bx_poly_abi_signature_slots[(Bit32u) slot].kind = (Bit32u) kind;
    write_poly_aarch64_reg(0, 0);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 ABI signature set slot=%llu kind=%llu",
      (unsigned long long) slot, (unsigned long long) kind));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_ABI_SIGNATURE_GET) {
    Bit64u slot = 0;
    if (!read_poly_aarch64_reg(0, &slot))
      return false;
    if (slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT) {
      write_poly_aarch64_reg(0, (Bit64u) (Bit64s) -22);
      RIP = next_rip;
      return true;
    }
    write_poly_aarch64_reg(0,
      bx_poly_abi_signature_slots[(Bit32u) slot].kind);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 ABI signature get slot=%llu",
      (unsigned long long) slot));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_LANDING_POLICY_SET) {
    Bit64u policy = 0;
    if (!read_poly_aarch64_reg(0, &policy))
      return false;
    if (!bx_poly_valid_landing_policy(policy)) {
      write_poly_aarch64_reg(0, (Bit64u) (Bit64s) -22);
      RIP = next_rip;
      return true;
    }
    bx_poly_landing_policy_flags = policy;
    write_poly_aarch64_reg(0, 0);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 landing policy set value=%llx",
      (unsigned long long) policy));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_LANDING_POLICY_GET) {
    write_poly_aarch64_reg(0, bx_poly_landing_policy_flags);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 landing policy get value=%llx",
      (unsigned long long) bx_poly_landing_policy_flags));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_RISCV_SWITCH) {
    if (!bx_poly_require_landing_target(BX_SEG_REG_CS, next_rip,
          BX_POLY_MODE_RAW_RISCV, BX_POLY_LANDING_POLICY_REQUIRE_SWITCH,
          "aarch64-switch"))
      return false;
    bx_poly_capture_tls_base_for_mode(bx_poly_current_mode);
    bx_poly_current_mode = BX_POLY_MODE_RAW_RISCV;
    bx_poly_prepare_tls_for_mode(bx_poly_current_mode);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: aarch64 polyctrl switch to riscv"));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_SWITCH_MODE) {
    Bit64u target = 0;
    Bit64u frontend = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &frontend))
      return false;
    Bit32u frontend_id = (Bit32u) frontend;
    Bit32u target_mode = BX_POLY_MODE_X86;
    if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode)) {
      BX_INFO(("poly_raw: reject aarch64 generic switch frontend=%u",
        frontend_id));
      return false;
    }
    if (!bx_poly_require_landing_target(BX_SEG_REG_CS, (bx_address) target,
          target_mode, BX_POLY_LANDING_POLICY_REQUIRE_SWITCH,
          "aarch64-generic-switch"))
      return false;
    bx_poly_capture_tls_base_for_mode(bx_poly_current_mode);
    bx_poly_current_mode = target_mode;
    if (target_mode == BX_POLY_MODE_X86)
      bx_poly_clear_cross_return_stack();
    bx_poly_prepare_tls_for_mode(target_mode);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = (bx_address) target;
    BX_DEBUG(("poly_raw: aarch64 generic switch frontend=%u mode=%u target=%llx",
      frontend_id, target_mode, (unsigned long long) target));
    return true;
  }

  if (insn == BX_POLY_AARCH64_CTRL_CALL_MODE) {
    Bit64u target = 0;
    Bit64u frontend = 0;
    Bit64u return_rip = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &frontend) ||
        !read_poly_aarch64_reg(18, &return_rip))
      return false;
    Bit32u frontend_id = (Bit32u) frontend;
    Bit32u target_mode = BX_POLY_MODE_X86;
    if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode) ||
        target_mode == BX_POLY_MODE_RAW_AARCH64) {
      BX_INFO(("poly_raw: reject aarch64 generic call frontend=%u mode=%u",
        frontend_id, target_mode));
      return false;
    }
    if (target_mode == BX_POLY_MODE_X86) {
      if (handle_poly_import_call(BX_POLY_MODE_RAW_AARCH64,
            (bx_address) target, (bx_address) return_rip))
        return true;
      return enter_poly_x86_direct_call(BX_POLY_MODE_RAW_AARCH64,
        (bx_address) target, (bx_address) return_rip,
        BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS);
    }
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64, target_mode,
      (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_DEFAULT);
  }

  Bit32u aarch64_signature_imm_slot = 0;
  if (bx_poly_aarch64_ctrl_slot(insn,
        BX_POLY_AARCH64_CTRL_SUBOP_CALL_SIG_IMM_BASE,
        &aarch64_signature_imm_slot)) {
    Bit64u target = 0;
    Bit64u frontend = 0;
    Bit64u return_rip = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &frontend) ||
        !read_poly_aarch64_reg(18, &return_rip))
      return false;
    Bit32u frontend_id = (Bit32u) frontend;
    Bit32u target_mode = BX_POLY_MODE_X86;
    if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode) ||
        target_mode == BX_POLY_MODE_RAW_AARCH64) {
      BX_INFO(("poly_raw: reject aarch64 immediate signature call frontend=%u mode=%u",
        frontend_id, target_mode));
      return false;
    }
    bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    Bit32u source_kind =
      bx_poly_abi_signature_slots[aarch64_signature_imm_slot].kind;
    if (target_mode == BX_POLY_MODE_X86) {
      if (handle_poly_import_call(BX_POLY_MODE_RAW_AARCH64,
            (bx_address) target, (bx_address) return_rip))
        return true;
      return enter_poly_x86_direct_call(BX_POLY_MODE_RAW_AARCH64,
        (bx_address) target, (bx_address) return_rip, source_kind);
    }
    Bit32u bridge_kind = BX_POLY_CROSS_BRIDGE_DEFAULT;
    if (!bx_poly_cross_bridge_for_abi_signature_kind(source_kind,
          &bridge_kind)) {
      BX_INFO(("poly_raw: reject aarch64 immediate signature call kind=%u",
        source_kind));
      return false;
    }
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64, target_mode,
      (bx_address) target, (bx_address) return_rip,
      bridge_kind);
  }

  if (insn == BX_POLY_AARCH64_CTRL_CALL_SIG_MODE) {
    Bit64u target = 0;
    Bit64u frontend = 0;
    Bit64u return_rip = 0;
    Bit64u signature_slot = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &frontend) ||
        !read_poly_aarch64_reg(18, &return_rip) ||
        !read_poly_aarch64_reg(19, &signature_slot))
      return false;
    Bit32u frontend_id = (Bit32u) frontend;
    Bit32u target_mode = BX_POLY_MODE_X86;
    if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode) ||
        target_mode == BX_POLY_MODE_RAW_AARCH64) {
      BX_INFO(("poly_raw: reject aarch64 generic signature call frontend=%u mode=%u",
        frontend_id, target_mode));
      return false;
    }
    if (signature_slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT) {
      BX_INFO(("poly_raw: reject aarch64 generic signature call slot=%llu",
        (unsigned long long) signature_slot));
      return false;
    }
    bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    Bit32u source_kind =
      bx_poly_abi_signature_slots[(Bit32u) signature_slot].kind;
    if (target_mode == BX_POLY_MODE_X86) {
      if (handle_poly_import_call(BX_POLY_MODE_RAW_AARCH64,
            (bx_address) target, (bx_address) return_rip))
        return true;
      return enter_poly_x86_direct_call(BX_POLY_MODE_RAW_AARCH64,
        (bx_address) target, (bx_address) return_rip, source_kind);
    }
    Bit32u bridge_kind = BX_POLY_CROSS_BRIDGE_DEFAULT;
    if (!bx_poly_cross_bridge_for_abi_signature_kind(source_kind,
          &bridge_kind)) {
      BX_INFO(("poly_raw: reject aarch64 generic signature call kind=%u",
        source_kind));
      return false;
    }
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64, target_mode,
      (bx_address) target, (bx_address) return_rip,
      bridge_kind);
  }

  if (insn == BX_POLY_AARCH64_CTRL_RISCV_CALL) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64,
      BX_POLY_MODE_RAW_RISCV, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_DEFAULT);
  }

  if (insn == BX_POLY_AARCH64_CTRL_RISCV_CALL_COMPACT_U32_F32 ||
      insn == BX_POLY_AARCH64_CTRL_RISCV_CALL_COMPACT_F32_U32) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &return_rip))
      return false;
    Bit32u bridge_kind =
      insn == BX_POLY_AARCH64_CTRL_RISCV_CALL_COMPACT_U32_F32 ?
      BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 :
      BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64,
      BX_POLY_MODE_RAW_RISCV, (bx_address) target, (bx_address) return_rip,
      bridge_kind);
  }

  if (insn == BX_POLY_AARCH64_CTRL_RISCV_CALL_FP64_STACK) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64,
      BX_POLY_MODE_RAW_RISCV, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_FP64_STACK);
  }

  if (insn == BX_POLY_AARCH64_CTRL_RISCV_CALL_VEC128_U32) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64,
      BX_POLY_MODE_RAW_RISCV, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_VEC128_U32);
  }

  if ((insn & 0xff000010) == 0x54000000) {
    Bit32u cond = insn & 0xf;
    Bit64s guest_offset = bx_poly_sign_extend((insn >> 5) & 0x7ffff, 19) << 2;
    bool taken = bx_poly_aarch64_condition_holds(cond);
    RIP = taken ? (bx_address) ((Bit64s) pc + guest_offset) : next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 b.cond cond=%u %s offset=%lld nzcv=%x",
      cond, taken ? "taken" : "not-taken", (long long) guest_offset, bx_poly_aarch64_nzcv));
    return true;
  }

  if ((insn & 0x7c000000) == 0x14000000) {
    Bit64s guest_offset = bx_poly_sign_extend(insn & 0x03ffffff, 26) << 2;
    if (insn & 0x80000000) {
      if (!write_poly_aarch64_reg(30, next_rip))
        return false;
      BX_DEBUG(("poly_raw: emulated aarch64 bl offset=%lld link=%llx", (long long) guest_offset, (unsigned long long) next_rip));
    }
    else {
      BX_DEBUG(("poly_raw: emulated aarch64 b offset=%lld", (long long) guest_offset));
    }
    RIP = (bx_address) ((Bit64s) pc + guest_offset);
    return true;
  }

  if ((insn & 0x7e000000) == 0x36000000) {
    Bit32u rt = insn & 0x1f;
    Bit32u bit = (((insn >> 31) & 0x1) << 5) | ((insn >> 19) & 0x1f);
    Bit64s guest_offset = bx_poly_sign_extend((insn >> 5) & 0x3fff, 14) << 2;
    bool branch_on_one = (insn & 0x01000000) != 0;
    Bit64u value = 0;
    if (!read_poly_aarch64_reg(rt, &value))
      return false;
    bool bit_set = (value & (BX_CONST64(1) << bit)) != 0;
    bool taken = branch_on_one ? bit_set : !bit_set;
    RIP = taken ? (bx_address) ((Bit64s) pc + guest_offset) : next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s x%u,#%u %s offset=%lld",
      branch_on_one ? "tbnz" : "tbz", rt, bit, taken ? "taken" : "not-taken",
      (long long) guest_offset));
    return true;
  }

  if ((insn & 0x7e000000) == 0x34000000) {
    Bit32u rt = insn & 0x1f;
    bool sf = (insn & 0x80000000) != 0;
    Bit32u op = (insn >> 24) & 1;
    Bit64u value = 0;
    if (!read_poly_aarch64_reg(rt, &value))
      return false;
    if (!sf)
      value = (Bit32u) value;
    bool taken = (op == 0) ? (value == 0) : (value != 0);
    if (taken) {
      Bit64s guest_offset = bx_poly_sign_extend((insn >> 5) & 0x7ffff, 19) << 2;
      RIP = (bx_address) ((Bit64s) pc + guest_offset);
      BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u taken offset=%lld",
        op ? "cbnz" : "cbz", sf ? "x" : "w", rt, (long long) guest_offset));
    }
    else {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u not-taken",
        op ? "cbnz" : "cbz", sf ? "x" : "w", rt));
    }
    return true;
  }

  if ((insn & 0xfffffc1f) == 0xd61f0000 ||
      (insn & 0xfffffc1f) == 0xd63f0000) {
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit64u target = 0;
    bool link = (insn & 0xfffffc1f) == 0xd63f0000;
    if (!read_poly_aarch64_reg(rn, &target))
      return false;
    if (link && !write_poly_aarch64_reg(30, next_rip))
      return false;
    if (target >= (Bit64u) BX_POLY_IMPORT_CALL_BASE) {
      Bit64u import_return = next_rip;
      // AArch64 PLT stubs branch with br x17 after the caller's bl set x30.
      if (!link && !read_poly_aarch64_reg(30, &import_return))
        return false;
      if (handle_poly_import_call(BX_POLY_MODE_RAW_AARCH64,
            (bx_address) target, (bx_address) import_return))
        return true;
    }
    RIP = (bx_address) target;
    BX_DEBUG(("poly_raw: emulated aarch64 %s x%u target=%llx", link ? "blr" : "br", rn, (unsigned long long) target));
    return true;
  }

  if ((insn & 0xfffffc1f) == 0xd65f0000) {
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit64u ret_addr = 0;
    if (!read_poly_aarch64_reg(rn, &ret_addr))
      return false;
    if (return_poly_cross_call(BX_POLY_MODE_RAW_AARCH64, (bx_address) ret_addr))
      return true;
    if (return_poly_abi_call(BX_POLY_MODE_RAW_AARCH64, (bx_address) ret_addr))
      return true;
    RIP = (bx_address) ret_addr;
    BX_DEBUG(("poly_raw: emulated aarch64 ret x%u target=%llx", rn, (unsigned long long) ret_addr));
    return true;
  }

  {
    Bit32u pair_op = insn & 0xffc00000;
    bool is_load = false;
    bool writeback = false;
    bool post_index = false;
    bool is_double = false;
    bool is_quad = false;
    const char *op_name = 0;

    switch (pair_op) {
    case 0x2c800000:
      writeback = true;
      post_index = true;
      op_name = "stp.s-post";
      break;
    case 0x2cc00000:
      is_load = true;
      writeback = true;
      post_index = true;
      op_name = "ldp.s-post";
      break;
    case 0x2d000000:
      op_name = "stp.s";
      break;
    case 0x2d400000:
      is_load = true;
      op_name = "ldp.s";
      break;
    case 0x2d800000:
      writeback = true;
      op_name = "stp.s-pre";
      break;
    case 0x2dc00000:
      is_load = true;
      writeback = true;
      op_name = "ldp.s-pre";
      break;
    case 0x6c800000:
      writeback = true;
      post_index = true;
      is_double = true;
      op_name = "stp.d-post";
      break;
    case 0x6cc00000:
      is_load = true;
      writeback = true;
      post_index = true;
      is_double = true;
      op_name = "ldp.d-post";
      break;
    case 0x6d000000:
      is_double = true;
      op_name = "stp.d";
      break;
    case 0x6d400000:
      is_load = true;
      is_double = true;
      op_name = "ldp.d";
      break;
    case 0x6d800000:
      writeback = true;
      is_double = true;
      op_name = "stp.d-pre";
      break;
    case 0x6dc00000:
      is_load = true;
      writeback = true;
      is_double = true;
      op_name = "ldp.d-pre";
      break;
    case 0xac800000:
      writeback = true;
      post_index = true;
      is_quad = true;
      op_name = "stp.q-post";
      break;
    case 0xacc00000:
      is_load = true;
      writeback = true;
      post_index = true;
      is_quad = true;
      op_name = "ldp.q-post";
      break;
    case 0xad000000:
      is_quad = true;
      op_name = "stp.q";
      break;
    case 0xad400000:
      is_load = true;
      is_quad = true;
      op_name = "ldp.q";
      break;
    case 0xad800000:
      writeback = true;
      is_quad = true;
      op_name = "stp.q-pre";
      break;
    case 0xadc00000:
      is_load = true;
      writeback = true;
      is_quad = true;
      op_name = "ldp.q-pre";
      break;
    }

    if (op_name != 0) {
      Bit32u rt = insn & 0x1f;
      Bit32u rn = (insn >> 5) & 0x1f;
      Bit32u rt2 = (insn >> 10) & 0x1f;
      Bit32u scale = is_quad ? 4 : (is_double ? 3 : 2);
      Bit64s offset = bx_poly_sign_extend((insn >> 15) & 0x7f, 7) << scale;
      Bit64u base = 0;

      if (rn == 31)
        base = RSP;
      else if (!read_poly_aarch64_reg(rn, &base))
        return false;

      bx_address addr = (bx_address) (post_index ? base : base + offset);
      if (is_load) {
        if (is_quad) {
          Bit64u lo0 = read_virtual_qword(BX_SEG_REG_DS, addr);
          Bit64u hi0 = read_virtual_qword(BX_SEG_REG_DS, addr + 8);
          Bit64u lo1 = read_virtual_qword(BX_SEG_REG_DS, addr + 16);
          Bit64u hi1 = read_virtual_qword(BX_SEG_REG_DS, addr + 24);
          if (!write_poly_aarch64_fp128_reg(rt, lo0, hi0) ||
              !write_poly_aarch64_fp128_reg(rt2, lo1, hi1))
            return false;
        }
        else if (is_double) {
          Bit64u value0 = read_virtual_qword(BX_SEG_REG_DS, addr);
          Bit64u value1 = read_virtual_qword(BX_SEG_REG_DS, addr + 8);
          if (!write_poly_aarch64_fp64_reg(rt, value0) ||
              !write_poly_aarch64_fp64_reg(rt2, value1))
            return false;
        }
        else {
          Bit32u value0 = read_virtual_dword(BX_SEG_REG_DS, addr);
          Bit32u value1 = read_virtual_dword(BX_SEG_REG_DS, addr + 4);
          if (!write_poly_aarch64_fp32_reg(rt, value0) ||
              !write_poly_aarch64_fp32_reg(rt2, value1))
            return false;
        }
      }
      else {
        if (is_quad) {
          Bit64u lo0 = 0, hi0 = 0, lo1 = 0, hi1 = 0;
          if (!read_poly_aarch64_fp128_reg(rt, &lo0, &hi0) ||
              !read_poly_aarch64_fp128_reg(rt2, &lo1, &hi1))
            return false;
          write_virtual_qword(BX_SEG_REG_DS, addr, lo0);
          write_virtual_qword(BX_SEG_REG_DS, addr + 8, hi0);
          write_virtual_qword(BX_SEG_REG_DS, addr + 16, lo1);
          write_virtual_qword(BX_SEG_REG_DS, addr + 24, hi1);
        }
        else if (is_double) {
          Bit64u value0 = 0, value1 = 0;
          if (!read_poly_aarch64_fp64_reg(rt, &value0) ||
              !read_poly_aarch64_fp64_reg(rt2, &value1))
            return false;
          write_virtual_qword(BX_SEG_REG_DS, addr, value0);
          write_virtual_qword(BX_SEG_REG_DS, addr + 8, value1);
        }
        else {
          Bit32u value0 = 0, value1 = 0;
          if (!read_poly_aarch64_fp32_reg(rt, &value0) ||
              !read_poly_aarch64_fp32_reg(rt2, &value1))
            return false;
          write_virtual_dword(BX_SEG_REG_DS, addr, value0);
          write_virtual_dword(BX_SEG_REG_DS, addr + 4, value1);
        }
      }

      if (writeback) {
        Bit64u new_base = base + offset;
        if (rn == 31)
          RSP = new_base;
        else if (!write_poly_aarch64_reg(rn, new_base))
          return false;
      }

      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s v%u,v%u,[x%u],offset=%lld addr=%llx",
        op_name, rt, rt2, rn, (long long) offset, (unsigned long long) addr));
      return true;
    }
  }

  {
    Bit32u pair_op = insn & 0xffc00000;
    bool is_load = false;
    bool writeback = false;
    bool post_index = false;
    Bit32u width = 8;
    const char *op_name = 0;

    switch (pair_op) {
    case 0x28800000:
      width = 4;
      writeback = true;
      post_index = true;
      op_name = "stp.w-post";
      break;
    case 0x28c00000:
      width = 4;
      is_load = true;
      writeback = true;
      post_index = true;
      op_name = "ldp.w-post";
      break;
    case 0x29000000:
      width = 4;
      op_name = "stp.w";
      break;
    case 0x29400000:
      width = 4;
      is_load = true;
      op_name = "ldp.w";
      break;
    case 0x29800000:
      width = 4;
      writeback = true;
      op_name = "stp.w-pre";
      break;
    case 0x29c00000:
      width = 4;
      is_load = true;
      writeback = true;
      op_name = "ldp.w-pre";
      break;
    case 0xa8800000:
      writeback = true;
      post_index = true;
      op_name = "stp-post";
      break;
    case 0xa8c00000:
      is_load = true;
      writeback = true;
      post_index = true;
      op_name = "ldp-post";
      break;
    case 0xa9000000:
      op_name = "stp";
      break;
    case 0xa9400000:
      is_load = true;
      op_name = "ldp";
      break;
    case 0xa9800000:
      writeback = true;
      op_name = "stp-pre";
      break;
    case 0xa9c00000:
      is_load = true;
      writeback = true;
      op_name = "ldp-pre";
      break;
    }

    if (op_name != 0) {
      Bit32u rt = insn & 0x1f;
      Bit32u rn = (insn >> 5) & 0x1f;
      Bit32u rt2 = (insn >> 10) & 0x1f;
      Bit64s offset = bx_poly_sign_extend((insn >> 15) & 0x7f, 7) << (width == 8 ? 3 : 2);
      Bit64u base = 0;
      Bit64u value0 = 0;
      Bit64u value1 = 0;

      if (rn == 31)
        base = RSP;
      else if (!read_poly_aarch64_reg(rn, &base))
        return false;

      bx_address addr = (bx_address) (post_index ? base : base + offset);
      if (is_load) {
        if (width == 8) {
          value0 = read_virtual_qword(BX_SEG_REG_DS, addr);
          value1 = read_virtual_qword(BX_SEG_REG_DS, addr + 8);
        }
        else {
          value0 = read_virtual_dword(BX_SEG_REG_DS, addr);
          value1 = read_virtual_dword(BX_SEG_REG_DS, addr + 4);
        }
        if (!write_poly_aarch64_reg(rt, value0) ||
            !write_poly_aarch64_reg(rt2, value1))
          return false;
      }
      else {
        if (!read_poly_aarch64_reg(rt, &value0) ||
            !read_poly_aarch64_reg(rt2, &value1))
          return false;
        if (width == 8) {
          write_virtual_qword(BX_SEG_REG_DS, addr, value0);
          write_virtual_qword(BX_SEG_REG_DS, addr + 8, value1);
        }
        else {
          write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) value0);
          write_virtual_dword(BX_SEG_REG_DS, addr + 4, (Bit32u) value1);
        }
      }

      if (writeback) {
        Bit64u new_base = base + offset;
        if (rn == 31)
          RSP = new_base;
        else if (!write_poly_aarch64_reg(rn, new_base))
          return false;
      }

      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s %c%u,%c%u,[x%u],offset=%lld addr=%llx",
        op_name, width == 8 ? 'x' : 'w', rt, width == 8 ? 'x' : 'w',
        rt2, rn, (long long) offset, (unsigned long long) addr));
      return true;
    }
  }

  if ((insn & 0x3b000000) == 0x39000000 && (insn & 0x04000000)) {
    Bit32u rt = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u size = (insn >> 30) & 0x3;
    Bit32u opc = (insn >> 22) & 0x3;
    Bit32u imm12 = (insn >> 10) & 0xfff;
    Bit64u base = 0;
    bx_address addr;

    if (size < 2 && !(size == 0 && (opc == 2 || opc == 3)))
      return false;
    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;

    Bit32u scale = (size == 0 && (opc == 2 || opc == 3)) ? 4 : size;
    addr = (bx_address) (base + ((Bit64u) imm12 << scale));
    if (opc & 1) {
      if (size == 0 && opc == 3) {
        Bit64u lo = read_virtual_qword(BX_SEG_REG_DS, addr);
        Bit64u hi = read_virtual_qword(BX_SEG_REG_DS, addr + 8);
        if (!write_poly_aarch64_fp128_reg(rt, lo, hi))
          return false;
      }
      else if (size == 2) {
        Bit32u value = read_virtual_dword(BX_SEG_REG_DS, addr);
        if (!write_poly_aarch64_fp32_reg(rt, value))
          return false;
      }
      else {
        Bit64u value = read_virtual_qword(BX_SEG_REG_DS, addr);
        if (!write_poly_aarch64_fp64_reg(rt, value))
          return false;
      }
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 fp ldr%u v%u,[x%u,#%u] addr=%llx",
        size == 0 ? 128U : (8U << size), rt, rn, imm12 << scale,
        (unsigned long long) addr));
      return true;
    }

    if (size == 0 && opc == 2) {
      Bit64u lo = 0, hi = 0;
      if (!read_poly_aarch64_fp128_reg(rt, &lo, &hi))
        return false;
      write_virtual_qword(BX_SEG_REG_DS, addr, lo);
      write_virtual_qword(BX_SEG_REG_DS, addr + 8, hi);
    }
    else if (size == 2) {
      Bit32u value = 0;
      if (!read_poly_aarch64_fp32_reg(rt, &value))
        return false;
      write_virtual_dword(BX_SEG_REG_DS, addr, value);
    }
    else {
      Bit64u value = 0;
      if (!read_poly_aarch64_fp64_reg(rt, &value))
        return false;
      write_virtual_qword(BX_SEG_REG_DS, addr, value);
    }
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 fp str%u v%u,[x%u,#%u] addr=%llx",
      size == 0 ? 128U : (8U << size), rt, rn, imm12 << scale,
      (unsigned long long) addr));
    return true;
  }

  if ((insn & 0x3b200000) == 0x38000000) {
    Bit32u rt = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u size = (insn >> 30) & 0x3;
    Bit32u opc = (insn >> 22) & 0x3;
    Bit64s offset = bx_poly_sign_extend((insn >> 12) & 0x1ff, 9);
    Bit32u addr_mode = (insn >> 10) & 0x3;
    bool post_index = addr_mode == 1;
    bool pre_index = addr_mode == 3;
    bool fp = (insn & 0x04000000) != 0;
    Bit64u base = 0;
    Bit64u value = 0;
    bx_address addr;

    if (addr_mode == 2)
      return false;

    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;

    addr = (bx_address) (post_index ? base : (Bit64s) base + offset);
    if (!fp && size == 3 && opc == 2) {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 prfum [x%u,#%lld] addr=%llx as no-op",
        rn, (long long) offset, (unsigned long long) addr));
      return true;
    }
    if (fp) {
      if (size < 2)
        return false;
      if (opc == 1) {
        if (size == 2) {
          Bit32u fp_value = read_virtual_dword(BX_SEG_REG_DS, addr);
          if (!write_poly_aarch64_fp32_reg(rt, fp_value))
            return false;
        }
        else {
          Bit64u fp_value = read_virtual_qword(BX_SEG_REG_DS, addr);
          if (!write_poly_aarch64_fp64_reg(rt, fp_value))
            return false;
        }
        if (pre_index || post_index) {
          Bit64u new_base = base + offset;
          if (rn == 31)
            RSP = new_base;
          else if (!write_poly_aarch64_reg(rn, new_base))
            return false;
        }
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated aarch64 fp ldr%u%s v%u,[x%u,#%lld] addr=%llx",
          8U << size, (pre_index || post_index) ? "-wb" : "ur",
          rt, rn, (long long) offset, (unsigned long long) addr));
        return true;
      }
      if (opc != 0)
        return false;
      if (size == 2) {
        Bit32u fp_value = 0;
        if (!read_poly_aarch64_fp32_reg(rt, &fp_value))
          return false;
        write_virtual_dword(BX_SEG_REG_DS, addr, fp_value);
      }
      else {
        Bit64u fp_value = 0;
        if (!read_poly_aarch64_fp64_reg(rt, &fp_value))
          return false;
        write_virtual_qword(BX_SEG_REG_DS, addr, fp_value);
      }
      if (pre_index || post_index) {
        Bit64u new_base = base + offset;
        if (rn == 31)
          RSP = new_base;
        else if (!write_poly_aarch64_reg(rn, new_base))
          return false;
      }
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 fp str%u%s v%u,[x%u,#%lld] addr=%llx",
        8U << size, (pre_index || post_index) ? "-wb" : "ur",
        rt, rn, (long long) offset, (unsigned long long) addr));
      return true;
    }

    if (opc == 1) {
      if (size == 0)
        value = read_virtual_byte(BX_SEG_REG_DS, addr);
      else if (size == 1)
        value = read_virtual_word(BX_SEG_REG_DS, addr);
      else if (size == 2)
        value = read_virtual_dword(BX_SEG_REG_DS, addr);
      else
        value = read_virtual_qword(BX_SEG_REG_DS, addr);
      if (!write_poly_aarch64_reg(rt, value))
        return false;
      if (pre_index || post_index) {
        Bit64u new_base = base + offset;
        if (rn == 31)
          RSP = new_base;
        else if (!write_poly_aarch64_reg(rn, new_base))
          return false;
      }
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 ldr%u%s x%u,[x%u,#%lld] addr=%llx value=%llu",
        8U << size, (pre_index || post_index) ? "-wb" : "ur",
        rt, rn, (long long) offset, (unsigned long long) addr,
        (unsigned long long) value));
      return true;
    }

    if ((opc == 2 && size < 3) || (opc == 3 && size < 2)) {
      if (size == 0)
        value = (Bit64u) bx_poly_sign_extend(read_virtual_byte(BX_SEG_REG_DS, addr), 8);
      else if (size == 1)
        value = (Bit64u) bx_poly_sign_extend(read_virtual_word(BX_SEG_REG_DS, addr), 16);
      else
        value = (Bit64u) bx_poly_sign_extend(read_virtual_dword(BX_SEG_REG_DS, addr), 32);
      if (opc == 3)
        value = (Bit32u) value;
      if (!write_poly_aarch64_reg(rt, value))
        return false;
      if (pre_index || post_index) {
        Bit64u new_base = base + offset;
        if (rn == 31)
          RSP = new_base;
        else if (!write_poly_aarch64_reg(rn, new_base))
          return false;
      }
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 ldrs%u%s x%u,[x%u,#%lld] addr=%llx value=%llu",
        8U << size, (pre_index || post_index) ? "-wb" : "ur",
        rt, rn, (long long) offset, (unsigned long long) addr,
        (unsigned long long) value));
      return true;
    }

    if (opc != 0)
      return false;
    if (!read_poly_aarch64_reg(rt, &value))
      return false;
    if (size == 0)
      write_virtual_byte(BX_SEG_REG_DS, addr, (Bit8u) value);
    else if (size == 1)
      write_virtual_word(BX_SEG_REG_DS, addr, (Bit16u) value);
    else if (size == 2)
      write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) value);
    else
      write_virtual_qword(BX_SEG_REG_DS, addr, value);
    if (pre_index || post_index) {
      Bit64u new_base = base + offset;
      if (rn == 31)
        RSP = new_base;
      else if (!write_poly_aarch64_reg(rn, new_base))
        return false;
    }
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 str%u%s x%u,[x%u,#%lld] addr=%llx value=%llu",
      8U << size, (pre_index || post_index) ? "-wb" : "ur",
      rt, rn, (long long) offset, (unsigned long long) addr,
      (unsigned long long) value));
    return true;
  }

  if ((insn & 0x3b200c00) == 0x38200800) {
    Bit32u rt = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u size = (insn >> 30) & 0x3;
    Bit32u opc = (insn >> 22) & 0x3;
    bool fp = (insn & 0x04000000) != 0;
    Bit32u option = (insn >> 13) & 0x7;
    Bit32u shift = (insn & 0x00001000) ? size : 0;
    Bit64u base = 0;
    Bit64u index = 0;
    Bit64u value = 0;
    bx_address addr;

    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;
    if (!read_poly_aarch64_reg(rm, &index))
      return false;

    if (option == 2)
      index = (Bit32u) index;
    else if (option == 3)
      index = index;
    else if (option == 6)
      index = (Bit64u) (Bit64s) (Bit32s) (Bit32u) index;
    else if (option == 7)
      index = (Bit64u) (Bit64s) index;
    else
      return false;

    addr = (bx_address) (base + (index << shift));
    if (!fp && size == 3 && opc == 2) {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 prfm [x%u,x%u,extend=%u,lsl=%u] addr=%llx as no-op",
        rn, rm, option, shift, (unsigned long long) addr));
      return true;
    }
    if (fp) {
      if (size < 2)
        return false;
      if (opc == 1) {
        if (size == 2) {
          Bit32u fp_value = read_virtual_dword(BX_SEG_REG_DS, addr);
          if (!write_poly_aarch64_fp32_reg(rt, fp_value))
            return false;
        }
        else {
          Bit64u fp_value = read_virtual_qword(BX_SEG_REG_DS, addr);
          if (!write_poly_aarch64_fp64_reg(rt, fp_value))
            return false;
        }
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated aarch64 fp ldr%u v%u,[x%u,x%u,extend=%u,lsl=%u] addr=%llx",
          8U << size, rt, rn, rm, option, shift, (unsigned long long) addr));
        return true;
      }
      if (opc != 0)
        return false;
      if (size == 2) {
        Bit32u fp_value = 0;
        if (!read_poly_aarch64_fp32_reg(rt, &fp_value))
          return false;
        write_virtual_dword(BX_SEG_REG_DS, addr, fp_value);
      }
      else {
        Bit64u fp_value = 0;
        if (!read_poly_aarch64_fp64_reg(rt, &fp_value))
          return false;
        write_virtual_qword(BX_SEG_REG_DS, addr, fp_value);
      }
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 fp str%u v%u,[x%u,x%u,extend=%u,lsl=%u] addr=%llx",
        8U << size, rt, rn, rm, option, shift, (unsigned long long) addr));
      return true;
    }

    if (opc == 1) {
      if (size == 0)
        value = read_virtual_byte(BX_SEG_REG_DS, addr);
      else if (size == 1)
        value = read_virtual_word(BX_SEG_REG_DS, addr);
      else if (size == 2)
        value = read_virtual_dword(BX_SEG_REG_DS, addr);
      else
        value = read_virtual_qword(BX_SEG_REG_DS, addr);
      if (!write_poly_aarch64_reg(rt, value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 ldr%u x%u,[x%u,x%u,extend=%u,lsl=%u] addr=%llx value=%llu",
        8U << size, rt, rn, rm, option, shift, (unsigned long long) addr,
        (unsigned long long) value));
      return true;
    }

    if ((opc == 2 && size < 3) || (opc == 3 && size < 2)) {
      if (size == 0)
        value = (Bit64u) bx_poly_sign_extend(read_virtual_byte(BX_SEG_REG_DS, addr), 8);
      else if (size == 1)
        value = (Bit64u) bx_poly_sign_extend(read_virtual_word(BX_SEG_REG_DS, addr), 16);
      else
        value = (Bit64u) bx_poly_sign_extend(read_virtual_dword(BX_SEG_REG_DS, addr), 32);
      if (opc == 3)
        value = (Bit32u) value;
      if (!write_poly_aarch64_reg(rt, value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 ldrs%u x%u,[x%u,x%u,extend=%u,lsl=%u] addr=%llx value=%llu",
        8U << size, rt, rn, rm, option, shift, (unsigned long long) addr,
        (unsigned long long) value));
      return true;
    }

    if (opc != 0)
      return false;
    if (!read_poly_aarch64_reg(rt, &value))
      return false;
    if (size == 0)
      write_virtual_byte(BX_SEG_REG_DS, addr, (Bit8u) value);
    else if (size == 1)
      write_virtual_word(BX_SEG_REG_DS, addr, (Bit16u) value);
    else if (size == 2)
      write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) value);
    else
      write_virtual_qword(BX_SEG_REG_DS, addr, value);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 str%u x%u,[x%u,x%u,extend=%u,lsl=%u] addr=%llx value=%llu",
      8U << size, rt, rn, rm, option, shift, (unsigned long long) addr,
      (unsigned long long) value));
    return true;
  }

  if ((insn & 0x3b000000) == 0x39000000) {
    Bit32u rt = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u size = (insn >> 30) & 0x3;
    Bit32u opc = (insn >> 22) & 0x3;
    Bit32u imm12 = (insn >> 10) & 0xfff;
    Bit64u base = 0;
    Bit64u value = 0;
    bx_address addr;

    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;

    addr = (bx_address) (base + ((Bit64u) imm12 << size));
    if (size == 3 && opc == 2) {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 prfm [x%u,#%u] addr=%llx as no-op",
        rn, imm12 << size, (unsigned long long) addr));
      return true;
    }
    if (opc == 1) {
      if (size == 0)
        value = read_virtual_byte(BX_SEG_REG_DS, addr);
      else if (size == 1)
        value = read_virtual_word(BX_SEG_REG_DS, addr);
      else if (size == 2)
        value = read_virtual_dword(BX_SEG_REG_DS, addr);
      else
        value = read_virtual_qword(BX_SEG_REG_DS, addr);
      if (!write_poly_aarch64_reg(rt, value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 ldr%u x%u,[x%u,#%u] addr=%llx value=%llu", 8U << size, rt, rn, imm12 << size, (unsigned long long) addr, (unsigned long long) value));
      return true;
    }

    if ((opc == 2 && size < 3) || (opc == 3 && size < 2)) {
      if (size == 0)
        value = (Bit64u) bx_poly_sign_extend(read_virtual_byte(BX_SEG_REG_DS, addr), 8);
      else if (size == 1)
        value = (Bit64u) bx_poly_sign_extend(read_virtual_word(BX_SEG_REG_DS, addr), 16);
      else
        value = (Bit64u) bx_poly_sign_extend(read_virtual_dword(BX_SEG_REG_DS, addr), 32);
      if (opc == 3)
        value = (Bit32u) value;
      if (!write_poly_aarch64_reg(rt, value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 ldrs%u x%u,[x%u,#%u] addr=%llx value=%llu", 8U << size, rt, rn, imm12 << size, (unsigned long long) addr, (unsigned long long) value));
      return true;
    }

    if (opc != 0)
      return false;
    if (!read_poly_aarch64_reg(rt, &value))
      return false;
    if (size == 0)
      write_virtual_byte(BX_SEG_REG_DS, addr, (Bit8u) value);
    else if (size == 1)
      write_virtual_word(BX_SEG_REG_DS, addr, (Bit16u) value);
    else if (size == 2)
      write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) value);
    else
      write_virtual_qword(BX_SEG_REG_DS, addr, value);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 str%u x%u,[x%u,#%u] addr=%llx value=%llu", 8U << size, rt, rn, imm12 << size, (unsigned long long) addr, (unsigned long long) value));
    return true;
  }

  if ((insn & 0xffe0001f) == 0xd4000001) {
    Bit32u syscall_id = (insn >> 5) & 0xffff;
    Bit64u syscall_value = 0, arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0, arg6 = 0, arg7 = 0;
    if (!read_poly_aarch64_reg(8, &syscall_value) ||
        !read_poly_aarch64_reg(0, &arg0) ||
        !read_poly_aarch64_reg(1, &arg1) ||
        !read_poly_aarch64_reg(2, &arg2) ||
        !read_poly_aarch64_reg(3, &arg3) ||
        !read_poly_aarch64_reg(4, &arg4) ||
        !read_poly_aarch64_reg(5, &arg5) ||
        !read_poly_aarch64_reg(6, &arg6) ||
        !read_poly_aarch64_reg(7, &arg7))
      return false;
    Bit32u syscall_reg = (Bit32u) syscall_value;
    return handle_poly_foreign_syscall("aarch64", "svc", syscall_reg,
      syscall_id, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, next_rip);
  }

  if ((insn & 0xffe0001f) == 0xd4200000) {
    Bit32u break_id = (insn >> 5) & 0xffff;
    return handle_poly_break_trap("aarch64", "brk", break_id, break_id, pc,
      next_rip);
  }

  return false;
}

bool BX_CPU_C::execute_poly_raw_riscv(Bit32u insn, bx_address pc)
{
  bx_address next_rip = pc + 4;

  {
    const char *fence_name = bx_poly_riscv_fence_name(insn);
    if (fence_name != 0) {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s as x86-tso no-op", fence_name));
      return true;
    }
  }

  if (insn == BX_POLY_RISCV_CTRL_X86_ESCAPE) {
    bx_poly_current_mode = BX_POLY_MODE_X86;
    bx_poly_clear_cross_return_stack();
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv polyctrl escape to x86"));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_TRAP_RETURN) {
    BX_DEBUG(("poly_raw: riscv polyctrl trap return"));
    return return_poly_architectural_trap();
  }

  if (insn == BX_POLY_RISCV_CTRL_LANDING) {
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv landing pad"));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_TRAP_VECTOR_SET) {
    Bit64u vector = 0;
    if (!read_poly_riscv_reg(10, &vector))
      return false;
    bx_poly_trap_vector = (bx_address) vector;
    bx_address stack_key = bx_poly_current_state_key(RSP);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
    bx_poly_propagate_trap_vector_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      stack_key);
    write_poly_riscv_reg(10, 0);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv trap vector set value=%llx",
      (unsigned long long) vector));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_TRAP_VECTOR_GET) {
    write_poly_riscv_reg(10, bx_poly_trap_vector);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv trap vector get value=%llx",
      (unsigned long long) bx_poly_trap_vector));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_TRAP_VECTOR_MODE_SET) {
    Bit64u mode = 0;
    if (!read_poly_riscv_reg(10, &mode))
      return false;
    if (!bx_poly_valid_frontend_mode((Bit32u) mode)) {
      write_poly_riscv_reg(10, (Bit64u) (Bit64s) -22);
      RIP = next_rip;
      return true;
    }
    bx_poly_trap_vector_mode = (Bit32u) mode;
    bx_address stack_key = bx_poly_current_state_key(RSP);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
    bx_poly_propagate_trap_vector_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      stack_key);
    write_poly_riscv_reg(10, 0);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv trap vector mode set value=%u",
      bx_poly_trap_vector_mode));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_TRAP_VECTOR_MODE_GET) {
    write_poly_riscv_reg(10, bx_poly_trap_vector_mode);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv trap vector mode get value=%u",
      bx_poly_trap_vector_mode));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_MONITOR_PACKET_SET) {
    Bit64u packet = 0;
    if (!read_poly_riscv_reg(10, &packet))
      return false;
    bx_poly_monitor_packet_addr = (bx_address) packet;
    bx_address stack_key = bx_poly_current_state_key(RSP);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
    bx_poly_propagate_trap_vector_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      stack_key);
    write_poly_riscv_reg(10, 0);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv monitor packet set value=%llx",
      (unsigned long long) packet));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_MONITOR_PACKET_GET) {
    write_poly_riscv_reg(10, bx_poly_monitor_packet_addr);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv monitor packet get value=%llx",
      (unsigned long long) bx_poly_monitor_packet_addr));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_ABI_SIGNATURE_SET) {
    Bit64u slot = 0;
    Bit64u kind = 0;
    if (!read_poly_riscv_reg(10, &slot) ||
        !read_poly_riscv_reg(11, &kind))
      return false;
    if (slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT ||
        !bx_poly_valid_abi_signature_kind((Bit32u) kind)) {
      write_poly_riscv_reg(10, (Bit64u) (Bit64s) -22);
      RIP = next_rip;
      return true;
    }
    bx_poly_abi_signature_slots[(Bit32u) slot].kind = (Bit32u) kind;
    write_poly_riscv_reg(10, 0);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv ABI signature set slot=%llu kind=%llu",
      (unsigned long long) slot, (unsigned long long) kind));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_ABI_SIGNATURE_GET) {
    Bit64u slot = 0;
    if (!read_poly_riscv_reg(10, &slot))
      return false;
    if (slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT) {
      write_poly_riscv_reg(10, (Bit64u) (Bit64s) -22);
      RIP = next_rip;
      return true;
    }
    write_poly_riscv_reg(10,
      bx_poly_abi_signature_slots[(Bit32u) slot].kind);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv ABI signature get slot=%llu",
      (unsigned long long) slot));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_LANDING_POLICY_SET) {
    Bit64u policy = 0;
    if (!read_poly_riscv_reg(10, &policy))
      return false;
    if (!bx_poly_valid_landing_policy(policy)) {
      write_poly_riscv_reg(10, (Bit64u) (Bit64s) -22);
      RIP = next_rip;
      return true;
    }
    bx_poly_landing_policy_flags = policy;
    write_poly_riscv_reg(10, 0);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv landing policy set value=%llx",
      (unsigned long long) policy));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_LANDING_POLICY_GET) {
    write_poly_riscv_reg(10, bx_poly_landing_policy_flags);
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv landing policy get value=%llx",
      (unsigned long long) bx_poly_landing_policy_flags));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_AARCH64_SWITCH) {
    if (!bx_poly_require_landing_target(BX_SEG_REG_CS, next_rip,
          BX_POLY_MODE_RAW_AARCH64, BX_POLY_LANDING_POLICY_REQUIRE_SWITCH,
          "riscv-switch"))
      return false;
    bx_poly_capture_tls_base_for_mode(bx_poly_current_mode);
    bx_poly_current_mode = BX_POLY_MODE_RAW_AARCH64;
    bx_poly_prepare_tls_for_mode(bx_poly_current_mode);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: riscv polyctrl switch to aarch64"));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_SWITCH_MODE) {
    Bit64u target = 0;
    Bit64u frontend = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &frontend))
      return false;
    Bit32u frontend_id = (Bit32u) frontend;
    Bit32u target_mode = BX_POLY_MODE_X86;
    if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode)) {
      BX_INFO(("poly_raw: reject riscv generic switch frontend=%u",
        frontend_id));
      return false;
    }
    if (!bx_poly_require_landing_target(BX_SEG_REG_CS, (bx_address) target,
          target_mode, BX_POLY_LANDING_POLICY_REQUIRE_SWITCH,
          "riscv-generic-switch"))
      return false;
    bx_poly_capture_tls_base_for_mode(bx_poly_current_mode);
    bx_poly_current_mode = target_mode;
    if (target_mode == BX_POLY_MODE_X86)
      bx_poly_clear_cross_return_stack();
    bx_poly_prepare_tls_for_mode(target_mode);
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = (bx_address) target;
    BX_DEBUG(("poly_raw: riscv generic switch frontend=%u mode=%u target=%llx",
      frontend_id, target_mode, (unsigned long long) target));
    return true;
  }

  if (insn == BX_POLY_RISCV_CTRL_CALL_MODE) {
    Bit64u target = 0;
    Bit64u frontend = 0;
    Bit64u return_rip = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &frontend) ||
        !read_poly_riscv_reg(7, &return_rip))
      return false;
    Bit32u frontend_id = (Bit32u) frontend;
    Bit32u target_mode = BX_POLY_MODE_X86;
    if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode) ||
        target_mode == BX_POLY_MODE_RAW_RISCV) {
      BX_INFO(("poly_raw: reject riscv generic call frontend=%u mode=%u",
        frontend_id, target_mode));
      return false;
    }
    if (target_mode == BX_POLY_MODE_X86) {
      if (handle_poly_import_call(BX_POLY_MODE_RAW_RISCV,
            (bx_address) target, (bx_address) return_rip))
        return true;
      return enter_poly_x86_direct_call(BX_POLY_MODE_RAW_RISCV,
        (bx_address) target, (bx_address) return_rip,
        BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS);
    }
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV, target_mode,
      (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_DEFAULT);
  }

  Bit32u riscv_signature_imm_slot = 0;
  if (bx_poly_riscv_ctrl_slot(insn,
        BX_POLY_RISCV_CTRL_SUBOP_CALL_SIG_IMM_BASE,
        &riscv_signature_imm_slot)) {
    Bit64u target = 0;
    Bit64u frontend = 0;
    Bit64u return_rip = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &frontend) ||
        !read_poly_riscv_reg(7, &return_rip))
      return false;
    Bit32u frontend_id = (Bit32u) frontend;
    Bit32u target_mode = BX_POLY_MODE_X86;
    if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode) ||
        target_mode == BX_POLY_MODE_RAW_RISCV) {
      BX_INFO(("poly_raw: reject riscv immediate signature call frontend=%u mode=%u",
        frontend_id, target_mode));
      return false;
    }
    bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    Bit32u source_kind =
      bx_poly_abi_signature_slots[riscv_signature_imm_slot].kind;
    if (target_mode == BX_POLY_MODE_X86) {
      if (handle_poly_import_call(BX_POLY_MODE_RAW_RISCV,
            (bx_address) target, (bx_address) return_rip))
        return true;
      return enter_poly_x86_direct_call(BX_POLY_MODE_RAW_RISCV,
        (bx_address) target, (bx_address) return_rip, source_kind);
    }
    Bit32u bridge_kind = BX_POLY_CROSS_BRIDGE_DEFAULT;
    if (!bx_poly_cross_bridge_for_abi_signature_kind(source_kind,
          &bridge_kind)) {
      BX_INFO(("poly_raw: reject riscv immediate signature call kind=%u",
        source_kind));
      return false;
    }
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV, target_mode,
      (bx_address) target, (bx_address) return_rip,
      bridge_kind);
  }

  if (insn == BX_POLY_RISCV_CTRL_CALL_SIG_MODE) {
    Bit64u target = 0;
    Bit64u frontend = 0;
    Bit64u return_rip = 0;
    Bit64u signature_slot = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &frontend) ||
        !read_poly_riscv_reg(7, &return_rip) ||
        !read_poly_riscv_reg(28, &signature_slot))
      return false;
    Bit32u frontend_id = (Bit32u) frontend;
    Bit32u target_mode = BX_POLY_MODE_X86;
    if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode) ||
        target_mode == BX_POLY_MODE_RAW_RISCV) {
      BX_INFO(("poly_raw: reject riscv generic signature call frontend=%u mode=%u",
        frontend_id, target_mode));
      return false;
    }
    if (signature_slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT) {
      BX_INFO(("poly_raw: reject riscv generic signature call slot=%llu",
        (unsigned long long) signature_slot));
      return false;
    }
    bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    Bit32u source_kind =
      bx_poly_abi_signature_slots[(Bit32u) signature_slot].kind;
    if (target_mode == BX_POLY_MODE_X86) {
      if (handle_poly_import_call(BX_POLY_MODE_RAW_RISCV,
            (bx_address) target, (bx_address) return_rip))
        return true;
      return enter_poly_x86_direct_call(BX_POLY_MODE_RAW_RISCV,
        (bx_address) target, (bx_address) return_rip, source_kind);
    }
    Bit32u bridge_kind = BX_POLY_CROSS_BRIDGE_DEFAULT;
    if (!bx_poly_cross_bridge_for_abi_signature_kind(source_kind,
          &bridge_kind)) {
      BX_INFO(("poly_raw: reject riscv generic signature call kind=%u",
        source_kind));
      return false;
    }
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV, target_mode,
      (bx_address) target, (bx_address) return_rip,
      bridge_kind);
  }

  if (insn == BX_POLY_RISCV_CTRL_AARCH64_CALL) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV,
      BX_POLY_MODE_RAW_AARCH64, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_DEFAULT);
  }

  if (insn == BX_POLY_RISCV_CTRL_AARCH64_CALL_COMPACT_U32_F32 ||
      insn == BX_POLY_RISCV_CTRL_AARCH64_CALL_COMPACT_F32_U32) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &return_rip))
      return false;
    Bit32u bridge_kind =
      insn == BX_POLY_RISCV_CTRL_AARCH64_CALL_COMPACT_U32_F32 ?
      BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 :
      BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV,
      BX_POLY_MODE_RAW_AARCH64, (bx_address) target, (bx_address) return_rip,
      bridge_kind);
  }

  if (insn == BX_POLY_RISCV_CTRL_AARCH64_CALL_FP64_STACK) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV,
      BX_POLY_MODE_RAW_AARCH64, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_FP64_STACK);
  }

  if (insn == BX_POLY_RISCV_CTRL_AARCH64_CALL_VEC128_U32) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV,
      BX_POLY_MODE_RAW_AARCH64, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_VEC128_U32);
  }

  if ((insn & 0x0000007f) == 0x0000002f) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u rs2 = (insn >> 20) & 0x1f;
    Bit32u funct5 = (insn >> 27) & 0x1f;
    bool is_word = funct3 == 0x2;
    bool is_dword = funct3 == 0x3;
    Bit64u base = 0;
    Bit64u right = 0;
    Bit64u old_value = 0;
    Bit64u new_value = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if (!is_word && !is_dword)
      return false;
    if (!read_poly_riscv_reg(rs1, &base))
      return false;
    bx_address addr = (bx_address) base;
    Bit32u size = is_word ? 4 : 8;

    if (funct5 == 0x02) {
      if (rs2 != 0)
        return false;
      if (is_word) {
        Bit32u loaded = read_virtual_dword(BX_SEG_REG_DS, addr);
        result = (Bit64u) bx_poly_sign_extend(loaded, 32);
        op_name = "lr.w";
      }
      else {
        result = read_virtual_qword(BX_SEG_REG_DS, addr);
        op_name = "lr.d";
      }
      bx_poly_riscv_reservation_valid = true;
      bx_poly_riscv_reservation_addr = addr;
      bx_poly_riscv_reservation_size = size;
      if (!write_poly_riscv_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,(x%u) addr=%llx value=%llu",
        op_name, rd, rs1, (unsigned long long) addr,
        (unsigned long long) result));
      return true;
    }

    if (!read_poly_riscv_reg(rs2, &right))
      return false;

    if (funct5 == 0x03) {
      bool success = bx_poly_riscv_reservation_valid &&
        bx_poly_riscv_reservation_addr == addr &&
        bx_poly_riscv_reservation_size == size;
      if (success) {
        if (is_word)
          write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) right);
        else
          write_virtual_qword(BX_SEG_REG_DS, addr, right);
      }
      bx_poly_riscv_reservation_valid = false;
      bx_poly_riscv_reservation_addr = 0;
      bx_poly_riscv_reservation_size = 0;
      if (!write_poly_riscv_reg(rd, success ? 0 : 1))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,x%u,(x%u) addr=%llx %s",
        is_word ? "sc.w" : "sc.d", rd, rs2, rs1,
        (unsigned long long) addr, success ? "success" : "fail"));
      return true;
    }

    if (is_word) {
      Bit32u old32 = read_virtual_dword(BX_SEG_REG_DS, addr);
      Bit32u right32 = (Bit32u) right;
      Bit32u new32 = 0;
      old_value = old32;
      switch (funct5) {
        case 0x00:
          op_name = "amoadd.w";
          new32 = old32 + right32;
          break;
        case 0x01:
          op_name = "amoswap.w";
          new32 = right32;
          break;
        case 0x04:
          op_name = "amoxor.w";
          new32 = old32 ^ right32;
          break;
        case 0x08:
          op_name = "amoor.w";
          new32 = old32 | right32;
          break;
        case 0x0c:
          op_name = "amoand.w";
          new32 = old32 & right32;
          break;
        case 0x10:
          op_name = "amomin.w";
          new32 = (Bit32s) old32 < (Bit32s) right32 ? old32 : right32;
          break;
        case 0x14:
          op_name = "amomax.w";
          new32 = (Bit32s) old32 > (Bit32s) right32 ? old32 : right32;
          break;
        case 0x18:
          op_name = "amominu.w";
          new32 = old32 < right32 ? old32 : right32;
          break;
        case 0x1c:
          op_name = "amomaxu.w";
          new32 = old32 > right32 ? old32 : right32;
          break;
        default:
          return false;
      }
      write_virtual_dword(BX_SEG_REG_DS, addr, new32);
      result = (Bit64u) bx_poly_sign_extend(old32, 32);
      new_value = new32;
    }
    else {
      old_value = read_virtual_qword(BX_SEG_REG_DS, addr);
      switch (funct5) {
        case 0x00:
          op_name = "amoadd.d";
          new_value = old_value + right;
          break;
        case 0x01:
          op_name = "amoswap.d";
          new_value = right;
          break;
        case 0x04:
          op_name = "amoxor.d";
          new_value = old_value ^ right;
          break;
        case 0x08:
          op_name = "amoor.d";
          new_value = old_value | right;
          break;
        case 0x0c:
          op_name = "amoand.d";
          new_value = old_value & right;
          break;
        case 0x10:
          op_name = "amomin.d";
          new_value = (Bit64s) old_value < (Bit64s) right ? old_value : right;
          break;
        case 0x14:
          op_name = "amomax.d";
          new_value = (Bit64s) old_value > (Bit64s) right ? old_value : right;
          break;
        case 0x18:
          op_name = "amominu.d";
          new_value = old_value < right ? old_value : right;
          break;
        case 0x1c:
          op_name = "amomaxu.d";
          new_value = old_value > right ? old_value : right;
          break;
        default:
          return false;
      }
      write_virtual_qword(BX_SEG_REG_DS, addr, new_value);
      result = old_value;
    }

    if (bx_poly_riscv_reservation_valid &&
        bx_poly_riscv_reservation_addr == addr &&
        bx_poly_riscv_reservation_size == size)
      bx_poly_riscv_reservation_valid = false;
    if (!write_poly_riscv_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated riscv %s x%u,x%u,(x%u) addr=%llx old=%llu new=%llu",
      op_name, rd, rs2, rs1, (unsigned long long) addr,
      (unsigned long long) result, (unsigned long long) new_value));
    return true;
  }

  {
    Bit32u opcode = insn & 0x0000007f;
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u rm = (insn >> 12) & 0x7;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u rs2 = (insn >> 20) & 0x1f;
    Bit32u fmt = (insn >> 25) & 0x3;
    Bit32u rs3 = (insn >> 27) & 0x1f;
    const char *op_name = "fmadd";
    Bit32u op = 0;

    if (opcode == 0x43 || opcode == 0x47 ||
        opcode == 0x4b || opcode == 0x4f) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;

      switch (opcode) {
        case 0x43:
          op_name = "fmadd";
          op = 0;
          break;
        case 0x47:
          op_name = "fmsub";
          op = softfloat_muladd_negate_c;
          break;
        case 0x4b:
          op_name = "fnmsub";
          op = softfloat_muladd_negate_product;
          break;
        case 0x4f:
          op_name = "fnmadd";
          op = softfloat_muladd_negate_result;
          break;
      }

      if (fmt == 0) {
        Bit32u product_left = 0, product_right = 0, addend = 0;
        if (!read_poly_riscv_fp32_reg(rs1, &product_left) ||
            !read_poly_riscv_fp32_reg(rs2, &product_right) ||
            !read_poly_riscv_fp32_reg(rs3, &addend))
          return false;
        Bit32u result = f32_mulAdd(product_left, product_right, addend, op,
          &status);
        bx_poly_riscv_accumulate_softfloat_fflags(&status);
        if (!write_poly_riscv_fp32_reg(rd, result))
          return false;
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated riscv %s.s f%u, f%u, f%u, f%u",
          op_name, rd, rs1, rs2, rs3));
        return true;
      }

      if (fmt == 1) {
        Bit64u product_left = 0, product_right = 0, addend = 0;
        if (!read_poly_riscv_fp64_reg(rs1, &product_left) ||
            !read_poly_riscv_fp64_reg(rs2, &product_right) ||
            !read_poly_riscv_fp64_reg(rs3, &addend))
          return false;
        Bit64u result = f64_mulAdd(product_left, product_right, addend, op,
          &status);
        bx_poly_riscv_accumulate_softfloat_fflags(&status);
        if (!write_poly_riscv_fp64_reg(rd, result))
          return false;
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated riscv %s.d f%u, f%u, f%u, f%u",
          op_name, rd, rs1, rs2, rs3));
        return true;
      }
    }
  }

  if ((insn & 0x0000007f) == 0x00000053) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u rm = (insn >> 12) & 0x7;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u rs2 = (insn >> 20) & 0x1f;
    Bit32u funct7 = (insn >> 25) & 0x7f;
    Bit32u left32_bits = 0;
    Bit32u right32_bits = 0;
    Bit32u result32_bits = 0;
    Bit64u left_bits = 0;
    Bit64u right_bits = 0;
    Bit64u result_bits = 0;
    const char *op_name = 0;
    bool fp32_op = false;

    if (rm > 4 && rm != 7)
      return false;
    if (funct7 == 0x00) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      op_name = "fadd.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = f32_add(left32_bits, right32_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x04) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      op_name = "fsub.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = f32_sub(left32_bits, right32_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x08) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      op_name = "fmul.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = f32_mul(left32_bits, right32_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x0c) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      op_name = "fdiv.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = f32_div(left32_bits, right32_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x14 && rm == 0) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmin.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = f32_minmax(left32_bits, right32_bits, 0, 1, false,
        &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x14 && rm == 1) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmax.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = f32_minmax(left32_bits, right32_bits, 1, 1, false,
        &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x01) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      op_name = "fadd.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = f64_add(left_bits, right_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x05) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      op_name = "fsub.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = f64_sub(left_bits, right_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x09) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      op_name = "fmul.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = f64_mul(left_bits, right_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x0d) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      op_name = "fdiv.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = f64_div(left_bits, right_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x15 && rm == 0) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmin.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = f64_minmax(left_bits, right_bits, 0, 1, false, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x15 && rm == 1) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmax.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = f64_minmax(left_bits, right_bits, 1, 1, false, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x2c && rs2 == 0) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fsqrt.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits))
        return false;
      result32_bits = f32_sqrt(left32_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x2d && rs2 == 0) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fsqrt.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits))
        return false;
      result_bits = f64_sqrt(left_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x20 && rs2 == 1) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      op_name = "fcvt.s.d";
      fp32_op = true;
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits))
        return false;
      result32_bits = f64_to_f32(left_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if (funct7 == 0x21 && rs2 == 0) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fcvt.d.s";
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits))
        return false;
      result_bits = f32_to_f64(left32_bits, &status);
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
    }
    else if ((funct7 == 0x68 || funct7 == 0x69) && rs2 <= 3) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      Bit64u value = 0;
      bool source_64 = rs2 >= 2;
      bool is_unsigned = (rs2 & 1) != 0;
      fp32_op = funct7 == 0x68;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;

      if (!read_poly_riscv_reg(rs1, &value))
        return false;
      if (fp32_op) {
        if (source_64)
          result32_bits = is_unsigned ?
            ui64_to_f32(value, &status) :
            i64_to_f32((Bit64s) value, &status);
        else
          result32_bits = is_unsigned ?
            ui32_to_f32((Bit32u) value, &status) :
            i32_to_f32((Bit32s) (Bit32u) value, &status);
      }
      else {
        if (source_64)
          result_bits = is_unsigned ?
            ui64_to_f64(value, &status) :
            i64_to_f64((Bit64s) value, &status);
        else
          result_bits = is_unsigned ?
            ui32_to_f64((Bit32u) value) :
            i32_to_f64((Bit32s) (Bit32u) value);
      }
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
      op_name = fp32_op ?
        (source_64 ? (is_unsigned ? "fcvt.s.lu" : "fcvt.s.l") :
          (is_unsigned ? "fcvt.s.wu" : "fcvt.s.w")) :
        (source_64 ? (is_unsigned ? "fcvt.d.lu" : "fcvt.d.l") :
          (is_unsigned ? "fcvt.d.wu" : "fcvt.d.w"));
    }
    else if (funct7 == 0x78 || funct7 == 0x79) {
      Bit64u value = 0;
      if (rm != 0 || rs2 != 0)
        return false;
      if (!read_poly_riscv_reg(rs1, &value))
        return false;
      if (funct7 == 0x78) {
        if (!write_poly_riscv_fp32_reg(rd, (Bit32u) value))
          return false;
        op_name = "fmv.w.x";
      }
      else {
        if (!write_poly_riscv_fp64_reg(rd, value))
          return false;
        op_name = "fmv.d.x";
      }
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s f%u,x%u value=%llu",
        op_name, rd, rs1, (unsigned long long) value));
      return true;
    }
    else if ((funct7 == 0x60 || funct7 == 0x61) &&
             (rs2 == 0 || rs2 == 1 || rs2 == 2 || rs2 == 3)) {
      Bit32u rounding_mode = bx_poly_riscv_softfloat_rounding_mode(rm);
      if (rounding_mode == 0xff)
        return false;
      bool source_fp32 = funct7 == 0x60;
      if (source_fp32) {
        if (!read_poly_riscv_fp32_reg(rs1, &left32_bits))
          return false;
      }
      else if (!read_poly_riscv_fp64_reg(rs1, &left_bits))
        return false;
      bool is_64 = rs2 >= 2;
      bool is_signed = (rs2 & 1) == 0;
      Bit64u result = 0;
      softfloat_status_t status = bx_poly_softfloat_status();
      status.softfloat_roundingMode = rounding_mode;
      if (source_fp32) {
        if (is_64) {
          result = is_signed ?
            (Bit64u) f32_to_i64(left32_bits, rounding_mode, true, &status) :
            f32_to_ui64(left32_bits, rounding_mode, true, &status);
        }
        else {
          result = is_signed ?
            (Bit64u) (Bit64s) (Bit32s) f32_to_i32(left32_bits,
              rounding_mode, true, &status) :
            (Bit64u) (Bit64s) (Bit32s) f32_to_ui32(left32_bits,
              rounding_mode, true, &status);
        }
      }
      else {
        if (is_64) {
          result = is_signed ?
            (Bit64u) f64_to_i64(left_bits, rounding_mode, true, &status) :
            f64_to_ui64(left_bits, rounding_mode, true, &status);
        }
        else {
          result = is_signed ?
            (Bit64u) (Bit64s) (Bit32s) f64_to_i32(left_bits,
              rounding_mode, true, &status) :
            (Bit64u) (Bit64s) (Bit32s) f64_to_ui32(left_bits,
              rounding_mode, true, &status);
        }
      }
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
      if (!write_poly_riscv_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,f%u result=%llu",
        source_fp32 ?
          (is_64 ? (is_signed ? "fcvt.l.s" : "fcvt.lu.s") :
            (is_signed ? "fcvt.w.s" : "fcvt.wu.s")) :
          (is_64 ? (is_signed ? "fcvt.l.d" : "fcvt.lu.d") :
            (is_signed ? "fcvt.w.d" : "fcvt.wu.d")),
        rd, rs1,
        (unsigned long long) result));
      return true;
    }
    else if ((funct7 == 0x70 || funct7 == 0x71) && rs2 == 0) {
      bool source_fp32 = funct7 == 0x70;
      Bit64u result = 0;
      if (source_fp32) {
        if (!read_poly_riscv_fp32_reg(rs1, &left32_bits))
          return false;
        if (rm == 0) {
          result = (Bit64u) (Bit64s) (Bit32s) left32_bits;
          op_name = "fmv.x.w";
        }
        else if (rm == 1) {
          result = bx_poly_riscv_fclass32(left32_bits);
          op_name = "fclass.s";
        }
        else
          return false;
      }
      else {
        if (!read_poly_riscv_fp64_reg(rs1, &left_bits))
          return false;
        if (rm == 0) {
          result = left_bits;
          op_name = "fmv.x.d";
        }
        else if (rm == 1) {
          result = bx_poly_riscv_fclass64(left_bits);
          op_name = "fclass.d";
        }
        else
          return false;
      }
      if (!write_poly_riscv_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,f%u result=%llu",
        op_name, rd, rs1, (unsigned long long) result));
      return true;
    }
    else if (funct7 == 0x10) {
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      if (rm == 0) {
        op_name = "fsgnj.s";
        result32_bits = (left32_bits & 0x7fffffff) | (right32_bits & 0x80000000);
      }
      else if (rm == 1) {
        op_name = "fsgnjn.s";
        result32_bits = (left32_bits & 0x7fffffff) | ((~right32_bits) & 0x80000000);
      }
      else if (rm == 2) {
        op_name = "fsgnjx.s";
        result32_bits = left32_bits ^ (right32_bits & 0x80000000);
      }
      else {
        return false;
      }
    }
    else if (funct7 == 0x11) {
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      if (rm == 0) {
        op_name = "fsgnj.d";
        result_bits = (left_bits & BX_CONST64(0x7fffffffffffffff)) |
          (right_bits & BX_CONST64(0x8000000000000000));
      }
      else if (rm == 1) {
        op_name = "fsgnjn.d";
        result_bits = (left_bits & BX_CONST64(0x7fffffffffffffff)) |
          ((~right_bits) & BX_CONST64(0x8000000000000000));
      }
      else if (rm == 2) {
        op_name = "fsgnjx.d";
        result_bits = left_bits ^ (right_bits & BX_CONST64(0x8000000000000000));
      }
      else {
        return false;
      }
    }
    else if (funct7 == 0x50 || funct7 == 0x51) {
      bool fp32_cmp = funct7 == 0x50;
      Bit64u result = 0;
      softfloat_status_t status = bx_poly_softfloat_status();
      if (fp32_cmp) {
        if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
            !read_poly_riscv_fp32_reg(rs2, &right32_bits))
          return false;
        int relation = (rm == 2) ?
          f32_compare(left32_bits, right32_bits, true, &status) :
          f32_compare(left32_bits, right32_bits, false, &status);
        if (rm == 0)
          result = relation == softfloat_relation_less ||
            relation == softfloat_relation_equal;
        else if (rm == 1)
          result = relation == softfloat_relation_less;
        else if (rm == 2)
          result = relation == softfloat_relation_equal;
        else
          return false;
      }
      else {
        if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
            !read_poly_riscv_fp64_reg(rs2, &right_bits))
          return false;
        int relation = (rm == 2) ?
          f64_compare(left_bits, right_bits, true, &status) :
          f64_compare(left_bits, right_bits, false, &status);
        if (rm == 0)
          result = relation == softfloat_relation_less ||
            relation == softfloat_relation_equal;
        else if (rm == 1)
          result = relation == softfloat_relation_less;
        else if (rm == 2)
          result = relation == softfloat_relation_equal;
        else
          return false;
      }
      bx_poly_riscv_accumulate_softfloat_fflags(&status);
      if (!write_poly_riscv_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv fcmp%s x%u,f%u,f%u result=%llu",
        fp32_cmp ? ".s" : ".d", rd, rs1, rs2, (unsigned long long) result));
      return true;
    }
    else {
      return false;
    }
    if (fp32_op) {
      if (!write_poly_riscv_fp32_reg(rd, result32_bits))
        return false;
    }
    else if (!write_poly_riscv_fp64_reg(rd, result_bits))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated riscv %s f%u,f%u,f%u", op_name, rd, rs1, rs2));
    return true;
  }

  if ((insn & 0x0000007f) == 0x00000037 ||
      (insn & 0x0000007f) == 0x00000017) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit64s imm = bx_poly_sign_extend(insn & 0xfffff000, 32);
    bool auipc = (insn & 0x0000007f) == 0x00000017;
    Bit64u result = auipc ? (Bit64u) ((Bit64s) pc + imm) : (Bit64u) imm;
    if (!write_poly_riscv_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated riscv %s x%u,%lld result=%llu", auipc ? "auipc" : "lui", rd, (long long) imm, (unsigned long long) result));
    return true;
  }

  if ((insn & 0x0000007f) == 0x00000013) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit64u base = 0;
    Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
    Bit32u shamt = (insn >> 20) & 0x3f;
    Bit32u shift_top = (insn >> 26) & 0x3f;
    Bit32u imm_raw = (insn >> 20) & 0xfff;
    Bit64u result = 0;
    const char *op_name = 0;

    if (!read_poly_riscv_reg(rs1, &base))
      return false;

    if (funct3 == 0x0) {
      op_name = "addi";
      result = (Bit64u) ((Bit64s) base + imm12);
    }
    else if (funct3 == 0x2) {
      op_name = "slti";
      result = (Bit64s) base < imm12 ? 1 : 0;
    }
    else if (funct3 == 0x3) {
      op_name = "sltiu";
      result = base < (Bit64u) imm12 ? 1 : 0;
    }
    else if (funct3 == 0x4) {
      op_name = "xori";
      result = base ^ (Bit64u) imm12;
    }
    else if (funct3 == 0x6) {
      op_name = "ori";
      result = base | (Bit64u) imm12;
    }
    else if (funct3 == 0x7) {
      op_name = "andi";
      result = base & (Bit64u) imm12;
    }
    else if (funct3 == 0x1 && shift_top == 0x00) {
      op_name = "slli";
      result = base << shamt;
    }
    else if (funct3 == 0x5 && shift_top == 0x00) {
      op_name = "srli";
      result = base >> shamt;
    }
    else if (funct3 == 0x5 && shift_top == 0x10) {
      op_name = "srai";
      result = (Bit64u) ((Bit64s) base >> shamt);
    }
    else if (funct3 == 0x1 && shift_top == 0x0a) {
      op_name = "bseti";
      result = base | (BX_CONST64(1) << shamt);
    }
    else if (funct3 == 0x1 && shift_top == 0x12) {
      op_name = "bclri";
      result = base & ~(BX_CONST64(1) << shamt);
    }
    else if (funct3 == 0x1 && shift_top == 0x1a) {
      op_name = "binvi";
      result = base ^ (BX_CONST64(1) << shamt);
    }
    else if (funct3 == 0x5 && shift_top == 0x12) {
      op_name = "bexti";
      result = (base >> shamt) & 1;
    }
    else if (funct3 == 0x1 && imm_raw == 0x600) {
      op_name = "clz";
      result = bx_poly_count_leading_zeroes(base, 64);
    }
    else if (funct3 == 0x1 && imm_raw == 0x601) {
      op_name = "ctz";
      result = bx_poly_count_trailing_zeroes(base, 64);
    }
    else if (funct3 == 0x1 && imm_raw == 0x602) {
      op_name = "cpop";
      result = bx_poly_count_ones64(base);
    }
    else if (funct3 == 0x1 && imm_raw == 0x604) {
      op_name = "sext.b";
      result = (Bit64u) (Bit64s) (Bit8s) (Bit8u) base;
    }
    else if (funct3 == 0x1 && imm_raw == 0x605) {
      op_name = "sext.h";
      result = (Bit64u) (Bit64s) (Bit16s) (Bit16u) base;
    }
    else if (funct3 == 0x5 && ((imm_raw >> 6) == 0x18)) {
      op_name = "rori";
      result = bx_poly_rotate_right(base, 64, shamt);
    }
    else if (funct3 == 0x5 && imm_raw == 0x287) {
      op_name = "orc.b";
      result = bx_poly_or_combine_bytes(base);
    }
    else if (funct3 == 0x5 && imm_raw == 0x6b8) {
      op_name = "rev8";
      result = bx_poly_reverse_bytes_in_lanes(base, 64, 64);
    }

    if (op_name == 0)
      return false;
    if (!write_poly_riscv_reg(rd, result))
      return false;
    RIP = next_rip;
    if (funct3 == 0x1 || funct3 == 0x5)
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,x%u,%u result=%llu", op_name, rd, rs1, shamt, (unsigned long long) result));
    else
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,x%u,%lld result=%llu", op_name, rd, rs1, (long long) imm12, (unsigned long long) result));
    return true;
  }

  if ((insn & 0x0000007f) == 0x0000001b) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u shamt = (insn >> 20) & 0x1f;
    Bit32u funct7 = (insn >> 25) & 0x7f;
    Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
    Bit32u imm_raw = (insn >> 20) & 0xfff;
    Bit64u base = 0;
    Bit32u result32 = 0;
    Bit64u result64 = 0;
    bool result64_valid = false;
    const char *op_name = 0;

    if (!read_poly_riscv_reg(rs1, &base))
      return false;

    if (funct3 == 0x0) {
      op_name = "addiw";
      result32 = (Bit32u) ((Bit64s) (Bit32s) (Bit32u) base + imm12);
    }
    else if (funct3 == 0x1 && funct7 == 0x00) {
      op_name = "slliw";
      result32 = ((Bit32u) base) << shamt;
    }
    else if (funct3 == 0x5 && funct7 == 0x00) {
      op_name = "srliw";
      result32 = ((Bit32u) base) >> shamt;
    }
    else if (funct3 == 0x5 && funct7 == 0x20) {
      op_name = "sraiw";
      result32 = (Bit32u) ((Bit32s) (Bit32u) base >> shamt);
    }
    else if (funct3 == 0x1 && imm_raw == 0x600) {
      op_name = "clzw";
      result32 = (Bit32u) bx_poly_count_leading_zeroes(base, 32);
    }
    else if (funct3 == 0x1 && imm_raw == 0x601) {
      op_name = "ctzw";
      result32 = (Bit32u) bx_poly_count_trailing_zeroes(base, 32);
    }
    else if (funct3 == 0x1 && imm_raw == 0x602) {
      op_name = "cpopw";
      result32 = bx_poly_count_ones64((Bit32u) base);
    }
    else if (funct3 == 0x1 && funct7 == 0x04) {
      op_name = "slli.uw";
      result64 = ((Bit64u) (Bit32u) base) << shamt;
      result64_valid = true;
    }

    if (op_name == 0)
      return false;
    Bit64u result = result64_valid ?
      result64 : (Bit64u) bx_poly_sign_extend(result32, 32);
    if (!write_poly_riscv_reg(rd, result))
      return false;
    RIP = next_rip;
    if (funct3 == 0x1 || funct3 == 0x5)
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,x%u,%u result=%llu", op_name, rd, rs1, shamt, (unsigned long long) result));
    else
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,x%u,%lld result=%llu", op_name, rd, rs1, (long long) imm12, (unsigned long long) result));
    return true;
  }

  if ((insn & 0x0000007f) == 0x00000033) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u rs2 = (insn >> 20) & 0x1f;
    Bit32u funct7 = (insn >> 25) & 0x7f;
    Bit64u left = 0;
    Bit64u right = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if (!read_poly_riscv_reg(rs1, &left) || !read_poly_riscv_reg(rs2, &right))
      return false;

    if (funct7 == 0x00 && funct3 == 0x0) {
      op_name = "add";
      result = left + right;
    }
    else if (funct7 == 0x20 && funct3 == 0x0) {
      op_name = "sub";
      result = left - right;
    }
    else if (funct7 == 0x01 && funct3 == 0x0) {
      op_name = "mul";
      result = left * right;
    }
    else if (funct7 == 0x01 && funct3 == 0x1) {
      op_name = "mulh";
      result = (Bit64u) (((unsigned __int128)
        ((__int128) (Bit64s) left * (__int128) (Bit64s) right)) >> 64);
    }
    else if (funct7 == 0x01 && funct3 == 0x2) {
      op_name = "mulhsu";
      result = (Bit64u) (((unsigned __int128)
        ((__int128) (Bit64s) left * (__int128) right)) >> 64);
    }
    else if (funct7 == 0x01 && funct3 == 0x3) {
      op_name = "mulhu";
      result = (Bit64u) (((unsigned __int128) left * right) >> 64);
    }
    else if (funct7 == 0x01 && funct3 == 0x4) {
      op_name = "div";
      if (right == 0)
        result = ~BX_CONST64(0);
      else if (left == (BX_CONST64(1) << 63) && right == ~BX_CONST64(0))
        result = left;
      else
        result = (Bit64u) ((Bit64s) left / (Bit64s) right);
    }
    else if (funct7 == 0x01 && funct3 == 0x5) {
      op_name = "divu";
      result = right == 0 ? ~BX_CONST64(0) : left / right;
    }
    else if (funct7 == 0x01 && funct3 == 0x6) {
      op_name = "rem";
      if (right == 0)
        result = left;
      else if (left == (BX_CONST64(1) << 63) && right == ~BX_CONST64(0))
        result = 0;
      else
        result = (Bit64u) ((Bit64s) left % (Bit64s) right);
    }
    else if (funct7 == 0x01 && funct3 == 0x7) {
      op_name = "remu";
      result = right == 0 ? left : left % right;
    }
    else if (funct7 == 0x00 && funct3 == 0x1) {
      op_name = "sll";
      result = left << (right & 0x3f);
    }
    else if (funct7 == 0x00 && funct3 == 0x2) {
      op_name = "slt";
      result = (Bit64s) left < (Bit64s) right ? 1 : 0;
    }
    else if (funct7 == 0x00 && funct3 == 0x3) {
      op_name = "sltu";
      result = left < right ? 1 : 0;
    }
    else if (funct7 == 0x00 && funct3 == 0x4) {
      op_name = "xor";
      result = left ^ right;
    }
    else if (funct7 == 0x00 && funct3 == 0x5) {
      op_name = "srl";
      result = left >> (right & 0x3f);
    }
    else if (funct7 == 0x20 && funct3 == 0x5) {
      op_name = "sra";
      result = (Bit64u) ((Bit64s) left >> (right & 0x3f));
    }
    else if (funct7 == 0x00 && funct3 == 0x6) {
      op_name = "or";
      result = left | right;
    }
    else if (funct7 == 0x00 && funct3 == 0x7) {
      op_name = "and";
      result = left & right;
    }
    else if (funct7 == 0x20 && funct3 == 0x4) {
      op_name = "xnor";
      result = ~(left ^ right);
    }
    else if (funct7 == 0x20 && funct3 == 0x6) {
      op_name = "orn";
      result = left | ~right;
    }
    else if (funct7 == 0x20 && funct3 == 0x7) {
      op_name = "andn";
      result = left & ~right;
    }
    else if (funct7 == 0x05 && funct3 == 0x4) {
      op_name = "min";
      result = (Bit64s) left < (Bit64s) right ? left : right;
    }
    else if (funct7 == 0x05 && funct3 == 0x5) {
      op_name = "minu";
      result = left < right ? left : right;
    }
    else if (funct7 == 0x05 && funct3 == 0x6) {
      op_name = "max";
      result = (Bit64s) left > (Bit64s) right ? left : right;
    }
    else if (funct7 == 0x05 && funct3 == 0x7) {
      op_name = "maxu";
      result = left > right ? left : right;
    }
    else if (funct7 == 0x30 && funct3 == 0x1) {
      op_name = "rol";
      result = bx_poly_rotate_left(left, 64, (Bit32u) right);
    }
    else if (funct7 == 0x30 && funct3 == 0x5) {
      op_name = "ror";
      result = bx_poly_rotate_right(left, 64, (Bit32u) right);
    }
    else if (funct7 == 0x14 && funct3 == 0x1) {
      op_name = "bset";
      result = left | (BX_CONST64(1) << (right & 0x3f));
    }
    else if (funct7 == 0x24 && funct3 == 0x1) {
      op_name = "bclr";
      result = left & ~(BX_CONST64(1) << (right & 0x3f));
    }
    else if (funct7 == 0x34 && funct3 == 0x1) {
      op_name = "binv";
      result = left ^ (BX_CONST64(1) << (right & 0x3f));
    }
    else if (funct7 == 0x24 && funct3 == 0x5) {
      op_name = "bext";
      result = (left >> (right & 0x3f)) & 1;
    }
    else if (funct7 == 0x07 && funct3 == 0x5) {
      op_name = "czero.eqz";
      result = right == 0 ? 0 : left;
    }
    else if (funct7 == 0x07 && funct3 == 0x7) {
      op_name = "czero.nez";
      result = right != 0 ? 0 : left;
    }
    else if (funct7 == 0x10 && funct3 == 0x2) {
      op_name = "sh1add";
      result = (left << 1) + right;
    }
    else if (funct7 == 0x10 && funct3 == 0x4) {
      op_name = "sh2add";
      result = (left << 2) + right;
    }
    else if (funct7 == 0x10 && funct3 == 0x6) {
      op_name = "sh3add";
      result = (left << 3) + right;
    }

    if (op_name != 0) {
      if (!write_poly_riscv_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,x%u,x%u result=%llu", op_name, rd, rs1, rs2, (unsigned long long) result));
      return true;
    }
  }

  if ((insn & 0x0000007f) == 0x0000003b) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u rs2 = (insn >> 20) & 0x1f;
    Bit32u funct7 = (insn >> 25) & 0x7f;
    Bit64u left = 0;
    Bit64u right = 0;
    Bit32u result32 = 0;
    Bit64u result64 = 0;
    bool result64_valid = false;
    const char *op_name = 0;

    if (!read_poly_riscv_reg(rs1, &left) || !read_poly_riscv_reg(rs2, &right))
      return false;

    if (funct7 == 0x00 && funct3 == 0x0) {
      op_name = "addw";
      result32 = (Bit32u) left + (Bit32u) right;
    }
    else if (funct7 == 0x20 && funct3 == 0x0) {
      op_name = "subw";
      result32 = (Bit32u) left - (Bit32u) right;
    }
    else if (funct7 == 0x01 && funct3 == 0x0) {
      op_name = "mulw";
      result32 = (Bit32u) ((Bit64s) (Bit32s) (Bit32u) left * (Bit64s) (Bit32s) (Bit32u) right);
    }
    else if (funct7 == 0x01 && funct3 == 0x4) {
      op_name = "divw";
      Bit32u right32 = (Bit32u) right;
      if (right32 == 0)
        result32 = 0xffffffff;
      else if ((Bit32u) left == 0x80000000 && right32 == 0xffffffff)
        result32 = 0x80000000;
      else
        result32 = (Bit32u) ((Bit32s) (Bit32u) left / (Bit32s) right32);
    }
    else if (funct7 == 0x01 && funct3 == 0x5) {
      op_name = "divuw";
      Bit32u right32 = (Bit32u) right;
      result32 = right32 == 0 ? 0xffffffff : (Bit32u) left / right32;
    }
    else if (funct7 == 0x01 && funct3 == 0x6) {
      op_name = "remw";
      Bit32u right32 = (Bit32u) right;
      if (right32 == 0)
        result32 = (Bit32u) left;
      else if ((Bit32u) left == 0x80000000 && right32 == 0xffffffff)
        result32 = 0;
      else
        result32 = (Bit32u) ((Bit32s) (Bit32u) left % (Bit32s) right32);
    }
    else if (funct7 == 0x01 && funct3 == 0x7) {
      op_name = "remuw";
      Bit32u right32 = (Bit32u) right;
      result32 = right32 == 0 ? (Bit32u) left : (Bit32u) left % right32;
    }
    else if (funct7 == 0x00 && funct3 == 0x1) {
      op_name = "sllw";
      result32 = (Bit32u) left << (right & 0x1f);
    }
    else if (funct7 == 0x00 && funct3 == 0x5) {
      op_name = "srlw";
      result32 = (Bit32u) left >> (right & 0x1f);
    }
    else if (funct7 == 0x20 && funct3 == 0x5) {
      op_name = "sraw";
      result32 = (Bit32u) ((Bit32s) (Bit32u) left >> (right & 0x1f));
    }
    else if (funct7 == 0x04 && funct3 == 0x4 && rs2 == 0) {
      op_name = "zext.h";
      result32 = (Bit16u) left;
    }
    else if (funct7 == 0x30 && funct3 == 0x1) {
      op_name = "rolw";
      result32 = (Bit32u) bx_poly_rotate_left((Bit32u) left, 32,
        (Bit32u) right);
    }
    else if (funct7 == 0x30 && funct3 == 0x5) {
      op_name = "rorw";
      result32 = (Bit32u) bx_poly_rotate_right((Bit32u) left, 32,
        (Bit32u) right);
    }
    else if (funct7 == 0x04 && funct3 == 0x0) {
      op_name = "add.uw";
      result64 = (Bit64u) (Bit32u) left + right;
      result64_valid = true;
    }
    else if (funct7 == 0x10 && funct3 == 0x2) {
      op_name = "sh1add.uw";
      result64 = (((Bit64u) (Bit32u) left) << 1) + right;
      result64_valid = true;
    }
    else if (funct7 == 0x10 && funct3 == 0x4) {
      op_name = "sh2add.uw";
      result64 = (((Bit64u) (Bit32u) left) << 2) + right;
      result64_valid = true;
    }
    else if (funct7 == 0x10 && funct3 == 0x6) {
      op_name = "sh3add.uw";
      result64 = (((Bit64u) (Bit32u) left) << 3) + right;
      result64_valid = true;
    }

    if (op_name == 0)
      return false;
    Bit64u result = result64_valid ?
      result64 : (Bit64u) bx_poly_sign_extend(result32, 32);
    if (!write_poly_riscv_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated riscv %s x%u,x%u,x%u result=%llu", op_name, rd, rs1, rs2, (unsigned long long) result));
    return true;
  }

  if ((insn & 0x0000007f) == 0x00000063) {
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u rs2 = (insn >> 20) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit64u left = 0;
    Bit64u right = 0;
    bool taken = false;
    const char *op_name = 0;
    if (!read_poly_riscv_reg(rs1, &left) || !read_poly_riscv_reg(rs2, &right))
      return false;

    if (funct3 == 0x0) {
      op_name = "beq";
      taken = left == right;
    }
    else if (funct3 == 0x1) {
      op_name = "bne";
      taken = left != right;
    }
    else if (funct3 == 0x4) {
      op_name = "blt";
      taken = (Bit64s) left < (Bit64s) right;
    }
    else if (funct3 == 0x5) {
      op_name = "bge";
      taken = (Bit64s) left >= (Bit64s) right;
    }
    else if (funct3 == 0x6) {
      op_name = "bltu";
      taken = left < right;
    }
    else if (funct3 == 0x7) {
      op_name = "bgeu";
      taken = left >= right;
    }
    else {
      return false;
    }

    if (taken) {
      Bit32u imm =
        (((insn >> 31) & 0x1) << 12) |
        (((insn >> 7) & 0x1) << 11) |
        (((insn >> 25) & 0x3f) << 5) |
        (((insn >> 8) & 0xf) << 1);
      Bit64s guest_offset = bx_poly_sign_extend(imm, 13);
      RIP = (bx_address) ((Bit64s) pc + guest_offset);
      BX_DEBUG(("poly_raw: emulated riscv %s taken offset=%lld", op_name, (long long) guest_offset));
    }
    else {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s not-taken", op_name));
    }
    return true;
  }

  if ((insn & 0x0000007f) == 0x0000006f) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u imm =
      (((insn >> 31) & 0x1) << 20) |
      (((insn >> 21) & 0x3ff) << 1) |
      (((insn >> 20) & 0x1) << 11) |
      (((insn >> 12) & 0xff) << 12);
    Bit64s guest_offset = bx_poly_sign_extend(imm, 21);
    if (!write_poly_riscv_reg(rd, next_rip))
      return false;
    RIP = (bx_address) ((Bit64s) pc + guest_offset);
    BX_DEBUG(("poly_raw: emulated riscv jal x%u offset=%lld link=%llx", rd, (long long) guest_offset, (unsigned long long) next_rip));
    return true;
  }

  if ((insn & 0x0000707f) == 0x00000067) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
    Bit64u base = 0;
    if (!read_poly_riscv_reg(rs1, &base))
      return false;
    if (!write_poly_riscv_reg(rd, next_rip))
      return false;
    // The x86 poly opcode can place the raw stream at any host byte lane.
    Bit64u target = (base + imm12) & ~BX_CONST64(1);
    if (return_poly_cross_call(BX_POLY_MODE_RAW_RISCV, (bx_address) target))
      return true;
    if (return_poly_abi_call(BX_POLY_MODE_RAW_RISCV, (bx_address) target))
      return true;
    if (rd != 0) {
      Bit64u import_return = next_rip;
      // RISC-V PLT stubs use a scratch link register while preserving ra as
      // the caller continuation. Direct jalr ra imports still return to next.
      if (rd != 1 && !read_poly_riscv_reg(1, &import_return))
        return false;
      if (handle_poly_import_call(BX_POLY_MODE_RAW_RISCV,
            (bx_address) target, (bx_address) import_return))
        return true;
    }
    target = bx_poly_riscv_indirect_target(target, pc);
    RIP = (bx_address) target;
    BX_DEBUG(("poly_raw: emulated riscv jalr x%u,%lld(x%u) target=%llx link=%llx", rd, (long long) imm12, rs1, (unsigned long long) RIP, (unsigned long long) next_rip));
    return true;
  }

  if ((insn & 0x0000007f) == 0x00000027) {
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u rs2 = (insn >> 20) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit32u imm = ((insn >> 7) & 0x1f) | (((insn >> 25) & 0x7f) << 5);
    Bit64s imm12 = bx_poly_sign_extend(imm, 12);
    Bit64u base = 0;
    const char *op_name = 0;
    if (!read_poly_riscv_reg(rs1, &base))
      return false;
    bx_address addr = (bx_address) ((Bit64s) base + imm12);

    if (funct3 == 0x2) {
      Bit32u value = 0;
      if (!read_poly_riscv_fp32_reg(rs2, &value))
        return false;
      write_virtual_dword(BX_SEG_REG_DS, addr, value);
      op_name = "fsw";
    }
    else if (funct3 == 0x3) {
      Bit64u value = 0;
      if (!read_poly_riscv_fp64_reg(rs2, &value))
        return false;
      write_virtual_qword(BX_SEG_REG_DS, addr, value);
      op_name = "fsd";
    }
    else {
      return false;
    }

    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated riscv %s f%u,%lld(x%u) addr=%llx", op_name, rs2, (long long) imm12, rs1, (unsigned long long) addr));
    return true;
  }

  if ((insn & 0x0000007f) == 0x00000023) {
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u rs2 = (insn >> 20) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit32u imm = ((insn >> 7) & 0x1f) | (((insn >> 25) & 0x7f) << 5);
    Bit64s imm12 = bx_poly_sign_extend(imm, 12);
    Bit64u base = 0;
    Bit64u value = 0;
    const char *op_name = 0;
    if (!read_poly_riscv_reg(rs1, &base))
      return false;
    if (!read_poly_riscv_reg(rs2, &value))
      return false;
    bx_address addr = (bx_address) ((Bit64s) base + imm12);

    if (funct3 == 0x0) {
      write_virtual_byte(BX_SEG_REG_DS, addr, (Bit8u) value);
      op_name = "sb";
    }
    else if (funct3 == 0x1) {
      write_virtual_word(BX_SEG_REG_DS, addr, (Bit16u) value);
      op_name = "sh";
    }
    else if (funct3 == 0x2) {
      write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) value);
      op_name = "sw";
    }
    else if (funct3 == 0x3) {
      write_virtual_qword(BX_SEG_REG_DS, addr, value);
      op_name = "sd";
    }
    else {
      return false;
    }

    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated riscv %s x%u,%lld(x%u) addr=%llx value=%llu", op_name, rs2, (long long) imm12, rs1, (unsigned long long) addr, (unsigned long long) value));
    return true;
  }

  if ((insn & 0x0000007f) == 0x00000007) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
    Bit64u base = 0;
    const char *op_name = 0;
    if (!read_poly_riscv_reg(rs1, &base))
      return false;
    bx_address addr = (bx_address) ((Bit64s) base + imm12);

    if (funct3 == 0x2) {
      Bit32u value = read_virtual_dword(BX_SEG_REG_DS, addr);
      if (!write_poly_riscv_fp32_reg(rd, value))
        return false;
      op_name = "flw";
    }
    else if (funct3 == 0x3) {
      Bit64u value = read_virtual_qword(BX_SEG_REG_DS, addr);
      if (!write_poly_riscv_fp64_reg(rd, value))
        return false;
      op_name = "fld";
    }
    else {
      return false;
    }

    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated riscv %s f%u,%lld(x%u) addr=%llx", op_name, rd, (long long) imm12, rs1, (unsigned long long) addr));
    return true;
  }

  if ((insn & 0x0000007f) == 0x00000003) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
    Bit64u base = 0;
    Bit64u value = 0;
    const char *op_name = 0;
    if (!read_poly_riscv_reg(rs1, &base))
      return false;
    bx_address addr = (bx_address) ((Bit64s) base + imm12);

    if (funct3 == 0x0) {
      value = (Bit64u) bx_poly_sign_extend(read_virtual_byte(BX_SEG_REG_DS, addr), 8);
      op_name = "lb";
    }
    else if (funct3 == 0x1) {
      value = (Bit64u) bx_poly_sign_extend(read_virtual_word(BX_SEG_REG_DS, addr), 16);
      op_name = "lh";
    }
    else if (funct3 == 0x2) {
      value = (Bit64u) bx_poly_sign_extend(read_virtual_dword(BX_SEG_REG_DS, addr), 32);
      op_name = "lw";
    }
    else if (funct3 == 0x3) {
      value = read_virtual_qword(BX_SEG_REG_DS, addr);
      op_name = "ld";
    }
    else if (funct3 == 0x4) {
      value = read_virtual_byte(BX_SEG_REG_DS, addr);
      op_name = "lbu";
    }
    else if (funct3 == 0x5) {
      value = read_virtual_word(BX_SEG_REG_DS, addr);
      op_name = "lhu";
    }
    else if (funct3 == 0x6) {
      value = read_virtual_dword(BX_SEG_REG_DS, addr);
      op_name = "lwu";
    }
    else {
      return false;
    }

    if (!write_poly_riscv_reg(rd, value))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated riscv %s x%u,%lld(x%u) addr=%llx value=%llu", op_name, rd, (long long) imm12, rs1, (unsigned long long) addr, (unsigned long long) value));
    return true;
  }

  if ((insn & 0x0000007f) == 0x00000073) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u funct3 = (insn >> 12) & 0x7;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u csr = (insn >> 20) & 0xfff;

    if (csr >= 0x001 && csr <= 0x003 && funct3 != 0) {
      Bit32u old_value = bx_poly_riscv_read_fp_csr(csr);
      Bit64u source64 = 0;
      Bit32u source = 0;
      bool write_csr = false;
      Bit32u new_value = old_value;

      if (funct3 >= 0x5) {
        source = rs1;
      }
      else if (!read_poly_riscv_reg(rs1, &source64)) {
        return false;
      }
      else {
        source = (Bit32u) source64;
      }

      switch (funct3) {
      case 0x1:
        new_value = source;
        write_csr = true;
        break;
      case 0x2:
        new_value = old_value | source;
        write_csr = (rs1 != 0);
        break;
      case 0x3:
        new_value = old_value & ~source;
        write_csr = (rs1 != 0);
        break;
      case 0x5:
        new_value = source;
        write_csr = true;
        break;
      case 0x6:
        new_value = old_value | source;
        write_csr = (rs1 != 0);
        break;
      case 0x7:
        new_value = old_value & ~source;
        write_csr = (rs1 != 0);
        break;
      default:
        return false;
      }

      if (write_csr && !bx_poly_riscv_write_fp_csr(csr, new_value))
        return false;
      if (!write_poly_riscv_reg(rd, old_value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv fp csr csr=%03x rd=x%u funct3=%u rs1=%u old=%u new=%u",
        csr, rd, funct3, rs1, old_value, bx_poly_riscv_read_fp_csr(csr)));
      return true;
    }
  }

  if (insn == 0x00000073) {
    Bit64u syscall_value = 0, arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0, arg6 = 0, arg7 = 0;
    if (!read_poly_riscv_reg(17, &syscall_value) ||
        !read_poly_riscv_reg(10, &arg0) ||
        !read_poly_riscv_reg(11, &arg1) ||
        !read_poly_riscv_reg(12, &arg2) ||
        !read_poly_riscv_reg(13, &arg3) ||
        !read_poly_riscv_reg(14, &arg4) ||
        !read_poly_riscv_reg(15, &arg5) ||
        !read_poly_riscv_reg(16, &arg6) ||
        !read_poly_riscv_reg(17, &arg7))
      return false;
    Bit32u syscall_number = (Bit32u) syscall_value;
    return handle_poly_foreign_syscall("riscv", "ecall", syscall_number, 0,
      arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, next_rip);
  }

  if (insn == 0x00100073) {
    Bit64u break_id = 0;
    if (!read_poly_riscv_reg(17, &break_id))
      return false;
    return handle_poly_break_trap("riscv", "ebreak", (Bit32u) break_id, 0, pc,
      next_rip);
  }

  return false;
}

bool BX_CPU_C::execute_poly_raw_riscv_compressed(Bit16u insn, bx_address pc)
{
  bx_address next_rip = pc + 2;
  Bit32u quadrant = insn & 0x3;
  Bit32u funct3 = ((Bit32u) insn >> 13) & 0x7;

  if (quadrant == 0x0) {
    if (funct3 == 0x0) {
      Bit32u rd = bx_poly_riscv_creg(((Bit32u) insn >> 2) & 0x7);
      Bit32u imm = bx_poly_riscv_caddi4spn_imm(insn);
      Bit64u sp = 0;
      if (imm == 0 || !read_poly_riscv_reg(2, &sp) ||
          !write_poly_riscv_reg(rd, sp + imm))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.addi4spn x%u,%u result=%llu", rd, imm, (unsigned long long) (sp + imm)));
      return true;
    }

    if (funct3 == 0x1 || funct3 == 0x5) {
      Bit32u rs1 = bx_poly_riscv_creg(((Bit32u) insn >> 7) & 0x7);
      Bit32u reg = bx_poly_riscv_creg(((Bit32u) insn >> 2) & 0x7);
      Bit32u imm = bx_poly_riscv_cld_imm(insn);
      Bit64u base = 0;
      if (!read_poly_riscv_reg(rs1, &base))
        return false;
      bx_address addr = (bx_address) (base + imm);
      if (funct3 == 0x1) {
        Bit64u value = read_virtual_qword(BX_SEG_REG_DS, addr);
        if (!write_poly_riscv_fp64_reg(reg, value))
          return false;
        BX_DEBUG(("poly_raw: emulated riscv c.fld f%u,%u(x%u) value=%llu", reg, imm, rs1, (unsigned long long) value));
      }
      else {
        Bit64u value = 0;
        if (!read_poly_riscv_fp64_reg(reg, &value))
          return false;
        write_virtual_qword(BX_SEG_REG_DS, addr, value);
        BX_DEBUG(("poly_raw: emulated riscv c.fsd f%u,%u(x%u) value=%llu", reg, imm, rs1, (unsigned long long) value));
      }
      RIP = next_rip;
      return true;
    }

    if (funct3 == 0x2 || funct3 == 0x6) {
      Bit32u rs1 = bx_poly_riscv_creg(((Bit32u) insn >> 7) & 0x7);
      Bit32u reg = bx_poly_riscv_creg(((Bit32u) insn >> 2) & 0x7);
      Bit32u imm = bx_poly_riscv_clw_imm(insn);
      Bit64u base = 0;
      if (!read_poly_riscv_reg(rs1, &base))
        return false;
      bx_address addr = (bx_address) (base + imm);
      if (funct3 == 0x2) {
        Bit64u value = (Bit64u) bx_poly_sign_extend(read_virtual_dword(BX_SEG_REG_DS, addr), 32);
        if (!write_poly_riscv_reg(reg, value))
          return false;
        BX_DEBUG(("poly_raw: emulated riscv c.lw x%u,%u(x%u) value=%llu", reg, imm, rs1, (unsigned long long) value));
      }
      else {
        Bit64u value = 0;
        if (!read_poly_riscv_reg(reg, &value))
          return false;
        write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) value);
        BX_DEBUG(("poly_raw: emulated riscv c.sw x%u,%u(x%u) value=%llu", reg, imm, rs1, (unsigned long long) value));
      }
      RIP = next_rip;
      return true;
    }

    if (funct3 == 0x3 || funct3 == 0x7) {
      Bit32u rs1 = bx_poly_riscv_creg(((Bit32u) insn >> 7) & 0x7);
      Bit32u reg = bx_poly_riscv_creg(((Bit32u) insn >> 2) & 0x7);
      Bit32u imm = bx_poly_riscv_cld_imm(insn);
      Bit64u base = 0;
      if (!read_poly_riscv_reg(rs1, &base))
        return false;
      bx_address addr = (bx_address) (base + imm);
      if (funct3 == 0x3) {
        Bit64u value = read_virtual_qword(BX_SEG_REG_DS, addr);
        if (!write_poly_riscv_reg(reg, value))
          return false;
        BX_DEBUG(("poly_raw: emulated riscv c.ld x%u,%u(x%u) value=%llu", reg, imm, rs1, (unsigned long long) value));
      }
      else {
        Bit64u value = 0;
        if (!read_poly_riscv_reg(reg, &value))
          return false;
        write_virtual_qword(BX_SEG_REG_DS, addr, value);
        BX_DEBUG(("poly_raw: emulated riscv c.sd x%u,%u(x%u) value=%llu", reg, imm, rs1, (unsigned long long) value));
      }
      RIP = next_rip;
      return true;
    }
  }

  if (quadrant == 0x1) {
    if (funct3 == 0x0) {
      Bit32u rd = ((Bit32u) insn >> 7) & 0x1f;
      Bit64s imm = bx_poly_riscv_ci_imm(insn);
      Bit64u value = 0;
      if (rd != 0) {
        if (!read_poly_riscv_reg(rd, &value) ||
            !write_poly_riscv_reg(rd, (Bit64u) ((Bit64s) value + imm)))
          return false;
      }
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.addi x%u,%lld", rd, (long long) imm));
      return true;
    }

    if (funct3 == 0x1) {
      Bit32u rd = ((Bit32u) insn >> 7) & 0x1f;
      Bit64s imm = bx_poly_riscv_ci_imm(insn);
      Bit64u value = 0;
      if (rd == 0 || !read_poly_riscv_reg(rd, &value))
        return false;
      Bit32u result32 = (Bit32u) ((Bit64s) (Bit32s) (Bit32u) value + imm);
      Bit64u result = (Bit64u) bx_poly_sign_extend(result32, 32);
      if (!write_poly_riscv_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.addiw x%u,%lld result=%llu", rd, (long long) imm, (unsigned long long) result));
      return true;
    }

    if (funct3 == 0x2) {
      Bit32u rd = ((Bit32u) insn >> 7) & 0x1f;
      Bit64s imm = bx_poly_riscv_ci_imm(insn);
      if (rd == 0) {
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated riscv c.li x0,%lld as no-op",
          (long long) imm));
        return true;
      }
      if (!write_poly_riscv_reg(rd, (Bit64u) imm))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.li x%u,%lld", rd, (long long) imm));
      return true;
    }

    if (funct3 == 0x3) {
      Bit32u rd = ((Bit32u) insn >> 7) & 0x1f;
      Bit64s imm = bx_poly_riscv_ci_imm(insn);
      if (rd == 2) {
        imm = bx_poly_riscv_caddi16sp_imm(insn);
        Bit64u sp = 0;
        if (imm == 0 || !read_poly_riscv_reg(2, &sp) ||
            !write_poly_riscv_reg(2, (Bit64u) ((Bit64s) sp + imm)))
          return false;
        BX_DEBUG(("poly_raw: emulated riscv c.addi16sp %lld", (long long) imm));
      }
      else {
        if (rd == 0 || imm == 0 || !write_poly_riscv_reg(rd, (Bit64u) (imm << 12)))
          return false;
        BX_DEBUG(("poly_raw: emulated riscv c.lui x%u,%lld", rd, (long long) (imm << 12)));
      }
      RIP = next_rip;
      return true;
    }

    if (funct3 == 0x4) {
      Bit32u op = ((Bit32u) insn >> 10) & 0x3;
      Bit32u rd = bx_poly_riscv_creg(((Bit32u) insn >> 7) & 0x7);
      Bit64u left = 0;
      const char *op_name = 0;
      Bit64u result = 0;

      if (!read_poly_riscv_reg(rd, &left))
        return false;

      if (op == 0x0 || op == 0x1) {
        Bit32u shamt = (((Bit32u) insn >> 2) & 0x1f) |
          ((((Bit32u) insn >> 12) & 0x1) << 5);
        if (op == 0x0) {
          op_name = "c.srli";
          result = left >> shamt;
        }
        else {
          op_name = "c.srai";
          result = (Bit64u) ((Bit64s) left >> shamt);
        }
        if (!write_poly_riscv_reg(rd, result))
          return false;
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated riscv %s x%u,%u result=%llu", op_name, rd, shamt, (unsigned long long) result));
        return true;
      }

      if (op == 0x2) {
        Bit64s imm = bx_poly_riscv_ci_imm(insn);
        result = left & (Bit64u) imm;
        if (!write_poly_riscv_reg(rd, result))
          return false;
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated riscv c.andi x%u,%lld result=%llu", rd, (long long) imm, (unsigned long long) result));
        return true;
      }

      Bit32u rs2 = bx_poly_riscv_creg(((Bit32u) insn >> 2) & 0x7);
      Bit32u alu_op = ((Bit32u) insn >> 5) & 0x3;
      bool word_op = (insn & 0x1000) != 0;
      Bit64u right = 0;
      if (!read_poly_riscv_reg(rs2, &right))
        return false;

      if (!word_op) {
        if (alu_op == 0x0) {
          op_name = "c.sub";
          result = left - right;
        }
        else if (alu_op == 0x1) {
          op_name = "c.xor";
          result = left ^ right;
        }
        else if (alu_op == 0x2) {
          op_name = "c.or";
          result = left | right;
        }
        else {
          op_name = "c.and";
          result = left & right;
        }
      }
      else {
        if (alu_op == 0x0) {
          op_name = "c.subw";
          result = (Bit64u) bx_poly_sign_extend((Bit32u) (left - right), 32);
        }
        else if (alu_op == 0x1) {
          op_name = "c.addw";
          result = (Bit64u) bx_poly_sign_extend((Bit32u) (left + right), 32);
        }
        else {
          return false;
        }
      }

      if (!write_poly_riscv_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,x%u result=%llu", op_name, rd, rs2, (unsigned long long) result));
      return true;
    }

    if (funct3 == 0x5) {
      Bit64s offset = bx_poly_riscv_cj_imm(insn);
      RIP = (bx_address) ((Bit64s) pc + offset);
      BX_DEBUG(("poly_raw: emulated riscv c.j offset=%lld", (long long) offset));
      return true;
    }

    if (funct3 == 0x6 || funct3 == 0x7) {
      Bit32u rs1 = bx_poly_riscv_creg(((Bit32u) insn >> 7) & 0x7);
      Bit64s offset = bx_poly_riscv_cb_imm(insn);
      Bit64u value = 0;
      if (!read_poly_riscv_reg(rs1, &value))
        return false;
      bool taken = funct3 == 0x6 ? value == 0 : value != 0;
      RIP = taken ? (bx_address) ((Bit64s) pc + offset) : next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s %s offset=%lld", funct3 == 0x6 ? "c.beqz" : "c.bnez", taken ? "taken" : "not-taken", (long long) offset));
      return true;
    }
  }

  if (quadrant == 0x2) {
    if (funct3 == 0x0) {
      Bit32u rd = ((Bit32u) insn >> 7) & 0x1f;
      Bit32u shamt = (((Bit32u) insn >> 2) & 0x1f) | ((((Bit32u) insn >> 12) & 0x1) << 5);
      Bit64u value = 0;
      if (rd == 0 || !read_poly_riscv_reg(rd, &value) ||
          !write_poly_riscv_reg(rd, value << shamt))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.slli x%u,%u", rd, shamt));
      return true;
    }

    if (funct3 == 0x1) {
      Bit32u rd = ((Bit32u) insn >> 7) & 0x1f;
      Bit32u imm = bx_poly_riscv_cldsp_imm(insn);
      Bit64u sp = 0;
      if (!read_poly_riscv_reg(2, &sp))
        return false;
      Bit64u value = read_virtual_qword(BX_SEG_REG_DS, (bx_address) (sp + imm));
      if (!write_poly_riscv_fp64_reg(rd, value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.fldsp f%u,%u(sp) value=%llu", rd, imm, (unsigned long long) value));
      return true;
    }

    if (funct3 == 0x2) {
      Bit32u rd = ((Bit32u) insn >> 7) & 0x1f;
      Bit32u imm = bx_poly_riscv_clwsp_imm(insn);
      Bit64u sp = 0;
      if (rd == 0 || !read_poly_riscv_reg(2, &sp))
        return false;
      Bit64u value = (Bit64u) bx_poly_sign_extend(
        read_virtual_dword(BX_SEG_REG_DS, (bx_address) (sp + imm)), 32);
      if (!write_poly_riscv_reg(rd, value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.lwsp x%u,%u(sp) value=%llu", rd, imm, (unsigned long long) value));
      return true;
    }

    if (funct3 == 0x3) {
      Bit32u rd = ((Bit32u) insn >> 7) & 0x1f;
      Bit32u imm = bx_poly_riscv_cldsp_imm(insn);
      Bit64u sp = 0;
      if (rd == 0 || !read_poly_riscv_reg(2, &sp))
        return false;
      Bit64u value = read_virtual_qword(BX_SEG_REG_DS, (bx_address) (sp + imm));
      if (!write_poly_riscv_reg(rd, value))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.ldsp x%u,%u(sp) value=%llu", rd, imm, (unsigned long long) value));
      return true;
    }

    if (funct3 == 0x4) {
      Bit32u rd = ((Bit32u) insn >> 7) & 0x1f;
      Bit32u rs2 = ((Bit32u) insn >> 2) & 0x1f;
      bool high = (insn & 0x1000) != 0;
      if (!high && rs2 == 0) {
        Bit64u target = 0;
        if (rd == 0 || !read_poly_riscv_reg(rd, &target))
          return false;
        target &= ~BX_CONST64(1);
        if (return_poly_cross_call(BX_POLY_MODE_RAW_RISCV, (bx_address) target))
          return true;
        if (return_poly_abi_call(BX_POLY_MODE_RAW_RISCV, (bx_address) target))
          return true;
        Bit64u import_return = 0;
        if (!read_poly_riscv_reg(1, &import_return))
          return false;
        if (handle_poly_import_call(BX_POLY_MODE_RAW_RISCV,
              (bx_address) target, (bx_address) import_return))
          return true;
        target = bx_poly_riscv_indirect_target(target, pc);
        RIP = (bx_address) target;
        BX_DEBUG(("poly_raw: emulated riscv c.jr x%u target=%llx", rd, (unsigned long long) target));
        return true;
      }
      if (!high && rs2 != 0) {
        Bit64u value = 0;
        if (rd == 0) {
          RIP = next_rip;
          BX_DEBUG(("poly_raw: emulated riscv c.mv x0,x%u as no-op", rs2));
          return true;
        }
        if (!read_poly_riscv_reg(rs2, &value) ||
            !write_poly_riscv_reg(rd, value))
          return false;
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated riscv c.mv x%u,x%u value=%llu", rd, rs2, (unsigned long long) value));
        return true;
      }
      if (high && rs2 == 0 && rd == 0) {
        Bit64u break_id = 0;
        if (!read_poly_riscv_reg(17, &break_id))
          return false;
        return handle_poly_break_trap("riscv", "c.ebreak", (Bit32u) break_id,
          0, pc, next_rip);
      }
      if (high && rs2 == 0) {
        Bit64u target = 0;
        if (!read_poly_riscv_reg(rd, &target) ||
            !write_poly_riscv_reg(1, next_rip))
          return false;
        target &= ~BX_CONST64(1);
        if (return_poly_cross_call(BX_POLY_MODE_RAW_RISCV, (bx_address) target))
          return true;
        if (return_poly_abi_call(BX_POLY_MODE_RAW_RISCV, (bx_address) target))
          return true;
        if (handle_poly_import_call(BX_POLY_MODE_RAW_RISCV,
              (bx_address) target, next_rip))
          return true;
        target = bx_poly_riscv_indirect_target(target, pc);
        RIP = (bx_address) target;
        BX_DEBUG(("poly_raw: emulated riscv c.jalr x%u target=%llx", rd, (unsigned long long) target));
        return true;
      }
      if (high && rs2 != 0) {
        Bit64u left = 0, right = 0;
        if (rd == 0 || !read_poly_riscv_reg(rd, &left) ||
            !read_poly_riscv_reg(rs2, &right) ||
            !write_poly_riscv_reg(rd, left + right))
          return false;
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated riscv c.add x%u,x%u result=%llu", rd, rs2, (unsigned long long) (left + right)));
        return true;
      }
    }

    if (funct3 == 0x5) {
      Bit32u rs2 = ((Bit32u) insn >> 2) & 0x1f;
      Bit32u imm = bx_poly_riscv_csdsp_imm(insn);
      Bit64u sp = 0, value = 0;
      if (!read_poly_riscv_reg(2, &sp) || !read_poly_riscv_fp64_reg(rs2, &value))
        return false;
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (sp + imm), value);
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.fsdsp f%u,%u(sp) value=%llu", rs2, imm, (unsigned long long) value));
      return true;
    }

    if (funct3 == 0x6) {
      Bit32u rs2 = ((Bit32u) insn >> 2) & 0x1f;
      Bit32u imm = bx_poly_riscv_cswsp_imm(insn);
      Bit64u sp = 0, value = 0;
      if (!read_poly_riscv_reg(2, &sp) || !read_poly_riscv_reg(rs2, &value))
        return false;
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) (sp + imm), (Bit32u) value);
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.swsp x%u,%u(sp) value=%llu", rs2, imm, (unsigned long long) value));
      return true;
    }

    if (funct3 == 0x7) {
      Bit32u rs2 = ((Bit32u) insn >> 2) & 0x1f;
      Bit32u imm = bx_poly_riscv_csdsp_imm(insn);
      Bit64u sp = 0, value = 0;
      if (!read_poly_riscv_reg(2, &sp) || !read_poly_riscv_reg(rs2, &value))
        return false;
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (sp + imm), value);
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv c.sdsp x%u,%u(sp) value=%llu", rs2, imm, (unsigned long long) value));
      return true;
    }
  }

  return false;
}

void BX_CPU_C::execute_poly_raw_step(void)
{
  bx_address pc = RIP;
  bx_address next_pc = pc;
  Bit32u insn = 0;
  Bit32u insn_bytes = 0;
  bool handled = false;
  const char *arch_name = "foreign";

  if (bx_poly_current_mode == BX_POLY_MODE_RAW_AARCH64) {
    arch_name = "aarch64";
    next_pc = pc + 4;
    insn_bytes = 4;
    insn = read_virtual_dword(BX_SEG_REG_CS, pc);
    bx_poly_foreign_insn_count++;
    handled = execute_poly_raw_aarch64(insn, pc);
  }
  else if (bx_poly_current_mode == BX_POLY_MODE_RAW_RISCV) {
    arch_name = "riscv";
    Bit16u half = read_virtual_word(BX_SEG_REG_CS, pc);
    bx_poly_foreign_insn_count++;
    if ((half & 0x3) != 0x3) {
      insn = half;
      next_pc = pc + 2;
      insn_bytes = 2;
      handled = execute_poly_raw_riscv_compressed(half, pc);
    }
    else {
      insn = read_virtual_dword(BX_SEG_REG_CS, pc);
      next_pc = pc + 4;
      insn_bytes = 4;
      handled = execute_poly_raw_riscv(insn, pc);
    }
  }

  if (!handled) {
    BX_INFO(("poly_raw: illegal mode=%u rip=%llx insn=%08x",
      bx_poly_current_mode, (unsigned long long) pc, insn));
    if (bx_poly_current_mode == BX_POLY_MODE_RAW_AARCH64 ||
        bx_poly_current_mode == BX_POLY_MODE_RAW_RISCV) {
      bx_poly_record_illegal_trap(bx_poly_current_mode, insn, insn_bytes,
        pc, next_pc);
      bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
        bx_poly_current_state_key(RSP));
      deliver_poly_architectural_trap(arch_name, "illegal", pc);
      return;
    }
    bx_poly_current_mode = BX_POLY_MODE_X86;
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    exception(BX_UD_EXCEPTION, 0);
  }
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxError(bxInstruction_c *i)
{
  unsigned ia_opcode = i->getIaOpcode();

  if (ia_opcode == BX_IA_ERROR) {
    BX_DEBUG(("BxError: Encountered an unknown instruction (signalling #UD)"));

    if (LOG_THIS getonoff(LOGLEV_DEBUG))
      debug_disasm_instruction(BX_CPU_THIS_PTR prev_rip);
  }
  else {
    BX_DEBUG(("%s: instruction not supported - signalling #UD", get_bx_opcode_name(ia_opcode)));
    for (unsigned n=0; n<BX_ISA_EXTENSIONS_ARRAY_SIZE; n++)
      BX_DEBUG(("ia_extensions_bitmask[%d]: %08x", n, BX_CPU_THIS_PTR ia_extensions_bitmask[n]));
  }

  exception(BX_UD_EXCEPTION, 0);

  BX_NEXT_TRACE(i); // keep compiler happy
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::UndefinedOpcode(bxInstruction_c *i)
{
  BX_DEBUG(("UndefinedOpcode: generate #UD exception"));
  exception(BX_UD_EXCEPTION, 0);

  BX_NEXT_TRACE(i); // keep compiler happy
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::POLYSYSCALL(bxInstruction_c *i)
{
  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::POLYCALL(bxInstruction_c *i)
{
  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::POLYRET(bxInstruction_c *i)
{
  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::POLYMODE(bxInstruction_c *i)
{
  if (BX_CPU_THIS_PTR poly_feature_enabled && handle_poly_opcode(i))
    return;

  BX_DEBUG(("POLYMODE: invalid or disabled poly opcode - signalling #UD"));
  exception(BX_UD_EXCEPTION, 0);

  BX_NEXT_TRACE(i); // keep compiler happy
}


bool BX_CPU_C::deliver_poly_architectural_trap(const char *arch_name,
  const char *trap_name, bx_address fallback_pc)
{
  Bit32u trap_mode = bx_poly_last_trap.mode;
  bx_address trap_vector = bx_poly_trap_vector;
  Bit32u trap_vector_mode = bx_poly_trap_vector_mode;

  bx_poly_trap_saved_regs.valid =
    trap_mode == BX_POLY_MODE_RAW_AARCH64 || trap_mode == BX_POLY_MODE_RAW_RISCV;
  bx_poly_trap_saved_regs.mode = trap_mode;
  bx_poly_trap_saved_regs.rax = RAX;
  bx_poly_trap_saved_regs.rbx = RBX;
  bx_poly_trap_saved_regs.rdi = RDI;
  bx_poly_trap_saved_regs.rsi = RSI;
  bx_poly_trap_saved_regs.rdx = RDX;
  bx_poly_trap_saved_regs.rcx = RCX;
  bx_poly_trap_saved_regs.r8 = R8;
  bx_poly_trap_saved_regs.r9 = R9;
  bx_poly_trap_saved_regs.r10 = R10;
  bx_poly_trap_saved_regs.r11 = R11;
  bx_poly_trap_saved_regs.r12 = R12;
  bx_poly_trap_saved_regs.rsp = RSP;
  for (unsigned n = 0; n < 8; n++) {
    bx_poly_trap_saved_regs.xmm_lo[n] = BX_READ_XMM_REG_LO_QWORD(n);
    bx_poly_trap_saved_regs.xmm_hi[n] = BX_READ_XMM_REG_HI_QWORD(n);
  }
  bx_poly_trap_saved_regs.aarch64_state_valid = false;
  bx_poly_trap_saved_regs.riscv_state_valid = false;

  if (trap_mode == BX_POLY_MODE_RAW_AARCH64) {
    bx_poly_trap_saved_regs.aarch64_state_valid = true;
    bx_poly_trap_saved_regs.aarch64_nzcv = bx_poly_aarch64_nzcv;
    for (unsigned n = 0; n < 31; n++) {
      bx_poly_trap_saved_regs.aarch64_x_valid[n] =
        read_poly_aarch64_reg(n, &bx_poly_trap_saved_regs.aarch64_x[n]);
      bx_poly_trap_saved_regs.aarch64_state_valid =
        bx_poly_trap_saved_regs.aarch64_state_valid &&
        bx_poly_trap_saved_regs.aarch64_x_valid[n];
    }
    for (unsigned n = 0; n < 32; n++) {
      Bit64u lo = 0, hi = 0;
      bx_poly_trap_saved_regs.aarch64_state_valid =
        bx_poly_trap_saved_regs.aarch64_state_valid &&
        read_poly_aarch64_fp128_reg(n, &lo, &hi);
      bx_poly_trap_saved_regs.aarch64_fp[n] = lo;
      bx_poly_trap_saved_regs.aarch64_fp_hi[n] = hi;
    }
  }
  else if (trap_mode == BX_POLY_MODE_RAW_RISCV) {
    bx_poly_trap_saved_regs.riscv_state_valid = true;
    bx_poly_trap_saved_regs.riscv_fflags = bx_poly_riscv_fflags;
    bx_poly_trap_saved_regs.riscv_frm = bx_poly_riscv_frm;
    for (unsigned n = 0; n < 32; n++) {
      bx_poly_trap_saved_regs.riscv_x_valid[n] =
        read_poly_riscv_reg(n, &bx_poly_trap_saved_regs.riscv_x[n]);
      bx_poly_trap_saved_regs.riscv_state_valid =
        bx_poly_trap_saved_regs.riscv_state_valid &&
        bx_poly_trap_saved_regs.riscv_x_valid[n];
    }
    for (unsigned n = 0; n < 32; n++) {
      Bit64u lo = 0, hi = 0;
      bx_poly_trap_saved_regs.riscv_state_valid =
        bx_poly_trap_saved_regs.riscv_state_valid &&
        read_poly_riscv_fp128_reg(n, &lo, &hi);
      bx_poly_trap_saved_regs.riscv_fp[n] = lo;
      bx_poly_trap_saved_regs.riscv_fp_hi[n] = hi;
    }
  }

  if (!bx_poly_valid_frontend_mode(trap_vector_mode)) {
    BX_INFO(("poly_ud: architectural %s %s trap has invalid vector mode=%u",
      arch_name, trap_name, trap_vector_mode));
    trap_vector = 0;
  }

  if (bx_poly_monitor_packet_addr != 0) {
    bx_address packet = bx_poly_monitor_packet_addr;
    write_virtual_qword(BX_SEG_REG_DS, packet,
      (Bit64u) bx_poly_last_trap.reason |
      ((Bit64u) bx_poly_last_trap.mode << 32));
    write_virtual_qword(BX_SEG_REG_DS, packet + 8, bx_poly_last_trap.number);
    write_virtual_qword(BX_SEG_REG_DS, packet + 16, bx_poly_last_trap.selector);
    write_virtual_qword(BX_SEG_REG_DS, packet + 24, bx_poly_last_trap.pc);
    write_virtual_qword(BX_SEG_REG_DS, packet + 32, bx_poly_last_trap.next_pc);
    write_virtual_qword(BX_SEG_REG_DS, packet + 40, bx_poly_trap_packet_flags());
    write_virtual_qword(BX_SEG_REG_DS, packet + 48, 0);
    write_virtual_qword(BX_SEG_REG_DS, packet + 56, 0);
    for (unsigned n = 0; n < BX_POLY_TRAP_PACKET_ARG_COUNT; n++)
      write_virtual_qword(BX_SEG_REG_DS, packet + 64 + n * 8,
        bx_poly_last_trap.args[n]);
  }

  bx_poly_current_mode = trap_vector_mode;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));

  if (trap_vector != 0) {
    if (trap_vector_mode == BX_POLY_MODE_X86) {
      RAX = bx_poly_last_trap.reason;
      RBX = bx_poly_last_trap.mode;
      RCX = bx_poly_last_trap.number;
      RDX = bx_poly_last_trap.pc;
      RSI = bx_poly_last_trap.selector;
      RDI = bx_poly_last_trap.args[0];
      R8 = bx_poly_last_trap.args[1];
      R9 = bx_poly_last_trap.args[2];
      R10 = bx_poly_last_trap.args[3];
      R11 = bx_poly_last_trap.args[4];
      R12 = bx_poly_last_trap.args[5];
      R13 = bx_poly_last_trap.args[6];
      R14 = bx_poly_last_trap.args[7];
    }
    else if (trap_vector_mode == BX_POLY_MODE_RAW_AARCH64) {
      write_poly_aarch64_reg(0, bx_poly_last_trap.reason);
      write_poly_aarch64_reg(1, bx_poly_last_trap.mode);
      write_poly_aarch64_reg(2, bx_poly_last_trap.number);
      write_poly_aarch64_reg(3, bx_poly_last_trap.pc);
      write_poly_aarch64_reg(4, bx_poly_last_trap.selector);
      write_poly_aarch64_reg(5, bx_poly_last_trap.args[0]);
      write_poly_aarch64_reg(6, bx_poly_last_trap.args[1]);
      write_poly_aarch64_reg(7, bx_poly_last_trap.args[2]);
      write_poly_aarch64_reg(8, bx_poly_last_trap.args[3]);
      write_poly_aarch64_reg(9, bx_poly_last_trap.args[4]);
      write_poly_aarch64_reg(10, bx_poly_last_trap.args[5]);
      write_poly_aarch64_reg(11, bx_poly_last_trap.args[6]);
      write_poly_aarch64_reg(12, bx_poly_last_trap.args[7]);
    }
    else {
      write_poly_riscv_reg(10, bx_poly_last_trap.reason);
      write_poly_riscv_reg(11, bx_poly_last_trap.mode);
      write_poly_riscv_reg(12, bx_poly_last_trap.number);
      write_poly_riscv_reg(13, bx_poly_last_trap.pc);
      write_poly_riscv_reg(14, bx_poly_last_trap.selector);
      write_poly_riscv_reg(15, bx_poly_last_trap.args[0]);
      write_poly_riscv_reg(16, bx_poly_last_trap.args[1]);
      write_poly_riscv_reg(17, bx_poly_last_trap.args[2]);
      write_poly_riscv_reg(5, bx_poly_last_trap.args[3]);
      write_poly_riscv_reg(6, bx_poly_last_trap.args[4]);
      write_poly_riscv_reg(7, bx_poly_last_trap.args[5]);
      write_poly_riscv_reg(28, bx_poly_last_trap.args[6]);
      write_poly_riscv_reg(29, bx_poly_last_trap.args[7]);
    }
    RIP = trap_vector;
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
      bx_poly_current_state_key(RSP));
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_ud: architectural %s %s trap vector=%llx source_mode=%u target_mode=%u pc=%llx next=%llx",
      arch_name, trap_name, (unsigned long long) trap_vector, trap_mode,
      trap_vector_mode,
      (unsigned long long) bx_poly_last_trap.pc,
      (unsigned long long) bx_poly_last_trap.next_pc));
    return true;
  }

  bx_poly_current_mode = BX_POLY_MODE_X86;
  unsigned vector = bx_poly_last_trap.reason == BX_POLY_TRAP_BREAK ?
    BX_BP_EXCEPTION : BX_UD_EXCEPTION;
  BX_INFO(("poly_ud: architectural %s %s trap exit without installed vector mode=%u pc=%llx vector=%u",
    arch_name, trap_name, trap_mode, (unsigned long long) fallback_pc, vector));
  RIP = fallback_pc;
  exception(vector, 0);
  return true;
}

bool BX_CPU_C::return_poly_architectural_trap(void)
{
  if (bx_poly_last_trap.reason == BX_POLY_TRAP_NONE ||
      bx_poly_last_trap.mode == BX_POLY_MODE_X86 ||
      bx_poly_last_trap.next_pc == 0) {
    BX_INFO(("poly_ud: reject trap return reason=%u mode=%u next=%llx",
      bx_poly_last_trap.reason, bx_poly_last_trap.mode,
      (unsigned long long) bx_poly_last_trap.next_pc));
    return false;
  }

  bx_poly_current_mode = bx_poly_last_trap.mode;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  if (bx_poly_trap_saved_regs.valid &&
      bx_poly_trap_saved_regs.mode == bx_poly_current_mode) {
    Bit64u result = RAX;
    RBX = bx_poly_trap_saved_regs.rbx;
    RDI = bx_poly_trap_saved_regs.rdi;
    RSI = bx_poly_trap_saved_regs.rsi;
    RDX = bx_poly_trap_saved_regs.rdx;
    RCX = bx_poly_trap_saved_regs.rcx;
    R8 = bx_poly_trap_saved_regs.r8;
    R9 = bx_poly_trap_saved_regs.r9;
    R10 = bx_poly_trap_saved_regs.r10;
    R11 = bx_poly_trap_saved_regs.r11;
    R12 = bx_poly_trap_saved_regs.r12;
    RSP = bx_poly_trap_saved_regs.rsp;
    RAX = result;
    for (unsigned n = 0; n < 8; n++) {
      BX_WRITE_XMM_REG_LO_QWORD(n, bx_poly_trap_saved_regs.xmm_lo[n]);
      BX_WRITE_XMM_REG_HI_QWORD(n, bx_poly_trap_saved_regs.xmm_hi[n]);
    }
    if (bx_poly_current_mode == BX_POLY_MODE_RAW_AARCH64 &&
        bx_poly_trap_saved_regs.aarch64_state_valid) {
      for (unsigned n = 1; n < 31; n++) {
        if (bx_poly_trap_saved_regs.aarch64_x_valid[n])
          write_poly_aarch64_reg(n, bx_poly_trap_saved_regs.aarch64_x[n]);
      }
      for (unsigned n = 0; n < 32; n++) {
        write_poly_aarch64_fp128_reg(n, bx_poly_trap_saved_regs.aarch64_fp[n],
          bx_poly_trap_saved_regs.aarch64_fp_hi[n]);
      }
      bx_poly_aarch64_nzcv = bx_poly_trap_saved_regs.aarch64_nzcv;
    }
    else if (bx_poly_current_mode == BX_POLY_MODE_RAW_RISCV &&
             bx_poly_trap_saved_regs.riscv_state_valid) {
      for (unsigned n = 1; n < 32; n++) {
        if (n != 10 && bx_poly_trap_saved_regs.riscv_x_valid[n])
          write_poly_riscv_reg(n, bx_poly_trap_saved_regs.riscv_x[n]);
      }
      for (unsigned n = 0; n < 32; n++) {
        write_poly_riscv_fp128_reg(n, bx_poly_trap_saved_regs.riscv_fp[n],
          bx_poly_trap_saved_regs.riscv_fp_hi[n]);
      }
      bx_poly_riscv_fflags = bx_poly_trap_saved_regs.riscv_fflags;
      bx_poly_riscv_frm = bx_poly_trap_saved_regs.riscv_frm;
    }
    bx_poly_clear_trap_saved_regs(&bx_poly_trap_saved_regs);
  }
  if (bx_poly_last_trap.reason == BX_POLY_TRAP_IMPORT &&
      return_poly_cross_call(bx_poly_current_mode,
        (bx_address) bx_poly_last_trap.next_pc)) {
    bx_poly_clear_trap_saved_regs(&bx_poly_trap_saved_regs);
    BX_INFO(("poly_ud: trap return completed cross return mode=%u result=%llx",
      bx_poly_current_mode, (unsigned long long) RAX));
    return true;
  }

  RIP = bx_poly_last_trap.next_pc;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  BX_INFO(("poly_ud: trap return mode=%u next=%llx result=%llx",
    bx_poly_current_mode, (unsigned long long) RIP, (unsigned long long) RAX));
  return true;
}

bool BX_CPU_C::handle_poly_foreign_syscall(const char *arch_name, const char *trap_name,
  Bit32u syscall_number, Bit32u trap_selector, Bit64u arg0, Bit64u arg1,
  Bit64u arg2, Bit64u arg3, Bit64u arg4, Bit64u arg5, Bit64u arg6,
  Bit64u arg7, bx_address next_rip)
{
  // Hardware/FPGA contract: capture an OS-neutral trap packet and hand it to
  // the architectural trap path. Linux syscall translation is guest policy.
  bx_poly_record_syscall_trap(bx_poly_current_mode, syscall_number, trap_selector,
    RIP, next_rip, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  return deliver_poly_architectural_trap(arch_name, trap_name, RIP);
}

bool BX_CPU_C::handle_poly_break_trap(const char *arch_name, const char *trap_name,
  Bit32u break_id, Bit32u trap_selector, bx_address trap_pc, bx_address next_rip)
{
  Bit64u trap_arg0 = RAX;
  Bit64u trap_arg1 = 0;
  Bit64u trap_arg2 = 0;
  Bit64u trap_arg3 = 0;
  Bit64u trap_arg4 = 0;
  Bit64u trap_arg5 = 0;
  Bit64u trap_arg6 = 0;
  Bit64u trap_arg7 = 0;

  if (bx_poly_current_mode == BX_POLY_MODE_RAW_AARCH64) {
    if (!read_poly_aarch64_reg(0, &trap_arg0) ||
        !read_poly_aarch64_reg(1, &trap_arg1) ||
        !read_poly_aarch64_reg(2, &trap_arg2) ||
        !read_poly_aarch64_reg(3, &trap_arg3) ||
        !read_poly_aarch64_reg(4, &trap_arg4) ||
        !read_poly_aarch64_reg(5, &trap_arg5) ||
        !read_poly_aarch64_reg(6, &trap_arg6) ||
        !read_poly_aarch64_reg(7, &trap_arg7))
      return false;
  }
  else if (bx_poly_current_mode == BX_POLY_MODE_RAW_RISCV) {
    if (!read_poly_riscv_reg(10, &trap_arg0) ||
        !read_poly_riscv_reg(11, &trap_arg1) ||
        !read_poly_riscv_reg(12, &trap_arg2) ||
        !read_poly_riscv_reg(13, &trap_arg3) ||
        !read_poly_riscv_reg(14, &trap_arg4) ||
        !read_poly_riscv_reg(15, &trap_arg5) ||
        !read_poly_riscv_reg(16, &trap_arg6) ||
        !read_poly_riscv_reg(17, &trap_arg7))
      return false;
  }

  // Hardware/FPGA contract: BRK/EBREAK is an OS-neutral breakpoint trap exit.
  // Runtime helper ids are guest policy, not CPU semantics.
  bx_poly_record_break_trap(bx_poly_current_mode, break_id, trap_selector,
    trap_pc, next_rip, trap_arg0, trap_arg1, trap_arg2, trap_arg3,
    trap_arg4, trap_arg5, trap_arg6, trap_arg7);
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
    bx_poly_current_state_key(RSP));
  return deliver_poly_architectural_trap(arch_name, trap_name, trap_pc);
}

bool BX_CPP_AttrRegparmN(1) BX_CPU_C::handle_poly_opcode(bxInstruction_c *i)
{
  (void) i;

  if (!BX_CPU_THIS_PTR poly_feature_enabled)
    return false;

  if (CPL != 3) {
    BX_INFO(("poly_ud: reject CPL=%u", CPL));
    return false;
  }

  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_current_state_key(RSP));

  Bit8u opcode0 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP);
  Bit8u opcode1 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 1);
  Bit8u opcode2 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 2);
  Bit8u opcode3 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 3);
  Bit8u opcode_m1 = 0;
  Bit8u opcode_m2 = 0;
  if (PREV_RIP > 0)
    opcode_m1 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP - 1);
  if (PREV_RIP > 1)
    opcode_m2 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP - 2);

  BX_DEBUG(("poly_op: bytes=%02x %02x %02x %02x prev=%02x prev2=%02x",
    opcode0, opcode1, opcode2, opcode3, opcode_m1, opcode_m2));

  if (opcode0 == 0x0f && opcode1 == 0x3a && opcode2 == 0xfc) {
    Bit8u op = opcode3;
    bx_address next_rip = PREV_RIP + 4;
      if (op == 0x00 || op == 0x01 || op == 0x02 || op == 0x03) {
        Bit32u target_mode = BX_POLY_MODE_X86;
        if (op == 0x00) {
          target_mode = BX_POLY_MODE_X86;
        }
        else if (op == 0x01) {
          target_mode = BX_POLY_MODE_RAW_AARCH64;
        }
        else if (op == 0x02) {
          target_mode = BX_POLY_MODE_RAW_RISCV;
        }
        else {
          Bit32u frontend_id = (Bit32u) R15;
          if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode)) {
            BX_INFO(("poly_ud: reject generic frontend id=%u", frontend_id));
            return false;
          }
        }
        bx_poly_current_mode = target_mode;
        if (target_mode == BX_POLY_MODE_X86)
          bx_poly_clear_cross_return_stack();
        bx_poly_set_tls_base_for_mode(target_mode, (bx_address) R13);
        bx_poly_mode_switch_count++;
        // A frontend switch changes the decoder, not the architectural thread
        // state. New per-thread banks are zero-initialized when allocated; an
        // explicit ENTER must preserve any existing foreign registers so
        // exported/imported state can resume correctly.
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_current_state_key(RSP));
        bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_current_state_key(RSP));
        BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
        RIP = next_rip;
        BX_DEBUG(("poly_op: x86 poly opcode op=0x%02x mode switch to %u",
          op, target_mode));
        return true;
      }
      if (op == 0x04) {
        Bit32u frontend_id = (Bit32u) R15;
        Bit32u target_mode = BX_POLY_MODE_X86;
        bx_address target_rip = (bx_address) RBX;
        if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode)) {
          BX_INFO(("poly_ud: reject generic switch frontend=%u", frontend_id));
          return false;
        }
        if (!bx_poly_require_landing_target(BX_SEG_REG_CS, target_rip,
              target_mode, BX_POLY_LANDING_POLICY_REQUIRE_SWITCH,
              "x86-pswitch"))
          return false;
        bx_poly_current_mode = target_mode;
        if (target_mode == BX_POLY_MODE_X86)
          bx_poly_clear_cross_return_stack();
        bx_poly_set_tls_base_for_mode(target_mode, (bx_address) R13);
        bx_poly_mode_switch_count++;
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_current_state_key(RSP));
        bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_current_state_key(RSP));
        BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
        RIP = target_rip;
        BX_DEBUG(("poly_op: x86 poly opcode pswitch frontend=%u mode=%u target=%llx",
          frontend_id, target_mode, (unsigned long long) target_rip));
        return true;
      }
      if (op == 0x05) {
        RIP = next_rip;
        BX_DEBUG(("poly_op: x86 landing pad"));
        return true;
      }
      if (op == 0x10)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x11)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_RISCV,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x12)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, true,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x13)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_RISCV,
          (bx_address) R10, (bx_address) R11, true,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x14)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_FPAIR32, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x15)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_RISCV,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_FPAIR32, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x16)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_FPAIR32);
      if (op == 0x17)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_RISCV,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_FPAIR32);
      if (op == 0x18)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_HETERO_U64_F64,
          BX_POLY_ARG_KIND_HETERO_U64_F64);
      if (op == 0x19)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_HETERO_F64_U64,
          BX_POLY_ARG_KIND_HETERO_F64_U64);
      if (op == 0x1a)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_HETERO_U64_F32,
          BX_POLY_ARG_KIND_HETERO_U64_F32);
      if (op == 0x1b)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_HETERO_F32_U64,
          BX_POLY_ARG_KIND_HETERO_F32_U64);
      if (op == 0x1c)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_RISCV,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_COMPACT_U32_F32,
          BX_POLY_ARG_KIND_COMPACT_U32_F32);
      if (op == 0x1d)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_RISCV,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_COMPACT_F32_U32,
          BX_POLY_ARG_KIND_COMPACT_F32_U32);
      if (op == 0x1e)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_FP64_STACK);
      if (op == 0x1f)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_RISCV,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_FP64_STACK);
      if (op == 0x21)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_VEC128_U32, BX_POLY_ARG_KIND_VEC128_U32);
      if (op == 0x22)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_RISCV,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_VEC128_U32, BX_POLY_ARG_KIND_VEC128_U32);
      if (op == 0x23)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_AARCH64_HFA3_F64, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x24)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_AARCH64_HFA4_F64, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x25)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_AARCH64_HFA3_F32, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x26)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_AARCH64_HFA4_F32, BX_POLY_ARG_KIND_DEFAULT);
      if (op == 0x27)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_AARCH64_HFA3_F64);
      if (op == 0x28)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_AARCH64_HFA4_F64);
      if (op == 0x29)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_AARCH64_HFA3_F32);
      if (op == 0x2a)
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) R10, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_AARCH64_HFA4_F32);
      if (op == 0x2b)
        return enter_poly_abi_signature_call(BX_POLY_MODE_RAW_AARCH64,
          (bx_address) RBX, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_DEFAULT,
          (Bit32u) R12);
      if (op == 0x2c)
        return enter_poly_abi_signature_call(BX_POLY_MODE_RAW_RISCV,
          (bx_address) RBX, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_DEFAULT,
          (Bit32u) R12);
      if (op == 0x2d) {
        Bit32u frontend_id = (Bit32u) R15;
        Bit32u target_mode = BX_POLY_MODE_X86;
        if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode)) {
          BX_INFO(("poly_ud: reject generic pcall frontend=%u", frontend_id));
          return false;
        }
        if (target_mode == BX_POLY_MODE_X86) {
          bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
            bx_poly_current_state_key(RSP));
          Bit32u signature_slot = (Bit32u) R12;
          if (signature_slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT) {
            BX_INFO(("poly_ud: reject generic pcall signature slot=%u",
              signature_slot));
            return false;
          }
          Bit32u source_kind =
            bx_poly_abi_signature_slots[signature_slot].kind;
          return enter_poly_x86_direct_call(BX_POLY_MODE_X86,
            (bx_address) RBX, (bx_address) R11, source_kind);
        }
        if (!bx_poly_is_raw_mode(target_mode)) {
          BX_INFO(("poly_ud: reject generic pcall mode=%u", target_mode));
          return false;
        }
        return enter_poly_abi_signature_call(target_mode,
          (bx_address) RBX, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_DEFAULT,
          (Bit32u) R12);
      }
      if (op == BX_POLY_X86_CTRL_PCALL_SIG_IMM_MODE) {
        Bit8u signature_slot = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 4);
        Bit32u frontend_id = (Bit32u) R15;
        Bit32u target_mode = BX_POLY_MODE_X86;
        if (!bx_poly_frontend_id_to_mode(frontend_id, &target_mode)) {
          BX_INFO(("poly_ud: reject immediate pcall frontend=%u",
            frontend_id));
          return false;
        }
        if (signature_slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT) {
          BX_INFO(("poly_ud: reject immediate pcall signature slot=%u",
            signature_slot));
          return false;
        }
        if (target_mode == BX_POLY_MODE_X86) {
          bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
            bx_poly_current_state_key(RSP));
          Bit32u source_kind =
            bx_poly_abi_signature_slots[signature_slot].kind;
          return enter_poly_x86_direct_call(BX_POLY_MODE_X86,
            (bx_address) RBX, (bx_address) R11, source_kind);
        }
        if (!bx_poly_is_raw_mode(target_mode)) {
          BX_INFO(("poly_ud: reject immediate pcall mode=%u", target_mode));
          return false;
        }
        return enter_poly_abi_signature_call(target_mode,
          (bx_address) RBX, (bx_address) R11, false,
          BX_POLY_RETURN_KIND_DEFAULT, BX_POLY_ARG_KIND_DEFAULT,
          signature_slot);
      }
      if (op == 0x20)
        return return_poly_import_x86_call();
      if (op == 0x60) {
        bx_poly_trap_vector = (bx_address) RAX;
        bx_address stack_key = bx_poly_current_state_key(RSP);
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          stack_key);
        bx_poly_propagate_trap_vector_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          stack_key);
        RIP = next_rip;
        BX_INFO(("poly_ud: trap vector set to %llx",
          (unsigned long long) bx_poly_trap_vector));
        return true;
      }
      if (op == 0x61) {
        RAX = bx_poly_trap_vector;
        RIP = next_rip;
        BX_INFO(("poly_ud: trap vector get value=%llx",
          (unsigned long long) RAX));
        return true;
      }
      if (op == 0x62)
        return return_poly_architectural_trap();
      if (op == 0x63) {
        if (!bx_poly_valid_frontend_mode((Bit32u) RAX)) {
          BX_INFO(("poly_ud: reject trap vector mode=%llu",
            (unsigned long long) RAX));
          RAX = (Bit64u) -22;
          RIP = next_rip;
          return true;
        }
        bx_poly_trap_vector_mode = (Bit32u) RAX;
        bx_address stack_key = bx_poly_current_state_key(RSP);
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          stack_key);
        bx_poly_propagate_trap_vector_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          stack_key);
        RIP = next_rip;
        BX_INFO(("poly_ud: trap vector mode set to %u",
          bx_poly_trap_vector_mode));
        return true;
      }
      if (op == 0x64) {
        RAX = bx_poly_trap_vector_mode;
        RIP = next_rip;
        BX_INFO(("poly_ud: trap vector mode get value=%llu",
          (unsigned long long) RAX));
        return true;
      }
      if (op == 0x6b) {
        bx_poly_monitor_packet_addr = (bx_address) RAX;
        bx_address stack_key = bx_poly_current_state_key(RSP);
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          stack_key);
        bx_poly_propagate_trap_vector_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          stack_key);
        RIP = next_rip;
        BX_INFO(("poly_ud: monitor packet address set to %llx",
          (unsigned long long) bx_poly_monitor_packet_addr));
        return true;
      }
      if (op == 0x6c) {
        RAX = bx_poly_monitor_packet_addr;
        RIP = next_rip;
        BX_INFO(("poly_ud: monitor packet address get value=%llx",
          (unsigned long long) RAX));
        return true;
      }
      if (op == 0x65 || op == 0x66) {
        BX_INFO(("poly_ud: reject reserved explicit state-key op=%02x", op));
        return false;
      }
      if (op == 0x67) {
        bx_address buffer = (bx_address) RAX;
        if (!export_poly_xsave_state(BX_SEG_REG_DS, buffer))
          return false;
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_current_state_key(RSP));
        RIP = next_rip;
        BX_INFO(("poly_ud: exported poly state buffer=%llx",
          (unsigned long long) buffer));
        return true;
      }
      if (op == 0x68) {
        bx_address buffer = (bx_address) RAX;
        if (!import_poly_xsave_state(BX_SEG_REG_DS, buffer)) {
          exception(BX_UD_EXCEPTION, 0);
          return true;
        }
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_current_state_key(RSP));
        bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_current_state_key(RSP));
        RIP = next_rip;
        BX_INFO(("poly_ud: imported poly state buffer=%llx",
          (unsigned long long) buffer));
        return true;
      }
      if (op == 0x69) {
        Bit32u slot = (Bit32u) RAX;
        Bit32u kind = (Bit32u) RDX;
        bx_address stack_key = bx_poly_current_state_key(RSP);
        bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
        if (slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT ||
            !bx_poly_valid_abi_signature_kind(kind)) {
          RAX = (Bit64u) -22;
          RIP = next_rip;
          BX_INFO(("poly_ud: reject ABI signature set slot=%u kind=%u",
            slot, kind));
          return true;
        }
        bx_poly_abi_signature_slots[slot].kind = kind;
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
        RAX = 0;
        RIP = next_rip;
        BX_INFO(("poly_ud: ABI signature set slot=%u kind=%u",
          slot, kind));
        return true;
      }
      if (op == 0x6a) {
        Bit32u slot = (Bit32u) RAX;
        bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_current_state_key(RSP));
        if (slot >= BX_POLY_ABI_SIGNATURE_SLOT_COUNT) {
          RAX = (Bit64u) -22;
          RIP = next_rip;
          BX_INFO(("poly_ud: reject ABI signature get slot=%u", slot));
          return true;
        }
        RAX = bx_poly_abi_signature_slots[slot].kind;
        RIP = next_rip;
        BX_INFO(("poly_ud: ABI signature get slot=%u kind=%llu",
          slot, (unsigned long long) RAX));
        return true;
      }
      if (op == BX_POLY_X86_CTRL_LANDING_POLICY_SET) {
        Bit64u policy = RAX;
        if (!bx_poly_valid_landing_policy(policy)) {
          RAX = (Bit64u) -22;
          RIP = next_rip;
          BX_INFO(("poly_ud: reject landing policy set value=%llx",
            (unsigned long long) policy));
          return true;
        }
        bx_poly_landing_policy_flags = policy;
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_current_state_key(RSP));
        RAX = 0;
        RIP = next_rip;
        BX_INFO(("poly_ud: landing policy set value=%llx",
          (unsigned long long) policy));
        return true;
      }
      if (op == BX_POLY_X86_CTRL_LANDING_POLICY_GET) {
        RAX = bx_poly_landing_policy_flags;
        RIP = next_rip;
        BX_INFO(("poly_ud: landing policy get value=%llx",
          (unsigned long long) RAX));
        return true;
      }
      if (op >= 0x30 && op <= 0x32) {
        Bit8u status_id = op - 0x30;
        if (status_id == 1)
          RAX = bx_poly_last_syscall_number;
        else if (status_id == 2)
          RAX = bx_poly_last_syscall_mode;
        else
          RAX = bx_poly_current_mode;
        RIP = next_rip;
        BX_INFO(("poly_ud: syscall status op=0x%02x id=%u current_mode=%u last_mode=%u number=%u",
          op, status_id, bx_poly_current_mode, bx_poly_last_syscall_mode,
          bx_poly_last_syscall_number));
        return true;
      }
      if (op >= 0x38 && op <= 0x3a) {
        Bit8u status_id = op - 0x38;
        if (status_id == 1)
          RAX = bx_poly_last_break_number;
        else if (status_id == 2)
          RAX = bx_poly_last_break_mode;
        else
          RAX = 0x4c000000 | (bx_poly_current_mode << 8) | status_id;
        RIP = next_rip;
        BX_INFO(("poly_ud: break status op=0x%02x id=%u current_mode=%u last_mode=%u number=%u",
          op, status_id, bx_poly_current_mode, bx_poly_last_break_mode,
          bx_poly_last_break_number));
        return true;
      }
      if (op >= 0x40 && op <= 0x44) {
        Bit8u status_id = op - 0x40;
        if (status_id == 0)
          RAX = bx_poly_mode_switch_count;
        else if (status_id == 2)
          RAX = bx_poly_foreign_insn_count;
        else if (status_id == 3)
          RAX = bx_poly_foreign_syscall_count;
        else if (status_id == 4)
          RAX = bx_poly_foreign_break_count;
        else
          RAX = bx_poly_current_mode;
        RIP = next_rip;
        BX_INFO(("poly_ud: switch status op=0x%02x id=%u mode=%u switches=%llu foreign_insns=%llu syscalls=%llu breaks=%llu",
          op, status_id, bx_poly_current_mode,
          (unsigned long long) bx_poly_mode_switch_count,
          (unsigned long long) bx_poly_foreign_insn_count,
          (unsigned long long) bx_poly_foreign_syscall_count,
          (unsigned long long) bx_poly_foreign_break_count));
        return true;
      }
      if (op >= 0x50 && op <= 0x5d) {
        Bit8u status_id = op - 0x50;
        if (status_id == 0)
          RAX = bx_poly_last_trap.reason;
        else if (status_id == 1)
          RAX = bx_poly_last_trap.mode;
        else if (status_id == 2)
          RAX = bx_poly_last_trap.number;
        else if (status_id >= 3 && status_id <= 8)
          RAX = bx_poly_last_trap.args[status_id - 3];
        else if (status_id == 9)
          RAX = bx_poly_last_trap.pc;
        else if (status_id == 10)
          RAX = bx_poly_last_trap.selector;
        else if (status_id == 12 || status_id == 13)
          RAX = bx_poly_last_trap.args[status_id - 6];
        else
          RAX = bx_poly_last_trap.next_pc;
        RIP = next_rip;
        BX_INFO(("poly_ud: trap status op=0x%02x id=%u reason=%u mode=%u number=%u selector=%u pc=%llx next=%llx",
          op, status_id, bx_poly_last_trap.reason, bx_poly_last_trap.mode,
          bx_poly_last_trap.number, bx_poly_last_trap.selector,
          (unsigned long long) bx_poly_last_trap.pc,
          (unsigned long long) bx_poly_last_trap.next_pc));
        return true;
      }
  }

  BX_INFO(("poly_op: reject non-poly opcode bytes=%02x %02x %02x %02x",
    opcode0, opcode1, opcode2, opcode3));
  return false;
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::NOP(bxInstruction_c *i)
{
  // No operation.

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::PAUSE(bxInstruction_c *i)
{
#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest)
    VMexit_PAUSE();
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT0_PAUSE)) SvmInterceptPAUSE();
  }
#endif

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::PREFETCH(bxInstruction_c *i)
{
#if BX_INSTRUMENTATION
  BX_INSTR_PREFETCH_HINT(BX_CPU_ID, i->src(), i->seg(), BX_CPU_RESOLVE_ADDR(i));
#endif

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::CPUID(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 4

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    VMexit(VMX_VMEXIT_CPUID, 0);
  }
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT0_CPUID)) Svm_Vmexit(SVM_VMEXIT_CPUID);
  }
#endif

#if BX_INSTRUMENTATION
  BX_INSTR_CPUID(BX_CPU_ID);
#endif

  struct cpuid_function_t leaf;
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE) {
    RAX = BX_POLY_CPUID_MAX;
    RBX = 0x796c6f50; // "Poly"
    RDX = 0x746f6c67; // "glot"
    RCX = 0x21555043; // "CPU!"
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 1) {
    Bit32u feature_mask =
          BX_POLY_CPUID_FEATURE_RAW_AARCH64 |
          BX_POLY_CPUID_FEATURE_RAW_RISCV |
          BX_POLY_CPUID_FEATURE_NEUTRAL_SWITCH |
          BX_POLY_CPUID_FEATURE_NATIVE_RET |
          BX_POLY_CPUID_FEATURE_PCALL_SYSV |
          BX_POLY_CPUID_FEATURE_PCALL_SRET |
          BX_POLY_CPUID_FEATURE_FP_BRIDGE |
          BX_POLY_CPUID_FEATURE_TRAP_RECORDS |
          BX_POLY_CPUID_FEATURE_USER_RETURN_RESTORE |
          BX_POLY_CPUID_FEATURE_X86_TSO |
          BX_POLY_CPUID_FEATURE_GENERIC_FRONTEND_IDS |
          BX_POLY_CPUID_FEATURE_X86_POLY_OPCODES |
          BX_POLY_CPUID_FEATURE_FPAIR32_RET |
          BX_POLY_CPUID_FEATURE_FPAIR32_ARG |
          BX_POLY_CPUID_FEATURE_HETERO_U64_F64 |
          BX_POLY_CPUID_FEATURE_HETERO_F64_U64 |
          BX_POLY_CPUID_FEATURE_HETERO_U64_F32 |
          BX_POLY_CPUID_FEATURE_HETERO_F32_U64 |
          BX_POLY_CPUID_FEATURE_COMPACT_U32_F32 |
          BX_POLY_CPUID_FEATURE_COMPACT_F32_U32 |
          BX_POLY_CPUID_FEATURE_NEUTRAL_COMPACT |
          BX_POLY_CPUID_FEATURE_TRAP_VECTOR |
          BX_POLY_CPUID_FEATURE_VEC128_BRIDGE |
          BX_POLY_CPUID_FEATURE_AARCH64_HFA64_RET |
          BX_POLY_CPUID_FEATURE_AARCH64_HFA32_RET |
          BX_POLY_CPUID_FEATURE_AARCH64_HFA_ARGS |
          BX_POLY_CPUID_FEATURE_FOREIGN_PCALL_SIG_IMM;
    RAX = 1; // poly CPUID ABI version
    RBX = (1U << BX_POLY_MODE_X86) |
          (1U << BX_POLY_MODE_RAW_AARCH64) |
          (1U << BX_POLY_MODE_RAW_RISCV);
    RCX = feature_mask;
    RDX = BX_POLY_STATE_XSAVE_COMPONENT_ARCH;
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 2) {
    if (ECX == 0) {
      RAX = BX_POLY_AARCH64_CTRL_X86_ESCAPE;
      RBX = BX_POLY_AARCH64_CTRL_RISCV_SWITCH;
      RCX = BX_POLY_RISCV_CTRL_X86_ESCAPE;
      RDX = BX_POLY_RISCV_CTRL_AARCH64_SWITCH;
    }
    else if (ECX == 1) {
      RAX = BX_POLY_AARCH64_CTRL_RISCV_CALL;
      RBX = BX_POLY_RISCV_CTRL_AARCH64_CALL;
      RCX = BX_POLY_AARCH64_CTRL_RISCV_CALL_COMPACT_U32_F32;
      RDX = BX_POLY_RISCV_CTRL_AARCH64_CALL_COMPACT_U32_F32;
    }
    else if (ECX == 2) {
      RAX = BX_POLY_IMPORT_FUNC_X86_SLOT0;
      RBX = BX_POLY_IMPORT_FUNC_X86_SLOT7 - BX_POLY_IMPORT_FUNC_X86_SLOT0 + 1;
      RCX = 0;
      RDX = (Bit32u) BX_POLY_IMPORT_CALL_STRIDE;
    }
    else if (ECX == 3) {
      RAX = BX_POLY_AARCH64_CTRL_RISCV_CALL_COMPACT_F32_U32;
      RBX = BX_POLY_RISCV_CTRL_AARCH64_CALL_COMPACT_F32_U32;
      RCX = 0;
      RDX = 0;
    }
    else if (ECX == 4) {
      RAX = BX_POLY_AARCH64_CTRL_TRAP_RETURN;
      RBX = BX_POLY_RISCV_CTRL_TRAP_RETURN;
      RCX = BX_POLY_AARCH64_CTRL(BX_POLY_AARCH64_CTRL_SUBOP_CALL_SIG_IMM_BASE +
        BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS_VEC128_U32);
      RDX = BX_POLY_RISCV_CTRL(BX_POLY_RISCV_CTRL_SUBOP_CALL_SIG_IMM_BASE +
        BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS_VEC128_U32);
    }
    else if (ECX == 5) {
      RAX = BX_POLY_IMPORT_CALL_COUNT;
      RBX = (Bit32u) (BX_POLY_IMPORT_CALL_BASE & 0xffffffff);
      RCX = (Bit32u) (BX_POLY_IMPORT_CALL_BASE >> 32);
      RDX = (Bit32u) BX_POLY_IMPORT_CALL_STRIDE;
    }
    else if (ECX == 6) {
      RAX = BX_POLY_AARCH64_CTRL_SWITCH_MODE;
      RBX = BX_POLY_RISCV_CTRL_SWITCH_MODE;
      RCX = BX_POLY_AARCH64_CTRL_CALL_MODE;
      RDX = BX_POLY_RISCV_CTRL_CALL_MODE;
    }
    else if (ECX == 7) {
      RAX = BX_POLY_X86_CTRL_PCALL_SIG_IMM_MODE;
      RBX = BX_POLY_ABI_SIGNATURE_SLOT_COUNT;
      RCX = BX_POLY_ABI_SIGNATURE_SLOT_EXCHANGE |
        (BX_POLY_ABI_SIGNATURE_SLOT_X86_SYSV_REGS << 8) |
        (BX_POLY_ABI_SIGNATURE_SLOT_X86_SYSV_REGS_I128 << 16) |
        (BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS << 24);
      RDX = BX_POLY_ABI_SIGNATURE_KIND_EXCHANGE |
        (BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS << 8) |
        (BX_POLY_ABI_SIGNATURE_KIND_X86_SYSV_REGS_I128 << 16) |
        (BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS << 24);
    }
    else if (ECX == 8) {
      RAX = BX_POLY_AARCH64_CTRL_CALL_SIG_MODE;
      RBX = BX_POLY_RISCV_CTRL_CALL_SIG_MODE;
      RCX = BX_POLY_ABI_SIGNATURE_SLOT_COUNT;
      RDX = 0;
    }
    else if (ECX == 9) {
      RAX = 0x05;
      RBX = BX_POLY_AARCH64_CTRL_LANDING;
      RCX = BX_POLY_RISCV_CTRL_LANDING;
      RDX = 0;
    }
    else if (ECX == 10) {
      RAX = BX_POLY_AARCH64_CTRL_ABI_SIGNATURE_SET;
      RBX = BX_POLY_AARCH64_CTRL_ABI_SIGNATURE_GET;
      RCX = BX_POLY_RISCV_CTRL_ABI_SIGNATURE_SET;
      RDX = BX_POLY_RISCV_CTRL_ABI_SIGNATURE_GET;
    }
    else if (ECX == 11) {
      RAX = BX_POLY_AARCH64_CTRL(BX_POLY_AARCH64_CTRL_SUBOP_CALL_SIG_IMM_BASE);
      RBX = BX_POLY_RISCV_CTRL(BX_POLY_RISCV_CTRL_SUBOP_CALL_SIG_IMM_BASE);
      RCX = BX_POLY_ABI_SIGNATURE_SLOT_COUNT;
      RDX = 0;
    }
    else if (ECX == 12) {
      RAX = BX_POLY_AARCH64_CTRL_TRAP_VECTOR_SET;
      RBX = BX_POLY_AARCH64_CTRL_MONITOR_PACKET_SET;
      RCX = BX_POLY_RISCV_CTRL_TRAP_VECTOR_SET;
      RDX = BX_POLY_RISCV_CTRL_MONITOR_PACKET_SET;
    }
    else if (ECX == 13) {
      RAX = BX_POLY_AARCH64_CTRL_TRAP_VECTOR_GET;
      RBX = BX_POLY_AARCH64_CTRL_TRAP_VECTOR_MODE_SET;
      RCX = BX_POLY_AARCH64_CTRL_TRAP_VECTOR_MODE_GET;
      RDX = BX_POLY_AARCH64_CTRL_MONITOR_PACKET_GET;
    }
    else if (ECX == 14) {
      RAX = BX_POLY_RISCV_CTRL_TRAP_VECTOR_GET;
      RBX = BX_POLY_RISCV_CTRL_TRAP_VECTOR_MODE_SET;
      RCX = BX_POLY_RISCV_CTRL_TRAP_VECTOR_MODE_GET;
      RDX = BX_POLY_RISCV_CTRL_MONITOR_PACKET_GET;
    }
    else if (ECX == 15) {
      RAX = BX_POLY_X86_CTRL_LANDING_POLICY_SET;
      RBX = BX_POLY_X86_CTRL_LANDING_POLICY_GET;
      RCX = BX_POLY_AARCH64_CTRL_LANDING_POLICY_SET;
      RDX = BX_POLY_AARCH64_CTRL_LANDING_POLICY_GET;
    }
    else if (ECX == 16) {
      RAX = BX_POLY_RISCV_CTRL_LANDING_POLICY_SET;
      RBX = BX_POLY_RISCV_CTRL_LANDING_POLICY_GET;
      RCX = (Bit32u) BX_POLY_LANDING_POLICY_SUPPORTED;
      RDX = BX_POLY_STATE_XSAVE_LANDING_POLICY_OFFSET;
    }
    else if (ECX == 17) {
      RAX = BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS_I128;
      RBX = BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_I128;
      RCX = BX_POLY_ABI_SIGNATURE_SLOT_NATIVE_REGS_VEC128_U32;
      RDX = BX_POLY_ABI_SIGNATURE_KIND_NATIVE_REGS_VEC128_U32;
    }
    else {
      RAX = 0;
      RBX = 0;
      RCX = 0;
      RDX = 0;
    }
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 3) {
    RAX = bx_poly_state_contract_flags();
    RBX = 0;
    RCX = BX_POLY_STATE_XSAVE_COMPONENT_ARCH;
    RDX = BX_POLY_STATE_XSAVE_BYTES_ARCH;
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 4) {
    RAX = BX_POLY_STATE_XSAVE_COMPONENT_ARCH;
    RBX = BX_POLY_STATE_XSAVE_BYTES_ARCH;
    RCX = BX_POLY_STATE_XSAVE_LAYOUT_VERSION |
          (BX_POLY_STATE_XSAVE_ALIGN_ARCH << 16);
    RDX = bx_poly_xsave_arch_flags();
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 5) {
    RAX = BX_POLY_TRAP_PACKET_LAYOUT_VERSION;
    RBX = BX_POLY_TRAP_PACKET_HEADER_BYTES;
    RCX = BX_POLY_TRAP_PACKET_ARG_COUNT;
    RDX = BX_POLY_TRAP_PACKET_FLAG_VECTOR_DELIVERY |
          BX_POLY_TRAP_PACKET_FLAG_NO_VECTOR_X86_EXCEPTIONS |
          BX_POLY_TRAP_PACKET_FLAG_TRAP_RETURN_RESTORE |
          BX_POLY_TRAP_PACKET_FLAG_ALL_FRONTEND_HANDLERS |
          BX_POLY_TRAP_PACKET_FLAG_STATUS_OPS |
          BX_POLY_TRAP_PACKET_FLAG_MONITOR_MEMORY;
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 6) {
    RAX = BX_POLY_INTERRUPT_ABI_VERSION;
    RBX = BX_POLY_INTERRUPT_FLAG_RAW_CPL3_ONLY |
          BX_POLY_INTERRUPT_FLAG_STANDARD_X86_ENTRY |
          BX_POLY_INTERRUPT_FLAG_STATE_COMPONENT_SAVE |
          BX_POLY_INTERRUPT_FLAG_PRECISE_FOREIGN_PC |
          BX_POLY_INTERRUPT_FLAG_EVENT_CHECK_BETWEEN_INSNS;
    RCX = BX_POLY_INTERRUPT_RETURN_IRET64 |
          BX_POLY_INTERRUPT_RETURN_SYSRET |
          BX_POLY_INTERRUPT_RETURN_SYSEXIT |
          BX_POLY_INTERRUPT_RETURN_SIGNAL;
    RDX = (1U << BX_POLY_MODE_RAW_AARCH64) |
          (1U << BX_POLY_MODE_RAW_RISCV);
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 7) {
    RAX = BX_POLY_MEMORY_ABI_VERSION;
    RBX = BX_POLY_MEMORY_MODEL_X86_TSO;
    RCX = BX_POLY_MEMORY_FLAG_SHARED_X86_MEMORY |
          BX_POLY_MEMORY_FLAG_AARCH64_BARRIERS_NOOP |
          BX_POLY_MEMORY_FLAG_RISCV_FENCES_NOOP |
          BX_POLY_MEMORY_FLAG_ATOMICS_COHERENT |
          BX_POLY_MEMORY_FLAG_NO_WEAK_REORDERING;
    RDX = (1U << BX_POLY_MODE_RAW_AARCH64) |
          (1U << BX_POLY_MODE_RAW_RISCV);
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 8) {
    if (ECX == 0) {
      RAX = BX_POLY_TRANSITION_ABI_VERSION;
      RBX = BX_POLY_TRANSITION_FLAG_DECODED_X86_OPCODES |
            BX_POLY_TRANSITION_FLAG_NATIVE_RAW_ESCAPES |
            BX_POLY_TRANSITION_FLAG_PIPELINE_FLUSH |
            BX_POLY_TRANSITION_FLAG_BLOCK_BOUNDARY |
            BX_POLY_TRANSITION_FLAG_PRECISE_NEXT_PC |
            BX_POLY_TRANSITION_FLAG_FIXED_RAW_WIDTH |
            BX_POLY_TRANSITION_FLAG_NEUTRAL_FOREIGN |
            BX_POLY_TRANSITION_FLAG_NATIVE_RETURN_COOKIE |
            BX_POLY_TRANSITION_FLAG_TRAP_RETURN |
            BX_POLY_TRANSITION_FLAG_INTERRUPTED_RAW |
            BX_POLY_TRANSITION_FLAG_LANDING_PADS |
            BX_POLY_TRANSITION_FLAG_LANDING_POLICY;
      RCX = BX_POLY_TRANSITION_AARCH64_ALIGN |
            (BX_POLY_TRANSITION_RISCV_ALIGN << 16);
      RDX = (1U << BX_POLY_MODE_X86) |
            (1U << BX_POLY_MODE_RAW_AARCH64) |
            (1U << BX_POLY_MODE_RAW_RISCV);
    }
    else if (ECX == 1) {
      RAX = BX_POLY_FRONTEND_X86;
      RBX = BX_POLY_FRONTEND_AARCH64;
      RCX = BX_POLY_FRONTEND_RISCV;
      RDX = (1U << BX_POLY_FRONTEND_X86) |
            (1U << BX_POLY_FRONTEND_AARCH64) |
            (1U << BX_POLY_FRONTEND_RISCV);
    }
    else {
      RAX = 0;
      RBX = 0;
      RCX = 0;
      RDX = 0;
    }
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 9) {
    RAX = BX_POLY_ABI_BRIDGE_ABI_VERSION;
    RBX = BX_POLY_ABI_BRIDGE_FLAG_X86_SYSV_TO_AAPCS64 |
          BX_POLY_ABI_BRIDGE_FLAG_X86_SYSV_TO_RISCV |
          BX_POLY_ABI_BRIDGE_FLAG_SRET |
          BX_POLY_ABI_BRIDGE_FLAG_SCALAR_FP |
          BX_POLY_ABI_BRIDGE_FLAG_FOCUSED_AGGREGATES |
          BX_POLY_ABI_BRIDGE_FLAG_TLS_BASE |
          BX_POLY_ABI_BRIDGE_FLAG_NO_CPU_HELPER_FALLBACK |
          BX_POLY_ABI_BRIDGE_FLAG_ORDINARY_X86_RET |
          BX_POLY_ABI_BRIDGE_FLAG_VEC128 |
          BX_POLY_ABI_BRIDGE_FLAG_REGISTER_SIGNATURES |
          BX_POLY_ABI_BRIDGE_FLAG_NATIVE_I128_SIGNATURES;
    RCX = BX_POLY_ABI_BRIDGE_GPR_ARG_COUNT |
          (BX_POLY_ABI_BRIDGE_FP_ARG_COUNT << 8) |
          (BX_POLY_ABI_BRIDGE_STACK_ALIGN << 16);
    RDX = (Bit32u) BX_POLY_IMPORT_CALL_STRIDE << 16;
    BX_NEXT_INSTR(i);
    return;
  }

  BX_CPU_THIS_PTR cpuid->get_cpuid_leaf(EAX, ECX, &leaf);

  RAX = leaf.eax;
  RBX = leaf.ebx;
  RCX = leaf.ecx;
  RDX = leaf.edx;
#endif

  BX_NEXT_INSTR(i);
}

//
// The shutdown state is very similar to the state following the exection
// if HLT instruction. In this mode the processor stops executing
// instructions until #NMI, #SMI, #RESET or #INIT is received. If
// shutdown occurs why in NMI interrupt handler or in SMM, a hardware
// reset must be used to restart the processor execution.
//
void BX_CPU_C::shutdown(void)
{
#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT0_SHUTDOWN)) Svm_Vmexit(SVM_VMEXIT_SHUTDOWN);
  }
#endif

  enter_sleep_state(BX_ACTIVITY_STATE_SHUTDOWN);

  longjmp(BX_CPU_THIS_PTR jmp_buf_env, 1); // go back to main decode loop
}

void BX_CPU_C::enter_sleep_state(unsigned state)
{
  switch(state) {
  case BX_ACTIVITY_STATE_ACTIVE:
    BX_ASSERT(0); // should not be used for entering active CPU state
    break;

  case BX_ACTIVITY_STATE_HLT:
    break;

  case BX_ACTIVITY_STATE_WAIT_FOR_SIPI:
    mask_event(BX_EVENT_INIT | BX_EVENT_SMI | BX_EVENT_NMI); // FIXME: all events should be masked
    // fall through - mask interrupts as well

  case BX_ACTIVITY_STATE_SHUTDOWN:
    BX_CPU_THIS_PTR clear_IF(); // masking interrupts
    break;

  case BX_ACTIVITY_STATE_MWAIT:
  case BX_ACTIVITY_STATE_MWAIT_IF:
    break;

  default:
    BX_PANIC(("enter_sleep_state: unknown state %d", state));
  }

  // artificial trap bit, why use another variable.
  BX_CPU_THIS_PTR activity_state = state;
  BX_CPU_THIS_PTR async_event = 1; // so processor knows to check
  // Execution completes.  The processor will remain in a sleep
  // state until one of the wakeup conditions is met.

  BX_INSTR_HLT(BX_CPU_ID);

#if BX_DEBUGGER
  if (bx_dbg.debugger_active)
    bx_dbg_halt(BX_CPU_ID);
#endif

#if BX_USE_IDLE_HACK
  bx_gui->sim_is_idle();
#endif
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::HLT(bxInstruction_c *i)
{
  // CPL is always 0 in real mode
  if (/* !real_mode() && */ CPL!=0) {
    BX_DEBUG(("HLT: %s priveledge check failed, CPL=%d, generate #GP(0)",
        cpu_mode_string(BX_CPU_THIS_PTR cpu_mode), CPL));
    exception(BX_GP_EXCEPTION, 0);
  }

  if (! BX_CPU_THIS_PTR get_IF()) {
#if BX_SUPPORT_SMP
    if (BX_CPU_THIS_PTR msr.apicbase & 0x100) // warn for BSP only
#endif
      BX_WARN(("[CPU%d] HLT instruction with IF=0!", BX_CPU_ID));
  }

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (BX_CPU_THIS_PTR vmcs.vmexec_ctrls1.HLT_VMEXIT()) {
      VMexit(VMX_VMEXIT_HLT, 0);
    }
  }
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT0_HLT)) Svm_Vmexit(SVM_VMEXIT_HLT);
  }
#endif

  // stops instruction execution and places the processor in a
  // HALT state. An enabled interrupt, NMI, or reset will resume
  // execution. If interrupt (including NMI) is used to resume
  // execution after HLT, the saved CS:eIP points to instruction
  // following HLT.
  enter_sleep_state(BX_ACTIVITY_STATE_HLT);

  BX_NEXT_TRACE(i);
}

/* 0F 08 */
void BX_CPP_AttrRegparmN(1) BX_CPU_C::INVD(bxInstruction_c *i)
{
  // CPL is always 0 in real mode
  if (/* !real_mode() && */ CPL!=0) {
    BX_ERROR(("%s: priveledge check failed, generate #GP(0)", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    VMexit(VMX_VMEXIT_INVD, 0);
  }
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT0_INVD)) Svm_Vmexit(SVM_VMEXIT_INVD);
  }
#endif

  invalidate_prefetch_q();

  BX_DEBUG(("INVD: Flush internal caches !"));
  BX_INSTR_CACHE_CNTRL(BX_CPU_ID, BX_INSTR_INVD);

  flushICaches();

  BX_NEXT_TRACE(i);
}

/* 0F 09 */
void BX_CPP_AttrRegparmN(1) BX_CPU_C::WBINVD(bxInstruction_c *i)
{
  // CPL is always 0 in real mode
  if (/* !real_mode() && */ CPL!=0) {
    BX_ERROR(("%s: priveledge check failed, generate #GP(0)", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (BX_CPU_THIS_PTR vmcs.vmexec_ctrls2.WBINVD_VMEXIT())
      VMexit(VMX_VMEXIT_WBINVD, 0);
  }
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT1_WBINVD)) Svm_Vmexit(SVM_VMEXIT_WBINVD);
  }
#endif

//invalidate_prefetch_q();

  BX_DEBUG(("WBINVD: WB-Invalidate internal caches !"));
  BX_INSTR_CACHE_CNTRL(BX_CPU_ID, BX_INSTR_WBINVD);

//flushICaches();

  BX_NEXT_TRACE(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::CLFLUSH(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  bx_address laddr;

  // CLFLUSH performs all the segmentation and paging checks that a 1-byte read would perform,
  // except that it also allows references to execute-only segments.
#if BX_SUPPORT_X86_64
  if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64)
    laddr = get_laddr64(i->seg(), eaddr);
  else
#endif
    laddr = agen_read_execute32(i->seg(), (Bit32u)eaddr, 1);

  tickle_read_linear(i->seg(), laddr);

  BX_INSTR_CLFLUSH(BX_CPU_ID, laddr, BX_CPU_THIS_PTR address_xlation.paddress1);

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::CLZERO(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  bx_address eaddr = RAX & ~BX_CONST64(CACHE_LINE_SIZE-1) & i->asize_mask();

  BxPackedZmmRegister zmmzero; // zmm is always made available even if EVEX is not compiled in
  zmmzero.clear();
  for (unsigned n=0; n<CACHE_LINE_SIZE; n += 64) {
    write_virtual_zmmword(i->seg(), eaddr+n, &zmmzero);
  }
#endif

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVDIR64B(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6

  BxPackedZmmRegister zmm; // zmm is always made available even if EVEX is not compiled in
  bx_address src_eaddr = BX_CPU_RESOLVE_ADDR(i);
  read_virtual_zmmword(i->seg(), src_eaddr, &zmm);

#if BX_SUPPORT_X86_64
  bx_address dst_eaddr = BX_READ_64BIT_REG(i->dst());
#else
  bx_address dst_eaddr = BX_READ_32BIT_REG(i->dst());
#endif
  write_virtual_zmmword_aligned(BX_SEG_REG_ES, dst_eaddr & i->asize_mask(), &zmm);

#endif

  BX_NEXT_INSTR(i);
}

void BX_CPU_C::handleCpuModeChange(void)
{
  unsigned mode = BX_CPU_THIS_PTR cpu_mode;

#if BX_SUPPORT_X86_64
  if (BX_CPU_THIS_PTR efer.get_LMA()) {
    if (! BX_CPU_THIS_PTR cr0.get_PE()) {
      BX_PANIC(("change_cpu_mode: EFER.LMA is set when CR0.PE=0 !"));
    }
    if (BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.l) {
      BX_CPU_THIS_PTR cpu_mode = BX_MODE_LONG_64;
    }
    else {
      BX_CPU_THIS_PTR cpu_mode = BX_MODE_LONG_COMPAT;
      // clear upper part of RIP/RSP when leaving 64-bit long mode
      BX_CLEAR_64BIT_HIGH(BX_64BIT_REG_RIP);
      BX_CLEAR_64BIT_HIGH(BX_64BIT_REG_RSP);
    }

    // switching between compatibility and long64 mode also affect SS.BASE
    // which is always zero in long64 mode
    invalidate_stack_cache();
  }
  else
#endif
  {
    if (BX_CPU_THIS_PTR cr0.get_PE()) {
      if (BX_CPU_THIS_PTR get_VM()) {
        BX_CPU_THIS_PTR cpu_mode = BX_MODE_IA32_V8086;
        CPL = 3;
      }
      else
        BX_CPU_THIS_PTR cpu_mode = BX_MODE_IA32_PROTECTED;
    }
    else {
      BX_CPU_THIS_PTR cpu_mode = BX_MODE_IA32_REAL;

      // CS segment in real mode always allows full access
      BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.p        = 1;
      BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.segment  = 1;  /* data/code segment */
      BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.type = BX_DATA_READ_WRITE_ACCESSED;

      CPL = 0;
    }
  }

  updateFetchModeMask();

#if BX_CPU_LEVEL >= 6
#if BX_SUPPORT_AVX
  handleAvxModeChange(); /* protected mode reloaded */
#endif
#endif

  // re-initialize protection keys
#if BX_SUPPORT_PKEYS
  set_PKeys(BX_CPU_THIS_PTR pkru, BX_CPU_THIS_PTR pkrs);
#endif

#if BX_DEBUGGER
  if (bx_dbg.debugger_active) {
    // assert magic async_event to stop trace execution
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  }
#endif

  if (mode != BX_CPU_THIS_PTR cpu_mode) {
    BX_DEBUG(("%s activated", cpu_mode_string(BX_CPU_THIS_PTR cpu_mode)));
#if BX_DEBUGGER
    if (bx_dbg.debugger_active) {
      if (BX_CPU_THIS_PTR mode_break) {
        BX_CPU_THIS_PTR stop_reason = STOP_MODE_BREAK_POINT;
        bx_debug_break(); // trap into debugger
      }
    }
#endif
  }
}

#if BX_CPU_LEVEL >= 4
void BX_CPU_C::handleAlignmentCheck(void)
{
  if (CPL == 3 && BX_CPU_THIS_PTR cr0.get_AM() && BX_CPU_THIS_PTR get_AC()) {
#if BX_SUPPORT_ALIGNMENT_CHECK == 0
    BX_PANIC(("WARNING: Alignment check (#AC exception) was not compiled in !"));
#else
    BX_CPU_THIS_PTR alignment_check_mask = 0xF;
#endif
  }
#if BX_SUPPORT_ALIGNMENT_CHECK
  else {
    BX_CPU_THIS_PTR alignment_check_mask = 0;
  }
#endif
}
#endif

void BX_CPU_C::handleFpuMmxModeChange(void)
{
  if (BX_CPU_THIS_PTR cr0.get_EM() || BX_CPU_THIS_PTR cr0.get_TS())
    clear_fpu_mmx_ok();
  else
    set_fpu_mmx_ok();

  updateFetchModeMask(); /* FPU_MMX_OK changed */
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxProtectedModeRequired(bxInstruction_c *i)
{
  if (! protected_mode())
    exception(BX_UD_EXCEPTION, 0);

  BX_ASSERT(0);

  BX_NEXT_TRACE(i); // keep compiler happy
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxNoFPU(bxInstruction_c *i)
{
  if (BX_CPU_THIS_PTR cr0.get_EM() || BX_CPU_THIS_PTR cr0.get_TS())
    exception(BX_NM_EXCEPTION, 0);

  BX_ASSERT(0);

  BX_NEXT_TRACE(i); // keep compiler happy
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxNoMMX(bxInstruction_c *i)
{
  if(BX_CPU_THIS_PTR cr0.get_EM())
    exception(BX_UD_EXCEPTION, 0);

  if(BX_CPU_THIS_PTR cr0.get_TS())
    exception(BX_NM_EXCEPTION, 0);

  BX_ASSERT(0);

  BX_NEXT_TRACE(i); // keep compiler happy
}

#if BX_CPU_LEVEL >= 6
void BX_CPU_C::handleSseModeChange(void)
{
  if(BX_CPU_THIS_PTR cr0.get_TS()) {
    clear_sse_ok();
  }
  else {
    if(BX_CPU_THIS_PTR cr0.get_EM() || !BX_CPU_THIS_PTR cr4.get_OSFXSR())
      clear_sse_ok();
    else
      set_sse_ok();
  }

  updateFetchModeMask(); /* SSE_OK changed */
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxNoSSE(bxInstruction_c *i)
{
  if(BX_CPU_THIS_PTR cr0.get_EM() || !BX_CPU_THIS_PTR cr4.get_OSFXSR())
    exception(BX_UD_EXCEPTION, 0);

  if(BX_CPU_THIS_PTR cr0.get_TS())
    exception(BX_NM_EXCEPTION, 0);

  BX_ASSERT(0);

  BX_NEXT_TRACE(i); // keep compiler happy
}

#if BX_SUPPORT_AVX
void BX_CPU_C::handleAvxModeChange(void)
{
  if (BX_CPU_THIS_PTR cr0.get_TS()) {
    clear_avx_ok();
  }
  else {
    if (! protected_mode() || ! BX_CPU_THIS_PTR cr4.get_OSXSAVE() ||
        (~BX_CPU_THIS_PTR xcr0.get32() & (BX_XCR0_SSE_MASK | BX_XCR0_YMM_MASK)) != 0) {
      clear_avx_ok();
    }
    else {
      set_avx_ok();

#if BX_SUPPORT_EVEX
      if ((~BX_CPU_THIS_PTR xcr0.get32() & BX_XCR0_OPMASK_MASK) != 0) {
        clear_opmask_ok();
        clear_evex_ok();
      }
      else {
        set_opmask_ok();

        if ((~BX_CPU_THIS_PTR xcr0.get32() & (BX_XCR0_ZMM_HI256_MASK | BX_XCR0_HI_ZMM_MASK)) != 0)
          clear_evex_ok();
        else
          set_evex_ok();
      }
#endif
    }
  }

#if BX_SUPPORT_AMX
  if (! long64_mode() || ! BX_CPU_THIS_PTR cr4.get_OSXSAVE() ||
      (~BX_CPU_THIS_PTR xcr0.get32() & (BX_XCR0_XTILECFG_MASK | BX_XCR0_XTILEDATA_MASK)) != 0)
    clear_amx_ok();
  else
    set_amx_ok();
#endif

  updateFetchModeMask(); /* AVX_OK changed */
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxNoAVX(bxInstruction_c *i)
{
  if (! protected_mode() || ! BX_CPU_THIS_PTR cr4.get_OSXSAVE())
    exception(BX_UD_EXCEPTION, 0);

  if (~BX_CPU_THIS_PTR xcr0.get32() & (BX_XCR0_SSE_MASK | BX_XCR0_YMM_MASK))
    exception(BX_UD_EXCEPTION, 0);

  if(BX_CPU_THIS_PTR cr0.get_TS())
    exception(BX_NM_EXCEPTION, 0);

  BX_ASSERT(0);

  BX_NEXT_TRACE(i); // keep compiler happy
}
#endif

#if BX_SUPPORT_EVEX
void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxNoOpMask(bxInstruction_c *i)
{
  if (! protected_mode() || ! BX_CPU_THIS_PTR cr4.get_OSXSAVE())
    exception(BX_UD_EXCEPTION, 0);

  if (~BX_CPU_THIS_PTR xcr0.get32() & (BX_XCR0_SSE_MASK | BX_XCR0_YMM_MASK | BX_XCR0_OPMASK_MASK))
    exception(BX_UD_EXCEPTION, 0);

  if(BX_CPU_THIS_PTR cr0.get_TS())
    exception(BX_NM_EXCEPTION, 0);

  BX_ASSERT(0);

  BX_NEXT_TRACE(i); // keep compiler happy
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxNoEVEX(bxInstruction_c *i)
{
  if (! protected_mode() || ! BX_CPU_THIS_PTR cr4.get_OSXSAVE())
    exception(BX_UD_EXCEPTION, 0);

  if (~BX_CPU_THIS_PTR xcr0.get32() & (BX_XCR0_SSE_MASK | BX_XCR0_YMM_MASK | BX_XCR0_OPMASK_MASK | BX_XCR0_ZMM_HI256_MASK | BX_XCR0_HI_ZMM_MASK))
    exception(BX_UD_EXCEPTION, 0);

  if(BX_CPU_THIS_PTR cr0.get_TS())
    exception(BX_NM_EXCEPTION, 0);

  BX_ASSERT(0);

  BX_NEXT_TRACE(i); // keep compiler happy
}
#endif

#if BX_SUPPORT_AMX
void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxNoAMX(bxInstruction_c *i)
{
  if (! long64_mode() || ! BX_CPU_THIS_PTR cr4.get_OSXSAVE())
    exception(BX_UD_EXCEPTION, 0);

  if (~BX_CPU_THIS_PTR xcr0.get32() & (BX_XCR0_XTILECFG_MASK | BX_XCR0_XTILEDATA_MASK))
    exception(BX_UD_EXCEPTION, 0);

  BX_ASSERT(0);

  BX_NEXT_TRACE(i); // keep compiler happy
}
#endif

#endif

void BX_CPU_C::handleCpuContextChange(void)
{
  TLB_flush();

  invalidate_prefetch_q();
  invalidate_stack_cache();

  handleInterruptMaskChange();

#if BX_CPU_LEVEL >= 4
  handleAlignmentCheck();
#endif

  handleCpuModeChange();

  handleFpuMmxModeChange();
#if BX_CPU_LEVEL >= 6
  handleSseModeChange();
#if BX_SUPPORT_AVX
  handleAvxModeChange();
#endif
#endif

#if BX_SUPPORT_X86_64
  BX_CPU_THIS_PTR linaddr_width = BX_CPU_THIS_PTR cr4.get_LA57() ? 57 : 48;
#endif
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDPMC(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 5
  // in real mode CPL=0
  if (! BX_CPU_THIS_PTR cr4.get_PCE() && CPL != 0 /* && protected_mode() */) {
    BX_ERROR(("%s: not allowed to use instruction !", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest)  {
    if (BX_CPU_THIS_PTR vmcs.vmexec_ctrls1.RDPMC_VMEXIT()) {
      VMexit(VMX_VMEXIT_RDPMC, 0);
    }
  }
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT0_RDPMC)) Svm_Vmexit(SVM_VMEXIT_RDPMC);
  }
#endif

  /* According to manual, Pentium 4 has 18 counters,
   * previous versions have two.  And the P4 also can do
   * short read-out (EDX always 0).  Otherwise it is
   * limited to 40 bits.
   */

  if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_SSE2)) { // Pentium 4 processor (see cpuid.cc)
    if ((ECX & 0x7fffffff) >= 18)
      exception(BX_GP_EXCEPTION, 0);
  }
  else {
    if ((ECX & 0xffffffff) >= 2)
      exception(BX_GP_EXCEPTION, 0);
  }

  // Most counters are for hardware specific details, which
  // we anyhow do not emulate (like pipeline stalls etc)

  // Could be interesting to count number of memory reads,
  // writes.  Misaligned etc...  But to monitor bochs, this
  // is easier done from the host.

  RAX = 0;
  RDX = 0; // if P4 and ECX & 0x10000000, then always 0 (short read 32 bits)

  BX_ERROR(("RDPMC: Performance Counters Support not implemented yet"));
#endif

  BX_NEXT_INSTR(i);
}

#if BX_CPU_LEVEL >= 5

#include "wide_int.h"

Bit64u BX_CPU_C::get_TSC(void)
{
  Bit64u tsc = bx_pc_system.time_ticks() + BX_CPU_THIS_PTR tsc_adjust;
  return tsc;
}

Bit64u BX_CPU_C::get_Virtual_TSC()
{
  Bit64u tsc = BX_CPU_THIS_PTR get_TSC();
#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (BX_CPU_THIS_PTR vmcs.vmexec_ctrls1.TSC_OFFSET() && BX_CPU_THIS_PTR vmcs.vmexec_ctrls2.TSC_SCALING()) {
      // RDTSC first computes the product of the value of the IA32_TIME_STAMP_COUNTER MSR and
      // the value of the TSC multiplier. It then shifts the value of the product right 48 bits and loads 
      // EAX:EDX with <the sum of that shifted value and the value of the TSC offset>.
      Bit128u product_128;
      long_mul(&product_128,tsc,BX_CPU_THIS_PTR vmcs.tsc_multiplier);
      tsc = (product_128.lo >> 48) | (product_128.hi << 16);   // tsc = (uint64) (long128(tsc_value * tsc_multiplier) >> 48);
    }
  }
#endif
#if BX_SUPPORT_VMX || BX_SUPPORT_SVM
  tsc += BX_CPU_THIS_PTR tsc_offset;    // BX_CPU_THIS_PTR tsc_offset = 0 if not in VMX or SVM guest
#endif
  return tsc;
}

#if BX_SUPPORT_VMX
Bit64u BX_CPU_C::compute_physical_TSC_delay(Bit64u tsc_delay)
{
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (BX_CPU_THIS_PTR vmcs.vmexec_ctrls1.TSC_OFFSET() && BX_CPU_THIS_PTR vmcs.vmexec_ctrls2.TSC_SCALING()) {
      // The virtual delay is multiplied by 2^48 (using a shift) to produce a 128-bit 
      // integer. That product is then divided by the TSC multiplier to produce a 64-bit integer.
      // The physical delay is that quotient.
      Bit128u product128, quotient;
      product128.hi = tsc_delay >> 16;
      product128.lo = tsc_delay << 48;
      long_div(&quotient, &tsc_delay /*just use it as temp to be destroyed*/, &product128, BX_CPU_THIS_PTR vmcs.tsc_multiplier);
      BX_ASSERT(quotient.hi == 0);
      tsc_delay = quotient.lo;                // tsc = Bit128(tsc_value << 48) / tsc_multiplier
    }
  }
  return tsc_delay;
}
#endif

void BX_CPU_C::set_TSC(Bit64u newval)
{
  // compute the correct setting of tsc_adjust so that a get_TSC()
  // will return newval
  BX_CPU_THIS_PTR tsc_adjust = newval - bx_pc_system.time_ticks();

  // verify
  BX_ASSERT(get_TSC() == newval);
}

#endif // BX_CPU_LEVEL >= 5

void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDTSC(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 5
  if (BX_CPU_THIS_PTR cr4.get_TSD() && CPL != 0) {
    BX_ERROR(("%s: not allowed to use instruction !", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (BX_CPU_THIS_PTR vmcs.vmexec_ctrls1.RDTSC_VMEXIT()) {
      VMexit(VMX_VMEXIT_RDTSC, 0);
    }
  }
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest)
    if (SVM_INTERCEPT(SVM_INTERCEPT0_RDTSC)) Svm_Vmexit(SVM_VMEXIT_RDTSC);
#endif

  Bit64u ticks = BX_CPU_THIS_PTR get_Virtual_TSC();

  RAX = GET32L(ticks);
  RDX = GET32H(ticks);

  BX_DEBUG(("RDTSC: ticks 0x%08x:%08x", EDX, EAX));
#endif

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDTSCP(bxInstruction_c *i)
{
#if BX_SUPPORT_X86_64

#if BX_SUPPORT_VMX
  // RDTSCP will always #UD in legacy VMX mode, the #UD takes priority over any other exception the instruction may incur.
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (! BX_CPU_THIS_PTR vmcs.vmexec_ctrls2.RDTSCP()) {
       BX_ERROR(("%s in VMX guest: not allowed to use instruction !", i->getIaOpcodeNameShort()));
       exception(BX_UD_EXCEPTION, 0);
    }
  }
#endif

  if (BX_CPU_THIS_PTR cr4.get_TSD() && CPL != 0) {
    BX_ERROR(("%s: not allowed to use instruction !", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (BX_CPU_THIS_PTR vmcs.vmexec_ctrls1.RDTSC_VMEXIT()) {
      VMexit(VMX_VMEXIT_RDTSCP, 0);
    }
  }
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest)
    if (SVM_INTERCEPT(SVM_INTERCEPT1_RDTSCP)) Svm_Vmexit(SVM_VMEXIT_RDTSCP);
#endif

  Bit64u ticks = BX_CPU_THIS_PTR get_Virtual_TSC();

  RAX = GET32L(ticks);
  RDX = GET32H(ticks);
  RCX = BX_CPU_THIS_PTR msr.tsc_aux;

#endif

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDPID_Ed(bxInstruction_c *i)
{
#if BX_SUPPORT_X86_64

#if BX_SUPPORT_VMX
  // RDTSCP will always #UD in legacy VMX mode
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (! BX_CPU_THIS_PTR vmcs.vmexec_ctrls2.RDTSCP()) {
       BX_ERROR(("%s in VMX guest: not allowed to use instruction !", i->getIaOpcodeNameShort()));
       exception(BX_UD_EXCEPTION, 0);
    }
  }
#endif

  BX_WRITE_32BIT_REGZ(i->dst(), BX_CPU_THIS_PTR msr.tsc_aux);
#endif

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::SYSENTER(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  if (real_mode()) {
    BX_ERROR(("%s: not recognized in real mode !", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }

#if BX_SUPPORT_FRED
  if (BX_CPU_THIS_PTR cr4.get_FRED()) {
    set_fred_event_info_and_data(BX_EVENT_SYSENTER, BX_EVENT_OTHER, false, i->ilen());
    FRED_EventDelivery(BX_EVENT_SYSENTER, BX_EVENT_OTHER, 0);
    BX_NEXT_TRACE(i);
  }
#endif

  if ((BX_CPU_THIS_PTR msr.sysenter_cs_msr & BX_SELECTOR_RPL_MASK) == 0) {
    BX_ERROR(("SYSENTER with zero sysenter_cs_msr !"));
    exception(BX_GP_EXCEPTION, 0);
  }

  invalidate_prefetch_q();

  BX_INSTR_FAR_BRANCH_ORIGIN();

  BX_CPU_THIS_PTR clear_VM();       // do this just like the book says to do
  BX_CPU_THIS_PTR clear_IF();
  BX_CPU_THIS_PTR clear_RF();

#if BX_SUPPORT_X86_64
  if (long_mode()) {
    if (!IsCanonical(BX_CPU_THIS_PTR msr.sysenter_eip_msr)) {
      BX_ERROR(("SYSENTER with non-canonical SYSENTER_EIP_MSR !"));
      exception(BX_GP_EXCEPTION, 0);
    }
    if (!IsCanonical(BX_CPU_THIS_PTR msr.sysenter_esp_msr)) {
      BX_ERROR(("SYSENTER with non-canonical SYSENTER_ESP_MSR !"));
      exception(BX_GP_EXCEPTION, 0);
    }
  }
#endif

#if BX_SUPPORT_CET
  if (ShadowStackEnabled(CPL))
    BX_CPU_THIS_PTR msr.ia32_pl_ssp[3] = SSP;
  if (ShadowStackEnabled(0)) SSP = 0;
  track_indirect(0);
#endif

  parse_selector(BX_CPU_THIS_PTR msr.sysenter_cs_msr & BX_SELECTOR_RPL_MASK,
                       &BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector);

  setup_flat_CS(0, long_mode());

  parse_selector((BX_CPU_THIS_PTR msr.sysenter_cs_msr + 8) & BX_SELECTOR_RPL_MASK,
                       &BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].selector);

  setup_flat_SS(0);

#if BX_SUPPORT_X86_64
  if (long_mode()) {
    RSP = BX_CPU_THIS_PTR msr.sysenter_esp_msr;
    RIP = BX_CPU_THIS_PTR msr.sysenter_eip_msr;
  }
  else
#endif
  {
    ESP = (Bit32u) BX_CPU_THIS_PTR msr.sysenter_esp_msr;
    EIP = (Bit32u) BX_CPU_THIS_PTR msr.sysenter_eip_msr;
  }

  BX_INSTR_FAR_BRANCH(BX_CPU_ID, BX_INSTR_IS_SYSENTER,
                      FAR_BRANCH_PREV_CS, FAR_BRANCH_PREV_RIP,
                      BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, RIP);
#endif

  BX_NEXT_TRACE(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::SYSEXIT(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6

#if BX_SUPPORT_X86_64 && BX_SUPPORT_FRED
  if (BX_CPU_THIS_PTR cr4.get_FRED()) {
    BX_ERROR(("%s: Not supported when FRED is enabled in CR4", i->getIaOpcodeNameShort()));
    exception(BX_UD_EXCEPTION, 0);
  }
#endif

  if (real_mode() || CPL != 0) {
    BX_ERROR(("SYSEXIT from real mode or with CPL<>0 !"));
    exception(BX_GP_EXCEPTION, 0);
  }
  if ((BX_CPU_THIS_PTR msr.sysenter_cs_msr & BX_SELECTOR_RPL_MASK) == 0) {
    BX_ERROR(("SYSEXIT with zero sysenter_cs_msr !"));
    exception(BX_GP_EXCEPTION, 0);
  }

  invalidate_prefetch_q();

#if BX_SUPPORT_MONITOR_MWAIT
  BX_CPU_THIS_PTR monitor.reset_umonitor();
#endif

  BX_INSTR_FAR_BRANCH_ORIGIN();

#if BX_SUPPORT_X86_64
  if (i->os64L()) {
    if (!IsCanonical(RDX)) {
       BX_ERROR(("SYSEXIT with non-canonical RDX (RIP) pointer !"));
       exception(BX_GP_EXCEPTION, 0);
    }
    if (!IsCanonical(RCX)) {
       BX_ERROR(("SYSEXIT with non-canonical RCX (RSP) pointer !"));
       exception(BX_GP_EXCEPTION, 0);
    }

    parse_selector(((BX_CPU_THIS_PTR msr.sysenter_cs_msr + 32) & BX_SELECTOR_RPL_MASK) | 3,
            &BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector);

    setup_flat_CS(3, true); // CPL3, long mode

    RSP = RCX;
    RIP = RDX;
  }
  else
#endif
  {
    parse_selector(((BX_CPU_THIS_PTR msr.sysenter_cs_msr + 16) & BX_SELECTOR_RPL_MASK) | 3,
            &BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector);

    setup_flat_CS(3, false); // CPL3, 32-bit mode

    ESP = ECX;
    EIP = EDX;
  }

  parse_selector(((BX_CPU_THIS_PTR msr.sysenter_cs_msr + (i->os64L() ? 40:24)) & BX_SELECTOR_RPL_MASK) | 3,
            &BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].selector);

  setup_flat_SS(3);

#if BX_SUPPORT_CET
  if (ShadowStackEnabled(CPL))
    SSP = BX_CPU_THIS_PTR msr.ia32_pl_ssp[3];
#endif

  poly_sysexit_return_to_user();

  BX_INSTR_FAR_BRANCH(BX_CPU_ID, BX_INSTR_IS_SYSEXIT,
                      FAR_BRANCH_PREV_CS, FAR_BRANCH_PREV_RIP,
                      BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, RIP);
#endif

  BX_NEXT_TRACE(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::SYSCALL(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 5
  bx_address temp_RIP;

  BX_DEBUG(("Execute SYSCALL instruction"));

  if (!BX_CPU_THIS_PTR efer.get_SCE()) {
    exception(BX_UD_EXCEPTION, 0);
  }

  invalidate_prefetch_q();

  BX_INSTR_FAR_BRANCH_ORIGIN();

#if BX_SUPPORT_FRED
  if (BX_CPU_THIS_PTR cr4.get_FRED()) {
    set_fred_event_info_and_data(BX_EVENT_SYSCALL, BX_EVENT_OTHER, false, i->ilen());
    FRED_EventDelivery(BX_EVENT_SYSENTER, BX_EVENT_OTHER, 0);
    BX_NEXT_TRACE(i);
  }
#endif

#if BX_SUPPORT_CET
  unsigned old_CPL = CPL;
#endif

#if BX_SUPPORT_X86_64
  if (long_mode())
  {
    RCX = RIP;
    R11 = read_eflags() & ~(EFlagsRFMask);

    if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
      temp_RIP = BX_CPU_THIS_PTR msr.lstar;
    }
    else {
      temp_RIP = BX_CPU_THIS_PTR msr.cstar;
    }

    // set up CS segment, flat, 64-bit DPL=0
    parse_selector((BX_CPU_THIS_PTR msr.star >> 32) & BX_SELECTOR_RPL_MASK,
                       &BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector);

    setup_flat_CS(0, true); // CPL0, long mode

    // set up SS segment, flat, 64-bit DPL=0
    parse_selector(((BX_CPU_THIS_PTR msr.star >> 32) + 8) & BX_SELECTOR_RPL_MASK,
                       &BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].selector);

    setup_flat_SS(0);

    writeEFlags(read_eflags() & ~(BX_CPU_THIS_PTR msr.fmask) & ~(EFlagsRFMask), EFlagsValidMask);
    RIP = temp_RIP;
  }
  else
#endif
  {
    // legacy mode

    ECX = EIP;
    temp_RIP = (Bit32u)(BX_CPU_THIS_PTR msr.star);

    // set up CS segment, flat, 32-bit DPL=0
    parse_selector((BX_CPU_THIS_PTR msr.star >> 32) & BX_SELECTOR_RPL_MASK,
                       &BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector);

    setup_flat_CS(0, false); // CPL0, 32-bit mode

    // set up SS segment, flat, 32-bit DPL=0
    parse_selector(((BX_CPU_THIS_PTR msr.star >> 32) + 8) & BX_SELECTOR_RPL_MASK,
                       &BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].selector);

    setup_flat_SS(0);

    BX_CPU_THIS_PTR clear_VM();
    BX_CPU_THIS_PTR clear_IF();
    BX_CPU_THIS_PTR clear_RF();
    RIP = temp_RIP;
  }

#if BX_SUPPORT_CET
  if (ShadowStackEnabled(old_CPL))
    BX_CPU_THIS_PTR msr.ia32_pl_ssp[3] = SSP;
  if (ShadowStackEnabled(0)) SSP = 0;
  track_indirect(0);
#endif

  BX_INSTR_FAR_BRANCH(BX_CPU_ID, BX_INSTR_IS_SYSCALL,
                      FAR_BRANCH_PREV_CS, FAR_BRANCH_PREV_RIP,
                      BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, RIP);
#endif

  BX_NEXT_TRACE(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::SYSRET(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 5

#if BX_SUPPORT_X86_64 && BX_SUPPORT_FRED
  if (BX_CPU_THIS_PTR cr4.get_FRED()) {
    BX_ERROR(("%s: Not supported when FRED is enabled in CR4", i->getIaOpcodeNameShort()));
    exception(BX_UD_EXCEPTION, 0);
  }
#endif

  bx_address temp_RIP;

  BX_DEBUG(("Execute SYSRET instruction"));

  if (!BX_CPU_THIS_PTR efer.get_SCE()) {
    exception(BX_UD_EXCEPTION, 0);
  }

  if(!protected_mode() || CPL != 0) {
    BX_ERROR(("%s: priveledge check failed, generate #GP(0)", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }

  invalidate_prefetch_q();

#if BX_SUPPORT_MONITOR_MWAIT
  BX_CPU_THIS_PTR monitor.reset_umonitor();
#endif

  BX_INSTR_FAR_BRANCH_ORIGIN();

#if BX_SUPPORT_X86_64
  if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64)
  {
    if (i->os64L()) {
      if (!IsCanonical(RCX)) {
        BX_ERROR(("SYSRET: canonical failure for RCX (RIP)"));
        exception(BX_GP_EXCEPTION, 0);
      }

      // Return to 64-bit mode, set up CS segment, flat, 64-bit DPL=3
      parse_selector((((BX_CPU_THIS_PTR msr.star >> 48) + 16) & BX_SELECTOR_RPL_MASK) | 3,
                       &BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector);

      setup_flat_CS(3, true); // CPL3, long mode

      temp_RIP = RCX;
    }
    else {
      // Return to 32-bit compatibility mode, set up CS segment, flat, 32-bit DPL=3
      parse_selector((BX_CPU_THIS_PTR msr.star >> 48) | 3,
                       &BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector);

      setup_flat_CS(3, false); // CPL3, 32-bit mode

      temp_RIP = ECX;
    }

    parse_selector((Bit16u)(((BX_CPU_THIS_PTR msr.star >> 48) + 8) | 3),
                       &BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].selector);

    // SS base, limit, attributes unchanged
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.valid   = SegValidCache | SegAccessROK | SegAccessWOK | SegAccessROK4G | SegAccessWOK4G;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.p       = 1;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.dpl     = 3;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.segment = 1;  /* data/code segment */
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.type    = BX_DATA_READ_WRITE_ACCESSED;

    writeEFlags((Bit32u) R11, EFlagsValidMask);
  }
  else // (!64BIT_MODE)
#endif
  {
    // Return to 32-bit legacy mode, set up CS segment, flat, 32-bit DPL=3
    parse_selector((BX_CPU_THIS_PTR msr.star >> 48) | 3,
                     &BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector);

    setup_flat_CS(3, false); // CPL3, 32-bit mode

    parse_selector((Bit16u)(((BX_CPU_THIS_PTR msr.star >> 48) + 8) | 3),
                     &BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].selector);

    // SS base, limit, attributes unchanged
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.valid   = SegValidCache | SegAccessROK | SegAccessWOK | SegAccessROK4G | SegAccessWOK4G;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.p       = 1;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.dpl     = 3;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.segment = 1;  /* data/code segment */
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.type    = BX_DATA_READ_WRITE_ACCESSED;

    BX_CPU_THIS_PTR assert_IF();
    temp_RIP = ECX;
  }

  RIP = temp_RIP;

#if BX_SUPPORT_CET
  if (ShadowStackEnabled(CPL))
    SSP = BX_CPU_THIS_PTR msr.ia32_pl_ssp[3];
#endif

  poly_sysret_return_to_user();

  BX_INSTR_FAR_BRANCH(BX_CPU_ID, BX_INSTR_IS_SYSRET,
                      FAR_BRANCH_PREV_CS, FAR_BRANCH_PREV_RIP,
                      BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, RIP);
#endif

  BX_NEXT_TRACE(i);
}

#if BX_SUPPORT_X86_64

void BX_CPU_C::swapgs()
{
  Bit64u temp_GS_base = MSR_GSBASE;
  MSR_GSBASE = BX_CPU_THIS_PTR msr.kernelgsbase;
  BX_CPU_THIS_PTR msr.kernelgsbase = temp_GS_base;
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::SWAPGS(bxInstruction_c *i)
{
#if BX_SUPPORT_FRED
  if (BX_CPU_THIS_PTR cr4.get_FRED()) {
    BX_ERROR(("%s: Not supported when FRED is enabled in CR4", i->getIaOpcodeNameShort()));
    exception(BX_UD_EXCEPTION, 0);
  }
#endif

  if(CPL != 0)
    exception(BX_GP_EXCEPTION, 0);

  swapgs();

  BX_NEXT_INSTR(i);
}

/* F3 0F AE /0 */
void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDFSBASE_Ed(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_FSGSBASE())
    exception(BX_UD_EXCEPTION, 0);

  BX_WRITE_32BIT_REGZ(i->dst(), (Bit32u) MSR_FSBASE);
  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDFSBASE_Eq(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_FSGSBASE())
    exception(BX_UD_EXCEPTION, 0);

  BX_WRITE_64BIT_REG(i->dst(), MSR_FSBASE);
  BX_NEXT_INSTR(i);
}

/* F3 0F AE /1 */
void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDGSBASE_Ed(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_FSGSBASE())
    exception(BX_UD_EXCEPTION, 0);

  BX_WRITE_32BIT_REGZ(i->dst(), (Bit32u) MSR_GSBASE);
  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDGSBASE_Eq(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_FSGSBASE())
    exception(BX_UD_EXCEPTION, 0);

  BX_WRITE_64BIT_REG(i->dst(), MSR_GSBASE);
  BX_NEXT_INSTR(i);
}

/* F3 0F AE /2 */
void BX_CPP_AttrRegparmN(1) BX_CPU_C::WRFSBASE_Ed(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_FSGSBASE())
    exception(BX_UD_EXCEPTION, 0);

  // 32-bit value is always canonical
  MSR_FSBASE = BX_READ_32BIT_REG(i->src());

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::WRFSBASE_Eq(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_FSGSBASE())
    exception(BX_UD_EXCEPTION, 0);

  Bit64u fsbase = BX_READ_64BIT_REG(i->src());
  if (!IsCanonical(fsbase)) {
    BX_ERROR(("%s: canonical failure !", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }
  MSR_FSBASE = fsbase;

  BX_NEXT_INSTR(i);
}

/* F3 0F AE /3 */
void BX_CPP_AttrRegparmN(1) BX_CPU_C::WRGSBASE_Ed(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_FSGSBASE())
    exception(BX_UD_EXCEPTION, 0);

  // 32-bit value is always canonical
  MSR_GSBASE = BX_READ_32BIT_REG(i->src());

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::WRGSBASE_Eq(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_FSGSBASE())
    exception(BX_UD_EXCEPTION, 0);

  Bit64u gsbase = BX_READ_64BIT_REG(i->src());
  if (!IsCanonical(gsbase)) {
    BX_ERROR(("%s: canonical failure !", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }
  MSR_GSBASE = gsbase;

  BX_NEXT_INSTR(i);
}

#endif // BX_SUPPORT_X86_64

#if BX_SUPPORT_PKEYS

void BX_CPU_C::set_PKeys(Bit32u pkru_val, Bit32u pkrs_val)
{
  BX_CPU_THIS_PTR pkru = pkru_val;
  BX_CPU_THIS_PTR pkrs = pkrs_val;

  for (unsigned i=0; i<16; i++) {
    BX_CPU_THIS_PTR rd_pkey[i] = BX_CPU_THIS_PTR wr_pkey[i] =
      TLB_SysReadOK | TLB_UserReadOK | TLB_SysWriteOK | TLB_UserWriteOK;

    if (long_mode()) {
      if (BX_CPU_THIS_PTR cr4.get_PKE()) {
        // accessDisable bit set
        if (pkru_val & (1<<(i*2))) {
          BX_CPU_THIS_PTR rd_pkey[i] &= ~(TLB_UserReadOK | TLB_UserWriteOK);
          BX_CPU_THIS_PTR wr_pkey[i] &= ~(TLB_UserReadOK | TLB_UserWriteOK);
        }

        // writeDisable bit set
        if (pkru_val & (1<<(i*2+1))) {
          BX_CPU_THIS_PTR wr_pkey[i] &= ~(TLB_UserWriteOK);
          if (BX_CPU_THIS_PTR cr0.get_WP())
            BX_CPU_THIS_PTR wr_pkey[i] &= ~(TLB_SysWriteOK);
        }
      }

      if (BX_CPU_THIS_PTR cr4.get_PKS()) {
        // accessDisable bit set
        if (pkrs_val & (1<<(i*2))) {
          BX_CPU_THIS_PTR rd_pkey[i] &= ~(TLB_SysReadOK | TLB_SysWriteOK);
          BX_CPU_THIS_PTR wr_pkey[i] &= ~(TLB_SysReadOK | TLB_SysWriteOK);
        }

        // writeDisable bit set
        if (pkrs_val & (1<<(i*2+1))) {
          if (BX_CPU_THIS_PTR cr0.get_WP())
            BX_CPU_THIS_PTR wr_pkey[i] &= ~(TLB_SysWriteOK);
        }
      }
    }

#if BX_SUPPORT_CET
    // replicate pkey access bits for shadow stack checks
    BX_CPU_THIS_PTR rd_pkey[i] |= BX_CPU_THIS_PTR rd_pkey[i]<<4;
    BX_CPU_THIS_PTR wr_pkey[i] |= BX_CPU_THIS_PTR wr_pkey[i]<<4;
#endif
  }
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDPKRU(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_PKE())
    exception(BX_UD_EXCEPTION, 0);

  if (ECX != 0)
    exception(BX_GP_EXCEPTION, 0);

  RAX = BX_CPU_THIS_PTR pkru;
  RDX = 0;

  BX_NEXT_INSTR(i);
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::WRPKRU(bxInstruction_c *i)
{
  if (! BX_CPU_THIS_PTR cr4.get_PKE())
    exception(BX_UD_EXCEPTION, 0);

  if ((ECX|EDX) != 0)
    exception(BX_GP_EXCEPTION, 0);

  BX_CPU_THIS_PTR set_PKeys(EAX, BX_CPU_THIS_PTR pkrs);

  BX_NEXT_TRACE(i);
}

#endif // BX_SUPPORT_PKEYS
