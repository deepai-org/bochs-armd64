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
  BX_POLY_TRAP_NONE = 0,
  BX_POLY_TRAP_SYSCALL = 1,
  BX_POLY_TRAP_BREAK = 2
};

static const Bit32u BX_POLY_AARCH64_BRK_X86_ESCAPE = 0x7fff;
static const Bit32u BX_POLY_AARCH64_BRK_RISCV_SWITCH = 0x7ffe;
static const Bit32u BX_POLY_AARCH64_BRK_RISCV_CALL = 0x7ffd;
static const Bit32u BX_POLY_AARCH64_BRK_RISCV_CALL_COMPACT_U32_F32 = 0x7ffc;
static const Bit32u BX_POLY_AARCH64_BRK_RISCV_CALL_COMPACT_F32_U32 = 0x7ffb;
static const Bit32u BX_POLY_AARCH64_BRK_RISCV_CALL_FP64_STACK = 0x7ffa;
static const Bit32u BX_POLY_RISCV_X86_ESCAPE = 0x0000000b;
static const Bit32u BX_POLY_RISCV_AARCH64_SWITCH = 0x0000002b;
static const Bit32u BX_POLY_RISCV_AARCH64_CALL = 0x0000005b;
static const Bit32u BX_POLY_RISCV_AARCH64_CALL_COMPACT_U32_F32 = 0x0000107b;
static const Bit32u BX_POLY_RISCV_AARCH64_CALL_COMPACT_F32_U32 = 0x0000207b;
static const Bit32u BX_POLY_RISCV_AARCH64_CALL_FP64_STACK = 0x0000307b;
static const Bit32u BX_POLY_CPUID_BASE = 0x40000000;
static const Bit32u BX_POLY_CPUID_MAX = 0x40000003;
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
static const Bit32u BX_POLY_CPUID_FEATURE_COMPAT_TRAPS = (1U << 11);
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
static const Bit32u BX_POLY_CPUID_STATE_OVERLAP_GPRS = (1U << 0);
static const Bit32u BX_POLY_CPUID_STATE_SYNTHETIC_BANKS = (1U << 1);
static const Bit32u BX_POLY_CPUID_STATE_KEY_CR3 = (1U << 2);
static const Bit32u BX_POLY_CPUID_STATE_KEY_FSBASE = (1U << 3);
static const Bit32u BX_POLY_CPUID_STATE_KEY_STACK_REGION = (1U << 4);
static const Bit32u BX_POLY_CPUID_STATE_USER_RETURN_RESTORE = (1U << 5);
static const Bit32u BX_POLY_CPUID_STATE_X86_TSO = (1U << 6);
static const Bit32u BX_POLY_CPUID_STATE_XSAVE_VISIBLE = (1U << 7);
static const Bit32u BX_POLY_STATE_STACK_KEY_SHIFT = 23;
static const Bit64u BX_POLY_RETURN_COOKIE = BX_CONST64(0xfffffffffffff000);
static const Bit64u BX_POLY_CROSS_RETURN_COOKIE = BX_CONST64(0xffffffffffffd000);
static const Bit64u BX_POLY_IMPORT_CALL_BASE = BX_CONST64(0xffffffffffffe000);
static const Bit64u BX_POLY_IMPORT_CALL_STRIDE = BX_CONST64(0x10);
static const Bit64u BX_POLY_IMPORT_X86_ADD_HELPER_SIZE = BX_CONST64(13);
static const Bit64u BX_POLY_IMPORT_X86_DESCRIPTOR_SIZE = BX_CONST64(16);
static const Bit32u BX_POLY_IMPORT_CALL_COUNT = 115;
static const Bit64u BX_POLY_FOREIGN_STACK_GAP = BX_CONST64(0x100);
static const Bit32u BX_POLY_FOREIGN_STACK_ARG_QWORDS = 8;

enum {
  BX_POLY_RETURN_KIND_DEFAULT = 0,
  BX_POLY_RETURN_KIND_FPAIR32 = 1,
  BX_POLY_RETURN_KIND_HETERO_U64_F64 = 2,
  BX_POLY_RETURN_KIND_HETERO_F64_U64 = 3,
  BX_POLY_RETURN_KIND_HETERO_U64_F32 = 4,
  BX_POLY_RETURN_KIND_HETERO_F32_U64 = 5,
  BX_POLY_RETURN_KIND_COMPACT_U32_F32 = 6,
  BX_POLY_RETURN_KIND_COMPACT_F32_U32 = 7
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
  BX_POLY_ARG_KIND_FP64_STACK = 8
};

enum {
  BX_POLY_CROSS_BRIDGE_DEFAULT = 0,
  BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 = 1,
  BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32 = 2,
  BX_POLY_CROSS_BRIDGE_FP64_STACK = 3
};

enum {
  BX_POLY_IMPORT_FUNC_ADD = 0,
  BX_POLY_IMPORT_FUNC_MUL = 1,
  BX_POLY_IMPORT_FUNC_X86_ADD = 2,
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
  BX_POLY_IMPORT_FUNC_STACK_CHK_FAIL = 114
};

static inline bool bx_poly_import_is_x86_descriptor(Bit64u import_id)
{
  return import_id >= BX_POLY_IMPORT_FUNC_X86_SLOT0 &&
    import_id <= BX_POLY_IMPORT_FUNC_X86_SLOT7;
}

static inline bool bx_poly_import_uses_x86_stack_args(Bit64u import_id)
{
  return import_id == BX_POLY_IMPORT_FUNC_X86_SLOT5;
}

enum {
  BX_POLY_AARCH64_ATOMIC_LDADD = 0,
  BX_POLY_AARCH64_ATOMIC_SWP = 1,
  BX_POLY_AARCH64_ATOMIC_LDCLR = 2,
  BX_POLY_AARCH64_ATOMIC_LDEOR = 3,
  BX_POLY_AARCH64_ATOMIC_LDSET = 4,
  BX_POLY_AARCH64_ATOMIC_CAS = 5
};

static bool bx_poly_aarch64_outline_atomic_descriptor(Bit32u import_id,
    Bit32u *op, Bit32u *size, const char **op_name)
{
  switch (import_id) {
    case BX_POLY_IMPORT_FUNC_AARCH64_LDADD8_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDADD;
      *size = 8;
      *op_name = "__aarch64_ldadd8_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDADD4_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDADD;
      *size = 4;
      *op_name = "__aarch64_ldadd4_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDADD2_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDADD;
      *size = 2;
      *op_name = "__aarch64_ldadd2_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDADD1_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDADD;
      *size = 1;
      *op_name = "__aarch64_ldadd1_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_SWP8_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_SWP;
      *size = 8;
      *op_name = "__aarch64_swp8_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_SWP4_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_SWP;
      *size = 4;
      *op_name = "__aarch64_swp4_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_SWP2_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_SWP;
      *size = 2;
      *op_name = "__aarch64_swp2_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_SWP1_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_SWP;
      *size = 1;
      *op_name = "__aarch64_swp1_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDCLR8_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDCLR;
      *size = 8;
      *op_name = "__aarch64_ldclr8_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDCLR4_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDCLR;
      *size = 4;
      *op_name = "__aarch64_ldclr4_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDCLR2_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDCLR;
      *size = 2;
      *op_name = "__aarch64_ldclr2_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDCLR1_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDCLR;
      *size = 1;
      *op_name = "__aarch64_ldclr1_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDEOR8_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDEOR;
      *size = 8;
      *op_name = "__aarch64_ldeor8_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDEOR4_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDEOR;
      *size = 4;
      *op_name = "__aarch64_ldeor4_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDEOR2_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDEOR;
      *size = 2;
      *op_name = "__aarch64_ldeor2_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDEOR1_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDEOR;
      *size = 1;
      *op_name = "__aarch64_ldeor1_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDSET8_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDSET;
      *size = 8;
      *op_name = "__aarch64_ldset8_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDSET4_ACQ_REL:
    case BX_POLY_IMPORT_FUNC_AARCH64_LDSET4_RELAX:
      *op = BX_POLY_AARCH64_ATOMIC_LDSET;
      *size = 4;
      *op_name = "__aarch64_ldset4_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDSET2_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDSET;
      *size = 2;
      *op_name = "__aarch64_ldset2_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_LDSET1_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_LDSET;
      *size = 1;
      *op_name = "__aarch64_ldset1_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_CAS8_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_CAS;
      *size = 8;
      *op_name = "__aarch64_cas8_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_CAS4_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_CAS;
      *size = 4;
      *op_name = "__aarch64_cas4_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_CAS2_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_CAS;
      *size = 2;
      *op_name = "__aarch64_cas2_acq_rel";
      return true;
    case BX_POLY_IMPORT_FUNC_AARCH64_CAS1_ACQ_REL:
      *op = BX_POLY_AARCH64_ATOMIC_CAS;
      *size = 1;
      *op_name = "__aarch64_cas1_acq_rel";
      return true;
    default:
      return false;
  }
}

static Bit64u bx_poly_aarch64_size_mask(Bit32u size)
{
  return size == 8 ? BX_CONST64(0xffffffffffffffff) :
    ((BX_CONST64(1) << (size * 8)) - 1);
}

static const unsigned BX_POLY_REG_STATE_SLOTS = 64;
static const unsigned BX_POLY_CROSS_RETURN_DEPTH = 8;

struct bx_poly_cross_return_frame_t {
  Bit32u caller_mode;
  Bit32u callee_mode;
  Bit32u bridge_kind;
  bx_address return_rip;
};

static Bit32u bx_poly_current_mode = BX_POLY_MODE_X86;
static bx_address bx_poly_raw_owner_cr3 = 0;
static bx_address bx_poly_raw_owner_fsbase = 0;
static bx_address bx_poly_raw_owner_stack_key = 0;
static Bit64u bx_poly_mode_switch_count = 0;
static Bit64u bx_poly_foreign_insn_count = 0;
static Bit64u bx_poly_foreign_syscall_count = 0;
static Bit64u bx_poly_foreign_libcall_count = 0;
static Bit32u bx_poly_last_syscall_mode = BX_POLY_MODE_X86;
static Bit32u bx_poly_last_syscall_number = 0;
static Bit32u bx_poly_last_libcall_mode = BX_POLY_MODE_X86;
static Bit32u bx_poly_last_libcall_number = 0;
static Bit32u bx_poly_last_trap_reason = BX_POLY_TRAP_NONE;
static Bit32u bx_poly_last_trap_mode = BX_POLY_MODE_X86;
static Bit32u bx_poly_last_trap_number = 0;
static bx_address bx_poly_last_trap_pc = 0;
static Bit64u bx_poly_last_trap_args[6];
static bool bx_poly_return_cookie_valid = false;
static Bit32u bx_poly_return_cookie_mode = BX_POLY_MODE_X86;
static bx_address bx_poly_return_cookie_rip = 0;
static bx_address bx_poly_return_cookie_rsp = 0;
static bool bx_poly_return_cookie_sret = false;
static bx_address bx_poly_return_cookie_sret_ptr = 0;
static Bit32u bx_poly_return_cookie_kind = BX_POLY_RETURN_KIND_DEFAULT;
static bx_poly_cross_return_frame_t bx_poly_cross_return_stack[BX_POLY_CROSS_RETURN_DEPTH];
static unsigned bx_poly_cross_return_top = 0;
static bool bx_poly_import_x86_return_valid = false;
static Bit32u bx_poly_import_x86_return_mode = BX_POLY_MODE_X86;
static bx_address bx_poly_import_x86_return_rip = 0;
static bx_address bx_poly_import_x86_return_rsp = 0;
static bool bx_poly_interrupted_raw_valid = false;
static Bit32u bx_poly_interrupted_raw_mode = BX_POLY_MODE_X86;
static bx_address bx_poly_interrupted_raw_rip = 0;
static bx_address bx_poly_foreign_tls_base = 0;
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
static bool bx_poly_riscv_reservation_valid = false;
static bx_address bx_poly_riscv_reservation_addr = 0;
static Bit32u bx_poly_riscv_reservation_size = 0;

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
  bx_poly_cross_return_frame_t cross_return_stack[BX_POLY_CROSS_RETURN_DEPTH];
  unsigned cross_return_top;
  bool import_x86_return_valid;
  Bit32u import_x86_return_mode;
  bx_address import_x86_return_rip;
  bx_address import_x86_return_rsp;
  bool interrupted_raw_valid;
  Bit32u interrupted_raw_mode;
  bx_address interrupted_raw_rip;
  bx_address foreign_tls_base;
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
  bool riscv_reservation_valid;
  bx_address riscv_reservation_addr;
  Bit32u riscv_reservation_size;
};

static bx_poly_reg_state_t bx_poly_reg_states[BX_POLY_REG_STATE_SLOTS];
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

static long double bx_poly_fp128_from_bits(Bit64u lo, Bit64u hi)
{
  union {
    struct {
      Bit64u lo;
      Bit64u hi;
    } bits;
    long double value;
  } fp;
  fp.bits.lo = lo;
  fp.bits.hi = hi;
  return fp.value;
}

static void bx_poly_fp128_to_bits(long double value, Bit64u *lo, Bit64u *hi)
{
  union {
    struct {
      Bit64u lo;
      Bit64u hi;
    } bits;
    long double value;
  } fp;
  fp.value = value;
  *lo = fp.bits.lo;
  *hi = fp.bits.hi;
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

static softfloat_status_t bx_poly_softfloat_status()
{
  softfloat_status_t status = {};
  status.softfloat_roundingMode = softfloat_round_near_even;
  status.softfloat_exceptionMasks = softfloat_all_exceptions_mask;
  status.extF80_roundingPrecision = 80;
  return status;
}

static Bit64u bx_poly_fp64_to_uint64_rtz(double value)
{
  if (!(value > 0.0))
    return 0;
  if (value >= 18446744073709551616.0)
    return BX_CONST64(0xffffffffffffffff);
  return (Bit64u) value;
}

static Bit64u bx_poly_fp128_to_uint64_rtz(long double value)
{
  if (!(value > 0.0L))
    return 0;
  if (value >= 18446744073709551616.0L)
    return BX_CONST64(0xffffffffffffffff);
  return (Bit64u) value;
}

static Bit64u bx_poly_fp128_to_int64_rtz(long double value)
{
  if (value != value)
    return 0;
  if (value >= 9223372036854775808.0L)
    return (Bit64u) BX_MAX_BIT64S;
  if (value <= -9223372036854775808.0L)
    return (Bit64u) BX_MIN_BIT64S;
  return (Bit64u) (Bit64s) value;
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

static Bit32u bx_poly_count_leading_zeros64(Bit64u value)
{
  if (value == 0)
    return 64;
  Bit32u count = 0;
  while ((value & BX_CONST64(0x8000000000000000)) == 0) {
    count++;
    value <<= 1;
  }
  return count;
}

static Bit32u bx_poly_count_trailing_zeros64(Bit64u value)
{
  if (value == 0)
    return 64;
  Bit32u count = 0;
  while ((value & 1) == 0) {
    count++;
    value >>= 1;
  }
  return count;
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

static void bx_poly_aarch64_set_fp64_compare_nzcv(double left, double right)
{
  if (left != left || right != right)
    bx_poly_aarch64_nzcv = 0x3;
  else if (left < right)
    bx_poly_aarch64_nzcv = 0x8;
  else if (left > right)
    bx_poly_aarch64_nzcv = 0x2;
  else
    bx_poly_aarch64_nzcv = 0x6;
}

static void bx_poly_aarch64_set_fp32_compare_nzcv(float left, float right)
{
  if (left != left || right != right)
    bx_poly_aarch64_nzcv = 0x3;
  else if (left < right)
    bx_poly_aarch64_nzcv = 0x8;
  else if (left > right)
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

static void bx_poly_record_trap(Bit32u reason, Bit32u mode, Bit32u number,
  bx_address pc, Bit64u arg0, Bit64u arg1, Bit64u arg2, Bit64u arg3,
  Bit64u arg4, Bit64u arg5)
{
  bx_poly_last_trap_reason = reason;
  bx_poly_last_trap_mode = mode;
  bx_poly_last_trap_number = number;
  bx_poly_last_trap_pc = pc;
  bx_poly_last_trap_args[0] = arg0;
  bx_poly_last_trap_args[1] = arg1;
  bx_poly_last_trap_args[2] = arg2;
  bx_poly_last_trap_args[3] = arg3;
  bx_poly_last_trap_args[4] = arg4;
  bx_poly_last_trap_args[5] = arg5;
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
}

static bx_address bx_poly_stack_key(bx_address rsp)
{
  return rsp & ~BX_CONST64(0x7fffff);
}

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

  for (unsigned n = 0; n < BX_POLY_REG_STATE_SLOTS; n++) {
    if (bx_poly_key_matches(&bx_poly_reg_states[n], cr3, fsbase, stack_key))
      return n;
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
  bx_poly_reg_states[victim].cross_return_top = 0;
  bx_poly_reg_states[victim].import_x86_return_valid = false;
  bx_poly_reg_states[victim].import_x86_return_mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].import_x86_return_rip = 0;
  bx_poly_reg_states[victim].import_x86_return_rsp = 0;
  bx_poly_reg_states[victim].interrupted_raw_valid = false;
  bx_poly_reg_states[victim].interrupted_raw_mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].interrupted_raw_rip = 0;
  bx_poly_reg_states[victim].foreign_tls_base = 0;
  bx_poly_reg_states[victim].aarch64_nzcv = 0;
  bx_poly_reg_states[victim].aarch64_reservation_valid = false;
  bx_poly_reg_states[victim].aarch64_reservation_addr = 0;
  bx_poly_reg_states[victim].aarch64_reservation_size = 0;
  bx_poly_reg_states[victim].riscv_reservation_valid = false;
  bx_poly_reg_states[victim].riscv_reservation_addr = 0;
  bx_poly_reg_states[victim].riscv_reservation_size = 0;
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++) {
    bx_poly_reg_states[victim].cross_return_stack[n].caller_mode = BX_POLY_MODE_X86;
    bx_poly_reg_states[victim].cross_return_stack[n].callee_mode = BX_POLY_MODE_X86;
    bx_poly_reg_states[victim].cross_return_stack[n].bridge_kind = BX_POLY_CROSS_BRIDGE_DEFAULT;
    bx_poly_reg_states[victim].cross_return_stack[n].return_rip = 0;
  }
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

static void bx_poly_save_current_reg_state(bx_address cr3, bx_address fsbase,
  bx_address stack_key)
{
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
  bx_poly_reg_states[slot].cross_return_top = bx_poly_cross_return_top;
  bx_poly_reg_states[slot].import_x86_return_valid = bx_poly_import_x86_return_valid;
  bx_poly_reg_states[slot].import_x86_return_mode = bx_poly_import_x86_return_mode;
  bx_poly_reg_states[slot].import_x86_return_rip = bx_poly_import_x86_return_rip;
  bx_poly_reg_states[slot].import_x86_return_rsp = bx_poly_import_x86_return_rsp;
  bx_poly_reg_states[slot].interrupted_raw_valid = bx_poly_interrupted_raw_valid;
  bx_poly_reg_states[slot].interrupted_raw_mode = bx_poly_interrupted_raw_mode;
  bx_poly_reg_states[slot].interrupted_raw_rip = bx_poly_interrupted_raw_rip;
  bx_poly_reg_states[slot].foreign_tls_base = bx_poly_foreign_tls_base;
  bx_poly_reg_states[slot].aarch64_nzcv = bx_poly_aarch64_nzcv;
  bx_poly_reg_states[slot].aarch64_reservation_valid = bx_poly_aarch64_reservation_valid;
  bx_poly_reg_states[slot].aarch64_reservation_addr = bx_poly_aarch64_reservation_addr;
  bx_poly_reg_states[slot].aarch64_reservation_size = bx_poly_aarch64_reservation_size;
  bx_poly_reg_states[slot].riscv_reservation_valid = bx_poly_riscv_reservation_valid;
  bx_poly_reg_states[slot].riscv_reservation_addr = bx_poly_riscv_reservation_addr;
  bx_poly_reg_states[slot].riscv_reservation_size = bx_poly_riscv_reservation_size;
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++)
    bx_poly_reg_states[slot].cross_return_stack[n] = bx_poly_cross_return_stack[n];
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
  bx_poly_cross_return_top = bx_poly_reg_states[slot].cross_return_top;
  bx_poly_import_x86_return_valid = bx_poly_reg_states[slot].import_x86_return_valid;
  bx_poly_import_x86_return_mode = bx_poly_reg_states[slot].import_x86_return_mode;
  bx_poly_import_x86_return_rip = bx_poly_reg_states[slot].import_x86_return_rip;
  bx_poly_import_x86_return_rsp = bx_poly_reg_states[slot].import_x86_return_rsp;
  bx_poly_interrupted_raw_valid = bx_poly_reg_states[slot].interrupted_raw_valid;
  bx_poly_interrupted_raw_mode = bx_poly_reg_states[slot].interrupted_raw_mode;
  bx_poly_interrupted_raw_rip = bx_poly_reg_states[slot].interrupted_raw_rip;
  if (bx_poly_interrupted_raw_valid)
    bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_foreign_tls_base = bx_poly_reg_states[slot].foreign_tls_base;
  bx_poly_aarch64_nzcv = bx_poly_reg_states[slot].aarch64_nzcv;
  bx_poly_aarch64_reservation_valid = bx_poly_reg_states[slot].aarch64_reservation_valid;
  bx_poly_aarch64_reservation_addr = bx_poly_reg_states[slot].aarch64_reservation_addr;
  bx_poly_aarch64_reservation_size = bx_poly_reg_states[slot].aarch64_reservation_size;
  bx_poly_riscv_reservation_valid = bx_poly_reg_states[slot].riscv_reservation_valid;
  bx_poly_riscv_reservation_addr = bx_poly_reg_states[slot].riscv_reservation_addr;
  bx_poly_riscv_reservation_size = bx_poly_reg_states[slot].riscv_reservation_size;
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++)
    bx_poly_cross_return_stack[n] = bx_poly_reg_states[slot].cross_return_stack[n];
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

bool BX_CPU_C::read_poly_aarch64_reg(Bit32u reg, Bit64u *value)
{
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  switch (reg) {
  case 0:
    *value = RAX;
    return true;
  case 1:
    *value = RDI;
    return true;
  case 2:
    *value = RSI;
    return true;
  case 3:
    *value = RDX;
    return true;
  case 4:
    *value = RCX;
    return true;
  case 5:
    *value = R8;
    return true;
  case 6:
    *value = R9;
    return true;
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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  switch (reg) {
  case 0:
    RAX = value;
    return true;
  case 1:
    RDI = value;
    return true;
  case 2:
    RSI = value;
    return true;
  case 3:
    RDX = value;
    return true;
  case 4:
    RCX = value;
    return true;
  case 5:
    R8 = value;
    return true;
  case 6:
    R9 = value;
    return true;
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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  switch (reg) {
  case 0:
    *value = 0;
    return true;
  case 2:
    *value = RSP;
    return true;
  case 10:
    *value = RAX;
    return true;
  case 11:
    *value = RDI;
    return true;
  case 12:
    *value = RSI;
    return true;
  case 13:
    *value = RDX;
    return true;
  case 14:
    *value = RCX;
    return true;
  case 15:
    *value = R8;
    return true;
  case 16:
    *value = R9;
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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  switch (reg) {
  case 0:
    return true;
  case 2:
    RSP = value;
    return true;
  case 10:
    RAX = value;
    return true;
  case 11:
    RDI = value;
    return true;
  case 12:
    RSI = value;
    return true;
  case 13:
    RDX = value;
    return true;
  case 14:
    RCX = value;
    return true;
  case 15:
    R8 = value;
    return true;
  case 16:
    R9 = value;
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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  if (reg < 8) {
    BX_WRITE_XMM_REG_LO_QWORD(reg, value);
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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  if (reg < 8) {
    BX_WRITE_XMM_REG_LO_QWORD(reg, lo);
    BX_WRITE_XMM_REG_HI_QWORD(reg, hi);
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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  if (reg >= 10 && reg <= 17) {
    BX_WRITE_XMM_REG_LO_QWORD(reg - 10, value);
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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  if (reg >= 10 && reg <= 17) {
    unsigned xmm = reg - 10;
    BX_WRITE_XMM_REG_LO_QWORD(xmm, lo);
    BX_WRITE_XMM_REG_HI_QWORD(xmm, hi);
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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  if (reg < 8) {
    BX_WRITE_XMM_REG_LO_DWORD(reg, value);
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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

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
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  if (reg >= 10 && reg <= 17) {
    BX_WRITE_XMM_REG_LO_DWORD(reg - 10, value);
    return true;
  }
  if (reg < 32) {
    bx_poly_riscv_fp[reg] =
      (bx_poly_riscv_fp[reg] & BX_CONST64(0xffffffff00000000)) | value;
    return true;
  }
  return false;
}

bool BX_CPU_C::enter_poly_abi_call(Bit32u mode, bx_address target_rip,
  bx_address return_rip, bool sret_call, Bit32u return_kind, Bit32u arg_kind)
{
  Bit64u args[8];
  Bit64u fp_args[8];
  bx_address sret_ptr = sret_call ? (bx_address) RDI : 0;
  bx_address original_rsp = RSP;
  bx_address foreign_stack_rsp =
    (bx_address) ((RSP - BX_POLY_FOREIGN_STACK_GAP) & ~BX_CONST64(0xf));
  bx_address stack_copy_base = arg_kind == BX_POLY_ARG_KIND_FP64_STACK ?
    original_rsp + 8 : original_rsp + 24;

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
  for (Bit32u n = 0; n < 8; n++)
    fp_args[n] = BX_READ_XMM_REG_LO_QWORD(n);

  for (Bit32u n = 0; n < BX_POLY_FOREIGN_STACK_ARG_QWORDS; n++) {
    Bit64u value = read_virtual_qword(BX_SEG_REG_SS, stack_copy_base + n * 8);
    write_virtual_qword(BX_SEG_REG_SS, foreign_stack_rsp + n * 8, value);
  }

  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_current_mode = mode;
  bx_poly_return_cookie_valid = true;
  bx_poly_return_cookie_mode = mode;
  bx_poly_return_cookie_rip = return_rip;
  bx_poly_return_cookie_rsp = original_rsp;
  bx_poly_return_cookie_sret = sret_call;
  bx_poly_return_cookie_sret_ptr = sret_ptr;
  bx_poly_return_cookie_kind = return_kind;
  bx_poly_foreign_tls_base = (bx_address) R13;
  RSP = foreign_stack_rsp;

  bool mapped = false;
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    bx_poly_reset_aarch64_regs();
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
  }
  else if (mode == BX_POLY_MODE_RAW_RISCV) {
    bx_poly_reset_riscv_regs();
    if (sret_call) {
      mapped =
        write_poly_riscv_reg(4, bx_poly_foreign_tls_base) &&
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
        write_poly_riscv_reg(4, bx_poly_foreign_tls_base) &&
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
  }
  else {
    mapped = false;
  }

  if (!mapped) {
    bx_poly_return_cookie_valid = false;
    bx_poly_return_cookie_mode = BX_POLY_MODE_X86;
    bx_poly_return_cookie_rsp = 0;
    bx_poly_return_cookie_rip = 0;
    bx_poly_return_cookie_sret = false;
    bx_poly_return_cookie_sret_ptr = 0;
    bx_poly_return_cookie_kind = BX_POLY_RETURN_KIND_DEFAULT;
    RSP = original_rsp;
    return false;
  }

  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  RIP = target_rip;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  BX_INFO(("poly_ud: pcall mode=%u target=%llx return=%llx sret=%u kind=%u arg=%u",
    mode, (unsigned long long) target_rip, (unsigned long long) return_rip,
    sret_call ? 1 : 0, return_kind, arg_kind));
  return true;
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
  bool sret_call = bx_poly_return_cookie_sret;
  bx_address sret_ptr = bx_poly_return_cookie_sret_ptr;
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
  else if (mode == BX_POLY_MODE_RAW_AARCH64)
    has_second_result = read_poly_aarch64_reg(1, &second_result);
  else if (mode == BX_POLY_MODE_RAW_RISCV)
    has_second_result = read_poly_riscv_reg(11, &second_result);

  bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_clear_cross_return_stack();
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_return_cookie_valid = false;
  bx_poly_return_cookie_mode = BX_POLY_MODE_X86;
  RSP = bx_poly_return_cookie_rsp;
  RIP = bx_poly_return_cookie_rip;
  if (sret_call)
    RAX = sret_ptr;
  else if (has_fpair32_result) {
    BX_WRITE_XMM_REG_LO_QWORD(0,
      ((Bit64u) fpair32_hi << 32) | (Bit64u) fpair32_lo);
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
  else if (has_second_result)
    RDX = second_result;
  bx_poly_return_cookie_rsp = 0;
  bx_poly_return_cookie_rip = 0;
  bx_poly_return_cookie_sret = false;
  bx_poly_return_cookie_sret_ptr = 0;
  bx_poly_return_cookie_kind = BX_POLY_RETURN_KIND_DEFAULT;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  BX_INFO(("poly_raw: pcall return mode=%u rip=%llx", mode, (unsigned long long) RIP));
  return true;
}

bool BX_CPU_C::enter_poly_cross_call(Bit32u caller_mode, Bit32u callee_mode,
  bx_address target_rip, bx_address return_rip, Bit32u bridge_kind)
{
  if (bx_poly_cross_return_top >= BX_POLY_CROSS_RETURN_DEPTH)
    return false;

  Bit64u args[8];
  for (Bit32u n = 0; n < 8; n++) {
    bool read_ok = false;
    if (caller_mode == BX_POLY_MODE_RAW_AARCH64)
      read_ok = read_poly_aarch64_reg(n, &args[n]);
    else if (caller_mode == BX_POLY_MODE_RAW_RISCV)
      read_ok = read_poly_riscv_reg(10 + n, &args[n]);
    if (!read_ok)
      return false;
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
  bx_poly_current_mode = callee_mode;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  RIP = target_rip;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  BX_INFO(("poly_raw: cross call caller=%u callee=%u depth=%u target=%llx return=%llx bridge=%u",
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

  Bit64u args[8];
  for (Bit32u n = 0; n < 8; n++) {
    bool read_ok = false;
    if (callee_mode == BX_POLY_MODE_RAW_AARCH64)
      read_ok = read_poly_aarch64_reg(n, &args[n]);
    else if (callee_mode == BX_POLY_MODE_RAW_RISCV)
      read_ok = read_poly_riscv_reg(10 + n, &args[n]);
    if (!read_ok)
      return false;
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
  else {
    mapped = false;
  }
  if (!mapped)
    return false;

  bx_poly_current_mode = frame->caller_mode;
  RIP = frame->return_rip;
  bx_poly_cross_return_top--;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  BX_INFO(("poly_raw: cross return callee=%u mode=%u depth=%u rip=%llx bridge=%u",
    callee_mode, bx_poly_current_mode, bx_poly_cross_return_top,
    (unsigned long long) RIP, bridge_kind));
  return true;
}

bool BX_CPU_C::return_poly_import_x86_call(void)
{
  if (!bx_poly_import_x86_return_valid)
    return false;

  Bit32u return_mode = bx_poly_import_x86_return_mode;
  bx_address return_rip = bx_poly_import_x86_return_rip;
  bx_address return_rsp = bx_poly_import_x86_return_rsp;
  bool mapped = false;
  if (return_mode == BX_POLY_MODE_RAW_AARCH64) {
    mapped = write_poly_aarch64_reg(0, RAX);
  }
  else if (return_mode == BX_POLY_MODE_RAW_RISCV) {
    mapped = write_poly_riscv_reg(10, RAX);
  }

  if (!mapped)
    return false;

  bx_poly_current_mode = return_mode;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  RIP = return_rip;
  RSP = return_rsp;
  bx_poly_import_x86_return_valid = false;
  bx_poly_import_x86_return_mode = BX_POLY_MODE_X86;
  bx_poly_import_x86_return_rip = 0;
  bx_poly_import_x86_return_rsp = 0;
  if (return_poly_abi_call(return_mode, return_rip))
    return true;
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  BX_INFO(("poly_ud: import x86 return mode=%u result=%llu rip=%llx",
    bx_poly_current_mode, (unsigned long long) RAX, (unsigned long long) RIP));
  return true;
}

void BX_CPU_C::poly_interrupt_enter(void)
{
  if (!BX_CPU_THIS_PTR poly_feature_enabled || CPL != 3)
    return;

  bx_address stack_key = bx_poly_stack_key(RSP);
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
  BX_INFO(("poly_raw: interrupt enter mode=%u rip=%llx",
    bx_poly_interrupted_raw_mode, (unsigned long long) bx_poly_interrupted_raw_rip));
}

void BX_CPU_C::poly_restore_raw_return_to_user(const char *source)
{
  if (!BX_CPU_THIS_PTR poly_feature_enabled || CPL != 3)
    return;

  bx_address stack_key = bx_poly_stack_key(RSP);
  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
  if (!bx_poly_interrupted_raw_valid ||
      !bx_poly_is_raw_mode(bx_poly_interrupted_raw_mode) ||
      bx_poly_interrupted_raw_rip != RIP)
    return;

  bx_poly_current_mode = bx_poly_interrupted_raw_mode;
  bx_poly_interrupted_raw_valid = false;
  bx_poly_interrupted_raw_mode = BX_POLY_MODE_X86;
  bx_poly_interrupted_raw_rip = 0;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, stack_key);
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  BX_INFO(("poly_raw: %s restore mode=%u rip=%llx",
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

  if (mode == BX_POLY_MODE_RAW_AARCH64 &&
      import_id == BX_POLY_IMPORT_FUNC_AARCH64_TLSDESC) {
    Bit64u descriptor_addr = 0;
    if (!read_poly_aarch64_reg(0, &descriptor_addr))
      return false;

    Bit64u tls_offset = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) (descriptor_addr + 8));
    if (!write_poly_aarch64_reg(0, tls_offset))
      return false;

    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import aarch64 tlsdesc descriptor=%llx offset=%llu tls_base=%llx return=%llx",
      (unsigned long long) descriptor_addr, (unsigned long long) tls_offset,
      (unsigned long long) bx_poly_foreign_tls_base,
      (unsigned long long) return_rip));
    return true;
  }

  if (mode == BX_POLY_MODE_RAW_RISCV &&
      import_id == BX_POLY_IMPORT_FUNC_RISCV_TLS_GET_ADDR) {
    Bit64u descriptor_addr = 0;
    if (!read_poly_riscv_reg(10, &descriptor_addr))
      return false;

    Bit64u tls_offset = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) (descriptor_addr + 8));
    Bit64u result = bx_poly_foreign_tls_base + tls_offset;
    if (!write_poly_riscv_reg(10, result))
      return false;

    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import riscv __tls_get_addr descriptor=%llx offset=%llu tls_base=%llx result=%llx return=%llx",
      (unsigned long long) descriptor_addr, (unsigned long long) tls_offset,
      (unsigned long long) bx_poly_foreign_tls_base,
      (unsigned long long) result, (unsigned long long) return_rip));
    return true;
  }

  Bit32u aarch64_atomic_op = 0;
  Bit32u aarch64_atomic_size = 0;
  const char *aarch64_atomic_name = 0;
  if (import_id == BX_POLY_IMPORT_FUNC_UDIVTI3 ||
      import_id == BX_POLY_IMPORT_FUNC_UMODTI3 ||
      import_id == BX_POLY_IMPORT_FUNC_DIVTI3 ||
      import_id == BX_POLY_IMPORT_FUNC_MODTI3) {
    Bit64u dividend_lo = 0, dividend_hi = 0, divisor_lo = 0, divisor_hi = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_reg(0, &dividend_lo) &&
        read_poly_aarch64_reg(1, &dividend_hi) &&
        read_poly_aarch64_reg(2, &divisor_lo) &&
        read_poly_aarch64_reg(3, &divisor_hi);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_reg(10, &dividend_lo) &&
        read_poly_riscv_reg(11, &dividend_hi) &&
        read_poly_riscv_reg(12, &divisor_lo) &&
        read_poly_riscv_reg(13, &divisor_hi);
    }
    if (!mapped)
      return false;

    unsigned __int128 divisor =
      ((unsigned __int128) divisor_hi << 64) | divisor_lo;
    if (divisor == 0)
      return false;

    unsigned __int128 result = 0;
    unsigned __int128 dividend =
      ((unsigned __int128) dividend_hi << 64) | dividend_lo;
    if (import_id == BX_POLY_IMPORT_FUNC_UDIVTI3) {
      result = dividend / divisor;
    }
    else if (import_id == BX_POLY_IMPORT_FUNC_UMODTI3) {
      result = dividend % divisor;
    }
    else {
      __int128 signed_dividend = (__int128) dividend;
      __int128 signed_divisor = (__int128) divisor;
      __int128 signed_result =
        import_id == BX_POLY_IMPORT_FUNC_DIVTI3 ?
        (signed_dividend / signed_divisor) :
        (signed_dividend % signed_divisor);
      result = (unsigned __int128) signed_result;
    }

    Bit64u result_lo = (Bit64u) result;
    Bit64u result_hi = (Bit64u) (result >> 64);
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = write_poly_aarch64_reg(0, result_lo) &&
        write_poly_aarch64_reg(1, result_hi);
    }
    else {
      mapped = write_poly_riscv_reg(10, result_lo) &&
        write_poly_riscv_reg(11, result_hi);
    }
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import int128 helper id=%u target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_FIXDFTI ||
      import_id == BX_POLY_IMPORT_FUNC_FIXUNSDFTI) {
    Bit64u source_bits = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_fp64_reg(0, &source_bits);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_fp64_reg(10, &source_bits);
    }
    if (!mapped)
      return false;

    double source = bx_poly_fp64_from_bits(source_bits);
    unsigned __int128 result =
      import_id == BX_POLY_IMPORT_FUNC_FIXUNSDFTI ?
      (unsigned __int128) source :
      (unsigned __int128) (__int128) source;
    Bit64u result_lo = (Bit64u) result;
    Bit64u result_hi = (Bit64u) (result >> 64);

    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = write_poly_aarch64_reg(0, result_lo) &&
        write_poly_aarch64_reg(1, result_hi);
    }
    else {
      mapped = write_poly_riscv_reg(10, result_lo) &&
        write_poly_riscv_reg(11, result_hi);
    }
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import double-to-int128 helper id=%u target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_FIXSFTI ||
      import_id == BX_POLY_IMPORT_FUNC_FIXUNSSFTI) {
    Bit32u source_bits = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_fp32_reg(0, &source_bits);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_fp32_reg(10, &source_bits);
    }
    if (!mapped)
      return false;

    float source = bx_poly_fp32_from_bits(source_bits);
    unsigned __int128 result =
      import_id == BX_POLY_IMPORT_FUNC_FIXUNSSFTI ?
      (unsigned __int128) source :
      (unsigned __int128) (__int128) source;
    Bit64u result_lo = (Bit64u) result;
    Bit64u result_hi = (Bit64u) (result >> 64);

    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = write_poly_aarch64_reg(0, result_lo) &&
        write_poly_aarch64_reg(1, result_hi);
    }
    else {
      mapped = write_poly_riscv_reg(10, result_lo) &&
        write_poly_riscv_reg(11, result_hi);
    }
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import float-to-int128 helper id=%u target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_FLOATTIDF ||
      import_id == BX_POLY_IMPORT_FUNC_FLOATUNTIDF) {
    Bit64u source_lo = 0, source_hi = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_reg(0, &source_lo) &&
        read_poly_aarch64_reg(1, &source_hi);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_reg(10, &source_lo) &&
        read_poly_riscv_reg(11, &source_hi);
    }
    if (!mapped)
      return false;

    unsigned __int128 unsigned_source =
      ((unsigned __int128) source_hi << 64) | source_lo;
    double result = import_id == BX_POLY_IMPORT_FUNC_FLOATUNTIDF ?
      (double) unsigned_source : (double) (__int128) unsigned_source;
    Bit64u result_bits = bx_poly_fp64_to_bits(result);

    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = write_poly_aarch64_fp64_reg(0, result_bits);
    }
    else {
      mapped = write_poly_riscv_fp64_reg(10, result_bits);
    }
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import int128-to-double helper id=%u target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_FLOATTISF ||
      import_id == BX_POLY_IMPORT_FUNC_FLOATUNTISF) {
    Bit64u source_lo = 0, source_hi = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_reg(0, &source_lo) &&
        read_poly_aarch64_reg(1, &source_hi);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_reg(10, &source_lo) &&
        read_poly_riscv_reg(11, &source_hi);
    }
    if (!mapped)
      return false;

    unsigned __int128 unsigned_source =
      ((unsigned __int128) source_hi << 64) | source_lo;
    float result = import_id == BX_POLY_IMPORT_FUNC_FLOATUNTISF ?
      (float) unsigned_source : (float) (__int128) unsigned_source;
    Bit32u result_bits = bx_poly_fp32_to_bits(result);

    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = write_poly_aarch64_fp32_reg(0, result_bits);
    }
    else {
      mapped = write_poly_riscv_fp32_reg(10, result_bits);
    }
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import int128-to-float helper id=%u target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_CLZDI2 ||
      import_id == BX_POLY_IMPORT_FUNC_CTZDI2 ||
      import_id == BX_POLY_IMPORT_FUNC_PARITYDI2 ||
      import_id == BX_POLY_IMPORT_FUNC_POPCOUNTDI2) {
    Bit64u source = 0;
    Bit64u result = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_reg(0, &source);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_reg(10, &source);
    }
    if (!mapped)
      return false;

    Bit32u ones = bx_poly_count_ones64(source);
    if (import_id == BX_POLY_IMPORT_FUNC_CLZDI2)
      result = bx_poly_count_leading_zeros64(source);
    else if (import_id == BX_POLY_IMPORT_FUNC_CTZDI2)
      result = bx_poly_count_trailing_zeros64(source);
    else if (import_id == BX_POLY_IMPORT_FUNC_PARITYDI2)
      result = ones & 1;
    else
      result = ones;

    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = write_poly_aarch64_reg(0, result);
    }
    else {
      mapped = write_poly_riscv_reg(10, result);
    }
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import bit helper id=%u source=%llx result=%llu target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) source,
      (unsigned long long) result, (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_ADDTF3 ||
      import_id == BX_POLY_IMPORT_FUNC_SUBTF3 ||
      import_id == BX_POLY_IMPORT_FUNC_MULTF3 ||
      import_id == BX_POLY_IMPORT_FUNC_DIVTF3) {
    Bit64u left_lo = 0, left_hi = 0, right_lo = 0, right_hi = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_fp128_reg(0, &left_lo, &left_hi) &&
        read_poly_aarch64_fp128_reg(1, &right_lo, &right_hi);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_reg(10, &left_lo) &&
        read_poly_riscv_reg(11, &left_hi) &&
        read_poly_riscv_reg(12, &right_lo) &&
        read_poly_riscv_reg(13, &right_hi);
    }
    if (!mapped)
      return false;

    long double left = bx_poly_fp128_from_bits(left_lo, left_hi);
    long double right = bx_poly_fp128_from_bits(right_lo, right_hi);
    long double result = 0.0L;
    if (import_id == BX_POLY_IMPORT_FUNC_ADDTF3)
      result = left + right;
    else if (import_id == BX_POLY_IMPORT_FUNC_SUBTF3)
      result = left - right;
    else if (import_id == BX_POLY_IMPORT_FUNC_MULTF3)
      result = left * right;
    else
      result = left / right;

    Bit64u result_lo = 0, result_hi = 0;
    bx_poly_fp128_to_bits(result, &result_lo, &result_hi);
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = write_poly_aarch64_fp128_reg(0, result_lo, result_hi);
    }
    else {
      mapped = write_poly_riscv_reg(10, result_lo) &&
        write_poly_riscv_reg(11, result_hi);
    }
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import tf binary helper id=%u target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_FLOATUNDITF ||
      import_id == BX_POLY_IMPORT_FUNC_FLOATDITF ||
      import_id == BX_POLY_IMPORT_FUNC_FLOATSITF ||
      import_id == BX_POLY_IMPORT_FUNC_FLOATUNSITF) {
    Bit64u source = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64)
      mapped = read_poly_aarch64_reg(0, &source);
    else if (mode == BX_POLY_MODE_RAW_RISCV)
      mapped = read_poly_riscv_reg(10, &source);
    if (!mapped)
      return false;

    Bit64u result_lo = 0, result_hi = 0;
    long double result = 0.0L;
    if (import_id == BX_POLY_IMPORT_FUNC_FLOATUNDITF)
      result = (long double) source;
    else if (import_id == BX_POLY_IMPORT_FUNC_FLOATDITF)
      result = (long double) (Bit64s) source;
    else if (import_id == BX_POLY_IMPORT_FUNC_FLOATUNSITF)
      result = (long double) (Bit32u) source;
    else
      result = (long double) (Bit32s) source;
    bx_poly_fp128_to_bits(result, &result_lo, &result_hi);
    if (mode == BX_POLY_MODE_RAW_AARCH64)
      mapped = write_poly_aarch64_fp128_reg(0, result_lo, result_hi);
    else
      mapped = write_poly_riscv_reg(10, result_lo) &&
        write_poly_riscv_reg(11, result_hi);
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import int-to-tf helper id=%u source=%llx target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) source,
      (unsigned long long) target_rip, (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_FIXUNSTFDI ||
      import_id == BX_POLY_IMPORT_FUNC_FIXTFDI ||
      import_id == BX_POLY_IMPORT_FUNC_FIXUNSTFSI ||
      import_id == BX_POLY_IMPORT_FUNC_FIXTFSI) {
    Bit64u source_lo = 0, source_hi = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_fp128_reg(0, &source_lo, &source_hi);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_reg(10, &source_lo) &&
        read_poly_riscv_reg(11, &source_hi);
    }
    if (!mapped)
      return false;

    long double source = bx_poly_fp128_from_bits(source_lo, source_hi);
    Bit64u result = 0;
    if (import_id == BX_POLY_IMPORT_FUNC_FIXUNSTFDI)
      result = bx_poly_fp128_to_uint64_rtz(source);
    else if (import_id == BX_POLY_IMPORT_FUNC_FIXTFDI)
      result = bx_poly_fp128_to_int64_rtz(source);
    else if (import_id == BX_POLY_IMPORT_FUNC_FIXUNSTFSI)
      result = (Bit64u) (Bit32u) bx_poly_fp128_to_uint64_rtz(source);
    else
      result = (Bit64u) (Bit64s) (Bit32s) bx_poly_fp128_to_int64_rtz(source);
    if (mode == BX_POLY_MODE_RAW_AARCH64)
      mapped = write_poly_aarch64_reg(0, result);
    else
      mapped = write_poly_riscv_reg(10, result);
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import tf-to-int helper id=%u result=%llx target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) result,
      (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_EXTENDSFTF2 ||
      import_id == BX_POLY_IMPORT_FUNC_EXTENDDFTF2) {
    bool fp32 = import_id == BX_POLY_IMPORT_FUNC_EXTENDSFTF2;
    bool mapped = false;
    long double result = 0.0L;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      if (fp32) {
        Bit32u source_bits = 0;
        mapped = read_poly_aarch64_fp32_reg(0, &source_bits);
        result = (long double) bx_poly_fp32_from_bits(source_bits);
      }
      else {
        Bit64u source_bits = 0;
        mapped = read_poly_aarch64_fp64_reg(0, &source_bits);
        result = (long double) bx_poly_fp64_from_bits(source_bits);
      }
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      if (fp32) {
        Bit32u source_bits = 0;
        mapped = read_poly_riscv_fp32_reg(10, &source_bits);
        result = (long double) bx_poly_fp32_from_bits(source_bits);
      }
      else {
        Bit64u source_bits = 0;
        mapped = read_poly_riscv_fp64_reg(10, &source_bits);
        result = (long double) bx_poly_fp64_from_bits(source_bits);
      }
    }
    if (!mapped)
      return false;

    Bit64u result_lo = 0, result_hi = 0;
    bx_poly_fp128_to_bits(result, &result_lo, &result_hi);
    if (mode == BX_POLY_MODE_RAW_AARCH64)
      mapped = write_poly_aarch64_fp128_reg(0, result_lo, result_hi);
    else
      mapped = write_poly_riscv_reg(10, result_lo) &&
        write_poly_riscv_reg(11, result_hi);
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import fp-to-tf helper id=%u target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_TRUNCTFSF2 ||
      import_id == BX_POLY_IMPORT_FUNC_TRUNCTFDF2) {
    Bit64u source_lo = 0, source_hi = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_fp128_reg(0, &source_lo, &source_hi);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_reg(10, &source_lo) &&
        read_poly_riscv_reg(11, &source_hi);
    }
    if (!mapped)
      return false;

    long double source = bx_poly_fp128_from_bits(source_lo, source_hi);
    if (import_id == BX_POLY_IMPORT_FUNC_TRUNCTFSF2) {
      Bit32u result_bits = bx_poly_fp32_to_bits((float) source);
      if (mode == BX_POLY_MODE_RAW_AARCH64)
        mapped = write_poly_aarch64_fp32_reg(0, result_bits);
      else
        mapped = write_poly_riscv_fp32_reg(10, result_bits);
    }
    else {
      Bit64u result_bits = bx_poly_fp64_to_bits((double) source);
      if (mode == BX_POLY_MODE_RAW_AARCH64)
        mapped = write_poly_aarch64_fp64_reg(0, result_bits);
      else
        mapped = write_poly_riscv_fp64_reg(10, result_bits);
    }
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import tf-to-fp helper id=%u target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_EQTF2 ||
      import_id == BX_POLY_IMPORT_FUNC_NETF2 ||
      import_id == BX_POLY_IMPORT_FUNC_LTTF2 ||
      import_id == BX_POLY_IMPORT_FUNC_LETF2 ||
      import_id == BX_POLY_IMPORT_FUNC_GTTF2 ||
      import_id == BX_POLY_IMPORT_FUNC_GETF2 ||
      import_id == BX_POLY_IMPORT_FUNC_UNORDTF2) {
    Bit64u left_lo = 0, left_hi = 0, right_lo = 0, right_hi = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_fp128_reg(0, &left_lo, &left_hi) &&
        read_poly_aarch64_fp128_reg(1, &right_lo, &right_hi);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_reg(10, &left_lo) &&
        read_poly_riscv_reg(11, &left_hi) &&
        read_poly_riscv_reg(12, &right_lo) &&
        read_poly_riscv_reg(13, &right_hi);
    }
    if (!mapped)
      return false;

    long double left = bx_poly_fp128_from_bits(left_lo, left_hi);
    long double right = bx_poly_fp128_from_bits(right_lo, right_hi);
    bool unordered = (left != left) || (right != right);
    Bit64u result = 0;
    if (import_id == BX_POLY_IMPORT_FUNC_UNORDTF2) {
      result = unordered ? 1 : 0;
    }
    else if (unordered) {
      if (import_id == BX_POLY_IMPORT_FUNC_EQTF2 ||
          import_id == BX_POLY_IMPORT_FUNC_NETF2 ||
          import_id == BX_POLY_IMPORT_FUNC_LTTF2 ||
          import_id == BX_POLY_IMPORT_FUNC_LETF2)
        result = 1;
      else
        result = (Bit64u) (Bit64s) -1;
    }
    else if (import_id == BX_POLY_IMPORT_FUNC_EQTF2 ||
             import_id == BX_POLY_IMPORT_FUNC_NETF2) {
      result = left == right ? 0 : 1;
    }
    else if (left < right) {
      result = (Bit64u) (Bit64s) -1;
    }
    else if (left > right) {
      result = 1;
    }
    else {
      result = 0;
    }

    if (mode == BX_POLY_MODE_RAW_AARCH64)
      mapped = write_poly_aarch64_reg(0, result);
    else
      mapped = write_poly_riscv_reg(10, result);
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import tf compare helper id=%u result=%llx target=%llx return=%llx",
      (unsigned) import_id, (unsigned long long) result,
      (unsigned long long) target_rip, (unsigned long long) return_rip));
    return true;
  }

  if (mode == BX_POLY_MODE_RAW_RISCV &&
      import_id == BX_POLY_IMPORT_FUNC_ATOMIC_COMPARE_EXCHANGE_16) {
    Bit64u ptr = 0, expected_ptr = 0, desired_lo = 0, desired_hi = 0;
    if (!read_poly_riscv_reg(10, &ptr) ||
        !read_poly_riscv_reg(11, &expected_ptr) ||
        !read_poly_riscv_reg(12, &desired_lo) ||
        !read_poly_riscv_reg(13, &desired_hi))
      return false;

    Bit64u actual_lo = read_virtual_qword(BX_SEG_REG_DS, (bx_address) ptr);
    Bit64u actual_hi = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) (ptr + 8));
    Bit64u expected_lo = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) expected_ptr);
    Bit64u expected_hi = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) (expected_ptr + 8));
    bool success = actual_lo == expected_lo && actual_hi == expected_hi;

    if (success) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) ptr, desired_lo);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (ptr + 8), desired_hi);
    }
    else {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) expected_ptr,
        actual_lo);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (expected_ptr + 8),
        actual_hi);
    }

    if (!write_poly_riscv_reg(10, success ? 1 : 0))
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import riscv __atomic_compare_exchange_16 target=%llx success=%u return=%llx",
      (unsigned long long) target_rip, success ? 1 : 0,
      (unsigned long long) return_rip));
    return true;
  }

  if (mode == BX_POLY_MODE_RAW_RISCV &&
      import_id == BX_POLY_IMPORT_FUNC_ATOMIC_LOAD_16) {
    Bit64u ptr = 0;
    if (!read_poly_riscv_reg(10, &ptr))
      return false;

    Bit64u result_lo = read_virtual_qword(BX_SEG_REG_DS, (bx_address) ptr);
    Bit64u result_hi = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) (ptr + 8));
    if (!write_poly_riscv_reg(10, result_lo) ||
        !write_poly_riscv_reg(11, result_hi))
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import riscv __atomic_load_16 target=%llx return=%llx",
      (unsigned long long) target_rip, (unsigned long long) return_rip));
    return true;
  }

  if (mode == BX_POLY_MODE_RAW_RISCV &&
      import_id == BX_POLY_IMPORT_FUNC_ATOMIC_STORE_16) {
    Bit64u ptr = 0, value_lo = 0, value_hi = 0;
    if (!read_poly_riscv_reg(10, &ptr) ||
        !read_poly_riscv_reg(11, &value_lo) ||
        !read_poly_riscv_reg(12, &value_hi))
      return false;

    write_virtual_qword(BX_SEG_REG_DS, (bx_address) ptr, value_lo);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) (ptr + 8), value_hi);

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import riscv __atomic_store_16 target=%llx return=%llx",
      (unsigned long long) target_rip, (unsigned long long) return_rip));
    return true;
  }

  if (mode == BX_POLY_MODE_RAW_AARCH64 &&
      import_id == BX_POLY_IMPORT_FUNC_ATOMIC_COMPARE_EXCHANGE_16) {
    Bit64u ptr = 0, expected_ptr = 0, desired_lo = 0, desired_hi = 0;
    if (!read_poly_aarch64_reg(0, &ptr) ||
        !read_poly_aarch64_reg(1, &expected_ptr) ||
        !read_poly_aarch64_reg(2, &desired_lo) ||
        !read_poly_aarch64_reg(3, &desired_hi))
      return false;

    Bit64u actual_lo = read_virtual_qword(BX_SEG_REG_DS, (bx_address) ptr);
    Bit64u actual_hi = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) (ptr + 8));
    Bit64u expected_lo = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) expected_ptr);
    Bit64u expected_hi = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) (expected_ptr + 8));
    bool success = actual_lo == expected_lo && actual_hi == expected_hi;

    if (success) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) ptr, desired_lo);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (ptr + 8), desired_hi);
    }
    else {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) expected_ptr,
        actual_lo);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (expected_ptr + 8),
        actual_hi);
    }

    if (!write_poly_aarch64_reg(0, success ? 1 : 0))
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import aarch64 __atomic_compare_exchange_16 target=%llx success=%u return=%llx",
      (unsigned long long) target_rip, success ? 1 : 0,
      (unsigned long long) return_rip));
    return true;
  }

  if (mode == BX_POLY_MODE_RAW_AARCH64 &&
      import_id == BX_POLY_IMPORT_FUNC_ATOMIC_LOAD_16) {
    Bit64u ptr = 0;
    if (!read_poly_aarch64_reg(0, &ptr))
      return false;

    Bit64u result_lo = read_virtual_qword(BX_SEG_REG_DS, (bx_address) ptr);
    Bit64u result_hi = read_virtual_qword(BX_SEG_REG_DS,
      (bx_address) (ptr + 8));
    if (!write_poly_aarch64_reg(0, result_lo) ||
        !write_poly_aarch64_reg(1, result_hi))
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import aarch64 __atomic_load_16 target=%llx return=%llx",
      (unsigned long long) target_rip, (unsigned long long) return_rip));
    return true;
  }

  if (mode == BX_POLY_MODE_RAW_AARCH64 &&
      import_id == BX_POLY_IMPORT_FUNC_ATOMIC_STORE_16) {
    Bit64u ptr = 0, value_lo = 0, value_hi = 0;
    if (!read_poly_aarch64_reg(0, &ptr) ||
        !read_poly_aarch64_reg(2, &value_lo) ||
        !read_poly_aarch64_reg(3, &value_hi))
      return false;

    write_virtual_qword(BX_SEG_REG_DS, (bx_address) ptr, value_lo);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) (ptr + 8), value_hi);

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import aarch64 __atomic_store_16 target=%llx return=%llx",
      (unsigned long long) target_rip, (unsigned long long) return_rip));
    return true;
  }

  if (mode == BX_POLY_MODE_RAW_AARCH64 &&
      bx_poly_aarch64_outline_atomic_descriptor(import_id, &aarch64_atomic_op,
        &aarch64_atomic_size, &aarch64_atomic_name)) {
    Bit64u arg0 = 0, arg1 = 0, arg2 = 0;
    Bit64u result = 0;
    if (!read_poly_aarch64_reg(0, &arg0) ||
        !read_poly_aarch64_reg(1, &arg1) ||
        !read_poly_aarch64_reg(2, &arg2))
      return false;

    bx_address addr = (bx_address)
      (aarch64_atomic_op == BX_POLY_AARCH64_ATOMIC_CAS ? arg2 : arg1);
    switch (aarch64_atomic_size) {
      case 1:
        result = read_virtual_byte(BX_SEG_REG_DS, addr);
        break;
      case 2:
        result = read_virtual_word(BX_SEG_REG_DS, addr);
        break;
      case 4:
        result = read_virtual_dword(BX_SEG_REG_DS, addr);
        break;
      case 8:
        result = read_virtual_qword(BX_SEG_REG_DS, addr);
        break;
      default:
        return false;
    }

    Bit64u mask = bx_poly_aarch64_size_mask(aarch64_atomic_size);
    Bit64u new_value = result;
    Bit64u source = arg0 & mask;
    switch (aarch64_atomic_op) {
      case BX_POLY_AARCH64_ATOMIC_LDADD:
        new_value = (result + source) & mask;
        break;
      case BX_POLY_AARCH64_ATOMIC_SWP:
        new_value = source;
        break;
      case BX_POLY_AARCH64_ATOMIC_LDCLR:
        new_value = result & ~source & mask;
        break;
      case BX_POLY_AARCH64_ATOMIC_LDEOR:
        new_value = (result ^ source) & mask;
        break;
      case BX_POLY_AARCH64_ATOMIC_LDSET:
        new_value = (result | source) & mask;
        break;
      case BX_POLY_AARCH64_ATOMIC_CAS:
        if (result != source)
          break;
        new_value = arg1 & mask;
        break;
      default:
        return false;
    }

    if (aarch64_atomic_op != BX_POLY_AARCH64_ATOMIC_CAS ||
        result == source) {
      switch (aarch64_atomic_size) {
        case 1:
          write_virtual_byte(BX_SEG_REG_DS, addr, (Bit8u) new_value);
          break;
        case 2:
          write_virtual_word(BX_SEG_REG_DS, addr, (Bit16u) new_value);
          break;
        case 4:
          write_virtual_dword(BX_SEG_REG_DS, addr, (Bit32u) new_value);
          break;
        case 8:
          write_virtual_qword(BX_SEG_REG_DS, addr, new_value);
          break;
      }
    }

    if (!write_poly_aarch64_reg(0, result))
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import aarch64 outline atomic %s target=%llx result=%llu return=%llx",
      aarch64_atomic_name, (unsigned long long) target_rip,
      (unsigned long long) result,
      (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_FP64_ADD) {
    Bit64u left_bits = 0, right_bits = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_fp64_reg(0, &left_bits) &&
        read_poly_aarch64_fp64_reg(1, &right_bits);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_fp64_reg(10, &left_bits) &&
        read_poly_riscv_fp64_reg(11, &right_bits);
    }
    if (!mapped)
      return false;

    Bit64u result_bits = bx_poly_fp64_to_bits(
      bx_poly_fp64_from_bits(left_bits) + bx_poly_fp64_from_bits(right_bits) + 10.0);
    if (mode == BX_POLY_MODE_RAW_AARCH64)
      mapped = write_poly_aarch64_fp64_reg(0, result_bits);
    else if (mode == BX_POLY_MODE_RAW_RISCV)
      mapped = write_poly_riscv_fp64_reg(10, result_bits);
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import fp64 call mode=%u descriptor=%u target=%llx arg0=%llx arg1=%llx result=%llx return=%llx",
      mode, (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned long long) left_bits, (unsigned long long) right_bits,
      (unsigned long long) result_bits, (unsigned long long) return_rip));
    return true;
  }

  if (import_id == BX_POLY_IMPORT_FUNC_FP32_ADD) {
    Bit32u left_bits = 0, right_bits = 0;
    bool mapped = false;
    if (mode == BX_POLY_MODE_RAW_AARCH64) {
      mapped = read_poly_aarch64_fp32_reg(0, &left_bits) &&
        read_poly_aarch64_fp32_reg(1, &right_bits);
    }
    else if (mode == BX_POLY_MODE_RAW_RISCV) {
      mapped = read_poly_riscv_fp32_reg(10, &left_bits) &&
        read_poly_riscv_fp32_reg(11, &right_bits);
    }
    if (!mapped)
      return false;

    Bit32u result_bits = bx_poly_fp32_to_bits(
      bx_poly_fp32_from_bits(left_bits) + bx_poly_fp32_from_bits(right_bits) + 10.0f);
    if (mode == BX_POLY_MODE_RAW_AARCH64)
      mapped = write_poly_aarch64_fp32_reg(0, result_bits);
    else if (mode == BX_POLY_MODE_RAW_RISCV)
      mapped = write_poly_riscv_fp32_reg(10, result_bits);
    if (!mapped)
      return false;

    if (return_poly_abi_call(mode, return_rip))
      return true;
    RIP = return_rip;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    BX_INFO(("poly_raw: import fp32 call mode=%u descriptor=%u target=%llx arg0=%x arg1=%x result=%x return=%llx",
      mode, (unsigned) import_id, (unsigned long long) target_rip,
      (unsigned) left_bits, (unsigned) right_bits,
      (unsigned) result_bits, (unsigned long long) return_rip));
    return true;
  }

  Bit64u arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0;
  Bit64u arg6 = 0, arg7 = 0;
  Bit64u result = 0;
  bool mapped = false;
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    mapped = read_poly_aarch64_reg(0, &arg0);
    if (mapped &&
        import_id != BX_POLY_IMPORT_FUNC_STRLEN &&
        import_id != BX_POLY_IMPORT_FUNC_STACK_CHK_FAIL)
      mapped = read_poly_aarch64_reg(1, &arg1);
    if (mapped &&
        (import_id == BX_POLY_IMPORT_FUNC_MEMCPY ||
         import_id == BX_POLY_IMPORT_FUNC_MEMSET ||
         import_id == BX_POLY_IMPORT_FUNC_MEMCMP ||
         import_id == BX_POLY_IMPORT_FUNC_MEMMOVE ||
         import_id == BX_POLY_IMPORT_FUNC_MEMPCPY ||
         import_id == BX_POLY_IMPORT_FUNC_BCMP ||
         import_id == BX_POLY_IMPORT_FUNC_BCOPY ||
         import_id == BX_POLY_IMPORT_FUNC_MEMRCHR ||
         import_id == BX_POLY_IMPORT_FUNC_MEMMEM ||
         bx_poly_import_is_x86_descriptor(import_id) ||
         import_id == BX_POLY_IMPORT_FUNC_STRNCMP ||
         import_id == BX_POLY_IMPORT_FUNC_STRNCASECMP ||
         import_id == BX_POLY_IMPORT_FUNC_MEMCHR ||
         import_id == BX_POLY_IMPORT_FUNC_STRNCPY ||
         import_id == BX_POLY_IMPORT_FUNC_STRNCAT ||
         import_id == BX_POLY_IMPORT_FUNC_STPNCPY))
      mapped = read_poly_aarch64_reg(2, &arg2);
    if (mapped && (import_id == BX_POLY_IMPORT_FUNC_MEMMEM ||
        bx_poly_import_is_x86_descriptor(import_id)))
      mapped = read_poly_aarch64_reg(3, &arg3);
    if (mapped && bx_poly_import_is_x86_descriptor(import_id))
      mapped = read_poly_aarch64_reg(4, &arg4) &&
        read_poly_aarch64_reg(5, &arg5);
    if (mapped && bx_poly_import_uses_x86_stack_args(import_id))
      mapped = read_poly_aarch64_reg(6, &arg6) &&
        read_poly_aarch64_reg(7, &arg7);
  }
  else if (mode == BX_POLY_MODE_RAW_RISCV) {
    mapped = read_poly_riscv_reg(10, &arg0);
    if (mapped &&
        import_id != BX_POLY_IMPORT_FUNC_STRLEN &&
        import_id != BX_POLY_IMPORT_FUNC_STACK_CHK_FAIL)
      mapped = read_poly_riscv_reg(11, &arg1);
    if (mapped &&
        (import_id == BX_POLY_IMPORT_FUNC_MEMCPY ||
         import_id == BX_POLY_IMPORT_FUNC_MEMSET ||
         import_id == BX_POLY_IMPORT_FUNC_MEMCMP ||
         import_id == BX_POLY_IMPORT_FUNC_MEMMOVE ||
         import_id == BX_POLY_IMPORT_FUNC_MEMPCPY ||
         import_id == BX_POLY_IMPORT_FUNC_BCMP ||
         import_id == BX_POLY_IMPORT_FUNC_BCOPY ||
         import_id == BX_POLY_IMPORT_FUNC_MEMRCHR ||
         import_id == BX_POLY_IMPORT_FUNC_MEMMEM ||
         bx_poly_import_is_x86_descriptor(import_id) ||
         import_id == BX_POLY_IMPORT_FUNC_STRNCMP ||
         import_id == BX_POLY_IMPORT_FUNC_STRNCASECMP ||
         import_id == BX_POLY_IMPORT_FUNC_MEMCHR ||
         import_id == BX_POLY_IMPORT_FUNC_STRNCPY ||
         import_id == BX_POLY_IMPORT_FUNC_STRNCAT ||
         import_id == BX_POLY_IMPORT_FUNC_STPNCPY))
      mapped = read_poly_riscv_reg(12, &arg2);
    if (mapped && (import_id == BX_POLY_IMPORT_FUNC_MEMMEM ||
        bx_poly_import_is_x86_descriptor(import_id)))
      mapped = read_poly_riscv_reg(13, &arg3);
    if (mapped && bx_poly_import_is_x86_descriptor(import_id))
      mapped = read_poly_riscv_reg(14, &arg4) &&
        read_poly_riscv_reg(15, &arg5);
    if (mapped && bx_poly_import_uses_x86_stack_args(import_id))
      mapped = read_poly_riscv_reg(16, &arg6) &&
        read_poly_riscv_reg(17, &arg7);
  }

  if (!mapped)
    return false;

  const char *op_name = 0;
  if (import_id == BX_POLY_IMPORT_FUNC_ADD) {
    result = arg0 + arg1 + 100;
    op_name = "poly_import_add";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_MUL) {
    result = arg0 * arg1 + 100;
    op_name = "poly_import_mul";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STACK_CHK_FAIL) {
    result = (Bit64u) -5;
    op_name = "__stack_chk_fail";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRLEN) {
    result = 0;
    while (result < 4096 &&
           read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + result)) != 0)
      result++;
    op_name = "strlen";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRNLEN) {
    Bit64u count = arg1 < 4096 ? arg1 : 4096;
    result = 0;
    while (result < count &&
           read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + result)) != 0)
      result++;
    op_name = "strnlen";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRCMP) {
    Bit64s cmp = 0;
    for (Bit64u n = 0; n < 4096; n++) {
      Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      if (left != right || left == 0 || right == 0) {
        cmp = (Bit64s) left - (Bit64s) right;
        break;
      }
    }
    result = (Bit64u) cmp;
    op_name = "strcmp";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRNCMP) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    Bit64s cmp = 0;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      if (left != right || left == 0 || right == 0) {
        cmp = (Bit64s) left - (Bit64s) right;
        break;
      }
    }
    result = (Bit64u) cmp;
    op_name = "strncmp";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRCASECMP) {
    Bit64s cmp = 0;
    for (Bit64u n = 0; n < 4096; n++) {
      Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      if (left >= 'A' && left <= 'Z')
        left += 'a' - 'A';
      if (right >= 'A' && right <= 'Z')
        right += 'a' - 'A';
      if (left != right || left == 0 || right == 0) {
        cmp = (Bit64s) left - (Bit64s) right;
        break;
      }
    }
    result = (Bit64u) cmp;
    op_name = "strcasecmp";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRNCASECMP) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    Bit64s cmp = 0;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      if (left >= 'A' && left <= 'Z')
        left += 'a' - 'A';
      if (right >= 'A' && right <= 'Z')
        right += 'a' - 'A';
      if (left != right || left == 0 || right == 0) {
        cmp = (Bit64s) left - (Bit64s) right;
        break;
      }
    }
    result = (Bit64u) cmp;
    op_name = "strncasecmp";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRCASESTR) {
    result = 0;
    Bit8u first = read_virtual_byte(BX_SEG_REG_DS, (bx_address) arg1);
    if (first >= 'A' && first <= 'Z')
      first += 'a' - 'A';
    if (first == 0) {
      result = arg0;
    }
    else {
      for (Bit64u n = 0; n < 4096; n++) {
        Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
        if (left >= 'A' && left <= 'Z')
          left += 'a' - 'A';
        if (left == 0)
          break;
        if (left != first)
          continue;

        bool matched = true;
        Bit64u m = 1;
        for (; m < 4096 - n; m++) {
          Bit8u needle = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + m));
          if (needle >= 'A' && needle <= 'Z')
            needle += 'a' - 'A';
          if (needle == 0)
            break;
          Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n + m));
          if (value >= 'A' && value <= 'Z')
            value += 'a' - 'A';
          if (value != needle || value == 0) {
            matched = false;
            break;
          }
        }
        if (m == 4096 - n)
          matched = false;
        if (matched) {
          result = arg0 + n;
          break;
        }
      }
    }
    op_name = "strcasestr";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_MEMCPY) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), value);
    }
    result = arg0;
    op_name = "memcpy";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_MEMMOVE) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    if (arg0 <= arg1) {
      for (Bit64u n = 0; n < count; n++) {
        Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
        write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), value);
      }
    }
    else {
      for (Bit64u n = count; n > 0; n--) {
        Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n - 1));
        write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n - 1), value);
      }
    }
    result = arg0;
    op_name = "memmove";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_MEMSET) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    Bit8u value = (Bit8u) arg1;
    for (Bit64u n = 0; n < count; n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), value);
    result = arg0;
    op_name = "memset";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_MEMCMP) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    Bit64s cmp = 0;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      if (left != right) {
        cmp = (Bit64s) left - (Bit64s) right;
        break;
      }
    }
    result = (Bit64u) cmp;
    op_name = "memcmp";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_MEMCHR) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    Bit8u needle = (Bit8u) arg1;
    result = 0;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      if (value == needle) {
        result = arg0 + n;
        break;
      }
    }
    op_name = "memchr";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRCHR) {
    Bit8u needle = (Bit8u) arg1;
    result = 0;
    for (Bit64u n = 0; n < 4096; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      if (value == needle) {
        result = arg0 + n;
        break;
      }
      if (value == 0)
        break;
    }
    op_name = "strchr";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRRCHR) {
    Bit8u needle = (Bit8u) arg1;
    result = 0;
    for (Bit64u n = 0; n < 4096; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      if (value == needle)
        result = arg0 + n;
      if (value == 0)
        break;
    }
    op_name = "strrchr";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRSTR) {
    result = 0;
    Bit8u first = read_virtual_byte(BX_SEG_REG_DS, (bx_address) arg1);
    if (first == 0) {
      result = arg0;
    }
    else {
      for (Bit64u n = 0; n < 4096; n++) {
        Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
        if (left == 0)
          break;
        if (left != first)
          continue;

        bool matched = true;
        Bit64u m = 1;
        for (; m < 4096 - n; m++) {
          Bit8u needle = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + m));
          if (needle == 0)
            break;
          Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n + m));
          if (value != needle || value == 0) {
            matched = false;
            break;
          }
        }
        if (m == 4096 - n)
          matched = false;
        if (matched) {
          result = arg0 + n;
          break;
        }
      }
    }
    op_name = "strstr";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRCPY) {
    for (Bit64u n = 0; n < 4096; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), value);
      if (value == 0)
        break;
    }
    result = arg0;
    op_name = "strcpy";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRNCPY) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    bool padding = false;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u value = 0;
      if (!padding) {
        value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
        if (value == 0)
          padding = true;
      }
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), value);
    }
    result = arg0;
    op_name = "strncpy";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRCAT) {
    Bit64u dest_len = 0;
    while (dest_len < 4096 &&
           read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + dest_len)) != 0)
      dest_len++;
    for (Bit64u n = 0; dest_len + n < 4096; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + dest_len + n), value);
      if (value == 0)
        break;
    }
    result = arg0;
    op_name = "strcat";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRNCAT) {
    Bit64u dest_len = 0;
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    while (dest_len < 4096 &&
           read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + dest_len)) != 0)
      dest_len++;
    Bit64u copied = 0;
    while (copied < count && dest_len + copied < 4095) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + copied));
      if (value == 0)
        break;
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + dest_len + copied), value);
      copied++;
    }
    if (dest_len + copied < 4096)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + dest_len + copied), 0);
    result = arg0;
    op_name = "strncat";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRSPN) {
    result = 0;
    for (; result < 4096; result++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + result));
      bool matched = false;
      if (value == 0)
        break;
      for (Bit64u n = 0; n < 4096; n++) {
        Bit8u accept = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
        if (accept == 0)
          break;
        if (accept == value) {
          matched = true;
          break;
        }
      }
      if (!matched)
        break;
    }
    op_name = "strspn";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRCSPN) {
    result = 0;
    for (; result < 4096; result++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + result));
      bool rejected = false;
      if (value == 0)
        break;
      for (Bit64u n = 0; n < 4096; n++) {
        Bit8u reject = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
        if (reject == 0)
          break;
        if (reject == value) {
          rejected = true;
          break;
        }
      }
      if (rejected)
        break;
    }
    op_name = "strcspn";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRPBRK) {
    result = 0;
    for (Bit64u offset = 0; offset < 4096; offset++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + offset));
      if (value == 0)
        break;
      for (Bit64u n = 0; n < 4096; n++) {
        Bit8u accept = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
        if (accept == 0)
          break;
        if (accept == value) {
          result = arg0 + offset;
          break;
        }
      }
      if (result != 0)
        break;
    }
    op_name = "strpbrk";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STPCPY) {
    result = arg0;
    for (Bit64u n = 0; n < 4096; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), value);
      if (value == 0) {
        result = arg0 + n;
        break;
      }
    }
    op_name = "stpcpy";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STPNCPY) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    bool padding = false;
    result = arg0 + count;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u value = 0;
      if (!padding) {
        value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
        if (value == 0) {
          padding = true;
          result = arg0 + n;
        }
      }
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), value);
    }
    op_name = "stpncpy";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_MEMPCPY) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), value);
    }
    result = arg0 + count;
    op_name = "mempcpy";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_RAWMEMCHR) {
    Bit8u needle = (Bit8u) arg1;
    result = 0;
    for (Bit64u n = 0; n < 4096; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      if (value == needle) {
        result = arg0 + n;
        break;
      }
    }
    op_name = "rawmemchr";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_STRCHRNUL) {
    Bit8u needle = (Bit8u) arg1;
    result = arg0;
    for (Bit64u n = 0; n < 4096; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      if (value == needle || value == 0) {
        result = arg0 + n;
        break;
      }
    }
    op_name = "strchrnul";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_BCMP) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    Bit64s cmp = 0;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
      Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      if (left != right) {
        cmp = (Bit64s) left - (Bit64s) right;
        break;
      }
    }
    result = (Bit64u) cmp;
    op_name = "bcmp";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_BCOPY) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    if (arg1 <= arg0) {
      for (Bit64u n = 0; n < count; n++) {
        Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n));
        write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n), value);
      }
    }
    else {
      for (Bit64u n = count; n > 0; n--) {
        Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n - 1));
        write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n - 1), value);
      }
    }
    result = arg1;
    op_name = "bcopy";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_BZERO) {
    Bit64u count = arg1 < 4096 ? arg1 : 4096;
    for (Bit64u n = 0; n < count; n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), 0);
    result = arg0;
    op_name = "bzero";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_MEMRCHR) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    Bit8u needle = (Bit8u) arg1;
    result = 0;
    for (Bit64u n = count; n > 0; n--) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n - 1));
      if (value == needle) {
        result = arg0 + n - 1;
        break;
      }
    }
    op_name = "memrchr";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_MEMMEM) {
    Bit64u haystack_len = arg1 < 4096 ? arg1 : 4096;
    Bit64u needle_len = arg3 < 4096 ? arg3 : 4096;
    result = 0;
    if (needle_len == 0) {
      result = arg0;
    }
    else if (needle_len <= haystack_len) {
      for (Bit64u n = 0; n <= haystack_len - needle_len; n++) {
        bool matched = true;
        for (Bit64u m = 0; m < needle_len; m++) {
          Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n + m));
          Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg2 + m));
          if (left != right) {
            matched = false;
            break;
          }
        }
        if (matched) {
          result = arg0 + n;
          break;
        }
      }
    }
    op_name = "memmem";
  }
  else if (import_id == BX_POLY_IMPORT_FUNC_X86_ADD ||
      bx_poly_import_is_x86_descriptor(import_id)) {
    if (R12 == 0 || !bx_poly_return_cookie_valid ||
        bx_poly_return_cookie_rsp < 32)
      return false;
    bx_address target = (bx_address) R12;
    bx_address trampoline = (bx_address) (R12 + BX_POLY_IMPORT_X86_ADD_HELPER_SIZE);
    if (bx_poly_import_is_x86_descriptor(import_id)) {
      Bit64u slot = import_id - BX_POLY_IMPORT_FUNC_X86_SLOT0;
      bx_address descriptor = (bx_address) (R12 +
        slot * BX_POLY_IMPORT_X86_DESCRIPTOR_SIZE);
      target = (bx_address) read_virtual_qword(BX_SEG_REG_DS, descriptor);
      trampoline = (bx_address) read_virtual_qword(BX_SEG_REG_DS,
        descriptor + 8);
      if (target == 0 || trampoline == 0)
        return false;
    }
    RDI = arg0;
    RSI = arg1;
    RDX = arg2;
    RCX = arg3;
    R8 = arg4;
    R9 = arg5;
    bx_address foreign_rsp = RSP;
    bx_address x86_rsp = bx_poly_return_cookie_rsp - 32;
    write_virtual_qword(BX_SEG_REG_SS, x86_rsp, trampoline);
    if (bx_poly_import_uses_x86_stack_args(import_id)) {
      write_virtual_qword(BX_SEG_REG_SS, x86_rsp + 8, arg6);
      write_virtual_qword(BX_SEG_REG_SS, x86_rsp + 16, arg7);
    }
    BX_INFO(("poly_raw: import x86 call mode=%u descriptor=%u target=%llx trampoline=%llx stack=%llx arg0=%llu arg1=%llu arg2=%llu arg3=%llu arg4=%llu arg5=%llu arg6=%llu arg7=%llu return=%llx",
      mode, (unsigned) import_id, (unsigned long long) target,
      (unsigned long long) trampoline, (unsigned long long) x86_rsp,
      (unsigned long long) arg0,
      (unsigned long long) arg1, (unsigned long long) arg2,
      (unsigned long long) arg3, (unsigned long long) arg4,
      (unsigned long long) arg5, (unsigned long long) arg6,
      (unsigned long long) arg7, (unsigned long long) return_rip));
    bx_poly_import_x86_return_valid = true;
    bx_poly_import_x86_return_mode = mode;
    bx_poly_import_x86_return_rip = return_rip;
    bx_poly_import_x86_return_rsp = foreign_rsp;
    bx_poly_current_mode = BX_POLY_MODE_X86;
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    RIP = target;
    RSP = x86_rsp;
    bx_poly_mode_switch_count++;
    BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    return true;
  }
  else
    return false;

  if (mode == BX_POLY_MODE_RAW_AARCH64)
    mapped = write_poly_aarch64_reg(0, result);
  else if (mode == BX_POLY_MODE_RAW_RISCV)
    mapped = write_poly_riscv_reg(10, result);

  if (!mapped)
    return false;

  if (return_poly_abi_call(mode, return_rip))
    return true;
  RIP = return_rip;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  BX_INFO(("poly_raw: import call mode=%u descriptor=%u op=%s target=%llx arg0=%llu arg1=%llu arg2=%llu result=%llu return=%llx",
    mode, (unsigned) import_id, op_name, (unsigned long long) target_rip,
    (unsigned long long) arg0, (unsigned long long) arg1,
    (unsigned long long) arg2,
    (unsigned long long) result, (unsigned long long) return_rip));
  return true;
}

bool BX_CPU_C::poly_raw_mode_active(void)
{
  if (!BX_CPU_THIS_PTR poly_feature_enabled || CPL != 3)
    return false;

  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  return bx_poly_is_raw_mode(bx_poly_current_mode);
}

bool BX_CPU_C::execute_poly_raw_aarch64(Bit32u insn, bx_address pc)
{
  bx_address next_rip = pc + 4;

  if (insn == 0xd503201f) {
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 nop"));
    return true;
  }

  if (insn == 0xd503305f) {
    bx_poly_aarch64_reservation_valid = false;
    bx_poly_aarch64_reservation_addr = 0;
    bx_poly_aarch64_reservation_size = 0;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 clrex"));
    return true;
  }

  if ((insn & 0xffffffe0) == 0xd53bd040) {
    Bit32u rd = insn & 0x1f;
    if (!write_poly_aarch64_reg(rd, bx_poly_foreign_tls_base))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 mrs x%u,tpidr_el0 value=%llx",
      rd, (unsigned long long) bx_poly_foreign_tls_base));
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
      op_name = "fadd.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits(bx_poly_fp32_from_bits(left32_bits) + bx_poly_fp32_from_bits(right32_bits));
    }
    else if ((insn & 0xffe0fc00) == 0x1e203800) {
      op_name = "fsub.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits(bx_poly_fp32_from_bits(left32_bits) - bx_poly_fp32_from_bits(right32_bits));
    }
    else if ((insn & 0xffe0fc00) == 0x1e200800) {
      op_name = "fmul.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits(bx_poly_fp32_from_bits(left32_bits) * bx_poly_fp32_from_bits(right32_bits));
    }
    else if ((insn & 0xffe0fc00) == 0x1e201800) {
      op_name = "fdiv.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits(bx_poly_fp32_from_bits(left32_bits) / bx_poly_fp32_from_bits(right32_bits));
    }
    else if ((insn & 0xffe0fc00) == 0x1e207800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fminnm.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_min(left32_bits, right32_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e206800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmaxnm.s";
      fp32_op = true;
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right32_bits))
        return false;
      result32_bits = f32_max(left32_bits, right32_bits, &status);
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
      op_name = "fcvt.s.d";
      fp32_op = true;
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits((float) bx_poly_fp64_from_bits(left_bits));
    }
    else if ((insn & 0xffe0fc00) == 0x1e602800) {
      op_name = "fadd.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits(bx_poly_fp64_from_bits(left_bits) + bx_poly_fp64_from_bits(right_bits));
    }
    else if ((insn & 0xffe0fc00) == 0x1e603800) {
      op_name = "fsub.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits(bx_poly_fp64_from_bits(left_bits) - bx_poly_fp64_from_bits(right_bits));
    }
    else if ((insn & 0xffe0fc00) == 0x1e600800) {
      op_name = "fmul.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits(bx_poly_fp64_from_bits(left_bits) * bx_poly_fp64_from_bits(right_bits));
    }
    else if ((insn & 0xffe0fc00) == 0x1e601800) {
      op_name = "fdiv.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits(bx_poly_fp64_from_bits(left_bits) / bx_poly_fp64_from_bits(right_bits));
    }
    else if ((insn & 0xffe0fc00) == 0x1e607800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fminnm.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_min(left_bits, right_bits, &status);
    }
    else if ((insn & 0xffe0fc00) == 0x1e606800) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmaxnm.d";
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      result_bits = f64_max(left_bits, right_bits, &status);
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
      op_name = "fcvt.d.s";
      if (!read_poly_aarch64_fp32_reg(rn, &left32_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits((double) bx_poly_fp32_from_bits(left32_bits));
    }
    else if ((insn & 0xfffffc00) == 0x5e21d800 ||
             (insn & 0xfffffc00) == 0x7e21d800 ||
             (insn & 0xfffffc00) == 0x5e61d800 ||
             (insn & 0xfffffc00) == 0x7e61d800) {
      Bit32u op = insn & 0xfffffc00;
      bool is_unsigned = (op & 0x20000000) != 0;
      fp32_op = (op & 0x00400000) == 0;
      op_name = is_unsigned ? "ucvtf" : "scvtf";

      if (fp32_op) {
        if (!read_poly_aarch64_fp32_reg(rn, &left32_bits))
          return false;
        result32_bits = is_unsigned ?
          bx_poly_fp32_to_bits((float) (Bit32u) left32_bits) :
          bx_poly_fp32_to_bits((float) (Bit32s) left32_bits);
      }
      else {
        if (!read_poly_aarch64_fp64_reg(rn, &left_bits))
          return false;
        result_bits = is_unsigned ?
          bx_poly_fp64_to_bits((double) left_bits) :
          bx_poly_fp64_to_bits((double) (Bit64s) left_bits);
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
        double source_value = (double) bx_poly_fp32_from_bits(left32_bits);
        result32_bits = is_unsigned ?
          bx_poly_fp64_to_uint32_rtz(source_value) :
          (Bit32u) bx_poly_fp64_to_int32_rtz(source_value);
      }
      else {
        if (!read_poly_aarch64_fp64_reg(rn, &left_bits))
          return false;
        double source_value = bx_poly_fp64_from_bits(left_bits);
        result_bits = is_unsigned ?
          bx_poly_fp64_to_uint64_rtz(source_value) :
          bx_poly_fp64_to_int64_rtz(source_value);
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
    if (output_double) {
      Bit64u result_bits = is_unsigned ?
        bx_poly_fp64_to_bits(input_64 ? (double) value : (double) (Bit32u) value) :
        bx_poly_fp64_to_bits(input_64 ? (double) (Bit64s) value : (double) (Bit32s) (Bit32u) value);
      if (!write_poly_aarch64_fp64_reg(rd, result_bits))
        return false;
    }
    else {
      Bit32u result_bits = is_unsigned ?
        bx_poly_fp32_to_bits(input_64 ? (float) value : (float) (Bit32u) value) :
        bx_poly_fp32_to_bits(input_64 ? (float) (Bit64s) value : (float) (Bit32s) (Bit32u) value);
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

    if (fp32_op) {
      Bit32u left_bits = 0;
      Bit32u right_bits = 0;
      if (!read_poly_aarch64_fp32_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp32_reg(rm, &right_bits))
        return false;
      bx_poly_aarch64_set_fp32_compare_nzcv(
        bx_poly_fp32_from_bits(left_bits), bx_poly_fp32_from_bits(right_bits));
    }
    else {
      Bit64u left_bits = 0;
      Bit64u right_bits = 0;
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits) ||
          !read_poly_aarch64_fp64_reg(rm, &right_bits))
        return false;
      bx_poly_aarch64_set_fp64_compare_nzcv(
        bx_poly_fp64_from_bits(left_bits), bx_poly_fp64_from_bits(right_bits));
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
    double source_value = source_fp32 ?
      (double) bx_poly_fp32_from_bits(fp32_bits) : bx_poly_fp64_from_bits(fp_bits);
    if (is_64)
      result = is_signed ?
        bx_poly_fp64_to_int64_rtz(source_value) :
        bx_poly_fp64_to_uint64_rtz(source_value);
    else
      result = is_signed ?
        (Bit32u) bx_poly_fp64_to_int32_rtz(source_value) :
        bx_poly_fp64_to_uint32_rtz(source_value);
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

    if (fp32_op) {
      Bit32u left_bits = 0;
      if (!read_poly_aarch64_fp32_reg(rn, &left_bits))
        return false;
      bx_poly_aarch64_set_fp32_compare_nzcv(
        bx_poly_fp32_from_bits(left_bits), 0.0f);
    }
    else {
      Bit64u left_bits = 0;
      if (!read_poly_aarch64_fp64_reg(rn, &left_bits))
        return false;
      bx_poly_aarch64_set_fp64_compare_nzcv(
        bx_poly_fp64_from_bits(left_bits), 0.0);
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

    if (rn != rm)
      return false;
    if (!read_poly_aarch64_fp128_reg(rn, &lo, &hi) ||
        !write_poly_aarch64_fp128_reg(rd, lo, hi))
      return false;

    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 mov v%u.16b,v%u.16b", rd, rn));
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

  if (insn == (0xd4200000 | (BX_POLY_AARCH64_BRK_X86_ESCAPE << 5))) {
    bx_poly_current_mode = BX_POLY_MODE_X86;
    bx_poly_clear_cross_return_stack();
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = next_rip;
    BX_INFO(("poly_raw: aarch64 brk #0x%x escape to x86", BX_POLY_AARCH64_BRK_X86_ESCAPE));
    return true;
  }

  if (insn == (0xd4200000 | (BX_POLY_AARCH64_BRK_RISCV_SWITCH << 5))) {
    bx_poly_current_mode = BX_POLY_MODE_RAW_RISCV;
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = next_rip;
    BX_INFO(("poly_raw: aarch64 brk #0x%x switch to riscv", BX_POLY_AARCH64_BRK_RISCV_SWITCH));
    return true;
  }

  if (insn == (0xd4200000 | (BX_POLY_AARCH64_BRK_RISCV_CALL << 5))) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64,
      BX_POLY_MODE_RAW_RISCV, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_DEFAULT);
  }

  if (insn == (0xd4200000 | (BX_POLY_AARCH64_BRK_RISCV_CALL_COMPACT_U32_F32 << 5)) ||
      insn == (0xd4200000 | (BX_POLY_AARCH64_BRK_RISCV_CALL_COMPACT_F32_U32 << 5))) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &return_rip))
      return false;
    Bit32u bridge_kind =
      insn == (0xd4200000 | (BX_POLY_AARCH64_BRK_RISCV_CALL_COMPACT_U32_F32 << 5)) ?
      BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 :
      BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64,
      BX_POLY_MODE_RAW_RISCV, (bx_address) target, (bx_address) return_rip,
      bridge_kind);
  }

  if (insn == (0xd4200000 | (BX_POLY_AARCH64_BRK_RISCV_CALL_FP64_STACK << 5))) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_aarch64_reg(16, &target) ||
        !read_poly_aarch64_reg(17, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_AARCH64,
      BX_POLY_MODE_RAW_RISCV, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_FP64_STACK);
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
    }

    if (op_name != 0) {
      Bit32u rt = insn & 0x1f;
      Bit32u rn = (insn >> 5) & 0x1f;
      Bit32u rt2 = (insn >> 10) & 0x1f;
      Bit32u scale = is_double ? 3 : 2;
      Bit64s offset = bx_poly_sign_extend((insn >> 15) & 0x7f, 7) << scale;
      Bit64u base = 0;

      if (rn == 31)
        base = RSP;
      else if (!read_poly_aarch64_reg(rn, &base))
        return false;

      bx_address addr = (bx_address) (post_index ? base : base + offset);
      if (is_load) {
        if (is_double) {
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
        if (is_double) {
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
    Bit64u syscall_value = 0, arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0;
    if (!read_poly_aarch64_reg(8, &syscall_value) ||
        !read_poly_aarch64_reg(0, &arg0) ||
        !read_poly_aarch64_reg(1, &arg1) ||
        !read_poly_aarch64_reg(2, &arg2) ||
        !read_poly_aarch64_reg(3, &arg3) ||
        !read_poly_aarch64_reg(4, &arg4) ||
        !read_poly_aarch64_reg(5, &arg5))
      return false;
    Bit32u syscall_reg = (Bit32u) syscall_value;
    Bit32u status_number = syscall_reg ? syscall_reg : syscall_id;
    return handle_poly_foreign_syscall("aarch64", "svc", "#", syscall_reg,
      status_number, syscall_id, arg0, arg1, arg2, arg3, arg4, arg5, next_rip);
  }

  if ((insn & 0xffe0001f) == 0xd4200000) {
    Bit32u libcall_id = (insn >> 5) & 0xffff;
    Bit64u arg1 = 0, arg2 = 0;
    if (!read_poly_aarch64_reg(2, &arg1) || !read_poly_aarch64_reg(3, &arg2))
      return false;
    handle_poly_libcall("aarch64", "brk", libcall_id, pc, arg1, arg2);
    RIP = next_rip;
    return true;
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

  if (insn == BX_POLY_RISCV_X86_ESCAPE) {
    bx_poly_current_mode = BX_POLY_MODE_X86;
    bx_poly_clear_cross_return_stack();
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = next_rip;
    BX_INFO(("poly_raw: riscv custom-0 escape to x86"));
    return true;
  }

  if (insn == BX_POLY_RISCV_AARCH64_SWITCH) {
    bx_poly_current_mode = BX_POLY_MODE_RAW_AARCH64;
    bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    bx_poly_mode_switch_count++;
    RIP = next_rip;
    BX_INFO(("poly_raw: riscv custom-1 switch to aarch64"));
    return true;
  }

  if (insn == BX_POLY_RISCV_AARCH64_CALL) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV,
      BX_POLY_MODE_RAW_AARCH64, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_DEFAULT);
  }

  if (insn == BX_POLY_RISCV_AARCH64_CALL_COMPACT_U32_F32 ||
      insn == BX_POLY_RISCV_AARCH64_CALL_COMPACT_F32_U32) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &return_rip))
      return false;
    Bit32u bridge_kind =
      insn == BX_POLY_RISCV_AARCH64_CALL_COMPACT_U32_F32 ?
      BX_POLY_CROSS_BRIDGE_COMPACT_U32_F32 :
      BX_POLY_CROSS_BRIDGE_COMPACT_F32_U32;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV,
      BX_POLY_MODE_RAW_AARCH64, (bx_address) target, (bx_address) return_rip,
      bridge_kind);
  }

  if (insn == BX_POLY_RISCV_AARCH64_CALL_FP64_STACK) {
    Bit64u target = 0;
    Bit64u return_rip = 0;
    if (!read_poly_riscv_reg(5, &target) ||
        !read_poly_riscv_reg(6, &return_rip))
      return false;
    return enter_poly_cross_call(BX_POLY_MODE_RAW_RISCV,
      BX_POLY_MODE_RAW_AARCH64, (bx_address) target, (bx_address) return_rip,
      BX_POLY_CROSS_BRIDGE_FP64_STACK);
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
    softfloat_status_t status = bx_poly_softfloat_status();

    if (opcode == 0x43 || opcode == 0x47 ||
        opcode == 0x4b || opcode == 0x4f) {
      if (rm > 4 && rm != 7)
        return false;

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
        if (!write_poly_riscv_fp32_reg(rd,
              f32_mulAdd(product_left, product_right, addend, op, &status)))
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
        if (!write_poly_riscv_fp64_reg(rd,
              f64_mulAdd(product_left, product_right, addend, op, &status)))
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
      op_name = "fadd.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits(bx_poly_fp32_from_bits(left32_bits) + bx_poly_fp32_from_bits(right32_bits));
    }
    else if (funct7 == 0x04) {
      op_name = "fsub.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits(bx_poly_fp32_from_bits(left32_bits) - bx_poly_fp32_from_bits(right32_bits));
    }
    else if (funct7 == 0x08) {
      op_name = "fmul.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits(bx_poly_fp32_from_bits(left32_bits) * bx_poly_fp32_from_bits(right32_bits));
    }
    else if (funct7 == 0x0c) {
      op_name = "fdiv.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits(bx_poly_fp32_from_bits(left32_bits) / bx_poly_fp32_from_bits(right32_bits));
    }
    else if (funct7 == 0x14 && rm == 0) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmin.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = f32_min(left32_bits, right32_bits, &status);
    }
    else if (funct7 == 0x14 && rm == 1) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmax.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
          !read_poly_riscv_fp32_reg(rs2, &right32_bits))
        return false;
      result32_bits = f32_max(left32_bits, right32_bits, &status);
    }
    else if (funct7 == 0x01) {
      op_name = "fadd.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits(bx_poly_fp64_from_bits(left_bits) + bx_poly_fp64_from_bits(right_bits));
    }
    else if (funct7 == 0x05) {
      op_name = "fsub.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits(bx_poly_fp64_from_bits(left_bits) - bx_poly_fp64_from_bits(right_bits));
    }
    else if (funct7 == 0x09) {
      op_name = "fmul.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits(bx_poly_fp64_from_bits(left_bits) * bx_poly_fp64_from_bits(right_bits));
    }
    else if (funct7 == 0x0d) {
      op_name = "fdiv.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits(bx_poly_fp64_from_bits(left_bits) / bx_poly_fp64_from_bits(right_bits));
    }
    else if (funct7 == 0x15 && rm == 0) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmin.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = f64_min(left_bits, right_bits, &status);
    }
    else if (funct7 == 0x15 && rm == 1) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fmax.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
          !read_poly_riscv_fp64_reg(rs2, &right_bits))
        return false;
      result_bits = f64_max(left_bits, right_bits, &status);
    }
    else if (funct7 == 0x2c && rs2 == 0) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fsqrt.s";
      fp32_op = true;
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits))
        return false;
      result32_bits = f32_sqrt(left32_bits, &status);
    }
    else if (funct7 == 0x2d && rs2 == 0) {
      softfloat_status_t status = bx_poly_softfloat_status();
      op_name = "fsqrt.d";
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits))
        return false;
      result_bits = f64_sqrt(left_bits, &status);
    }
    else if (funct7 == 0x20 && rs2 == 1) {
      op_name = "fcvt.s.d";
      fp32_op = true;
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits))
        return false;
      result32_bits = bx_poly_fp32_to_bits((float) bx_poly_fp64_from_bits(left_bits));
    }
    else if (funct7 == 0x21 && rs2 == 0) {
      op_name = "fcvt.d.s";
      if (!read_poly_riscv_fp32_reg(rs1, &left32_bits))
        return false;
      result_bits = bx_poly_fp64_to_bits((double) bx_poly_fp32_from_bits(left32_bits));
    }
    else if ((funct7 == 0x68 || funct7 == 0x69) && rs2 <= 3) {
      Bit64u value = 0;
      bool source_64 = rs2 >= 2;
      bool is_unsigned = (rs2 & 1) != 0;
      fp32_op = funct7 == 0x68;

      if (!read_poly_riscv_reg(rs1, &value))
        return false;
      if (fp32_op) {
        result32_bits = is_unsigned ?
          bx_poly_fp32_to_bits(source_64 ? (float) value : (float) (Bit32u) value) :
          bx_poly_fp32_to_bits(source_64 ? (float) (Bit64s) value : (float) (Bit32s) (Bit32u) value);
      }
      else {
        result_bits = is_unsigned ?
          bx_poly_fp64_to_bits(source_64 ? (double) value : (double) (Bit32u) value) :
          bx_poly_fp64_to_bits(source_64 ? (double) (Bit64s) value : (double) (Bit32s) (Bit32u) value);
      }
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
      if (rm != 1)
        return false;
      bool source_fp32 = funct7 == 0x60;
      if (source_fp32) {
        if (!read_poly_riscv_fp32_reg(rs1, &left32_bits))
          return false;
      }
      else if (!read_poly_riscv_fp64_reg(rs1, &left_bits))
        return false;
      double source_value = source_fp32 ?
        (double) bx_poly_fp32_from_bits(left32_bits) : bx_poly_fp64_from_bits(left_bits);
      bool is_64 = rs2 >= 2;
      bool is_signed = (rs2 & 1) == 0;
      Bit64u result = 0;
      if (is_64) {
        result = is_signed ?
          bx_poly_fp64_to_int64_rtz(source_value) :
          bx_poly_fp64_to_uint64_rtz(source_value);
      }
      else {
        result = is_signed ?
          bx_poly_fp64_to_int32_rtz(source_value) :
          (Bit64u) (Bit64s) (Bit32s) bx_poly_fp64_to_uint32_rtz(source_value);
      }
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
      if (fp32_cmp) {
        if (!read_poly_riscv_fp32_reg(rs1, &left32_bits) ||
            !read_poly_riscv_fp32_reg(rs2, &right32_bits))
          return false;
        float left = bx_poly_fp32_from_bits(left32_bits);
        float right = bx_poly_fp32_from_bits(right32_bits);
        if (left != left || right != right)
          result = 0;
        else if (rm == 0)
          result = left <= right;
        else if (rm == 1)
          result = left < right;
        else if (rm == 2)
          result = left == right;
        else
          return false;
      }
      else {
        if (!read_poly_riscv_fp64_reg(rs1, &left_bits) ||
            !read_poly_riscv_fp64_reg(rs2, &right_bits))
          return false;
        double left = bx_poly_fp64_from_bits(left_bits);
        double right = bx_poly_fp64_from_bits(right_bits);
        if (left != left || right != right)
          result = 0;
        else if (rm == 0)
          result = left <= right;
        else if (rm == 1)
          result = left < right;
        else if (rm == 2)
          result = left == right;
        else
          return false;
      }
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
    Bit64u base = 0;
    Bit32u result32 = 0;
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

    if (op_name == 0)
      return false;
    Bit64u result = (Bit64u) bx_poly_sign_extend(result32, 32);
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

    if (op_name == 0)
      return false;
    Bit64u result = (Bit64u) bx_poly_sign_extend(result32, 32);
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

    if (csr == 0x001 && funct3 == 0x2 && rs1 == 0) {
      if (!write_poly_riscv_reg(rd, 0))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv frflags x%u", rd));
      return true;
    }

    if (csr == 0x001 && funct3 == 0x1 && rd == 0) {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv fsflags x%u", rs1));
      return true;
    }
  }

  if (insn == 0x00000073) {
    Bit64u syscall_value = 0, arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0;
    if (!read_poly_riscv_reg(17, &syscall_value) ||
        !read_poly_riscv_reg(10, &arg0) ||
        !read_poly_riscv_reg(11, &arg1) ||
        !read_poly_riscv_reg(12, &arg2) ||
        !read_poly_riscv_reg(13, &arg3) ||
        !read_poly_riscv_reg(14, &arg4) ||
        !read_poly_riscv_reg(15, &arg5))
      return false;
    Bit32u syscall_number = (Bit32u) syscall_value;
    return handle_poly_foreign_syscall("riscv", "ecall", "a7=", syscall_number,
      syscall_number, syscall_number, arg0, arg1, arg2, arg3, arg4, arg5, next_rip);
  }

  if (insn == 0x00100073) {
    Bit64u libcall_id = 0, arg1 = 0, arg2 = 0;
    if (!read_poly_riscv_reg(17, &libcall_id) ||
        !read_poly_riscv_reg(12, &arg1) ||
        !read_poly_riscv_reg(13, &arg2))
      return false;
    handle_poly_libcall("riscv", "ebreak", (Bit32u) libcall_id, pc, arg1, arg2);
    RIP = next_rip;
    return true;
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
      if (rd == 0 || !write_poly_riscv_reg(rd, (Bit64u) imm))
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
        if (rd == 0 || !read_poly_riscv_reg(rs2, &value) ||
            !write_poly_riscv_reg(rd, value))
          return false;
        RIP = next_rip;
        BX_DEBUG(("poly_raw: emulated riscv c.mv x%u,x%u value=%llu", rd, rs2, (unsigned long long) value));
        return true;
      }
      if (high && rs2 == 0 && rd == 0) {
        Bit64u libcall_id = 0, arg1 = 0, arg2 = 0;
        if (!read_poly_riscv_reg(17, &libcall_id) ||
            !read_poly_riscv_reg(12, &arg1) ||
            !read_poly_riscv_reg(13, &arg2))
          return false;
        handle_poly_libcall("riscv", "c.ebreak", (Bit32u) libcall_id, pc, arg1, arg2);
        RIP = next_rip;
        return true;
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
  Bit32u insn = 0;
  bool handled = false;

  if (bx_poly_current_mode == BX_POLY_MODE_RAW_AARCH64) {
    insn = read_virtual_dword(BX_SEG_REG_CS, pc);
    bx_poly_foreign_insn_count++;
    handled = execute_poly_raw_aarch64(insn, pc);
  }
  else if (bx_poly_current_mode == BX_POLY_MODE_RAW_RISCV) {
    Bit16u half = read_virtual_word(BX_SEG_REG_CS, pc);
    bx_poly_foreign_insn_count++;
    if ((half & 0x3) != 0x3) {
      insn = half;
      handled = execute_poly_raw_riscv_compressed(half, pc);
    }
    else {
      insn = read_virtual_dword(BX_SEG_REG_CS, pc);
      handled = execute_poly_raw_riscv(insn, pc);
    }
  }

  if (!handled) {
    BX_INFO(("poly_raw: unhandled mode=%u rip=%llx insn=%08x", bx_poly_current_mode, (unsigned long long) pc, insn));
    bx_poly_current_mode = BX_POLY_MODE_X86;
    bx_poly_clear_cross_return_stack();
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    exception(BX_UD_EXCEPTION, 0);
  }
}

struct bx_poly_scalar_syscall_entry {
  Bit32u number;
  Bit64u result;
  const char *name;
  const char *result_name;
  bool require_arg0_zero;
};

static const bx_poly_scalar_syscall_entry bx_poly_scalar_syscalls[] = {
  { 25, 0, "fcntl", "result", false },
  { 29, 0, "ioctl", "result", false },
  { 48, 0, "faccessat", "result", false },
  { 96, 4243, "set_tid_address", "tid", false },
  { 98, 0, "futex", "result", false },
  { 99, 0, "set_robust_list", "result", false },
  { 134, 0, "rt_sigaction", "result", false },
  { 135, 0, "rt_sigprocmask", "result", false },
  { 155, 4242, "getpgid", "pgid", true },
  { 156, 4242, "getsid", "sid", true },
  { 172, 4242, "getpid", "pid", false },
  { 173, 4241, "getppid", "ppid", false },
  { 174, 1000, "getuid", "uid", false },
  { 175, 1000, "geteuid", "euid", false },
  { 176, 1000, "getgid", "gid", false },
  { 177, 1000, "getegid", "egid", false },
  { 178, 4243, "gettid", "tid", false },
  { 233, 0, "madvise", "result", false },
  { 293, 0, "rseq", "result", false }
};

static bool bx_poly_lookup_scalar_syscall(Bit32u number, Bit64u arg0, const bx_poly_scalar_syscall_entry **entry)
{
  for (unsigned n = 0; n < sizeof(bx_poly_scalar_syscalls) / sizeof(bx_poly_scalar_syscalls[0]); n++) {
    if (bx_poly_scalar_syscalls[n].number != number)
      continue;
    if (bx_poly_scalar_syscalls[n].require_arg0_zero && arg0 != 0)
      return false;
    *entry = &bx_poly_scalar_syscalls[n];
    return true;
  }
  return false;
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::BxError(bxInstruction_c *i)
{
  unsigned ia_opcode = i->getIaOpcode();

  if (BX_CPU_THIS_PTR poly_feature_enabled && handle_poly_ud(i)) {
    BX_DEBUG(("poly opcode emulated from #UD"));
    return;
  }

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
  if (BX_CPU_THIS_PTR poly_feature_enabled) {
    BX_INFO(("UndefinedOpcode(poly): CPL=%u prev_rip=%llx rip=%llx", CPL, (unsigned long long) BX_CPU_THIS_PTR prev_rip, (unsigned long long) RIP));
  }

  if (BX_CPU_THIS_PTR poly_feature_enabled && handle_poly_ud(i)) {
    BX_DEBUG(("poly opcode emulated from #UD"));
    return;
  }

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
  if (BX_CPU_THIS_PTR poly_feature_enabled && handle_poly_ud(i))
    return;

  BX_DEBUG(("POLYMODE: invalid or disabled poly opcode - signalling #UD"));
  exception(BX_UD_EXCEPTION, 0);

  BX_NEXT_TRACE(i); // keep compiler happy
}

bool BX_CPU_C::handle_poly_exit_syscall(const char *arch_name, Bit32u syscall_number)
{
  if (syscall_number != 93 && syscall_number != 94)
    return false;

  Bit64u exit_code = RAX;
  bx_address ret_addr = (bx_address) read_virtual_qword(BX_SEG_REG_SS, RSP);
  RSP += 8;
  RAX = exit_code;
  bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_clear_cross_return_stack();
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  RIP = ret_addr;
  BX_INFO(("poly_ud: emulated %s %s code=%llu rip=%llx", arch_name,
    syscall_number == 94 ? "exit_group" : "exit",
    (unsigned long long) exit_code, (unsigned long long) ret_addr));
  return true;
}

void BX_CPU_C::handle_poly_unknown_syscall(const char *arch_name, const char *trap_name,
  const char *number_prefix, Bit32u syscall_number)
{
  RAX = 0x53000000 | (syscall_number << 8) | bx_poly_current_mode;
  BX_INFO(("poly_ud: emulated %s %s %s%u mode=%u", arch_name, trap_name, number_prefix, syscall_number, bx_poly_current_mode));
}

bool BX_CPU_C::handle_poly_foreign_syscall(const char *arch_name, const char *trap_name,
  const char *number_prefix, Bit32u dispatch_number, Bit32u status_number,
  Bit32u unknown_number, Bit64u arg0, Bit64u arg1, Bit64u arg2, Bit64u arg3,
  Bit64u arg4, Bit64u arg5, bx_address next_rip)
{
  const bx_poly_scalar_syscall_entry *scalar_syscall = 0;
  bx_poly_last_syscall_mode = bx_poly_current_mode;
  bx_poly_last_syscall_number = status_number;
  bx_poly_foreign_syscall_count++;
  bx_poly_record_trap(BX_POLY_TRAP_SYSCALL, bx_poly_current_mode, status_number,
    RIP, arg0, arg1, arg2, arg3, arg4, arg5);

  if (handle_poly_file_syscall(arch_name, dispatch_number, arg0, arg1, arg2, arg3, arg4, arg5)) {
  }
  else if (handle_poly_memory_syscall(arch_name, dispatch_number, arg0, arg1, arg2, arg3, arg4, arg5)) {
  }
  else if (handle_poly_process_syscall(arch_name, dispatch_number, arg0, arg1, arg2, arg3, arg4, arg5)) {
  }
  else if (bx_poly_lookup_scalar_syscall(dispatch_number, arg0, &scalar_syscall)) {
    RAX = scalar_syscall->result;
    BX_INFO(("poly_ud: emulated %s %s %s=%llu", arch_name, scalar_syscall->name, scalar_syscall->result_name, (unsigned long long) RAX));
  }
  else if (handle_poly_exit_syscall(arch_name, dispatch_number)) {
    return true;
  }
  else {
    handle_poly_unknown_syscall(arch_name, trap_name, number_prefix, unknown_number);
  }

  RIP = next_rip;
  return true;
}

bool BX_CPU_C::handle_poly_libcall(const char *arch_name, const char *trap_name,
  Bit32u libcall_id, bx_address trap_pc, Bit64u arg1, Bit64u arg2)
{
  bx_poly_last_libcall_mode = bx_poly_current_mode;
  bx_poly_last_libcall_number = libcall_id;
  bx_poly_foreign_libcall_count++;
  bx_poly_record_trap(BX_POLY_TRAP_BREAK, bx_poly_current_mode, libcall_id,
    trap_pc, RDI, arg1, arg2, 0, 0, 0);

  if (libcall_id == 1) {
    RAX = 0;
    while (RAX < 4096 && read_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + RAX)) != 0)
      RAX++;
    BX_INFO(("poly_ud: emulated %s %s strlen addr=%llx len=%llu", arch_name, trap_name, (unsigned long long) RDI, (unsigned long long) RAX));
  }
  else if (libcall_id == 2) {
    Bit64u count = RAX < 4096 ? RAX : 4096;
    Bit8u value = (Bit8u) arg1;
    for (Bit64u n = 0; n < count; n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + n), value);
    RAX = count;
    BX_INFO(("poly_ud: emulated %s %s memfill addr=%llx count=%llu value=%u", arch_name, trap_name, (unsigned long long) RDI, (unsigned long long) count, value));
  }
  else if (libcall_id == 3) {
    Bit64u count = arg2 < 4096 ? arg2 : 4096;
    Bit64s result = 0;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + n));
      Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      if (left != right) {
        result = (Bit64s) left - (Bit64s) right;
        break;
      }
    }
    RAX = (Bit64u) result;
    BX_INFO(("poly_ud: emulated %s %s memcmp left=%llx right=%llx count=%llu result=%lld", arch_name, trap_name, (unsigned long long) RDI, (unsigned long long) arg1, (unsigned long long) count, (long long) result));
  }
  else if (libcall_id == 4) {
    Bit64u count = RAX < 4096 ? RAX : 4096;
    for (Bit64u n = 0; n < count; n++) {
      Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + n), value);
    }
    RAX = count;
    BX_INFO(("poly_ud: emulated %s %s memcpy dest=%llx src=%llx count=%llu", arch_name, trap_name, (unsigned long long) RDI, (unsigned long long) arg1, (unsigned long long) count));
  }
  else {
    RAX = 0x4c000000 | (bx_poly_current_mode << 8) | libcall_id;
    BX_INFO(("poly_ud: emulated %s %s #%u libcall mode=%u", arch_name, trap_name, libcall_id, bx_poly_current_mode));
  }

  return true;
}

bool BX_CPU_C::handle_poly_process_syscall(const char *arch_name, Bit32u syscall_number,
  Bit64u arg0, Bit64u arg1, Bit64u arg2, Bit64u arg3, Bit64u arg4, Bit64u arg5)
{
  (void) arg4;
  (void) arg5;

  if (syscall_number == 90) {
    if (arg1 != 0) {
      for (unsigned n = 0; n < 6; n++)
        write_virtual_dword(BX_SEG_REG_DS, (bx_address) (arg1 + n * 4), 0);
    }
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s capget hdr=%llx data=%llx result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 91) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s capset hdr=%llx data=%llx result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 100) {
    if (arg1)
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 0);
    if (arg2)
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg2, 24);
    RAX = (arg1 && arg2) ? 0 : (Bit64u) -14;
    BX_INFO(("poly_ud: emulated %s get_robust_list pid=%llu head=%llx len=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 92) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s personality persona=%llx result=0", arch_name, (unsigned long long) arg0));
    return true;
  }

  if (syscall_number == 95) {
    RAX = (Bit64u) -10;
    BX_INFO(("poly_ud: emulated %s waitid idtype=%llu id=%llu infop=%llx options=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 129 || syscall_number == 130 || syscall_number == 131) {
    const char *name = syscall_number == 129 ? "kill" :
      syscall_number == 130 ? "tkill" : "tgkill";
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s %s arg0=%lld arg1=%lld arg2=%lld result=0", arch_name, name, (long long) arg0, (long long) arg1, (long long) arg2));
    return true;
  }

  if (syscall_number == 132) {
    if (arg1) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 0);
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 2);
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) (arg1 + 12), 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 16), 0);
    }
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s sigaltstack new=%llx old=%llx result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 260) {
    RAX = (Bit64u) -10;
    BX_INFO(("poly_ud: emulated %s wait4 pid=%lld status=%llx options=%llx rusage=%llx result=%lld", arch_name, (long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 140) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s setpriority which=%llu who=%llu prio=%llu result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2));
    return true;
  }

  if (syscall_number == 141) {
    RAX = 20;
    BX_INFO(("poly_ud: emulated %s getpriority which=%llu who=%llu result=20", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 154) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s setpgid pid=%llu pgid=%llu result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 157) {
    RAX = 4242;
    BX_INFO(("poly_ud: emulated %s setsid sid=4242", arch_name));
    return true;
  }

  if (syscall_number == 166) {
    RAX = 022;
    BX_INFO(("poly_ud: emulated %s umask mask=%llo previous=%llo", arch_name, (unsigned long long) arg0, (unsigned long long) RAX));
    return true;
  }

  if (syscall_number == 167) {
    if (arg0 == 16 && arg1 != 0) {
      const char name[] = "poly";
      for (unsigned n = 0; n < sizeof(name); n++)
        write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n), (Bit8u) name[n]);
    }
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s prctl option=%llu arg1=%llx result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 143 || syscall_number == 144 || syscall_number == 145 ||
      syscall_number == 146 || syscall_number == 147 || syscall_number == 149 ||
      syscall_number == 159) {
    const char *name = syscall_number == 143 ? "setregid" :
      syscall_number == 144 ? "setgid" :
      syscall_number == 145 ? "setreuid" :
      syscall_number == 146 ? "setuid" :
      syscall_number == 147 ? "setresuid" :
      syscall_number == 149 ? "setresgid" : "setgroups";
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s %s arg0=%llu arg1=%llu arg2=%llu result=0", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2));
    return true;
  }

  if (syscall_number == 148 || syscall_number == 150) {
    const char *name = syscall_number == 148 ? "getresuid" : "getresgid";
    if (arg0 == 0 || arg1 == 0 || arg2 == 0) {
      RAX = (Bit64u) -14;
      BX_INFO(("poly_ud: emulated %s %s invalid addrs=%llx,%llx,%llx result=%lld", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
      return true;
    }
    write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg0, 1000);
    write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg1, 1000);
    write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg2, 1000);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s %s addrs=%llx,%llx,%llx value=1000 result=0", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2));
    return true;
  }

  if (syscall_number == 151 || syscall_number == 152) {
    RAX = 1000;
    BX_INFO(("poly_ud: emulated %s %s id=%llu previous=1000", arch_name, syscall_number == 151 ? "setfsuid" : "setfsgid", (unsigned long long) arg0));
    return true;
  }

  if (syscall_number == 158) {
    if (arg0 == 0) {
      RAX = 1;
      BX_INFO(("poly_ud: emulated %s getgroups size=0 result=1", arch_name));
      return true;
    }
    if (arg1 == 0) {
      RAX = (Bit64u) -14;
      BX_INFO(("poly_ud: emulated %s getgroups size=%llu list=0 result=%lld", arch_name, (unsigned long long) arg0, (long long) RAX));
      return true;
    }
    write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg1, 1000);
    RAX = 1;
    BX_INFO(("poly_ud: emulated %s getgroups size=%llu list=%llx gid=1000 result=1", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  return false;
}

bool BX_CPU_C::handle_poly_file_syscall(const char *arch_name, Bit32u syscall_number,
  Bit64u arg0, Bit64u arg1, Bit64u arg2, Bit64u arg3, Bit64u arg4, Bit64u arg5)
{
  const Bit8u stat_magic[] = {'P', 'S', 'T', 'A', 'T', '!', '!', '\0'};

  if (syscall_number >= 5 && syscall_number <= 16) {
    const char *name = syscall_number == 5 ? "setxattr" :
      syscall_number == 6 ? "lsetxattr" :
      syscall_number == 7 ? "fsetxattr" :
      syscall_number == 8 ? "getxattr" :
      syscall_number == 9 ? "lgetxattr" :
      syscall_number == 10 ? "fgetxattr" :
      syscall_number == 11 ? "listxattr" :
      syscall_number == 12 ? "llistxattr" :
      syscall_number == 13 ? "flistxattr" :
      syscall_number == 14 ? "removexattr" :
      syscall_number == 15 ? "lremovexattr" : "fremovexattr";
    if (syscall_number >= 8 && syscall_number <= 10) {
      const Bit8u value[] = {'P', 'X', 'A', '!'};
      Bit64u count = arg3 < sizeof(value) ? arg3 : sizeof(value);
      if (arg2 != 0) {
        for (Bit64u n = 0; n < count; n++)
          write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg2 + n), value[n]);
      }
      RAX = arg2 == 0 ? sizeof(value) : count;
    }
    else if (syscall_number >= 11 && syscall_number <= 13) {
      const Bit8u list_name[] = {'u', 's', 'e', 'r', '.', 'p', 'o', 'l', 'y', '\0'};
      Bit64u count = arg2 < sizeof(list_name) ? arg2 : sizeof(list_name);
      if (arg1 != 0) {
        for (Bit64u n = 0; n < count; n++)
          write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n), list_name[n]);
      }
      RAX = arg1 == 0 ? sizeof(list_name) : count;
    }
    else {
      RAX = 0;
    }
    BX_INFO(("poly_ud: emulated %s %s arg0=%llx arg1=%llx arg2=%llx arg3=%llx arg4=%llx result=%lld", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (long long) RAX));
    return true;
  }

  if (syscall_number == 17) {
    const char cwd[] = "/poly";
    Bit64u needed = sizeof(cwd);
    if (arg1 < needed) {
      RAX = (Bit64u) -34;
      BX_INFO(("poly_ud: emulated %s getcwd range addr=%llx size=%llu needed=%llu", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) needed));
    }
    else {
      for (unsigned n = 0; n < sizeof(cwd); n++)
        write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), (Bit8u) cwd[n]);
      RAX = needed;
      BX_INFO(("poly_ud: emulated %s getcwd addr=%llx size=%llu cwd=%s", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, cwd));
    }
    return true;
  }

  if (syscall_number == 43 || syscall_number == 44) {
    const char *name = syscall_number == 43 ? "statfs" : "fstatfs";
    if (arg1 == 0) {
      RAX = (Bit64u) -14;
    }
    else {
      for (unsigned n = 0; n < sizeof(stat_magic); n++)
        write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n), stat_magic[n]);
      RAX = 0;
    }
    BX_INFO(("poly_ud: emulated %s %s arg0=%llx buf=%llx result=%lld", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 45 || syscall_number == 46 || syscall_number == 47) {
    const char *name = syscall_number == 45 ? "truncate" :
      syscall_number == 46 ? "ftruncate" : "fallocate";
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s %s arg0=%llx arg1=%llx arg2=%llx arg3=%llx result=0", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3));
    return true;
  }

  if (syscall_number == 49 || syscall_number == 50 || syscall_number == 52 ||
      syscall_number == 53 || syscall_number == 54 || syscall_number == 55) {
    const char *name = syscall_number == 49 ? "chdir" :
      syscall_number == 50 ? "fchdir" :
      syscall_number == 52 ? "fchmod" :
      syscall_number == 53 ? "fchmodat" :
      syscall_number == 54 ? "fchownat" : "fchown";
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s %s arg0=%llx arg1=%llx arg2=%llx arg3=%llx result=0", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3));
    return true;
  }

  if (syscall_number == 19) {
    RAX = 7;
    BX_INFO(("poly_ud: emulated %s eventfd2 initval=%llu flags=%llu result=7", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number >= 30 && syscall_number <= 33) {
    const char *name = syscall_number == 30 ? "ioprio_set" :
      syscall_number == 31 ? "ioprio_get" :
      syscall_number == 32 ? "flock" : "mknodat";
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s %s arg0=%llx arg1=%llx arg2=%llx arg3=%llx result=0", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3));
    return true;
  }

  if ((syscall_number >= 34 && syscall_number <= 41) ||
      syscall_number == 51 || syscall_number == 276 ||
      (syscall_number >= 428 && syscall_number <= 433) ||
      syscall_number == 442) {
    const char *name = syscall_number == 34 ? "mkdirat" :
      syscall_number == 35 ? "unlinkat" :
      syscall_number == 36 ? "symlinkat" :
      syscall_number == 37 ? "linkat" :
      syscall_number == 38 ? "renameat" :
      syscall_number == 39 ? "umount2" :
      syscall_number == 40 ? "mount" :
      syscall_number == 41 ? "pivot_root" :
      syscall_number == 51 ? "chroot" :
      syscall_number == 276 ? "renameat2" :
      syscall_number == 428 ? "open_tree" :
      syscall_number == 429 ? "move_mount" :
      syscall_number == 430 ? "fsopen" :
      syscall_number == 431 ? "fsconfig" :
      syscall_number == 432 ? "fsmount" :
      syscall_number == 433 ? "fspick" : "mount_setattr";
    RAX = syscall_number == 428 ? 15 :
      syscall_number == 430 ? 16 :
      syscall_number == 432 ? 17 :
      syscall_number == 433 ? 18 : 0;
    BX_INFO(("poly_ud: emulated %s %s arg0=%llx arg1=%llx arg2=%llx arg3=%llx arg4=%llx result=%lld", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (long long) RAX));
    return true;
  }

  if (syscall_number == 20) {
    RAX = 4;
    BX_INFO(("poly_ud: emulated %s epoll_create1 flags=%llu result=4", arch_name, (unsigned long long) arg0));
    return true;
  }

  if (syscall_number == 21) {
    RAX = arg0 == 4 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s epoll_ctl epfd=%llu op=%llu fd=%llu event=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 22) {
    RAX = arg0 == 4 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s epoll_pwait epfd=%llu events=%llx maxevents=%llu timeout=%lld sigmask=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) arg3, (unsigned long long) arg4, (long long) RAX));
    return true;
  }

  if (syscall_number == 26) {
    RAX = 14;
    BX_INFO(("poly_ud: emulated %s inotify_init1 flags=%llu result=14", arch_name, (unsigned long long) arg0));
    return true;
  }

  if (syscall_number == 27) {
    RAX = (arg0 == 14 && arg1) ? 31 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s inotify_add_watch fd=%llu pathname=%llx mask=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 28) {
    RAX = (arg0 == 14 && arg1 == 31) ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s inotify_rm_watch fd=%llu wd=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 24) {
    RAX = (arg0 == 5 || arg0 == 7) ? arg1 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s dup3 oldfd=%llu newfd=%llu flags=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 198) {
    RAX = 5;
    BX_INFO(("poly_ud: emulated %s socket domain=%llu type=%llu protocol=%llu result=5", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2));
    return true;
  }

  if (syscall_number == 199) {
    if (arg3) {
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg3, 11);
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) (arg3 + 4), 12);
      RAX = 0;
    }
    else {
      RAX = (Bit64u) -14;
    }
    BX_INFO(("poly_ud: emulated %s socketpair domain=%llu type=%llu protocol=%llu sv=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 200) {
    RAX = arg0 == 5 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s bind fd=%llu addr=%llx addrlen=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 201) {
    RAX = arg0 == 5 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s listen fd=%llu backlog=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 202) {
    RAX = arg0 == 5 ? 6 : (Bit64u) -9;
    if (arg0 == 5 && arg1 && arg2) {
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) arg1, 2);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 1), 0);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 2), 0x30);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 3), 0x39);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 4), 127);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 5), 0);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 6), 0);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 7), 1);
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg2, 16);
    }
    BX_INFO(("poly_ud: emulated %s accept fd=%llu addr=%llx addrlen=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 203) {
    RAX = arg0 == 5 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s connect fd=%llu addr=%llx addrlen=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 204 || syscall_number == 205) {
    RAX = arg0 == 5 ? 0 : (Bit64u) -9;
    if (RAX == 0 && arg1 && arg2) {
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) arg1, 2);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 1), 0);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 2), 0x30);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 3), 0x39);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 4), 127);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 5), 0);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 6), 0);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 7), 1);
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg2, 16);
    }
    BX_INFO(("poly_ud: emulated %s %s fd=%llu addr=%llx addrlen=%llx result=%lld", arch_name, syscall_number == 204 ? "getsockname" : "getpeername", (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 206 && arg0 == 5) {
    Bit64u checksum = 0;
    for (Bit64u n = 0; n < arg2 && n < 4096; n++)
      checksum += read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
    RAX = arg2;
    BX_INFO(("poly_ud: emulated %s sendto fd=5 buf=%llx len=%llu flags=%llu dest=%llx addrlen=%llu checksum=%llu", arch_name, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (unsigned long long) arg5, (unsigned long long) checksum));
    return true;
  }

  if (syscall_number == 207 && arg0 == 5) {
    const Bit8u input[] = {'N', 'E', 'T', '!'};
    const Bit64u input_size = 4;
    Bit64u count = arg2 < input_size ? arg2 : input_size;
    for (Bit64u n = 0; n < count; n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n), input[n]);
    RAX = count;
    BX_INFO(("poly_ud: emulated %s recvfrom fd=5 buf=%llx len=%llu flags=%llu src=%llx addrlen=%llx result=%llu", arch_name, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (unsigned long long) arg5, (unsigned long long) RAX));
    return true;
  }

  if (syscall_number == 208) {
    RAX = arg0 == 5 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s setsockopt fd=%llu level=%llu optname=%llu optval=%llx optlen=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (long long) RAX));
    return true;
  }

  if (syscall_number == 209) {
    RAX = arg0 == 5 ? 0 : (Bit64u) -9;
    if (RAX == 0) {
      if (arg3)
        write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg3, 0);
      if (arg4)
        write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg4, 4);
    }
    BX_INFO(("poly_ud: emulated %s getsockopt fd=%llu level=%llu optname=%llu optval=%llx optlen=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (long long) RAX));
    return true;
  }

  if (syscall_number == 210) {
    RAX = arg0 == 5 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s shutdown fd=%llu how=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 223) {
    RAX = arg0 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s fadvise64 fd=%llu offset=%llu len=%llu advice=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 242) {
    RAX = arg0 == 5 ? 6 : (Bit64u) -9;
    if (arg0 == 5 && arg1 && arg2) {
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) arg1, 2);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 1), 0);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 2), 0x30);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 3), 0x39);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 4), 127);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 5), 0);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 6), 0);
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 7), 1);
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg2, 16);
    }
    BX_INFO(("poly_ud: emulated %s accept4 fd=%llu addr=%llx addrlen=%llx flags=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 59) {
    if (arg0) {
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg0, 9);
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) (arg0 + 4), 10);
      RAX = 0;
    }
    else {
      RAX = (Bit64u) -14;
    }
    BX_INFO(("poly_ud: emulated %s pipe2 pipefd=%llx flags=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 82 || syscall_number == 83) {
    RAX = arg0 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s %s fd=%llu result=%lld", arch_name, syscall_number == 82 ? "fsync" : "fdatasync", (unsigned long long) arg0, (long long) RAX));
    return true;
  }

  if (syscall_number == 84) {
    RAX = arg0 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s sync_file_range fd=%llu offset=%llu nbytes=%llu flags=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 85) {
    RAX = 13;
    BX_INFO(("poly_ud: emulated %s timerfd_create clockid=%llu flags=%llu result=13", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 86) {
    RAX = arg0 == 13 ? 0 : (Bit64u) -9;
    if (RAX == 0 && arg3) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg3, 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg3 + 8), 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg3 + 16), 21);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg3 + 24), 0);
    }
    BX_INFO(("poly_ud: emulated %s timerfd_settime fd=%llu flags=%llu new_value=%llx old_value=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 87) {
    RAX = arg0 == 13 ? 0 : (Bit64u) -9;
    if (RAX == 0 && arg1) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 16), 34);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 24), 0);
    }
    BX_INFO(("poly_ud: emulated %s timerfd_gettime fd=%llu curr_value=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 107) {
    RAX = arg2 ? 0 : (Bit64u) -14;
    if (RAX == 0)
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg2, 23);
    BX_INFO(("poly_ud: emulated %s timer_create clockid=%llu sevp=%llx timerid=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 108) {
    RAX = arg0 == 23 && arg1 ? 0 : (Bit64u) -22;
    if (RAX == 0) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 16), 44);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 24), 0);
    }
    BX_INFO(("poly_ud: emulated %s timer_gettime timerid=%llu curr=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 109) {
    RAX = arg0 == 23 ? 0 : (Bit64u) -22;
    BX_INFO(("poly_ud: emulated %s timer_getoverrun timerid=%llu result=%lld", arch_name, (unsigned long long) arg0, (long long) RAX));
    return true;
  }

  if (syscall_number == 110) {
    RAX = arg0 == 23 && arg2 ? 0 : (Bit64u) -22;
    if (RAX == 0 && arg3) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg3, 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg3 + 8), 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg3 + 16), 55);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg3 + 24), 0);
    }
    BX_INFO(("poly_ud: emulated %s timer_settime timerid=%llu flags=%llu new=%llx old=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 111) {
    RAX = arg0 == 23 ? 0 : (Bit64u) -22;
    BX_INFO(("poly_ud: emulated %s timer_delete timerid=%llu result=%lld", arch_name, (unsigned long long) arg0, (long long) RAX));
    return true;
  }

  if (syscall_number == 63 && (arg0 == 0 || arg0 == 3)) {
    const Bit8u stdin_input[] = {'R', 'X', '!', '!'};
    const Bit8u file_input[] = {'F', 'D', '!', '!'};
    const Bit8u *input = arg0 == 3 ? file_input : stdin_input;
    const Bit64u input_size = 4;
    Bit64u count = arg2 < input_size ? arg2 : input_size;
    for (Bit64u n = 0; n < count; n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n), input[n]);
    RAX = count;
    BX_INFO(("poly_ud: emulated %s read fd=%llu addr=%llx count=%llu", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) count));
    return true;
  }

  if (syscall_number == 64 && arg0 == 1) {
    Bit64u checksum = 0;
    for (Bit64u n = 0; n < arg2 && n < 4096; n++)
      checksum += read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
    RAX = arg2;
    BX_INFO(("poly_ud: emulated %s write fd=1 addr=%llx count=%llu checksum=%llu", arch_name, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) checksum));
    return true;
  }

  if (syscall_number == 67 && arg0 == 3) {
    const Bit8u input[] = {'P', 'D', '!', '!'};
    const Bit64u input_size = 4;
    Bit64u count = arg2 < input_size ? arg2 : input_size;
    for (Bit64u n = 0; n < count; n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n), input[n]);
    RAX = count;
    BX_INFO(("poly_ud: emulated %s pread64 fd=3 addr=%llx count=%llu offset=%llu result=%llu", arch_name, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) RAX));
    return true;
  }

  if (syscall_number == 68 && arg0 == 1) {
    Bit64u checksum = 0;
    for (Bit64u n = 0; n < arg2 && n < 4096; n++)
      checksum += read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
    RAX = arg2;
    BX_INFO(("poly_ud: emulated %s pwrite64 fd=1 addr=%llx count=%llu offset=%llu checksum=%llu", arch_name, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) checksum));
    return true;
  }

  if (syscall_number == 69 && arg0 == 3) {
    const Bit8u input[] = {'P', 'V', '!', '!'};
    const Bit64u input_size = 4;
    Bit64u total = 0;
    Bit64u copied = 0;
    Bit64u iovcnt = arg2 < 16 ? arg2 : 16;
    for (Bit64u iov = 0; iov < iovcnt && copied < input_size; iov++) {
      bx_address iov_addr = (bx_address) (arg1 + iov * 16);
      Bit64u base = read_virtual_qword(BX_SEG_REG_DS, iov_addr);
      Bit64u len = read_virtual_qword(BX_SEG_REG_DS, iov_addr + 8);
      Bit64u count = len < (input_size - copied) ? len : (input_size - copied);
      for (Bit64u n = 0; n < count; n++)
        write_virtual_byte(BX_SEG_REG_DS, (bx_address) (base + n), input[copied + n]);
      copied += count;
      total += count;
    }
    RAX = total;
    BX_INFO(("poly_ud: emulated %s preadv fd=3 iov=%llx iovcnt=%llu offset=%llu offset_hi=%llu total=%llu", arch_name, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (unsigned long long) total));
    return true;
  }

  if (syscall_number == 70 && arg0 == 1) {
    Bit64u total = 0;
    Bit64u checksum = 0;
    Bit64u iovcnt = arg2 < 16 ? arg2 : 16;
    for (Bit64u iov = 0; iov < iovcnt; iov++) {
      bx_address iov_addr = (bx_address) (arg1 + iov * 16);
      Bit64u base = read_virtual_qword(BX_SEG_REG_DS, iov_addr);
      Bit64u len = read_virtual_qword(BX_SEG_REG_DS, iov_addr + 8);
      total += len;
      for (Bit64u n = 0; n < len && n < 4096; n++)
        checksum += read_virtual_byte(BX_SEG_REG_DS, (bx_address) (base + n));
    }
    RAX = total;
    BX_INFO(("poly_ud: emulated %s pwritev fd=1 iov=%llx iovcnt=%llu offset=%llu offset_hi=%llu total=%llu checksum=%llu", arch_name, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (unsigned long long) total, (unsigned long long) checksum));
    return true;
  }

  if (syscall_number == 72) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s pselect6 nfds=%llu readfds=%llx writefds=%llx exceptfds=%llx timeout=%llx sigmask=%llx result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (unsigned long long) arg5));
    return true;
  }

  if (syscall_number == 73) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s ppoll fds=%llx nfds=%llu timeout=%llx sigmask=%llx result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3));
    return true;
  }

  if (syscall_number == 65 && (arg0 == 0 || arg0 == 3)) {
    const Bit8u stdin_input[] = {'R', 'V', '!', '!'};
    const Bit8u file_input[] = {'F', 'V', '!', '!'};
    const Bit8u *input = arg0 == 3 ? file_input : stdin_input;
    const Bit64u input_size = 4;
    Bit64u total = 0;
    Bit64u copied = 0;
    Bit64u iovcnt = arg2 < 16 ? arg2 : 16;
    for (Bit64u iov = 0; iov < iovcnt && copied < input_size; iov++) {
      bx_address iov_addr = (bx_address) (arg1 + iov * 16);
      Bit64u base = read_virtual_qword(BX_SEG_REG_DS, iov_addr);
      Bit64u len = read_virtual_qword(BX_SEG_REG_DS, iov_addr + 8);
      Bit64u count = len < (input_size - copied) ? len : (input_size - copied);
      for (Bit64u n = 0; n < count; n++)
        write_virtual_byte(BX_SEG_REG_DS, (bx_address) (base + n), input[copied + n]);
      copied += count;
      total += count;
    }
    RAX = total;
    BX_INFO(("poly_ud: emulated %s readv fd=%llu iov=%llx iovcnt=%llu total=%llu", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) total));
    return true;
  }

  if (syscall_number == 66 && (arg0 == 1 || arg0 == 2)) {
    Bit64u total = 0;
    Bit64u checksum = 0;
    Bit64u iovcnt = arg2 < 16 ? arg2 : 16;
    for (Bit64u iov = 0; iov < iovcnt; iov++) {
      bx_address iov_addr = (bx_address) (arg1 + iov * 16);
      Bit64u base = read_virtual_qword(BX_SEG_REG_DS, iov_addr);
      Bit64u len = read_virtual_qword(BX_SEG_REG_DS, iov_addr + 8);
      total += len;
      for (Bit64u n = 0; n < len && n < 4096; n++)
        checksum += read_virtual_byte(BX_SEG_REG_DS, (bx_address) (base + n));
    }
    RAX = total;
    BX_INFO(("poly_ud: emulated %s writev fd=%llu iov=%llx iovcnt=%llu total=%llu checksum=%llu", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) total, (unsigned long long) checksum));
    return true;
  }

  if (syscall_number == 78 && arg2 != 0 && arg3 != 0) {
    const char target[] = "poly!";
    Bit64u count = (sizeof(target) - 1) < arg3 ? (sizeof(target) - 1) : arg3;
    for (Bit64u n = 0; n < count; n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg2 + n), (Bit8u) target[n]);
    RAX = count;
    BX_INFO(("poly_ud: emulated %s readlinkat dirfd=%lld path=%llx buf=%llx size=%llu result=%llu", arch_name, (long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) RAX));
    return true;
  }

  if (syscall_number == 79 && arg2 != 0) {
    for (unsigned n = 0; n < sizeof(stat_magic); n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg2 + n), stat_magic[n]);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s newfstatat dirfd=%lld path=%llx stat=%llx flags=%llu", arch_name, (long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3));
    return true;
  }

  if (syscall_number == 80 && arg1 != 0 && arg0 <= 3) {
    for (unsigned n = 0; n < sizeof(stat_magic); n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n), stat_magic[n]);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s fstat fd=%llu stat=%llx", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 291 && arg4 != 0) {
    for (unsigned n = 0; n < sizeof(stat_magic); n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg4 + n), stat_magic[n]);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s statx dirfd=%lld path=%llx flags=%llu mask=%llu statx=%llx", arch_name, (long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4));
    return true;
  }

  if (syscall_number == 56) {
    char path[16];
    unsigned n;
    for (n = 0; n < sizeof(path) - 1; n++) {
      path[n] = (char) read_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + n));
      if (path[n] == '\0')
        break;
    }
    path[n] = '\0';
    RAX = strcmp(path, "poly!") == 0 ? 3 : (Bit64u) -2;
    BX_INFO(("poly_ud: emulated %s openat dirfd=%llu path=%s flags=%llu result=%lld", arch_name, (unsigned long long) arg0, path, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 57) {
    RAX = arg0 == 3 ? 0 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s close fd=%llu result=%lld", arch_name, (unsigned long long) arg0, (long long) RAX));
    return true;
  }

  if (syscall_number == 61 && arg1 != 0 && arg2 >= 24 && arg0 <= 3) {
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 1);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 1);
    write_virtual_word(BX_SEG_REG_DS, (bx_address) (arg1 + 16), 24);
    write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 18), 4);
    write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 19), '.');
    write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg1 + 20), '\0');
    RAX = 24;
    BX_INFO(("poly_ud: emulated %s getdents64 fd=%llu dirent=%llx count=%llu result=24", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2));
    return true;
  }

  if (syscall_number == 62) {
    RAX = (arg0 == 3 && arg2 <= 2) ? arg1 : (Bit64u) -9;
    BX_INFO(("poly_ud: emulated %s lseek fd=%llu offset=%llu whence=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 160) {
    const char sysname[] = "Linux";
    for (unsigned n = 0; n < sizeof(sysname); n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), (Bit8u) sysname[n]);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s uname addr=%llx sysname=%s", arch_name, (unsigned long long) arg0, sysname));
    return true;
  }

  return false;
}

bool BX_CPU_C::handle_poly_memory_syscall(const char *arch_name, Bit32u syscall_number,
  Bit64u arg0, Bit64u arg1, Bit64u arg2, Bit64u arg3, Bit64u arg4, Bit64u arg5)
{
  if (syscall_number == 101) {
    if (arg1) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 0);
    }
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s nanosleep req=%llx rem=%llx result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 102) {
    if (arg1) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 16), 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 24), 0);
    }
    RAX = arg1 ? 0 : (Bit64u) -14;
    BX_INFO(("poly_ud: emulated %s getitimer which=%llu curr=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 103) {
    if (arg2) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg2, 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg2 + 8), 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg2 + 16), 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg2 + 24), 0);
    }
    RAX = arg1 ? 0 : (Bit64u) -14;
    BX_INFO(("poly_ud: emulated %s setitimer which=%llu new=%llx old=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 113 && arg0 == 0) {
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 123);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 456789);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s clock_gettime clk=0 addr=%llx sec=123 nsec=456789", arch_name, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 114) {
    if (arg1) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 1);
    }
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s clock_getres clk=%llu addr=%llx sec=0 nsec=1", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 115) {
    if (arg3) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg3, 0);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg3 + 8), 0);
    }
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s clock_nanosleep clk=%llu flags=%llu req=%llx rem=%llx result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3));
    return true;
  }

  if (syscall_number == 118) {
    RAX = arg1 ? 0 : (Bit64u) -14;
    BX_INFO(("poly_ud: emulated %s sched_setparam pid=%llu param=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 119) {
    RAX = arg2 ? 0 : (Bit64u) -14;
    BX_INFO(("poly_ud: emulated %s sched_setscheduler pid=%llu policy=%llu param=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 120) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s sched_getscheduler pid=%llu policy=0", arch_name, (unsigned long long) arg0));
    return true;
  }

  if (syscall_number == 121) {
    if (arg1)
      write_virtual_dword(BX_SEG_REG_DS, (bx_address) arg1, 0);
    RAX = arg1 ? 0 : (Bit64u) -14;
    BX_INFO(("poly_ud: emulated %s sched_getparam pid=%llu param=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 122) {
    RAX = arg2 && arg1 >= 8 ? 0 : (Bit64u) -22;
    BX_INFO(("poly_ud: emulated %s sched_setaffinity pid=%llu len=%llu mask=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 123) {
    RAX = arg2 && arg1 >= 8 ? 8 : (Bit64u) -22;
    if (RAX == 8)
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg2, 1);
    BX_INFO(("poly_ud: emulated %s sched_getaffinity pid=%llu len=%llu mask=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  if (syscall_number == 124) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s sched_yield result=0", arch_name));
    return true;
  }

  if (syscall_number == 125 || syscall_number == 126) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s %s policy=%llu result=0", arch_name, syscall_number == 125 ? "sched_get_priority_max" : "sched_get_priority_min", (unsigned long long) arg0));
    return true;
  }

  if (syscall_number == 153) {
    if (arg0 != 0) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg0, 11);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg0 + 8), 22);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg0 + 16), 33);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg0 + 24), 44);
    }
    RAX = 987;
    BX_INFO(("poly_ud: emulated %s times addr=%llx ticks=987 utime=11", arch_name, (unsigned long long) arg0));
    return true;
  }

  if (syscall_number == 163) {
    if (arg1 != 0) {
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 8388608);
      write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), (Bit64u) -1);
      RAX = 0;
    }
    else {
      RAX = (Bit64u) -14;
    }
    BX_INFO(("poly_ud: emulated %s getrlimit resource=%llu addr=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 164) {
    RAX = arg1 != 0 ? 0 : (Bit64u) -14;
    BX_INFO(("poly_ud: emulated %s setrlimit resource=%llu addr=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (long long) RAX));
    return true;
  }

  if (syscall_number == 165 && arg0 == 0) {
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 321);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 654321);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s getrusage who=0 addr=%llx utime_sec=321 utime_usec=654321", arch_name, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 168 && arg0 != 0 && arg1 != 0) {
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg0, 12);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 34);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s getcpu cpu_addr=%llx node_addr=%llx cpu=12 node=34", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 169 && arg0 != 0 && arg1 == 0) {
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg0, 246);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg0 + 8), 13579);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s gettimeofday addr=%llx sec=246 usec=13579", arch_name, (unsigned long long) arg0));
    return true;
  }

  if (syscall_number == 179) {
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg0, 98765);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg0 + 8), 111);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s sysinfo addr=%llx uptime=98765 load0=111", arch_name, (unsigned long long) arg0));
    return true;
  }

  if (syscall_number == 261 && arg3 != 0) {
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg3, 8388608);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg3 + 8), (Bit64u) -1);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s prlimit64 pid=%llu resource=%llu old_limit=%llx", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg3));
    return true;
  }

  if (syscall_number == 278 && arg0 != 0) {
    const Bit8u random_data[] = {'P', 'R', 'N', 'D', '!', '!', '\0', '\0'};
    Bit64u count = arg1 < sizeof(random_data) ? arg1 : sizeof(random_data);
    for (Bit64u n = 0; n < count; n++)
      write_virtual_byte(BX_SEG_REG_DS, (bx_address) (arg0 + n), random_data[n]);
    RAX = count;
    BX_INFO(("poly_ud: emulated %s getrandom addr=%llx count=%llu flags=%llu result=%llu", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) RAX));
    return true;
  }

  if (syscall_number == 222 && arg0 == 0) {
    if (arg3 == 34 && arg4 == 5 && arg5 == 7)
      RAX = arg1 + arg2 + arg3 + arg4 + arg5;
    else
      RAX = RDI;
    BX_INFO(("poly_ud: emulated %s mmap addr=0 len=%llu prot=%llu flags=%llu fd=%llu offset=%llu result=%llx", arch_name, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (unsigned long long) arg5, (unsigned long long) RAX));
    return true;
  }

  if (syscall_number == 214) {
    RAX = arg0 != 0 ? arg0 : RDI;
    BX_INFO(("poly_ud: emulated %s brk addr=%llx result=%llx", arch_name, (unsigned long long) arg0, (unsigned long long) RAX));
    return true;
  }

  if (syscall_number == 216) {
    RAX = arg0 != 0 ? arg0 : (Bit64u) -22;
    BX_INFO(("poly_ud: emulated %s mremap old_addr=%llx old_size=%llu new_size=%llu flags=%llu new_addr=%llx result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (long long) RAX));
    return true;
  }

  if (syscall_number == 215 && arg0 != 0 && arg1 != 0) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s munmap addr=%llx len=%llu result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1));
    return true;
  }

  if (syscall_number == 226 && arg0 != 0 && arg1 != 0) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s mprotect addr=%llx len=%llu prot=%llu result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2));
    return true;
  }

  if (syscall_number == 228 || syscall_number == 229 ||
      syscall_number == 230 || syscall_number == 231 ||
      syscall_number == 284) {
    const char *name = syscall_number == 228 ? "mlock" :
      syscall_number == 229 ? "munlock" :
      syscall_number == 230 ? "mlockall" :
      syscall_number == 231 ? "munlockall" : "mlock2";
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s %s arg0=%llx arg1=%llx arg2=%llx result=0", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2));
    return true;
  }

  if (syscall_number == 436) {
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s close_range first=%llu last=%llu flags=%llu result=0", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2));
    return true;
  }

  if (syscall_number == 220 || syscall_number == 221 ||
      syscall_number == 236 ||
      syscall_number == 237 || syscall_number == 238 || syscall_number == 239 ||
      syscall_number == 277 || syscall_number == 280 || syscall_number == 282 ||
      (syscall_number >= 288 && syscall_number <= 290) ||
      syscall_number == 424 ||
      (syscall_number >= 425 && syscall_number <= 427) ||
      syscall_number == 434 || syscall_number == 435 ||
      syscall_number == 437 || syscall_number == 438 ||
      syscall_number == 440 ||
      (syscall_number >= 444 && syscall_number <= 446) ||
      (syscall_number >= 448 && syscall_number <= 450)) {
    const char *name = syscall_number == 220 ? "clone" :
      syscall_number == 221 ? "execve" :
      syscall_number == 236 ? "get_mempolicy" :
      syscall_number == 237 ? "set_mempolicy" :
      syscall_number == 238 ? "migrate_pages" :
      syscall_number == 239 ? "move_pages" :
      syscall_number == 277 ? "seccomp" :
      syscall_number == 280 ? "bpf" :
      syscall_number == 282 ? "userfaultfd" :
      syscall_number == 288 ? "pkey_mprotect" :
      syscall_number == 289 ? "pkey_alloc" :
      syscall_number == 290 ? "pkey_free" :
      syscall_number == 424 ? "pidfd_send_signal" :
      syscall_number == 425 ? "io_uring_setup" :
      syscall_number == 426 ? "io_uring_enter" :
      syscall_number == 427 ? "io_uring_register" :
      syscall_number == 434 ? "pidfd_open" :
      syscall_number == 435 ? "clone3" :
      syscall_number == 436 ? "close_range" :
      syscall_number == 437 ? "openat2" :
      syscall_number == 438 ? "pidfd_getfd" :
      syscall_number == 440 ? "process_madvise" :
      syscall_number == 444 ? "landlock_create_ruleset" :
      syscall_number == 445 ? "landlock_add_rule" :
      syscall_number == 446 ? "landlock_restrict_self" :
      syscall_number == 448 ? "process_mrelease" :
      syscall_number == 449 ? "futex_waitv" : "set_mempolicy_home_node";
    RAX = (Bit64u) -38;
    BX_INFO(("poly_ud: emulated %s %s unavailable arg0=%llx arg1=%llx arg2=%llx arg3=%llx result=%lld", arch_name, name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (long long) RAX));
    return true;
  }

  if (syscall_number == 283) {
    RAX = arg0 == 0 ? 1 : 0;
    BX_INFO(("poly_ud: emulated %s membarrier cmd=%llu flags=%llu cpu_id=%llu result=%lld", arch_name, (unsigned long long) arg0, (unsigned long long) arg1, (unsigned long long) arg2, (long long) RAX));
    return true;
  }

  return false;
}

bool BX_CPP_AttrRegparmN(1) BX_CPU_C::handle_poly_ud(bxInstruction_c *i)
{
  (void) i;

  if (!BX_CPU_THIS_PTR poly_feature_enabled)
    return false;

  if (CPL != 3) {
    BX_INFO(("poly_ud: reject CPL=%u", CPL));
    return false;
  }

  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));

  Bit8u opcode0 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP);
  Bit8u opcode1 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 1);
  Bit8u opcode2 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 2);
  Bit8u opcode_m1 = 0;
  Bit8u opcode_m2 = 0;
  if (PREV_RIP > 0)
    opcode_m1 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP - 1);
  if (PREV_RIP > 1)
    opcode_m2 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP - 2);

  BX_INFO(("poly_ud: bytes=%02x %02x %02x prev=%02x prev2=%02x", opcode0, opcode1, opcode2, opcode_m1, opcode_m2));

  if (opcode0 == 0x0f && opcode1 == 0x24) {
    Bit8u op = opcode2;
    Bit8u magic0 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 3);
    Bit8u magic1 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 4);
    Bit8u magic2 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 5);
    Bit8u magic3 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 6);
    Bit8u magic4 = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + 7);
    if (magic0 == 'P' && magic1 == 'O' && magic2 == 'L' &&
        magic3 == 'Y' && magic4 == '!') {
      bx_address next_rip = PREV_RIP + 8;
      if (op == 0x00 || op == 0x01 || op == 0x02) {
        if (op == 0x00) {
          bx_poly_current_mode = BX_POLY_MODE_X86;
          bx_poly_clear_cross_return_stack();
        }
        else if (op == 0x01) {
          bx_poly_current_mode = BX_POLY_MODE_RAW_AARCH64;
        }
        else {
          bx_poly_current_mode = BX_POLY_MODE_RAW_RISCV;
        }
        bx_poly_mode_switch_count++;
        if (bx_poly_current_mode == BX_POLY_MODE_RAW_AARCH64)
          bx_poly_reset_aarch64_regs();
        if (bx_poly_current_mode == BX_POLY_MODE_RAW_RISCV)
          bx_poly_reset_riscv_regs();
        bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_stack_key(RSP));
        bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE,
          bx_poly_stack_key(RSP));
        BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
        RIP = next_rip;
        BX_INFO(("poly_ud: x86 poly opcode op=0x%02x mode switch to %u",
          op, bx_poly_current_mode));
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
      if (op == 0x20)
        return return_poly_import_x86_call();
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
          RAX = bx_poly_last_libcall_number;
        else if (status_id == 2)
          RAX = bx_poly_last_libcall_mode;
        else
          RAX = 0x4c000000 | (bx_poly_current_mode << 8) | status_id;
        RIP = next_rip;
        BX_INFO(("poly_ud: libcall status op=0x%02x id=%u current_mode=%u last_mode=%u number=%u",
          op, status_id, bx_poly_current_mode, bx_poly_last_libcall_mode,
          bx_poly_last_libcall_number));
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
          RAX = bx_poly_foreign_libcall_count;
        else
          RAX = bx_poly_current_mode;
        RIP = next_rip;
        BX_INFO(("poly_ud: switch status op=0x%02x id=%u mode=%u switches=%llu foreign_insns=%llu syscalls=%llu libcalls=%llu",
          op, status_id, bx_poly_current_mode,
          (unsigned long long) bx_poly_mode_switch_count,
          (unsigned long long) bx_poly_foreign_insn_count,
          (unsigned long long) bx_poly_foreign_syscall_count,
          (unsigned long long) bx_poly_foreign_libcall_count));
        return true;
      }
      if (op >= 0x50 && op <= 0x59) {
        Bit8u status_id = op - 0x50;
        if (status_id == 0)
          RAX = bx_poly_last_trap_reason;
        else if (status_id == 1)
          RAX = bx_poly_last_trap_mode;
        else if (status_id == 2)
          RAX = bx_poly_last_trap_number;
        else if (status_id >= 3 && status_id <= 8)
          RAX = bx_poly_last_trap_args[status_id - 3];
        else
          RAX = bx_poly_last_trap_pc;
        RIP = next_rip;
        BX_INFO(("poly_ud: trap status op=0x%02x id=%u reason=%u mode=%u number=%u pc=%llx",
          op, status_id, bx_poly_last_trap_reason, bx_poly_last_trap_mode,
          bx_poly_last_trap_number, (unsigned long long) bx_poly_last_trap_pc));
        return true;
      }
    }
  }

  BX_INFO(("poly_ud: reject non-poly opcode bytes=%02x %02x %02x",
    opcode0, opcode1, opcode2));
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
    RAX = 1; // poly CPUID ABI version
    RBX = (1U << BX_POLY_MODE_X86) |
          (1U << BX_POLY_MODE_RAW_AARCH64) |
          (1U << BX_POLY_MODE_RAW_RISCV);
    RCX = BX_POLY_CPUID_FEATURE_RAW_AARCH64 |
          BX_POLY_CPUID_FEATURE_RAW_RISCV |
          BX_POLY_CPUID_FEATURE_NEUTRAL_SWITCH |
          BX_POLY_CPUID_FEATURE_NATIVE_RET |
          BX_POLY_CPUID_FEATURE_PCALL_SYSV |
          BX_POLY_CPUID_FEATURE_PCALL_SRET |
          BX_POLY_CPUID_FEATURE_FP_BRIDGE |
          BX_POLY_CPUID_FEATURE_TRAP_RECORDS |
          BX_POLY_CPUID_FEATURE_USER_RETURN_RESTORE |
          BX_POLY_CPUID_FEATURE_X86_TSO |
          BX_POLY_CPUID_FEATURE_THREAD_BANKS |
          BX_POLY_CPUID_FEATURE_COMPAT_TRAPS |
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
          BX_POLY_CPUID_FEATURE_X86_IMPORT_DESCRIPTORS |
          BX_POLY_CPUID_FEATURE_FP64_STACK_ARGS |
          BX_POLY_CPUID_FEATURE_NEUTRAL_FP64_STACK;
    RDX = 0; // no architectural XSAVE component is exposed yet
    BX_NEXT_INSTR(i);
    return;
  }
  if (BX_CPU_THIS_PTR poly_feature_enabled && EAX == BX_POLY_CPUID_BASE + 2) {
    if (ECX == 0) {
      RAX = BX_POLY_AARCH64_BRK_X86_ESCAPE |
            (BX_POLY_AARCH64_BRK_RISCV_SWITCH << 16);
      RBX = BX_POLY_AARCH64_BRK_RISCV_CALL;
      RCX = BX_POLY_RISCV_X86_ESCAPE;
      RDX = BX_POLY_RISCV_AARCH64_SWITCH;
    }
    else if (ECX == 1) {
      RAX = BX_POLY_RISCV_AARCH64_CALL;
      RBX = BX_POLY_RISCV_AARCH64_CALL_COMPACT_U32_F32;
      RCX = BX_POLY_RISCV_AARCH64_CALL_COMPACT_F32_U32;
      RDX = 0;
    }
    else if (ECX == 2) {
      RAX = BX_POLY_IMPORT_FUNC_X86_SLOT0;
      RBX = BX_POLY_IMPORT_FUNC_X86_SLOT7 - BX_POLY_IMPORT_FUNC_X86_SLOT0 + 1;
      RCX = (Bit32u) BX_POLY_IMPORT_X86_DESCRIPTOR_SIZE;
      RDX = (Bit32u) BX_POLY_IMPORT_CALL_STRIDE;
    }
    else if (ECX == 3) {
      RAX = BX_POLY_AARCH64_BRK_RISCV_CALL_FP64_STACK;
      RBX = BX_POLY_RISCV_AARCH64_CALL_FP64_STACK;
      RCX = 0;
      RDX = 0;
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
    RAX = BX_POLY_CPUID_STATE_OVERLAP_GPRS |
          BX_POLY_CPUID_STATE_SYNTHETIC_BANKS |
          BX_POLY_CPUID_STATE_KEY_CR3 |
          BX_POLY_CPUID_STATE_KEY_FSBASE |
          BX_POLY_CPUID_STATE_KEY_STACK_REGION |
          BX_POLY_CPUID_STATE_USER_RETURN_RESTORE |
          BX_POLY_CPUID_STATE_X86_TSO;
    RBX = BX_POLY_STATE_STACK_KEY_SHIFT;
    RCX = 0; // no XCR0 component is assigned in this Bochs prototype
    RDX = 0; // no XSAVE byte area is exposed in this Bochs prototype
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
