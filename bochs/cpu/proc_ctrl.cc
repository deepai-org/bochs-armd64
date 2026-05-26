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
static const Bit32u BX_POLY_RISCV_X86_ESCAPE = 0x0000000b;
static const Bit32u BX_POLY_RISCV_AARCH64_SWITCH = 0x0000002b;
static const Bit32u BX_POLY_RISCV_AARCH64_CALL = 0x0000005b;
static const Bit64u BX_POLY_RETURN_COOKIE = BX_CONST64(0xfffffffffffff000);
static const Bit64u BX_POLY_CROSS_RETURN_COOKIE = BX_CONST64(0xffffffffffffd000);
static const Bit64u BX_POLY_IMPORT_CALL_BASE = BX_CONST64(0xffffffffffffe000);
static const Bit64u BX_POLY_IMPORT_CALL_STRIDE = BX_CONST64(0x10);
static const Bit64u BX_POLY_IMPORT_X86_ADD_HELPER_SIZE = BX_CONST64(13);
static const Bit32u BX_POLY_IMPORT_CALL_COUNT = 4;
static const Bit64u BX_POLY_FOREIGN_STACK_GAP = BX_CONST64(0x100);
static const Bit32u BX_POLY_FOREIGN_STACK_ARG_QWORDS = 8;

enum {
  BX_POLY_IMPORT_FUNC_ADD = 0,
  BX_POLY_IMPORT_FUNC_MUL = 1,
  BX_POLY_IMPORT_FUNC_X86_ADD = 2,
  BX_POLY_IMPORT_FUNC_FP64_ADD = 3
};

static const unsigned BX_POLY_REG_STATE_SLOTS = 64;
static const unsigned BX_POLY_CROSS_RETURN_DEPTH = 8;

struct bx_poly_cross_return_frame_t {
  Bit32u caller_mode;
  Bit32u callee_mode;
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
static bx_poly_cross_return_frame_t bx_poly_cross_return_stack[BX_POLY_CROSS_RETURN_DEPTH];
static unsigned bx_poly_cross_return_top = 0;
static bool bx_poly_import_x86_return_valid = false;
static Bit32u bx_poly_import_x86_return_mode = BX_POLY_MODE_X86;
static bx_address bx_poly_import_x86_return_rip = 0;
static bx_address bx_poly_import_x86_return_rsp = 0;
static bool bx_poly_interrupted_raw_valid = false;
static Bit32u bx_poly_interrupted_raw_mode = BX_POLY_MODE_X86;
static bx_address bx_poly_interrupted_raw_rip = 0;
static Bit64u bx_poly_aarch64_x[32];
static bool bx_poly_aarch64_x_valid[32];
static Bit32u bx_poly_aarch64_nzcv = 0;
static Bit64u bx_poly_riscv_x[32];
static bool bx_poly_riscv_x_valid[32];

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
  bx_poly_cross_return_frame_t cross_return_stack[BX_POLY_CROSS_RETURN_DEPTH];
  unsigned cross_return_top;
  bool import_x86_return_valid;
  Bit32u import_x86_return_mode;
  bx_address import_x86_return_rip;
  bx_address import_x86_return_rsp;
  bool interrupted_raw_valid;
  Bit32u interrupted_raw_mode;
  bx_address interrupted_raw_rip;
  Bit64u aarch64_x[32];
  bool aarch64_x_valid[32];
  Bit32u aarch64_nzcv;
  Bit64u riscv_x[32];
  bool riscv_x_valid[32];
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

static Bit32u bx_poly_riscv_cldsp_imm(Bit16u insn)
{
  return ((((Bit32u) insn >> 12) & 0x1) << 5) |
    ((((Bit32u) insn >> 5) & 0x3) << 3) |
    ((((Bit32u) insn >> 2) & 0x7) << 6);
}

static Bit32u bx_poly_riscv_csdsp_imm(Bit16u insn)
{
  return ((((Bit32u) insn >> 10) & 0x7) << 3) |
    ((((Bit32u) insn >> 7) & 0x7) << 6);
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
  }
  bx_poly_aarch64_nzcv = 0;
}

static void bx_poly_reset_riscv_regs()
{
  for (unsigned n = 0; n < 32; n++) {
    bx_poly_riscv_x[n] = 0;
    bx_poly_riscv_x_valid[n] = false;
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
  bx_poly_reg_states[victim].cross_return_top = 0;
  bx_poly_reg_states[victim].import_x86_return_valid = false;
  bx_poly_reg_states[victim].import_x86_return_mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].import_x86_return_rip = 0;
  bx_poly_reg_states[victim].import_x86_return_rsp = 0;
  bx_poly_reg_states[victim].interrupted_raw_valid = false;
  bx_poly_reg_states[victim].interrupted_raw_mode = BX_POLY_MODE_X86;
  bx_poly_reg_states[victim].interrupted_raw_rip = 0;
  bx_poly_reg_states[victim].aarch64_nzcv = 0;
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++) {
    bx_poly_reg_states[victim].cross_return_stack[n].caller_mode = BX_POLY_MODE_X86;
    bx_poly_reg_states[victim].cross_return_stack[n].callee_mode = BX_POLY_MODE_X86;
    bx_poly_reg_states[victim].cross_return_stack[n].return_rip = 0;
  }
  for (unsigned n = 0; n < 32; n++) {
    bx_poly_reg_states[victim].aarch64_x[n] = 0;
    bx_poly_reg_states[victim].aarch64_x_valid[n] = false;
    bx_poly_reg_states[victim].riscv_x[n] = 0;
    bx_poly_reg_states[victim].riscv_x_valid[n] = false;
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
  bx_poly_reg_states[slot].cross_return_top = bx_poly_cross_return_top;
  bx_poly_reg_states[slot].import_x86_return_valid = bx_poly_import_x86_return_valid;
  bx_poly_reg_states[slot].import_x86_return_mode = bx_poly_import_x86_return_mode;
  bx_poly_reg_states[slot].import_x86_return_rip = bx_poly_import_x86_return_rip;
  bx_poly_reg_states[slot].import_x86_return_rsp = bx_poly_import_x86_return_rsp;
  bx_poly_reg_states[slot].interrupted_raw_valid = bx_poly_interrupted_raw_valid;
  bx_poly_reg_states[slot].interrupted_raw_mode = bx_poly_interrupted_raw_mode;
  bx_poly_reg_states[slot].interrupted_raw_rip = bx_poly_interrupted_raw_rip;
  bx_poly_reg_states[slot].aarch64_nzcv = bx_poly_aarch64_nzcv;
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++)
    bx_poly_reg_states[slot].cross_return_stack[n] = bx_poly_cross_return_stack[n];
  for (unsigned n = 0; n < 32; n++) {
    bx_poly_reg_states[slot].aarch64_x[n] = bx_poly_aarch64_x[n];
    bx_poly_reg_states[slot].aarch64_x_valid[n] = bx_poly_aarch64_x_valid[n];
    bx_poly_reg_states[slot].riscv_x[n] = bx_poly_riscv_x[n];
    bx_poly_reg_states[slot].riscv_x_valid[n] = bx_poly_riscv_x_valid[n];
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
  bx_poly_aarch64_nzcv = bx_poly_reg_states[slot].aarch64_nzcv;
  for (unsigned n = 0; n < BX_POLY_CROSS_RETURN_DEPTH; n++)
    bx_poly_cross_return_stack[n] = bx_poly_reg_states[slot].cross_return_stack[n];
  for (unsigned n = 0; n < 32; n++) {
    bx_poly_aarch64_x[n] = bx_poly_reg_states[slot].aarch64_x[n];
    bx_poly_aarch64_x_valid[n] = bx_poly_reg_states[slot].aarch64_x_valid[n];
    bx_poly_riscv_x[n] = bx_poly_reg_states[slot].riscv_x[n];
    bx_poly_riscv_x_valid[n] = bx_poly_reg_states[slot].riscv_x_valid[n];
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
  if (reg < 8) {
    *value = BX_READ_XMM_REG_LO_QWORD(reg);
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_aarch64_fp64_reg(Bit32u reg, Bit64u value)
{
  if (reg < 8) {
    BX_WRITE_XMM_REG_LO_QWORD(reg, value);
    return true;
  }
  return false;
}

bool BX_CPU_C::read_poly_riscv_fp64_reg(Bit32u reg, Bit64u *value)
{
  if (reg >= 10 && reg <= 17) {
    *value = BX_READ_XMM_REG_LO_QWORD(reg - 10);
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_riscv_fp64_reg(Bit32u reg, Bit64u value)
{
  if (reg >= 10 && reg <= 17) {
    BX_WRITE_XMM_REG_LO_QWORD(reg - 10, value);
    return true;
  }
  return false;
}

bool BX_CPU_C::read_poly_aarch64_fp32_reg(Bit32u reg, Bit32u *value)
{
  if (reg < 8) {
    *value = BX_READ_XMM_REG_LO_DWORD(reg);
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_aarch64_fp32_reg(Bit32u reg, Bit32u value)
{
  if (reg < 8) {
    BX_WRITE_XMM_REG_LO_DWORD(reg, value);
    return true;
  }
  return false;
}

bool BX_CPU_C::read_poly_riscv_fp32_reg(Bit32u reg, Bit32u *value)
{
  if (reg >= 10 && reg <= 17) {
    *value = BX_READ_XMM_REG_LO_DWORD(reg - 10);
    return true;
  }
  return false;
}

bool BX_CPU_C::write_poly_riscv_fp32_reg(Bit32u reg, Bit32u value)
{
  if (reg >= 10 && reg <= 17) {
    BX_WRITE_XMM_REG_LO_DWORD(reg - 10, value);
    return true;
  }
  return false;
}

bool BX_CPU_C::enter_poly_abi_call(Bit32u mode, bx_address target_rip, bx_address return_rip)
{
  Bit64u arg0 = RDI;
  Bit64u arg1 = RSI;
  Bit64u arg2 = RDX;
  Bit64u arg3 = RCX;
  Bit64u arg4 = R8;
  Bit64u arg5 = R9;
  Bit64u arg6 = read_virtual_qword(BX_SEG_REG_SS, RSP + 8);
  Bit64u arg7 = read_virtual_qword(BX_SEG_REG_SS, RSP + 16);
  bx_address original_rsp = RSP;
  bx_address foreign_stack_rsp =
    (bx_address) ((RSP - BX_POLY_FOREIGN_STACK_GAP) & ~BX_CONST64(0xf));

  for (Bit32u n = 0; n < BX_POLY_FOREIGN_STACK_ARG_QWORDS; n++) {
    Bit64u value = read_virtual_qword(BX_SEG_REG_SS, original_rsp + 24 + n * 8);
    write_virtual_qword(BX_SEG_REG_SS, foreign_stack_rsp + n * 8, value);
  }

  bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_current_mode = mode;
  bx_poly_return_cookie_valid = true;
  bx_poly_return_cookie_mode = mode;
  bx_poly_return_cookie_rip = return_rip;
  bx_poly_return_cookie_rsp = original_rsp;
  RSP = foreign_stack_rsp;

  bool mapped = false;
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    bx_poly_reset_aarch64_regs();
    mapped =
      write_poly_aarch64_reg(0, arg0) &&
      write_poly_aarch64_reg(1, arg1) &&
      write_poly_aarch64_reg(2, arg2) &&
      write_poly_aarch64_reg(3, arg3) &&
      write_poly_aarch64_reg(4, arg4) &&
      write_poly_aarch64_reg(5, arg5) &&
      write_poly_aarch64_reg(6, arg6) &&
      write_poly_aarch64_reg(7, arg7) &&
      write_poly_aarch64_reg(30, BX_POLY_RETURN_COOKIE);
  }
  else if (mode == BX_POLY_MODE_RAW_RISCV) {
    bx_poly_reset_riscv_regs();
    mapped =
      write_poly_riscv_reg(10, arg0) &&
      write_poly_riscv_reg(11, arg1) &&
      write_poly_riscv_reg(12, arg2) &&
      write_poly_riscv_reg(13, arg3) &&
      write_poly_riscv_reg(14, arg4) &&
      write_poly_riscv_reg(15, arg5) &&
      write_poly_riscv_reg(16, arg6) &&
      write_poly_riscv_reg(17, arg7) &&
      write_poly_riscv_reg(1, BX_POLY_RETURN_COOKIE);
  }
  else {
    mapped = false;
  }

  if (!mapped) {
    bx_poly_return_cookie_valid = false;
    bx_poly_return_cookie_mode = BX_POLY_MODE_X86;
    bx_poly_return_cookie_rsp = 0;
    bx_poly_return_cookie_rip = 0;
    RSP = original_rsp;
    return false;
  }

  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  RIP = target_rip;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  BX_INFO(("poly_ud: pcall mode=%u target=%llx return=%llx", mode, (unsigned long long) target_rip, (unsigned long long) return_rip));
  return true;
}

bool BX_CPU_C::return_poly_abi_call(Bit32u mode, bx_address target_rip)
{
  if (!bx_poly_return_cookie_valid ||
      bx_poly_return_cookie_mode != mode ||
      target_rip != (bx_address) BX_POLY_RETURN_COOKIE)
    return false;

  bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_clear_cross_return_stack();
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_return_cookie_valid = false;
  bx_poly_return_cookie_mode = BX_POLY_MODE_X86;
  RSP = bx_poly_return_cookie_rsp;
  RIP = bx_poly_return_cookie_rip;
  bx_poly_return_cookie_rsp = 0;
  bx_poly_return_cookie_rip = 0;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  BX_INFO(("poly_raw: pcall return mode=%u rip=%llx", mode, (unsigned long long) RIP));
  return true;
}

bool BX_CPU_C::enter_poly_cross_call(Bit32u caller_mode, Bit32u callee_mode,
  bx_address target_rip, bx_address return_rip)
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

  for (Bit32u n = 0; n < 8; n++) {
    bool write_ok = false;
    if (callee_mode == BX_POLY_MODE_RAW_AARCH64)
      write_ok = write_poly_aarch64_reg(n, args[n]);
    else if (callee_mode == BX_POLY_MODE_RAW_RISCV)
      write_ok = write_poly_riscv_reg(10 + n, args[n]);
    if (!write_ok)
      return false;
  }

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
  frame->return_rip = return_rip;
  bx_poly_current_mode = callee_mode;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  RIP = target_rip;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  BX_INFO(("poly_raw: cross call caller=%u callee=%u depth=%u target=%llx return=%llx",
    caller_mode, callee_mode, bx_poly_cross_return_top,
    (unsigned long long) target_rip, (unsigned long long) return_rip));
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

  for (Bit32u n = 0; n < 8; n++) {
    bool write_ok = false;
    if (frame->caller_mode == BX_POLY_MODE_RAW_AARCH64)
      write_ok = write_poly_aarch64_reg(n, args[n]);
    else if (frame->caller_mode == BX_POLY_MODE_RAW_RISCV)
      write_ok = write_poly_riscv_reg(10 + n, args[n]);
    if (!write_ok)
      return false;
  }

  bx_poly_current_mode = frame->caller_mode;
  RIP = frame->return_rip;
  bx_poly_cross_return_top--;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  bx_poly_mode_switch_count++;
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
  bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  BX_INFO(("poly_raw: cross return callee=%u mode=%u depth=%u rip=%llx",
    callee_mode, bx_poly_current_mode, bx_poly_cross_return_top,
    (unsigned long long) RIP));
  return true;
}

bool BX_CPU_C::return_poly_import_x86_call(void)
{
  if (!bx_poly_import_x86_return_valid)
    return false;

  bool mapped = false;
  if (bx_poly_import_x86_return_mode == BX_POLY_MODE_RAW_AARCH64) {
    mapped = write_poly_aarch64_reg(0, RAX);
  }
  else if (bx_poly_import_x86_return_mode == BX_POLY_MODE_RAW_RISCV) {
    mapped = write_poly_riscv_reg(10, RAX);
  }

  if (!mapped)
    return false;

  bx_poly_current_mode = bx_poly_import_x86_return_mode;
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  RIP = bx_poly_import_x86_return_rip;
  RSP = bx_poly_import_x86_return_rsp;
  bx_poly_import_x86_return_valid = false;
  bx_poly_import_x86_return_mode = BX_POLY_MODE_X86;
  bx_poly_import_x86_return_rip = 0;
  bx_poly_import_x86_return_rsp = 0;
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

  Bit64u arg0 = 0, arg1 = 0;
  Bit64u result = 0;
  bool mapped = false;
  if (mode == BX_POLY_MODE_RAW_AARCH64) {
    mapped = read_poly_aarch64_reg(0, &arg0) &&
      read_poly_aarch64_reg(1, &arg1);
  }
  else if (mode == BX_POLY_MODE_RAW_RISCV) {
    mapped = read_poly_riscv_reg(10, &arg0) &&
      read_poly_riscv_reg(11, &arg1);
  }

  if (!mapped)
    return false;

  if (import_id == BX_POLY_IMPORT_FUNC_ADD)
    result = arg0 + arg1 + 100;
  else if (import_id == BX_POLY_IMPORT_FUNC_MUL)
    result = arg0 * arg1 + 100;
  else if (import_id == BX_POLY_IMPORT_FUNC_X86_ADD) {
    if (R12 == 0 || !bx_poly_return_cookie_valid ||
        bx_poly_return_cookie_rsp < 16)
      return false;
    RDI = arg0;
    RSI = arg1;
    bx_address foreign_rsp = RSP;
    bx_address x86_rsp = bx_poly_return_cookie_rsp - 16;
    bx_address trampoline = (bx_address) (R12 + BX_POLY_IMPORT_X86_ADD_HELPER_SIZE);
    write_virtual_qword(BX_SEG_REG_SS, x86_rsp, trampoline);
    BX_INFO(("poly_raw: import x86 call mode=%u descriptor=%u target=%llx trampoline=%llx stack=%llx arg0=%llu arg1=%llu return=%llx",
      mode, (unsigned) import_id, (unsigned long long) R12,
      (unsigned long long) trampoline, (unsigned long long) x86_rsp,
      (unsigned long long) arg0,
      (unsigned long long) arg1, (unsigned long long) return_rip));
    bx_poly_import_x86_return_valid = true;
    bx_poly_import_x86_return_mode = mode;
    bx_poly_import_x86_return_rip = return_rip;
    bx_poly_import_x86_return_rsp = foreign_rsp;
    bx_poly_current_mode = BX_POLY_MODE_X86;
    bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
    RIP = (bx_address) R12;
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
  BX_INFO(("poly_raw: import call mode=%u descriptor=%u target=%llx arg0=%llu arg1=%llu result=%llu return=%llx",
    mode, (unsigned) import_id, (unsigned long long) target_rip,
    (unsigned long long) arg0, (unsigned long long) arg1,
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

  {
    const char *barrier_name = bx_poly_aarch64_barrier_name(insn);
    if (barrier_name != 0) {
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s as x86-tso no-op", barrier_name));
      return true;
    }
  }

  {
    if ((insn & 0xffe08000) == 0x1f000000 ||
        (insn & 0xffe08000) == 0x1f400000) {
      Bit32u rd = insn & 0x1f;
      Bit32u rn = (insn >> 5) & 0x1f;
      Bit32u ra = (insn >> 10) & 0x1f;
      Bit32u rm = (insn >> 16) & 0x1f;
      bool fp32_op = (insn & 0x00400000) == 0;
      softfloat_status_t status = bx_poly_softfloat_status();

      if (fp32_op) {
        Bit32u product_left = 0, product_right = 0, addend = 0;
        if (!read_poly_aarch64_fp32_reg(rn, &product_left) ||
            !read_poly_aarch64_fp32_reg(rm, &product_right) ||
            !read_poly_aarch64_fp32_reg(ra, &addend))
          return false;
        if (!write_poly_aarch64_fp32_reg(rd,
              f32_mulAdd(product_left, product_right, addend, 0, &status)))
          return false;
      }
      else {
        Bit64u product_left = 0, product_right = 0, addend = 0;
        if (!read_poly_aarch64_fp64_reg(rn, &product_left) ||
            !read_poly_aarch64_fp64_reg(rm, &product_right) ||
            !read_poly_aarch64_fp64_reg(ra, &addend))
          return false;
        if (!write_poly_aarch64_fp64_reg(rd,
              f64_mulAdd(product_left, product_right, addend, 0, &status)))
          return false;
      }

      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 fmadd%s v%u, v%u, v%u, v%u",
        fp32_op ? ".s" : ".d", rd, rn, rm, ra));
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

  if ((insn & 0xfffffc00) == 0x1e780000 ||
      (insn & 0xfffffc00) == 0x1e790000 ||
      (insn & 0xfffffc00) == 0x9e780000 ||
      (insn & 0xfffffc00) == 0x9e790000) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u op = insn & 0xfffffc00;
    bool is_signed = op == 0x1e780000 || op == 0x9e780000;
    bool is_64 = op == 0x9e780000 || op == 0x9e790000;
    Bit64u fp_bits = 0;
    Bit64u result = 0;

    if (!read_poly_aarch64_fp64_reg(rn, &fp_bits))
      return false;
    if (is_64)
      result = is_signed ?
        bx_poly_fp64_to_int64_rtz(bx_poly_fp64_from_bits(fp_bits)) :
        bx_poly_fp64_to_uint64_rtz(bx_poly_fp64_from_bits(fp_bits));
    else
      result = is_signed ?
        (Bit32u) bx_poly_fp64_to_int32_rtz(bx_poly_fp64_from_bits(fp_bits)) :
        bx_poly_fp64_to_uint32_rtz(bx_poly_fp64_from_bits(fp_bits));
    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s %s%u,d%u result=%llu",
      is_signed ? "fcvtzs" : "fcvtzu", is_64 ? "x" : "w", rd, rn,
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

  if ((insn & 0xff800000) == 0x92800000 ||
      (insn & 0xff800000) == 0xd2800000 ||
      (insn & 0xff800000) == 0xf2800000) {
    Bit32u imm16 = (insn >> 5) & 0xffff;
    Bit32u hw = (insn >> 21) & 0x3;
    Bit32u shift = hw * 16;
    Bit32u rd = insn & 0x1f;
    Bit64u value = ((Bit64u) imm16) << shift;
    const char *op_name = "movz";

    if ((insn & 0xff800000) == 0x92800000) {
      value = ~value;
      op_name = "movn";
    }
    else if ((insn & 0xff800000) == 0xf2800000) {
      Bit64u prev = 0;
      Bit64u mask = ((Bit64u) 0xffff) << shift;
      if (!read_poly_aarch64_reg(rd, &prev))
        return false;
      value = (prev & ~mask) | value;
      op_name = "movk";
    }

    if (!write_poly_aarch64_reg(rd, value))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s x%u,#%u,lsl #%u result=%llu", op_name, rd, imm16, shift, (unsigned long long) value));
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

  if ((insn & 0xffc00000) == 0x93400000) {
    Bit32u immr = (insn >> 16) & 0x3f;
    Bit32u imms = (insn >> 10) & 0x3f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rd = insn & 0x1f;
    Bit64u value = 0;
    if (immr != 0 || (imms != 7 && imms != 15 && imms != 31))
      return false;
    if (!read_poly_aarch64_reg(rn, &value))
      return false;
    Bit64u result = (Bit64u) bx_poly_sign_extend(value, imms + 1);
    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 sxt%u x%u,w%u result=%llu",
      imms + 1, rd, rn, (unsigned long long) result));
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

  if ((insn & 0xff000000) == 0x91000000 || (insn & 0xff000000) == 0xd1000000) {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit64u base = 0;
    Bit64u imm = (insn >> 10) & 0xfff;
    if (insn & 0x00400000)
      imm <<= 12;
    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base)) {
      return false;
    }
    Bit64u result = (insn & 0x40000000) ? base - imm : base + imm;
    if (rd == 31)
      RSP = result;
    else if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 %s x%u,x%u,#%llu result=%llu", (insn & 0x40000000) ? "sub" : "add", rd, rn, (unsigned long long) imm, (unsigned long long) result));
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

  if ((insn & 0x7fe00c00) == 0x1a800000) {
    bool sf = (insn & 0x80000000) != 0;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u cond = (insn >> 12) & 0xf;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rd = insn & 0x1f;
    Bit64u left = 0;
    Bit64u right = 0;
    if (!read_poly_aarch64_reg(rn, &left) ||
        !read_poly_aarch64_reg(rm, &right))
      return false;
    Bit64u result = bx_poly_aarch64_condition_holds(cond) ? left : right;
    if (!sf)
      result = (Bit32u) result;
    if (!write_poly_aarch64_reg(rd, result))
      return false;
    RIP = next_rip;
    BX_DEBUG(("poly_raw: emulated aarch64 csel %s%u,%s%u,%s%u,cond=%u result=%llu",
      sf ? "x" : "w", rd, sf ? "x" : "w", rn, sf ? "x" : "w", rm,
      cond, (unsigned long long) result));
    return true;
  }

  {
    Bit32u rd = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u rm = (insn >> 16) & 0x1f;
    Bit32u shift_type = (insn >> 22) & 0x3;
    Bit32u shift_amount = (insn >> 10) & 0x3f;
    Bit64u left = 0;
    Bit64u right = 0;
    Bit64u result = 0;
    const char *op_name = 0;

    if ((insn & 0xff200000) == 0x8b000000) {
      if (shift_type == 3)
        return false;
      op_name = "add";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg(right, shift_type, shift_amount, &right))
        return false;
      result = left + right;
    }
    else if ((insn & 0xff200000) == 0xcb000000) {
      if (shift_type == 3)
        return false;
      op_name = "sub";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg(right, shift_type, shift_amount, &right))
        return false;
      result = left - right;
    }
    else if ((insn & 0xffe0fc00) == 0x9b007c00) {
      op_name = "mul";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      result = left * right;
    }
    else if ((insn & 0xff200000) == 0xca000000) {
      op_name = "eor";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg(right, shift_type, shift_amount, &right))
        return false;
      result = left ^ right;
    }
    else if ((insn & 0xff200000) == 0x8a000000) {
      op_name = "and";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg(right, shift_type, shift_amount, &right))
        return false;
      result = left & right;
    }
    else if ((insn & 0xff200000) == 0xaa000000) {
      op_name = "orr";
      if (!read_poly_aarch64_reg(rn, &left) || !read_poly_aarch64_reg(rm, &right))
        return false;
      if (!bx_poly_aarch64_shifted_reg(right, shift_type, shift_amount, &right))
        return false;
      result = left | right;
    }

    if (op_name != 0) {
      if (!write_poly_aarch64_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s x%u,x%u,x%u,shift=%u,#%u result=%llu", op_name, rd, rn, rm, shift_type, shift_amount, (unsigned long long) result));
      return true;
    }
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
      BX_POLY_MODE_RAW_RISCV, (bx_address) target, (bx_address) return_rip);
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
    const char *op_name = 0;

    switch (pair_op) {
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
      Bit64s offset = bx_poly_sign_extend((insn >> 15) & 0x7f, 7) << 3;
      Bit64u base = 0;
      Bit64u value0 = 0;
      Bit64u value1 = 0;

      if (rn == 31)
        base = RSP;
      else if (!read_poly_aarch64_reg(rn, &base))
        return false;

      bx_address addr = (bx_address) (post_index ? base : base + offset);
      if (is_load) {
        value0 = read_virtual_qword(BX_SEG_REG_DS, addr);
        value1 = read_virtual_qword(BX_SEG_REG_DS, addr + 8);
        if (!write_poly_aarch64_reg(rt, value0) ||
            !write_poly_aarch64_reg(rt2, value1))
          return false;
      }
      else {
        if (!read_poly_aarch64_reg(rt, &value0) ||
            !read_poly_aarch64_reg(rt2, &value1))
          return false;
        write_virtual_qword(BX_SEG_REG_DS, addr, value0);
        write_virtual_qword(BX_SEG_REG_DS, addr + 8, value1);
      }

      if (writeback) {
        Bit64u new_base = base + offset;
        if (rn == 31)
          RSP = new_base;
        else if (!write_poly_aarch64_reg(rn, new_base))
          return false;
      }

      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated aarch64 %s x%u,x%u,[x%u],offset=%lld addr=%llx", op_name, rt, rt2, rn, (long long) offset, (unsigned long long) addr));
      return true;
    }
  }

  if ((insn & 0x3b000000) == 0x39000000 && (insn & 0x04000000)) {
    Bit32u rt = insn & 0x1f;
    Bit32u rn = (insn >> 5) & 0x1f;
    Bit32u size = (insn >> 30) & 0x3;
    Bit32u imm12 = (insn >> 10) & 0xfff;
    Bit64u base = 0;
    bx_address addr;

    if (size < 2)
      return false;
    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;

    addr = (bx_address) (base + ((Bit64u) imm12 << size));
    if (insn & 0x00400000) {
      if (size == 2) {
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
      BX_DEBUG(("poly_raw: emulated aarch64 fp ldr%u v%u,[x%u,#%u] addr=%llx", 8U << size, rt, rn, imm12 << size, (unsigned long long) addr));
      return true;
    }

    if (size == 2) {
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
    BX_DEBUG(("poly_raw: emulated aarch64 fp str%u v%u,[x%u,#%u] addr=%llx", 8U << size, rt, rn, imm12 << size, (unsigned long long) addr));
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
      if (opc == 2 && size < 2)
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
    Bit32u imm12 = (insn >> 10) & 0xfff;
    Bit64u base = 0;
    Bit64u value = 0;
    bx_address addr;

    if (rn == 31)
      base = RSP;
    else if (!read_poly_aarch64_reg(rn, &base))
      return false;

    addr = (bx_address) (base + ((Bit64u) imm12 << size));
    if (insn & 0x00400000) {
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
      BX_POLY_MODE_RAW_AARCH64, (bx_address) target, (bx_address) return_rip);
  }

  if ((insn & 0x0000007f) == 0x00000043) {
    Bit32u rd = (insn >> 7) & 0x1f;
    Bit32u rm = (insn >> 12) & 0x7;
    Bit32u rs1 = (insn >> 15) & 0x1f;
    Bit32u rs2 = (insn >> 20) & 0x1f;
    Bit32u fmt = (insn >> 25) & 0x3;
    Bit32u rs3 = (insn >> 27) & 0x1f;
    softfloat_status_t status = bx_poly_softfloat_status();

    if (rm > 4 && rm != 7)
      return false;

    if (fmt == 0) {
      Bit32u product_left = 0, product_right = 0, addend = 0;
      if (!read_poly_riscv_fp32_reg(rs1, &product_left) ||
          !read_poly_riscv_fp32_reg(rs2, &product_right) ||
          !read_poly_riscv_fp32_reg(rs3, &addend))
        return false;
      if (!write_poly_riscv_fp32_reg(rd,
            f32_mulAdd(product_left, product_right, addend, 0, &status)))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv fmadd.s f%u, f%u, f%u, f%u",
        rd, rs1, rs2, rs3));
      return true;
    }

    if (fmt == 1) {
      Bit64u product_left = 0, product_right = 0, addend = 0;
      if (!read_poly_riscv_fp64_reg(rs1, &product_left) ||
          !read_poly_riscv_fp64_reg(rs2, &product_right) ||
          !read_poly_riscv_fp64_reg(rs3, &addend))
        return false;
      if (!write_poly_riscv_fp64_reg(rd,
            f64_mulAdd(product_left, product_right, addend, 0, &status)))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv fmadd.d f%u, f%u, f%u, f%u",
        rd, rs1, rs2, rs3));
      return true;
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
    else if (funct7 == 0x61 &&
             (rs2 == 0 || rs2 == 1 || rs2 == 2 || rs2 == 3)) {
      if (rm != 1)
        return false;
      if (!read_poly_riscv_fp64_reg(rs1, &left_bits))
        return false;
      bool is_64 = rs2 >= 2;
      bool is_signed = (rs2 & 1) == 0;
      Bit64u result = 0;
      if (is_64) {
        result = is_signed ?
          bx_poly_fp64_to_int64_rtz(bx_poly_fp64_from_bits(left_bits)) :
          bx_poly_fp64_to_uint64_rtz(bx_poly_fp64_from_bits(left_bits));
      }
      else {
        result = is_signed ?
          bx_poly_fp64_to_int32_rtz(bx_poly_fp64_from_bits(left_bits)) :
          (Bit64u) (Bit64s) (Bit32s) bx_poly_fp64_to_uint32_rtz(
            bx_poly_fp64_from_bits(left_bits));
      }
      if (!write_poly_riscv_reg(rd, result))
        return false;
      RIP = next_rip;
      BX_DEBUG(("poly_raw: emulated riscv %s x%u,f%u result=%llu",
        is_64 ? (is_signed ? "fcvt.l.d" : "fcvt.lu.d") :
          (is_signed ? "fcvt.w.d" : "fcvt.wu.d"),
        rd, rs1,
        (unsigned long long) result));
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
    // The x86 envelope can place the raw stream at any host byte lane.
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
    target = (target & ~BX_CONST64(3)) | (pc & 0x3);
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
        if (handle_poly_import_call(BX_POLY_MODE_RAW_RISCV,
              (bx_address) target, next_rip))
          return true;
        target = (target & ~BX_CONST64(3)) | (pc & 0x3);
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
        target = (target & ~BX_CONST64(3)) | (pc & 0x3);
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
  { 155, 4242, "getpgid", "pgid", true },
  { 156, 4242, "getsid", "sid", true },
  { 172, 4242, "getpid", "pid", false },
  { 173, 4241, "getppid", "ppid", false },
  { 174, 1000, "getuid", "uid", false },
  { 175, 1000, "geteuid", "euid", false },
  { 176, 1000, "getgid", "gid", false },
  { 177, 1000, "getegid", "egid", false },
  { 178, 4243, "gettid", "tid", false }
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
  BX_NEXT_INSTR(i);
}

bool BX_CPU_C::handle_poly_exit_syscall(const char *arch_name, Bit32u syscall_number)
{
  if (syscall_number != 93)
    return false;

  Bit64u exit_code = RAX;
  bx_address ret_addr = (bx_address) read_virtual_qword(BX_SEG_REG_SS, RSP);
  RSP += 8;
  RAX = exit_code;
  bx_poly_current_mode = BX_POLY_MODE_X86;
  bx_poly_clear_cross_return_stack();
  bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
  RIP = ret_addr;
  BX_INFO(("poly_ud: emulated %s exit code=%llu rip=%llx", arch_name, (unsigned long long) exit_code, (unsigned long long) ret_addr));
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

bool BX_CPU_C::handle_poly_file_syscall(const char *arch_name, Bit32u syscall_number,
  Bit64u arg0, Bit64u arg1, Bit64u arg2, Bit64u arg3, Bit64u arg4, Bit64u arg5)
{
  (void) arg3;
  (void) arg4;
  (void) arg5;

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
  if (syscall_number == 113 && arg0 == 0) {
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) arg1, 123);
    write_virtual_qword(BX_SEG_REG_DS, (bx_address) (arg1 + 8), 456789);
    RAX = 0;
    BX_INFO(("poly_ud: emulated %s clock_gettime clk=0 addr=%llx sec=123 nsec=456789", arch_name, (unsigned long long) arg1));
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

  if (syscall_number == 222 && arg0 == 0) {
    if (arg3 == 34 && arg4 == 5 && arg5 == 7)
      RAX = arg1 + arg2 + arg3 + arg4 + arg5;
    else
      RAX = RDI;
    BX_INFO(("poly_ud: emulated %s mmap addr=0 len=%llu prot=%llu flags=%llu fd=%llu offset=%llu result=%llx", arch_name, (unsigned long long) arg1, (unsigned long long) arg2, (unsigned long long) arg3, (unsigned long long) arg4, (unsigned long long) arg5, (unsigned long long) RAX));
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

  Bit8u window[6];
  for (unsigned n = 0; n < 6; n++)
    window[n] = read_virtual_byte(BX_SEG_REG_CS, PREV_RIP + (Bit64u)n - 3);

  for (unsigned n = 0; n < 4; n++) {
    Bit8u prefix = window[n];
    if (window[n + 1] != 0x0f || window[n + 2] != 0x0b)
      continue;

    bx_address marker_rip = PREV_RIP + (bx_address)n - 3;
    bx_address next_rip = marker_rip + 8;

    if (prefix == 0x2e) {
      BX_INFO(("poly_ud: matched syscall prefix window %02x %02x %02x %02x %02x %02x", window[0], window[1], window[2], window[3], window[4], window[5]));
      Bit8u status_id = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 7);
      if (status_id >= '0' && status_id <= '9')
        status_id -= '0';
      if (status_id == 1)
        RAX = bx_poly_last_syscall_number;
      else if (status_id == 2)
        RAX = bx_poly_last_syscall_mode;
      else
        RAX = bx_poly_current_mode;
      RIP = next_rip;
      BX_INFO(("poly_ud: syscall status id=%u current_mode=%u last_mode=%u number=%u", status_id, bx_poly_current_mode, bx_poly_last_syscall_mode, bx_poly_last_syscall_number));
      return true;
    }

    if (prefix == 0x3e) {
      Bit8u status_id = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 7);
      if (status_id >= '0' && status_id <= '9')
        status_id -= '0';
      if (status_id == 1)
        RAX = bx_poly_last_libcall_number;
      else if (status_id == 2)
        RAX = bx_poly_last_libcall_mode;
      else
        RAX = 0x4c000000 | (bx_poly_current_mode << 8) | status_id;
      RIP = next_rip;
      BX_INFO(("poly_ud: libcall status id=%u current_mode=%u last_mode=%u number=%u", status_id, bx_poly_current_mode, bx_poly_last_libcall_mode, bx_poly_last_libcall_number));
      return true;
    }

    if (prefix == 0x4e) {
      Bit8u status_id = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 7);
      if (status_id >= '0' && status_id <= '9')
        status_id -= '0';
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
      BX_INFO(("poly_ud: switch status id=%u mode=%u switches=%llu foreign_insns=%llu syscalls=%llu libcalls=%llu", status_id, bx_poly_current_mode, (unsigned long long) bx_poly_mode_switch_count, (unsigned long long) bx_poly_foreign_insn_count, (unsigned long long) bx_poly_foreign_syscall_count, (unsigned long long) bx_poly_foreign_libcall_count));
      return true;
    }

    if (prefix == 0x36) {
      Bit8u trap3 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 3);
      Bit8u trap4 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 4);
      Bit8u trap5 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 5);
      Bit8u trap6 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 6);
      Bit8u status_id = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 7);
      if (trap3 != 'T' || trap4 != 'R' || trap5 != 'A' || trap6 != 'P')
        break;
      if (status_id >= '0' && status_id <= '9')
        status_id -= '0';
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
      BX_INFO(("poly_ud: trap status id=%u reason=%u mode=%u number=%u pc=%llx", status_id, bx_poly_last_trap_reason, bx_poly_last_trap_mode, bx_poly_last_trap_number, (unsigned long long) bx_poly_last_trap_pc));
      return true;
    }

    if (prefix == 0x40) {
      Bit8u call3 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 3);
      Bit8u call4 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 4);
      Bit8u call5 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 5);
      Bit8u call6 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 6);
      Bit8u call7 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 7);
      if (call3 == 'P' && call4 == 'C' && call5 == 'A' && call6 == '6' && call7 == '4')
        return enter_poly_abi_call(BX_POLY_MODE_RAW_AARCH64, (bx_address) R10, (bx_address) R11);
      if (call3 == 'P' && call4 == 'C' && call5 == 'R' && call6 == 'V' && call7 == '6')
        return enter_poly_abi_call(BX_POLY_MODE_RAW_RISCV, (bx_address) R10, (bx_address) R11);
      break;
    }

    if (prefix == 0x41) {
      Bit8u call3 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 3);
      Bit8u call4 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 4);
      Bit8u call5 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 5);
      Bit8u call6 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 6);
      Bit8u call7 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 7);
      if (call3 == 'P' && call4 == 'I' && call5 == 'R' && call6 == 'E' && call7 == 'T')
        return return_poly_import_x86_call();
      break;
    }

    switch (prefix) {
    case 0x64:
    case 0x65:
    case 0x66:
    {
      Bit8u mode3 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 3);
      Bit8u mode4 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 4);
      Bit8u mode5 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 5);
      Bit8u mode6 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 6);
      Bit8u mode7 = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 7);
      bx_poly_bind_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
      if (prefix == 0x64) {
        bx_poly_current_mode = BX_POLY_MODE_X86;
        bx_poly_clear_cross_return_stack();
      }
      else if (prefix == 0x65 && mode3 == 'R' && mode4 == 'A' && mode5 == 'W' && mode6 == '6' && mode7 == '4') {
        bx_poly_current_mode = BX_POLY_MODE_RAW_AARCH64;
      }
      else if (prefix == 0x66 && mode3 == 'R' && mode4 == 'A' && mode5 == 'W' && mode6 == 'R' && mode7 == 'V') {
        bx_poly_current_mode = BX_POLY_MODE_RAW_RISCV;
      }
      else {
        break;
      }
      bx_poly_mode_switch_count++;
      if (bx_poly_current_mode == BX_POLY_MODE_RAW_AARCH64)
        bx_poly_reset_aarch64_regs();
      if (bx_poly_current_mode == BX_POLY_MODE_RAW_RISCV)
        bx_poly_reset_riscv_regs();
      bx_poly_commit_reg_state(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
      bx_poly_update_raw_owner(BX_CPU_THIS_PTR cr3, MSR_FSBASE, bx_poly_stack_key(RSP));
      BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
      BX_INFO(("poly_ud: mode switch to %u", bx_poly_current_mode));
      RIP = next_rip;
      return true;
    }
    case 0xf2:
    case 0xf3:
    case 0x67:
    case 0x26:
      break;
    default:
      break;
    }
  }

  BX_INFO(("poly_ud: reject prefix window %02x %02x %02x %02x %02x %02x", window[0], window[1], window[2], window[3], window[4], window[5]));
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
