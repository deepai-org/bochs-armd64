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

enum {
  BX_POLY_MODE_X86 = 0,
  BX_POLY_MODE_AARCH64 = 1,
  BX_POLY_MODE_RISCV = 2
};

static Bit32u bx_poly_current_mode = BX_POLY_MODE_X86;
static Bit32u bx_poly_return_mode = BX_POLY_MODE_X86;
static bool bx_poly_call_active = false;
static Bit32u bx_poly_last_syscall_mode = BX_POLY_MODE_X86;
static Bit32u bx_poly_last_syscall_number = 0;
static Bit32u bx_poly_last_libcall_mode = BX_POLY_MODE_X86;
static Bit32u bx_poly_last_libcall_number = 0;
static Bit64u bx_poly_aarch64_x1 = 0;
static Bit64u bx_poly_aarch64_x2 = 0;
static Bit32u bx_poly_aarch64_x8 = 0;
static Bit64u bx_poly_riscv_a1 = 0;
static Bit64u bx_poly_riscv_a2 = 0;
static Bit32u bx_poly_riscv_a7 = 0;

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

bool BX_CPP_AttrRegparmN(1) BX_CPU_C::handle_poly_ud(bxInstruction_c *i)
{
  (void) i;

  if (!BX_CPU_THIS_PTR poly_feature_enabled)
    return false;

  if (CPL != 3) {
    BX_INFO(("poly_ud: reject CPL=%u", CPL));
    return false;
  }

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
      RAX = status_id == 1 ? bx_poly_last_syscall_number : bx_poly_current_mode;
      RIP = next_rip;
      BX_INFO(("poly_ud: syscall status id=%u mode=%u number=%u", status_id, bx_poly_last_syscall_mode, bx_poly_last_syscall_number));
      return true;
    }

    if (prefix == 0x3e) {
      Bit8u status_id = read_virtual_byte(BX_SEG_REG_CS, marker_rip + 7);
      if (status_id >= '0' && status_id <= '9')
        status_id -= '0';
      RAX = status_id == 1 ? bx_poly_last_libcall_number : 0x4c000000 | (bx_poly_current_mode << 8) | status_id;
      RIP = next_rip;
      BX_INFO(("poly_ud: libcall status id=%u mode=%u number=%u", status_id, bx_poly_last_libcall_mode, bx_poly_last_libcall_number));
      return true;
    }

    switch (prefix) {
    case 0x64:
    case 0x65:
    case 0x66:
      bx_poly_current_mode =
        (prefix == 0x64) ? BX_POLY_MODE_X86 :
        (prefix == 0x65) ? BX_POLY_MODE_AARCH64 : BX_POLY_MODE_RISCV;
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64) {
        bx_poly_aarch64_x1 = 0;
        bx_poly_aarch64_x2 = 0;
        bx_poly_aarch64_x8 = 0;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV) {
        bx_poly_riscv_a1 = 0;
        bx_poly_riscv_a2 = 0;
        bx_poly_riscv_a7 = 0;
      }
      BX_INFO(("poly_ud: mode switch to %u", bx_poly_current_mode));
      RIP = next_rip;
      return true;
    case 0xf2:
      bx_poly_return_mode = bx_poly_current_mode;
      bx_poly_current_mode = BX_POLY_MODE_AARCH64;
      bx_poly_call_active = true;
      BX_INFO(("poly_ud: call mode=%u return=%u", bx_poly_current_mode, bx_poly_return_mode));
      RIP = next_rip;
      return true;
    case 0xf3:
      if (bx_poly_call_active) {
        bx_poly_current_mode = bx_poly_return_mode;
        bx_poly_call_active = false;
      }
      BX_INFO(("poly_ud: return mode=%u", bx_poly_current_mode));
      RIP = next_rip;
      return true;
    case 0x67: {
      Bit32u insn =
        ((Bit32u) read_virtual_byte(BX_SEG_REG_CS, marker_rip + 3)) |
        ((Bit32u) read_virtual_byte(BX_SEG_REG_CS, marker_rip + 4) << 8) |
        ((Bit32u) read_virtual_byte(BX_SEG_REG_CS, marker_rip + 5) << 16) |
        ((Bit32u) read_virtual_byte(BX_SEG_REG_CS, marker_rip + 6) << 24);
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffe00000) == 0xd2800000) {
        Bit32u imm16 = (insn >> 5) & 0xffff;
        Bit32u rd = insn & 0x1f;
        if (rd == 0)
          RAX = imm16;
        else if (rd == 1)
          bx_poly_aarch64_x1 = imm16;
        else if (rd == 2)
          bx_poly_aarch64_x2 = imm16;
        else if (rd == 8)
          bx_poly_aarch64_x8 = imm16;
        else
          break;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 movz x%u,#%u", rd, imm16));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffc003ff) == 0x91000000) {
        Bit32u imm12 = (insn >> 10) & 0xfff;
        RAX += imm12;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 add x0,x0,#%u", imm12));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffc003ff) == 0xd1000000) {
        Bit32u imm12 = (insn >> 10) & 0xfff;
        RAX -= imm12;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 sub x0,x0,#%u", imm12));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffc003ff) == 0x91000041) {
        Bit32u imm12 = (insn >> 10) & 0xfff;
        Bit32u rn = (insn >> 5) & 0x1f;
        if (rn != 2)
          break;
        bx_poly_aarch64_x1 = RDI + imm12;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 add x1,x2,#%u value=%llu", imm12, (unsigned long long) bx_poly_aarch64_x1));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffc003ff) == 0x91000040) {
        Bit32u imm12 = (insn >> 10) & 0xfff;
        Bit32u rn = (insn >> 5) & 0x1f;
        if (rn != 2)
          break;
        RAX = RDI + imm12;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 add x0,x2,#%u value=%llu", imm12, (unsigned long long) RAX));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffc0fc00) == 0x8b000000) {
        Bit32u rd = insn & 0x1f;
        Bit32u rn = (insn >> 5) & 0x1f;
        Bit32u rm = (insn >> 16) & 0x1f;
        if (rd != 0 || rn != 0 || rm != 1)
          break;
        RAX += bx_poly_aarch64_x1;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 add x0,x0,x1 value=%llu", (unsigned long long) bx_poly_aarch64_x1));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffc0fc00) == 0xcb000000) {
        Bit32u rd = insn & 0x1f;
        Bit32u rn = (insn >> 5) & 0x1f;
        Bit32u rm = (insn >> 16) & 0x1f;
        if (rd != 0 || rn != 0 || rm != 2)
          break;
        RAX -= RDI;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 sub x0,x0,x2 value=%llu", (unsigned long long) RDI));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && insn == 0x9b017c00) {
        RAX *= bx_poly_aarch64_x1;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 mul x0,x0,x1 value=%llu", (unsigned long long) bx_poly_aarch64_x1));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xfc000000) == 0x14000000) {
        Bit64s guest_offset = bx_poly_sign_extend(insn & 0x03ffffff, 26) << 2;
        Bit64s marker_offset = bx_poly_marker_offset(guest_offset);
        RIP = (bx_address) ((Bit64s) marker_rip + marker_offset);
        BX_INFO(("poly_ud: emulated aarch64 b offset=%lld marker_offset=%lld", (long long) guest_offset, (long long) marker_offset));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0x7e000000) == 0x34000000) {
        Bit32u rt = insn & 0x1f;
        Bit32u op = (insn >> 24) & 0x1;
        if (rt != 0)
          break;
        bool taken = (op == 0) ? (RAX == 0) : (RAX != 0);
        if (taken) {
          Bit64s guest_offset = bx_poly_sign_extend((insn >> 5) & 0x7ffff, 19) << 2;
          Bit64s marker_offset = bx_poly_marker_offset(guest_offset);
          RIP = (bx_address) ((Bit64s) marker_rip + marker_offset);
          BX_INFO(("poly_ud: emulated aarch64 %s x0 taken offset=%lld marker_offset=%lld", op ? "cbnz" : "cbz", (long long) guest_offset, (long long) marker_offset));
        }
        else {
          RIP = next_rip;
          BX_INFO(("poly_ud: emulated aarch64 %s x0 not-taken", op ? "cbnz" : "cbz"));
        }
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && insn == 0xd65f03c0) {
        bx_address ret_addr = (bx_address) read_virtual_qword(BX_SEG_REG_SS, RSP);
        RSP += 8;
        RIP = ret_addr;
        BX_INFO(("poly_ud: emulated aarch64 ret rip=%llx", (unsigned long long) ret_addr));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffc00000) == 0xf9000000) {
        Bit32u rt = insn & 0x1f;
        Bit32u rn = (insn >> 5) & 0x1f;
        Bit32u imm12 = (insn >> 10) & 0xfff;
        bx_address addr;
        Bit64u value;
        if (rt == 0 && rn == 2) {
          addr = (bx_address) (RDI + ((Bit64u) imm12 << 3));
          value = RAX;
        }
        else if (rt == 1 && rn == 0) {
          addr = (bx_address) (RAX + ((Bit64u) imm12 << 3));
          value = bx_poly_aarch64_x1;
        }
        else {
          break;
        }
        write_virtual_qword(BX_SEG_REG_DS, addr, value);
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 str x%u,[x%u,#%u] addr=%llx value=%llu", rt, rn, imm12 << 3, (unsigned long long) addr, (unsigned long long) value));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffc00000) == 0xf9400000) {
        Bit32u rt = insn & 0x1f;
        Bit32u rn = (insn >> 5) & 0x1f;
        Bit32u imm12 = (insn >> 10) & 0xfff;
        if (rt != 0 || (rn != 0 && rn != 2))
          break;
        bx_address addr = (bx_address) ((rn == 2 ? RDI : RAX) + ((Bit64u) imm12 << 3));
        RAX = read_virtual_qword(BX_SEG_REG_DS, addr);
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated aarch64 ldr x0,[x%u,#%u] addr=%llx value=%llu", rn, imm12 << 3, (unsigned long long) addr, (unsigned long long) RAX));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffe0001f) == 0xd4000001) {
        Bit32u syscall_id = (insn >> 5) & 0xffff;
        bx_poly_last_syscall_mode = bx_poly_current_mode;
        bx_poly_last_syscall_number = bx_poly_aarch64_x8 ? bx_poly_aarch64_x8 : syscall_id;
        if (bx_poly_aarch64_x8 == 17) {
          const char cwd[] = "/poly";
          Bit64u addr = RAX;
          Bit64u needed = sizeof(cwd);
          if (bx_poly_aarch64_x1 < needed) {
            RAX = (Bit64u) -34;
            BX_INFO(("poly_ud: emulated aarch64 getcwd range addr=%llx size=%llu needed=%llu", (unsigned long long) addr, (unsigned long long) bx_poly_aarch64_x1, (unsigned long long) needed));
          }
          else {
            for (unsigned n = 0; n < sizeof(cwd); n++)
              write_virtual_byte(BX_SEG_REG_DS, (bx_address) (addr + n), (Bit8u) cwd[n]);
            BX_INFO(("poly_ud: emulated aarch64 getcwd addr=%llx size=%llu cwd=%s", (unsigned long long) addr, (unsigned long long) bx_poly_aarch64_x1, cwd));
            RAX = needed;
          }
        }
        else if (bx_poly_aarch64_x8 == 63 && (RAX == 0 || RAX == 3)) {
          Bit64u fd = RAX;
          const Bit8u stdin_input[] = {'R', 'X', '!', '!'};
          const Bit8u file_input[] = {'F', 'D', '!', '!'};
          const Bit8u *input = fd == 3 ? file_input : stdin_input;
          const Bit64u input_size = 4;
          Bit64u count = bx_poly_aarch64_x2 < input_size ? bx_poly_aarch64_x2 : input_size;
          for (Bit64u n = 0; n < count; n++)
            write_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_aarch64_x1 + n), input[n]);
          RAX = count;
          BX_INFO(("poly_ud: emulated aarch64 read fd=%llu addr=%llx count=%llu", (unsigned long long) fd, (unsigned long long) bx_poly_aarch64_x1, (unsigned long long) count));
        }
        else if (bx_poly_aarch64_x8 == 64 && RAX == 1) {
          Bit64u checksum = 0;
          for (Bit64u n = 0; n < bx_poly_aarch64_x2 && n < 4096; n++)
            checksum += read_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_aarch64_x1 + n));
          RAX = bx_poly_aarch64_x2;
          BX_INFO(("poly_ud: emulated aarch64 write fd=1 addr=%llx count=%llu checksum=%llu", (unsigned long long) bx_poly_aarch64_x1, (unsigned long long) bx_poly_aarch64_x2, (unsigned long long) checksum));
        }
        else if (bx_poly_aarch64_x8 == 56) {
          Bit64u dirfd = RAX;
          char path[16];
          unsigned n;
          for (n = 0; n < sizeof(path) - 1; n++) {
            path[n] = (char) read_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_aarch64_x1 + n));
            if (path[n] == '\0')
              break;
          }
          path[n] = '\0';
          RAX = strcmp(path, "poly!") == 0 ? 3 : (Bit64u) -2;
          BX_INFO(("poly_ud: emulated aarch64 openat dirfd=%llu path=%s flags=%llu result=%lld", (unsigned long long) dirfd, path, (unsigned long long) bx_poly_aarch64_x2, (long long) RAX));
        }
        else if (bx_poly_aarch64_x8 == 57) {
          Bit64u fd = RAX;
          RAX = fd == 3 ? 0 : (Bit64u) -9;
          BX_INFO(("poly_ud: emulated aarch64 close fd=%llu result=%lld", (unsigned long long) fd, (long long) RAX));
        }
        else if (bx_poly_aarch64_x8 == 62) {
          Bit64u fd = RAX;
          RAX = (fd == 3 && bx_poly_aarch64_x2 <= 2) ? bx_poly_aarch64_x1 : (Bit64u) -9;
          BX_INFO(("poly_ud: emulated aarch64 lseek fd=%llu offset=%llu whence=%llu result=%lld", (unsigned long long) fd, (unsigned long long) bx_poly_aarch64_x1, (unsigned long long) bx_poly_aarch64_x2, (long long) RAX));
        }
        else if (bx_poly_aarch64_x8 == 113 && RAX == 0) {
          write_virtual_qword(BX_SEG_REG_DS, (bx_address) bx_poly_aarch64_x1, 123);
          write_virtual_qword(BX_SEG_REG_DS, (bx_address) (bx_poly_aarch64_x1 + 8), 456789);
          RAX = 0;
          BX_INFO(("poly_ud: emulated aarch64 clock_gettime clk=0 addr=%llx sec=123 nsec=456789", (unsigned long long) bx_poly_aarch64_x1));
        }
        else if (bx_poly_aarch64_x8 == 222 && RAX == 0) {
          RAX = RDI;
          BX_INFO(("poly_ud: emulated aarch64 mmap addr=0 len=%llu result=%llx", (unsigned long long) bx_poly_aarch64_x1, (unsigned long long) RAX));
        }
        else if (bx_poly_aarch64_x8 == 172) {
          RAX = 4242;
          BX_INFO(("poly_ud: emulated aarch64 getpid pid=%llu", (unsigned long long) RAX));
        }
        else if (bx_poly_aarch64_x8 == 174) {
          RAX = 1000;
          BX_INFO(("poly_ud: emulated aarch64 getuid uid=%llu", (unsigned long long) RAX));
        }
        else if (bx_poly_aarch64_x8 == 93) {
          Bit64u exit_code = RAX;
          bx_address ret_addr = (bx_address) read_virtual_qword(BX_SEG_REG_SS, RSP);
          RSP += 8;
          RAX = exit_code;
          RIP = ret_addr;
          BX_INFO(("poly_ud: emulated aarch64 exit code=%llu rip=%llx", (unsigned long long) exit_code, (unsigned long long) ret_addr));
          return true;
        }
        else if (bx_poly_aarch64_x8 == 160) {
          const char sysname[] = "Linux";
          for (unsigned n = 0; n < sizeof(sysname); n++)
            write_virtual_byte(BX_SEG_REG_DS, (bx_address) (RAX + n), (Bit8u) sysname[n]);
          BX_INFO(("poly_ud: emulated aarch64 uname addr=%llx sysname=%s", (unsigned long long) RAX, sysname));
          RAX = 0;
        }
        else {
          RAX = 0x53000000 | (syscall_id << 8) | bx_poly_current_mode;
          BX_INFO(("poly_ud: emulated aarch64 svc #%u mode=%u", syscall_id, bx_poly_current_mode));
        }
        RIP = next_rip;
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_AARCH64 && (insn & 0xffe0001f) == 0xd4200000) {
        Bit32u libcall_id = (insn >> 5) & 0xffff;
        bx_poly_last_libcall_mode = bx_poly_current_mode;
        bx_poly_last_libcall_number = libcall_id;
        if (libcall_id == 1) {
          RAX = 0;
          while (RAX < 4096 && read_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + RAX)) != 0)
            RAX++;
          BX_INFO(("poly_ud: emulated aarch64 brk strlen addr=%llx len=%llu", (unsigned long long) RDI, (unsigned long long) RAX));
        }
        else if (libcall_id == 2) {
          Bit64u count = RAX < 4096 ? RAX : 4096;
          Bit8u value = (Bit8u) bx_poly_aarch64_x1;
          for (Bit64u n = 0; n < count; n++)
            write_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + n), value);
          RAX = count;
          BX_INFO(("poly_ud: emulated aarch64 brk memfill addr=%llx count=%llu value=%u", (unsigned long long) RDI, (unsigned long long) count, value));
        }
        else if (libcall_id == 3) {
          Bit64u count = bx_poly_aarch64_x2 < 4096 ? bx_poly_aarch64_x2 : 4096;
          Bit64s result = 0;
          for (Bit64u n = 0; n < count; n++) {
            Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + n));
            Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_aarch64_x1 + n));
            if (left != right) {
              result = (Bit64s) left - (Bit64s) right;
              break;
            }
          }
          RAX = (Bit64u) result;
          BX_INFO(("poly_ud: emulated aarch64 brk memcmp left=%llx right=%llx count=%llu result=%lld", (unsigned long long) RDI, (unsigned long long) bx_poly_aarch64_x1, (unsigned long long) count, (long long) result));
        }
        else if (libcall_id == 4) {
          Bit64u count = RAX < 4096 ? RAX : 4096;
          for (Bit64u n = 0; n < count; n++) {
            Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_aarch64_x1 + n));
            write_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + n), value);
          }
          RAX = count;
          BX_INFO(("poly_ud: emulated aarch64 brk memcpy dest=%llx src=%llx count=%llu", (unsigned long long) RDI, (unsigned long long) bx_poly_aarch64_x1, (unsigned long long) count));
        }
        else {
          RAX = 0x4c000000 | (bx_poly_current_mode << 8) | libcall_id;
          BX_INFO(("poly_ud: emulated aarch64 brk #%u libcall mode=%u", libcall_id, bx_poly_current_mode));
        }
        RIP = next_rip;
        return true;
      }
      break;
    }
    case 0x26: {
      Bit32u insn =
        ((Bit32u) read_virtual_byte(BX_SEG_REG_CS, marker_rip + 3)) |
        ((Bit32u) read_virtual_byte(BX_SEG_REG_CS, marker_rip + 4) << 8) |
        ((Bit32u) read_virtual_byte(BX_SEG_REG_CS, marker_rip + 5) << 16) |
        ((Bit32u) read_virtual_byte(BX_SEG_REG_CS, marker_rip + 6) << 24);
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0x000fffff) == 0x00000513) {
        Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
        RAX = (Bit64u) imm12;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv addi a0,x0,%lld", (long long) imm12));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0x000fffff) == 0x00050513) {
        Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
        RAX = (Bit64u) ((Bit64s) RAX + imm12);
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv addi a0,a0,%lld", (long long) imm12));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0x000fffff) == 0x00060513) {
        Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
        RAX = (Bit64u) (RDI + imm12);
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv addi a0,a2,%lld value=%llu", (long long) imm12, (unsigned long long) RAX));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0x000fffff) == 0x00000593) {
        Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
        bx_poly_riscv_a1 = (Bit64u) imm12;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv addi a1,x0,%lld", (long long) imm12));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0x000fffff) == 0x00060593) {
        Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
        bx_poly_riscv_a1 = (Bit64u) (RDI + imm12);
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv addi a1,a2,%lld value=%llu", (long long) imm12, (unsigned long long) bx_poly_riscv_a1));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0x000fffff) == 0x00000613) {
        Bit64s imm12 = bx_poly_sign_extend(insn >> 20, 12);
        bx_poly_riscv_a2 = (Bit64u) imm12;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv addi a2,x0,%lld", (long long) imm12));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0xfe00707f) == 0x00000033) {
        Bit32u rd = (insn >> 7) & 0x1f;
        Bit32u rs1 = (insn >> 15) & 0x1f;
        Bit32u rs2 = (insn >> 20) & 0x1f;
        if (rd != 10 || rs1 != 10 || rs2 != 11)
          break;
        RAX += bx_poly_riscv_a1;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv add a0,a0,a1 value=%llu", (unsigned long long) bx_poly_riscv_a1));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0xfe00707f) == 0x40000033) {
        Bit32u rd = (insn >> 7) & 0x1f;
        Bit32u rs1 = (insn >> 15) & 0x1f;
        Bit32u rs2 = (insn >> 20) & 0x1f;
        if (rd != 10 || rs1 != 10 || rs2 != 12)
          break;
        RAX -= RDI;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv sub a0,a0,a2 value=%llu", (unsigned long long) RDI));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0xfe00707f) == 0x02000033) {
        Bit32u rd = (insn >> 7) & 0x1f;
        Bit32u rs1 = (insn >> 15) & 0x1f;
        Bit32u rs2 = (insn >> 20) & 0x1f;
        if (rd != 10 || rs1 != 10 || rs2 != 11)
          break;
        RAX *= bx_poly_riscv_a1;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv mul a0,a0,a1 value=%llu", (unsigned long long) bx_poly_riscv_a1));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && ((insn & 0x0000707f) == 0x00000063 || (insn & 0x0000707f) == 0x00001063)) {
        Bit32u rs1 = (insn >> 15) & 0x1f;
        Bit32u rs2 = (insn >> 20) & 0x1f;
        Bit32u funct3 = (insn >> 12) & 0x7;
        Bit32u imm =
          (((insn >> 31) & 0x1) << 12) |
          (((insn >> 7) & 0x1) << 11) |
          (((insn >> 25) & 0x3f) << 5) |
          (((insn >> 8) & 0xf) << 1);
        if (rs2 != 0 || (rs1 != 0 && rs1 != 10))
          break;
        Bit64u rs1_value = rs1 == 10 ? RAX : 0;
        bool taken = (funct3 == 0) ? (rs1_value == 0) : (rs1_value != 0);
        if (taken) {
          Bit64s guest_offset = bx_poly_sign_extend(imm, 13);
          Bit64s marker_offset = bx_poly_marker_offset(guest_offset);
          RIP = (bx_address) ((Bit64s) marker_rip + marker_offset);
          BX_INFO(("poly_ud: emulated riscv %s %s,x0 taken offset=%lld marker_offset=%lld", funct3 == 0 ? "beq" : "bne", rs1 == 10 ? "a0" : "x0", (long long) guest_offset, (long long) marker_offset));
        }
        else {
          RIP = next_rip;
          BX_INFO(("poly_ud: emulated riscv %s %s,x0 not-taken", funct3 == 0 ? "beq" : "bne", rs1 == 10 ? "a0" : "x0"));
        }
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && insn == 0x00008067) {
        bx_address ret_addr = (bx_address) read_virtual_qword(BX_SEG_REG_SS, RSP);
        RSP += 8;
        RIP = ret_addr;
        BX_INFO(("poly_ud: emulated riscv jalr x0,0(ra) ret rip=%llx", (unsigned long long) ret_addr));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0x0000707f) == 0x00003023) {
        Bit32u rs1 = (insn >> 15) & 0x1f;
        Bit32u rs2 = (insn >> 20) & 0x1f;
        Bit32u imm = ((insn >> 7) & 0x1f) | (((insn >> 25) & 0x7f) << 5);
        Bit64s offset = bx_poly_sign_extend(imm, 12);
        bx_address addr;
        Bit64u value;
        if (rs1 == 12 && rs2 == 10) {
          addr = (bx_address) (RDI + offset);
          value = RAX;
        }
        else if (rs1 == 10 && rs2 == 11) {
          addr = (bx_address) (RAX + offset);
          value = bx_poly_riscv_a1;
        }
        else {
          break;
        }
        write_virtual_qword(BX_SEG_REG_DS, addr, value);
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv sd x%u,%lld(x%u) addr=%llx value=%llu", rs2, (long long) offset, rs1, (unsigned long long) addr, (unsigned long long) value));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0x0000707f) == 0x00003003) {
        Bit32u rd = (insn >> 7) & 0x1f;
        Bit32u rs1 = (insn >> 15) & 0x1f;
        Bit64s offset = bx_poly_sign_extend(insn >> 20, 12);
        if (rd != 10 || (rs1 != 10 && rs1 != 12))
          break;
        bx_address addr = (bx_address) ((rs1 == 12 ? RDI : RAX) + offset);
        RAX = read_virtual_qword(BX_SEG_REG_DS, addr);
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv ld a0,%lld(x%u) addr=%llx value=%llu", (long long) offset, rs1, (unsigned long long) addr, (unsigned long long) RAX));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && (insn & 0x000fffff) == 0x00000893) {
        bx_poly_riscv_a7 = (insn >> 20) & 0xfff;
        RIP = next_rip;
        BX_INFO(("poly_ud: emulated riscv addi a7,x0,%u", bx_poly_riscv_a7));
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && insn == 0x00000073) {
        bx_poly_last_syscall_mode = bx_poly_current_mode;
        bx_poly_last_syscall_number = bx_poly_riscv_a7;
        if (bx_poly_riscv_a7 == 17) {
          const char cwd[] = "/poly";
          Bit64u addr = RAX;
          Bit64u needed = sizeof(cwd);
          if (bx_poly_riscv_a1 < needed) {
            RAX = (Bit64u) -34;
            BX_INFO(("poly_ud: emulated riscv getcwd range addr=%llx size=%llu needed=%llu", (unsigned long long) addr, (unsigned long long) bx_poly_riscv_a1, (unsigned long long) needed));
          }
          else {
            for (unsigned n = 0; n < sizeof(cwd); n++)
              write_virtual_byte(BX_SEG_REG_DS, (bx_address) (addr + n), (Bit8u) cwd[n]);
            BX_INFO(("poly_ud: emulated riscv getcwd addr=%llx size=%llu cwd=%s", (unsigned long long) addr, (unsigned long long) bx_poly_riscv_a1, cwd));
            RAX = needed;
          }
        }
        else if (bx_poly_riscv_a7 == 63 && (RAX == 0 || RAX == 3)) {
          Bit64u fd = RAX;
          const Bit8u stdin_input[] = {'R', 'X', '!', '!'};
          const Bit8u file_input[] = {'F', 'D', '!', '!'};
          const Bit8u *input = fd == 3 ? file_input : stdin_input;
          const Bit64u input_size = 4;
          Bit64u count = bx_poly_riscv_a2 < input_size ? bx_poly_riscv_a2 : input_size;
          for (Bit64u n = 0; n < count; n++)
            write_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_riscv_a1 + n), input[n]);
          RAX = count;
          BX_INFO(("poly_ud: emulated riscv read fd=%llu addr=%llx count=%llu", (unsigned long long) fd, (unsigned long long) bx_poly_riscv_a1, (unsigned long long) count));
        }
        else if (bx_poly_riscv_a7 == 64 && RAX == 1) {
          Bit64u checksum = 0;
          for (Bit64u n = 0; n < bx_poly_riscv_a2 && n < 4096; n++)
            checksum += read_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_riscv_a1 + n));
          RAX = bx_poly_riscv_a2;
          BX_INFO(("poly_ud: emulated riscv write fd=1 addr=%llx count=%llu checksum=%llu", (unsigned long long) bx_poly_riscv_a1, (unsigned long long) bx_poly_riscv_a2, (unsigned long long) checksum));
        }
        else if (bx_poly_riscv_a7 == 56) {
          Bit64u dirfd = RAX;
          char path[16];
          unsigned n;
          for (n = 0; n < sizeof(path) - 1; n++) {
            path[n] = (char) read_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_riscv_a1 + n));
            if (path[n] == '\0')
              break;
          }
          path[n] = '\0';
          RAX = strcmp(path, "poly!") == 0 ? 3 : (Bit64u) -2;
          BX_INFO(("poly_ud: emulated riscv openat dirfd=%llu path=%s flags=%llu result=%lld", (unsigned long long) dirfd, path, (unsigned long long) bx_poly_riscv_a2, (long long) RAX));
        }
        else if (bx_poly_riscv_a7 == 57) {
          Bit64u fd = RAX;
          RAX = fd == 3 ? 0 : (Bit64u) -9;
          BX_INFO(("poly_ud: emulated riscv close fd=%llu result=%lld", (unsigned long long) fd, (long long) RAX));
        }
        else if (bx_poly_riscv_a7 == 62) {
          Bit64u fd = RAX;
          RAX = (fd == 3 && bx_poly_riscv_a2 <= 2) ? bx_poly_riscv_a1 : (Bit64u) -9;
          BX_INFO(("poly_ud: emulated riscv lseek fd=%llu offset=%llu whence=%llu result=%lld", (unsigned long long) fd, (unsigned long long) bx_poly_riscv_a1, (unsigned long long) bx_poly_riscv_a2, (long long) RAX));
        }
        else if (bx_poly_riscv_a7 == 113 && RAX == 0) {
          write_virtual_qword(BX_SEG_REG_DS, (bx_address) bx_poly_riscv_a1, 123);
          write_virtual_qword(BX_SEG_REG_DS, (bx_address) (bx_poly_riscv_a1 + 8), 456789);
          RAX = 0;
          BX_INFO(("poly_ud: emulated riscv clock_gettime clk=0 addr=%llx sec=123 nsec=456789", (unsigned long long) bx_poly_riscv_a1));
        }
        else if (bx_poly_riscv_a7 == 222 && RAX == 0) {
          RAX = RDI;
          BX_INFO(("poly_ud: emulated riscv mmap addr=0 len=%llu result=%llx", (unsigned long long) bx_poly_riscv_a1, (unsigned long long) RAX));
        }
        else if (bx_poly_riscv_a7 == 172) {
          RAX = 4242;
          BX_INFO(("poly_ud: emulated riscv getpid pid=%llu", (unsigned long long) RAX));
        }
        else if (bx_poly_riscv_a7 == 174) {
          RAX = 1000;
          BX_INFO(("poly_ud: emulated riscv getuid uid=%llu", (unsigned long long) RAX));
        }
        else if (bx_poly_riscv_a7 == 93) {
          Bit64u exit_code = RAX;
          bx_address ret_addr = (bx_address) read_virtual_qword(BX_SEG_REG_SS, RSP);
          RSP += 8;
          RAX = exit_code;
          RIP = ret_addr;
          BX_INFO(("poly_ud: emulated riscv exit code=%llu rip=%llx", (unsigned long long) exit_code, (unsigned long long) ret_addr));
          return true;
        }
        else if (bx_poly_riscv_a7 == 160) {
          const char sysname[] = "Linux";
          for (unsigned n = 0; n < sizeof(sysname); n++)
            write_virtual_byte(BX_SEG_REG_DS, (bx_address) (RAX + n), (Bit8u) sysname[n]);
          BX_INFO(("poly_ud: emulated riscv uname addr=%llx sysname=%s", (unsigned long long) RAX, sysname));
          RAX = 0;
        }
        else {
          RAX = 0x53000000 | (bx_poly_riscv_a7 << 8) | bx_poly_current_mode;
          BX_INFO(("poly_ud: emulated riscv ecall a7=%u mode=%u", bx_poly_riscv_a7, bx_poly_current_mode));
        }
        RIP = next_rip;
        return true;
      }
      if (bx_poly_current_mode == BX_POLY_MODE_RISCV && insn == 0x00100073) {
        bx_poly_last_libcall_mode = bx_poly_current_mode;
        bx_poly_last_libcall_number = bx_poly_riscv_a7;
        if (bx_poly_riscv_a7 == 1) {
          RAX = 0;
          while (RAX < 4096 && read_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + RAX)) != 0)
            RAX++;
          BX_INFO(("poly_ud: emulated riscv ebreak strlen addr=%llx len=%llu", (unsigned long long) RDI, (unsigned long long) RAX));
        }
        else if (bx_poly_riscv_a7 == 2) {
          Bit64u count = RAX < 4096 ? RAX : 4096;
          Bit8u value = (Bit8u) bx_poly_riscv_a1;
          for (Bit64u n = 0; n < count; n++)
            write_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + n), value);
          RAX = count;
          BX_INFO(("poly_ud: emulated riscv ebreak memfill addr=%llx count=%llu value=%u", (unsigned long long) RDI, (unsigned long long) count, value));
        }
        else if (bx_poly_riscv_a7 == 3) {
          Bit64u count = bx_poly_riscv_a2 < 4096 ? bx_poly_riscv_a2 : 4096;
          Bit64s result = 0;
          for (Bit64u n = 0; n < count; n++) {
            Bit8u left = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + n));
            Bit8u right = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_riscv_a1 + n));
            if (left != right) {
              result = (Bit64s) left - (Bit64s) right;
              break;
            }
          }
          RAX = (Bit64u) result;
          BX_INFO(("poly_ud: emulated riscv ebreak memcmp left=%llx right=%llx count=%llu result=%lld", (unsigned long long) RDI, (unsigned long long) bx_poly_riscv_a1, (unsigned long long) count, (long long) result));
        }
        else if (bx_poly_riscv_a7 == 4) {
          Bit64u count = RAX < 4096 ? RAX : 4096;
          for (Bit64u n = 0; n < count; n++) {
            Bit8u value = read_virtual_byte(BX_SEG_REG_DS, (bx_address) (bx_poly_riscv_a1 + n));
            write_virtual_byte(BX_SEG_REG_DS, (bx_address) (RDI + n), value);
          }
          RAX = count;
          BX_INFO(("poly_ud: emulated riscv ebreak memcpy dest=%llx src=%llx count=%llu", (unsigned long long) RDI, (unsigned long long) bx_poly_riscv_a1, (unsigned long long) count));
        }
        else {
          RAX = 0x4c000000 | (bx_poly_current_mode << 8) | bx_poly_riscv_a7;
          BX_INFO(("poly_ud: emulated riscv ebreak a7=%u libcall mode=%u", bx_poly_riscv_a7, bx_poly_current_mode));
        }
        RIP = next_rip;
        return true;
      }
      break;
    }
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
