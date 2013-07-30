//NOTE: compile with -m32
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <map>
#include <ext/hash_map>
#if WINDOWS
#include <Windows.h>
#else
#include <sys/mman.h>
#endif
#include "x86sim.h"

using namespace std;
using namespace __gnu_cxx;

// let const byte* be a hashable type.
namespace __gnu_cxx {
  template <> struct hash<const byte*> {
    size_t operator()(const byte* x) const {
      return (size_t)x;
    }
    bool operator()(const byte* x, const byte* y) const {
      return x == y;
    }
  };
}

#define error(args...) { fprintf(stdout, "ERROR "); fprintf(stdout, ## args); exit(1); }

// maximum factor that the generated code will be bigger than the original code
#define EXPANSION 2

class X86SimImpl;

class X86SimImpl : public X86Sim {
 public:
  X86SimImpl(const byte *code, int size) : code_base(code), code_size(size) {
    map_table = (byte**)malloc(code_size * sizeof(byte*));
    if (!map_table) error("can't alloc map_table\n");
    int buf_size = code_size * EXPANSION;
#if WINDOWS
    // need to do VirtualAlloc in case DER is enabled.
    buf_start = (byte*)VirtualAlloc(NULL, buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buf_start) error("can't alloc code buf\n");
#else
    // need execute privileges on the code buffer starting with OSX 10.7.
    buf_start = (byte*)mmap(NULL, buf_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (buf_start == (byte*)-1) error("can't alloc code buf\n");
#endif
    buf_end = buf_start + buf_size;
    for (int i = 0; i < 8; i++) regs[i] = 0;
    eflags = 0; // keep popf from loading junk and crashing
    reset();
  }
  ~X86SimImpl() {
    free(map_table);
#if WINDOWS
    VirtualFree(buf_start, 0, MEM_RELEASE);
#else
    munmap(buf_start, buf_end - buf_start);
#endif
  }
  
  // simulated code lives here
  const byte *code_base;
  int code_size;
  
  // maps from offset in simulated code (addr - code_base) to location of its implementation
  byte **map_table;
  
  // buffer for code written by simulator
  byte *buf_start;
  byte *buf_end;
  byte *buf; // current position

  // a scratch location: set to map_table[eip - code_base] before calling enter_stub
  byte *eip_impl;
  
  // place to save registers of simulator
  struct {
    uint32_t ebx;
    uint32_t esp;
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;
  } simulator_state;
  
  // stub routines
  byte *enter_stub;
  byte *exit_stub;

  hash_map<const byte*, void (*)(X86Sim*)> actions;
  hash_map<const byte*, void (*)(X86Sim*)> listeners;

  // add the n bytes of code to the end of the code buffer.
  void gen(const byte *p, int n) {
    while (n) {
      if (buf == buf_end) error("too much generated code\n");
      *buf++ = *p++;
      n--;
    }
  }
  
  // handy shortcuts to call gen
  void genByte(byte x) {
    gen(&x, 1);
  }
  void genInt(uint32_t x) {
    gen((byte*)&x, 4);
  }
  void genAddr(const void *x) {
    genInt((uint32_t)x);
  }
  void genSaveReg(int reg, uint32_t *addr) {
    if (reg == EAX) {
      genByte(0xa3);
    } else {
      genByte(0x89);
      genByte(0x05 + 8 * reg);
    }
    genInt((uint32_t)addr);
  }
  void genLoadReg(uint32_t *addr, int reg) {
    if (reg == EAX) {
      genByte(0xa1);
    } else {
      genByte(0x8b);
      genByte(0x05 + 8 * reg);
    }
    genInt((uint32_t)addr);
  }
  void genSaveEflags() {
    genByte(0x9c); // pushf
    genByte(0x8f); // pop to eflags
    genByte(0x05);
    genAddr(&eflags);
  }
  void genLoadEflags() {
    genByte(0xff); // push eflags
    genByte(0x35);
    genAddr(&eflags);
    genByte(0x9d); // popf
  }
  
  void genActionStub(void(*action)(X86Sim*)) {
    // save registers of simulated machine
    for (int r = 0; r < 8; r++) {
      genSaveReg(r, &regs[r]);
    }
    
    // restore registers of simulator
    genLoadReg(&simulator_state.ebx, EBX);
    genLoadReg(&simulator_state.esp, ESP);
    genLoadReg(&simulator_state.ebp, EBP);
    genLoadReg(&simulator_state.esi, ESI);
    genLoadReg(&simulator_state.edi, EDI);
    
    // save eflags
    genSaveEflags();
    
    // push 8 bytes to align stack (esp -= 8)
    genByte(0x83);
    genByte(0xec);
    genByte(0x08);
    
    // push action argument
    genByte(0x68); // push constant
    genAddr(this);
    
    // call action
    genByte(0xe8);
    genInt((byte*)action - (buf + 4));

    // pop the padding and arg
    genByte(0x83);
    genByte(0xc4);
    genByte(0x0c);
    
    // return to go()
    genByte(0xc3);
  }
  void genListenerStub(void (*listener)(X86Sim*)) {
    // save registers of simulated machine
    for (int r = 0; r < 8; r++) {
      genSaveReg(r, &regs[r]);
    }
    
    // load stack of simulator
    genLoadReg(&simulator_state.esp, ESP);
    
    // save eflags
    genSaveEflags();
    
    // push 8 bytes to align stack (esp -= 8)
    genByte(0x83);
    genByte(0xec);
    genByte(0x08);
    
    // push action argument
    genByte(0x68); // push constant
    genAddr(this);
    
    // call listener
    genByte(0xe8);
    genInt((byte*)listener - (buf + 4));
    
    // pop the alignment padding (esp += 12)
    genByte(0x83);
    genByte(0xc4);
    genByte(0x0c);
    
    // load eflags
    genLoadEflags();
    
    // load registers
    for (int r = 0; r < 8; r++) {
      genLoadReg(&regs[r], r);
    }
  }

  // on entry, the simulated eax is stored in regs[EAX], and
  // eax now contains the jump destination simulated address.
  // The generated snippet will jump to the corresponding implementation
  // address, or (via the exit_stub) exit the simulator.
  void genIndirectJump() {
    // save simulated target address
    genSaveReg(EAX, (uint32_t*)&eip);
    
    // load implementation address from map table into eax
    genByte(0x8b);
    genByte(0x04);
    genByte(0x85);
    genInt((uint32_t)map_table - 4 * (uint32_t)code_base);
    
    // save jump location
    genSaveReg(EAX, (uint32_t*)&eip_impl);
    
    // restore eax
    genLoadReg(&regs[EAX], EAX);
    
    // jump to target location
    genByte(0xff);
    genByte(0x25);
    genAddr(&eip_impl);
  }
  
  // reset state of simulator
  void reset() {
    buf = buf_start;
    
    // generate enter stub
    enter_stub = buf;
    
    // save callee-save registers
    genSaveReg(EBX, &simulator_state.ebx);
    genSaveReg(ESP, &simulator_state.esp);
    genSaveReg(EBP, &simulator_state.ebp);
    genSaveReg(ESI, &simulator_state.esi);
    genSaveReg(EDI, &simulator_state.edi);
    
    // load state of simulated machine
    genLoadEflags();
    for (int r = 0; r < 8; r++) {
      genLoadReg(&regs[r], r);
    }
    
    // jump to starting address
    genByte(0xff);
    genByte(0x25);
    genAddr(&eip_impl);
  
    // generate exit stub
    exit_stub = buf;
    
    // save registers of simulated machine
    for (int r = 0; r < 8; r++) {
      genSaveReg(r, &regs[r]);
    }
    
    // restore registers of simulator
    genLoadReg(&simulator_state.ebx, EBX);
    genLoadReg(&simulator_state.esp, ESP);
    genLoadReg(&simulator_state.ebp, EBP);
    genLoadReg(&simulator_state.esi, ESI);
    genLoadReg(&simulator_state.edi, EDI);
    
    // save eflags
    genSaveEflags();
    
    // return
    genByte(0xc3);
    
    // mark all code as not generated
    for (int i = 0; i < code_size; i++) map_table[i] = exit_stub;
  }
  
  struct InstructionInfo {
    int length;              // of the instruction in bytes
    int kind;                // from the list below
    int condition;           // jump condition (COND_JUMP) (jb=2,jae=3,...)
    const byte *destination; // jump taken destination (JUMP, CALL, COND_JUMP)
  };
  
#define NORMAL 0
#define JUMP 1
#define COND_JUMP 2
#define CALL 3
#define INDIRECT_JUMP 4
#define INDIRECT_CALL 5
#define RET 6

  // length of the mod/rm portion of an instruction
  static int rmlen(const byte *addr) {
    int modrm = addr[0];
    int mod = modrm >> 6;
    int rm = modrm & 7;
    int len = 1;
    if (mod != 3) {
      if (rm == 4) { // has sib byte
        len++;
        int b = addr[1] & 7;
        if (b == EBP && mod == 0) {
          len += 4;
        }
      } else if (rm == 5 && mod == 0) {
        len += 4;
      }
      if (mod == 1) {
        len += 1;
      } else if (mod == 2) {
        len += 4;
      }
    }
    return len;
  }
  
  InstructionInfo getInstructionInfo(const byte *addr) {
    InstructionInfo i;
    i.kind = NORMAL;
    switch (addr[0]) {
      // normal ops
      case 0x40: // inc
      case 0x41:
      case 0x42:
      case 0x43:
      case 0x44:
      case 0x45:
      case 0x46:
      case 0x47:
      case 0x48: // dec
      case 0x49:
      case 0x4a:
      case 0x4b:
      case 0x4c:
      case 0x4d:
      case 0x4e:
      case 0x4f:
      case 0x50: // push
      case 0x51:
      case 0x52:
      case 0x53:
      case 0x54:
      case 0x55:
      case 0x56:
      case 0x57:
      case 0x58: // pop
      case 0x59:
      case 0x5a:
      case 0x5b:
      case 0x5c:
      case 0x5d:
      case 0x5e:
      case 0x5f:
      case 0x90: // nop
      case 0x98: // cwtl
      case 0x99: // cltd
      case 0xc9: // leave
      case 0xfc: // cld
      case 0xfd: // std
        i.length = 1;
        break;

        // normal ops with 1-byte constant
      case 0x04: // add
      case 0x0c: // or
      case 0x14: // adc
      case 0x1c: // sbb
      case 0x24: // and
      case 0x2c: // sub
      case 0x34: // xor
      case 0x3c: // cmp
      case 0x6a: // push
      case 0xa8: // test
      case 0xb0: // mov
      case 0xb1:
      case 0xb2:
      case 0xb3:
      case 0xb4:
      case 0xb5:
      case 0xb6:
      case 0xb7:
        i.length = 2;
        break;

        // normal ops with a 4-byte constant
      case 0x05: // add
      case 0x0d: // or
      case 0x15: // adc
      case 0x1d: // sbb
      case 0x25: // and
      case 0x2d: // sub
      case 0x35: // xor
      case 0x3d: // cmp
      case 0x68: // push
      case 0xa0: // mov
      case 0xa1: // mov
      case 0xa2: // mov
      case 0xa3: // mov
      case 0xa9: // test
      case 0xb8: // mov
      case 0xb9:
      case 0xba:
      case 0xbb:
      case 0xbc:
      case 0xbd:
      case 0xbe:
      case 0xbf:
        i.length = 5;
        break;

        // normal ops with a mod/rm
      case 0x00: // add
      case 0x01:
      case 0x02:
      case 0x03:
      case 0x08: // or
      case 0x09:
      case 0x0a:
      case 0x0b:
      case 0x10: // adc
      case 0x11:
      case 0x12:
      case 0x13:
      case 0x18: // sbb
      case 0x19:
      case 0x1a:
      case 0x1b:
      case 0x20: // and
      case 0x21:
      case 0x22:
      case 0x23:
      case 0x28: // sub
      case 0x29:
      case 0x2a:
      case 0x2b:
      case 0x30: // xor
      case 0x31:
      case 0x32:
      case 0x33:
      case 0x38: // cmp
      case 0x39:
      case 0x3a:
      case 0x3b:
      case 0x84: // test
      case 0x85:
      case 0x88: // mov
      case 0x89:
      case 0x8a:
      case 0x8b:
      case 0x8d: // lea
      case 0x8f: // pop
      case 0xd0: // shift
      case 0xd1:
      case 0xd3:
        i.length = 1 + rmlen(addr + 1);
        break;

        // normal ops with a mod/rm and a 1-byte constant
      case 0x6b: // imul
      case 0x80: // alu
      case 0x83:
      case 0xc0: // shift
      case 0xc1:
      case 0xc6: // mov
        i.length = 2 + rmlen(addr + 1);
        break;
      
        // normal ops with a mod/rm and a 4-byte constant
      case 0x69: // imul
      case 0x81: // alu
      case 0xc7: // mov
        i.length = 5 + rmlen(addr + 1);
        break;

        // conditional jumps
      case 0x70:
      case 0x71:
      case 0x72:
      case 0x73:
      case 0x74:
      case 0x75:
      case 0x76:
      case 0x77:
      case 0x78:
      case 0x79:
      case 0x7a:
      case 0x7b:
      case 0x7c:
      case 0x7d:
      case 0x7e:
      case 0x7f:
        i.length = 2;
        i.kind = COND_JUMP;
        i.destination = addr + 2 + (signed char)addr[1];
        i.condition = addr[0] & 0xf;
        break;
      
      case 0xc3: // ret
        i.length = 1;
        i.kind = RET;
        break;
      case 0xe8: // call
        i.length = 5;
        i.kind = CALL;
        i.destination = addr + 5 + *(uint32_t*)(addr + 1);
        break;
      case 0xe9: // jump
        i.length = 5;
        i.kind = JUMP;
        i.destination = addr + 5 + *(uint32_t*)(addr + 1);
        break;
      case 0xeb: // jump
        i.length = 2;
        i.kind = JUMP;
        i.destination = addr + 2 + (signed char)addr[1];
        break;
      
      case 0xf2: // xmm junk
        if (addr[1] == 0x0f && (addr[2] == 0x10 || addr[2] == 0x11)) {
          i.length = 3 + rmlen(addr + 3);
          break;
        }
        printf("unknown f2: %x %x\n", addr[1], addr[2]);
        exit(1);

      case 0xf3: // rep insns
        i.length = 2;
        break;
      
      case 0xf6: // misc 8-bit ops
        i.length = 1 + rmlen(addr + 1);
        if (((addr[1] >> 3) & 7) == 0) { // special case for test
          i.length++;
        }
        break;
      case 0xf7: // misc 32-bit ops
        i.length = 1 + rmlen(addr + 1);
        if (((addr[1] >> 3) & 7) == 0) { // special case for test
          i.length += 4;
        }
        break;

      case 0xfe: // misc 8-bit ops
        i.length = 1 + rmlen(addr + 1);
        break;
      case 0xff: // misc ops
        i.length = 1 + rmlen(addr + 1);
        switch ((addr[1] >> 3) & 7) {
          case 2:
            i.kind = INDIRECT_CALL;
            break;
          case 4:
            i.kind = INDIRECT_JUMP;
            break;
        }
        break;
      
      case 0x0f: // two-byte insns
        switch (addr[1]) {
          case 0x31: // rdtsc
            i.length = 2;
            break;
          case 0x1f: // nop
          case 0x29: // movaps
          case 0x40: // cmov
          case 0x41:
          case 0x42:
          case 0x43:
          case 0x44:
          case 0x45:
          case 0x46:
          case 0x47:
          case 0x48:
          case 0x49:
          case 0x4a:
          case 0x4b:
          case 0x4c:
          case 0x4d:
          case 0x4e:
          case 0x4f:
          case 0x90: // set
          case 0x91:
          case 0x92:
          case 0x93:
          case 0x94:
          case 0x95:
          case 0x96:
          case 0x97:
          case 0x98:
          case 0x99:
          case 0x9a:
          case 0x9b:
          case 0x9c:
          case 0x9d:
          case 0x9e:
          case 0x9f:
          case 0xa3: // bt
          case 0xa5: // shld
          case 0xad: // shrd
          case 0xaf: // imul
          case 0xb6: // movzbl
          case 0xb7: // movzwl
          case 0xbd: // bsr
          case 0xbe: // movsbl
          case 0xbf: // movswl
            i.length = 2 + rmlen(addr + 2);
            break;

          case 0xa4: // shld
          case 0xac: // shrd
          case 0xba: // bt
            i.length = 3 + rmlen(addr + 2);
            break;

          case 0x80: // conditional branches
          case 0x81:
          case 0x82:
          case 0x83:
          case 0x84:
          case 0x85:
          case 0x86:
          case 0x87:
          case 0x88:
          case 0x89:
          case 0x8a:
          case 0x8b:
          case 0x8c:
          case 0x8d:
          case 0x8e:
          case 0x8f:
            i.length = 6;
            i.kind = COND_JUMP;
            i.destination = addr + 6 + *(uint32_t*)(addr + 2);
            i.condition = addr[1] & 0xf;
            break;
          
          default:
            printf("no info for 0f %02x %x\n", addr[1], addr - code_base);
            exit(1);
        }
        break;
      case 0x66: // 2-byte prefix
        switch (addr[1]) {
          case 0x40: // inc
          case 0x41:
          case 0x42:
          case 0x43:
          case 0x44:
          case 0x45:
          case 0x46:
          case 0x47:
          case 0x48: // dec
          case 0x49:
          case 0x4a:
          case 0x4b:
          case 0x4c:
          case 0x4d:
          case 0x4e:
          case 0x4f:
          case 0x90: // nop
            i.length = 2;
            break;
            // normal ops with 1-byte constant
          case 0x04: // add
          case 0x0c: // or
          case 0x14: // adc
          case 0x1c: // sbb
          case 0x24: // and
          case 0x2c: // sub
          case 0x34: // xor
          case 0x3c: // cmp
          case 0xa8: // test
          case 0xb0: // mov
          case 0xb1:
          case 0xb2:
          case 0xb3:
          case 0xb4:
          case 0xb5:
          case 0xb6:
          case 0xb7:
            i.length = 3;
            break;
          
            // normal ops with a 2-byte constant
          case 0x05: // add
          case 0x0d: // or
          case 0x15: // adc
          case 0x1d: // sbb
          case 0x25: // and
          case 0x2d: // sub
          case 0x35: // xor
          case 0x3d: // cmp
          case 0xa9: // test
          case 0xb8: // mov
          case 0xb9:
          case 0xba:
          case 0xbb:
          case 0xbc:
          case 0xbd:
          case 0xbe:
          case 0xbf:
            i.length = 4;
            break;

            // normal ops with a 4-byte constant
          case 0xa1:
          case 0xa3:
            i.length = 6;
            break;
          
            // normal ops with a mod/rm
          case 0x00: // add
          case 0x01:
          case 0x02:
          case 0x03:
          case 0x08: // or
          case 0x09:
          case 0x0a:
          case 0x0b:
          case 0x10: // adc
          case 0x11:
          case 0x12:
          case 0x13:
          case 0x18: // sbb
          case 0x19:
          case 0x1a:
          case 0x1b:
          case 0x20: // and
          case 0x21:
          case 0x22:
          case 0x23:
          case 0x28: // sub
          case 0x29:
          case 0x2a:
          case 0x2b:
          case 0x30: // xor
          case 0x31:
          case 0x32:
          case 0x33:
          case 0x38: // cmp
          case 0x39:
          case 0x3a:
          case 0x3b:
          case 0x84: // test
          case 0x85:
          case 0x88: // mov
          case 0x89:
          case 0x8a:
          case 0x8b:
          case 0xd0: // shift
          case 0xd1:
          case 0xd3:
            i.length = 2 + rmlen(addr + 2);
            break;
          
            // normal ops with a mod/rm and a 1-byte constant
          case 0x6b: // imul
          case 0x80: // alu
          case 0x83:
          case 0xc0: // shift
          case 0xc1:
          case 0xc6: // mov
            i.length = 3 + rmlen(addr + 2);
            break;
          
            // normal ops with a mod/rm and a 2-byte constant
          case 0x69: // imul
          case 0x81: // alu
          case 0xc7: // mov
            i.length = 4 + rmlen(addr + 2);
            break;
          
          case 0x0f: // two-byte insns
            switch (addr[2]) {
              case 0x1f: // nop
              case 0x40: // cmov
              case 0x41:
              case 0x42:
              case 0x43:
              case 0x44:
              case 0x45:
              case 0x46:
              case 0x47:
              case 0x48:
              case 0x49:
              case 0x4a:
              case 0x4b:
              case 0x4c:
              case 0x4d:
              case 0x4e:
              case 0x4f:
              case 0xaf: // imul
              case 0xef: // pxor
                i.length = 3 + rmlen(addr + 3);
                break;
              default:
                printf("no info for 66 0f %x %x\n", addr[2], addr - code_base);
                exit(1);
            }
            break;
          
          case 0xf7: // misc ops
          case 0xff: // inc, dec
            i.length = 2 + rmlen(addr + 2);
            break;
          
          case 0x2e: // %cs: prefix
            if (addr[2] == 0x0f && addr[3] == 0x1f) { // nop
              i.length = 4 + rmlen(addr + 4);
              break;
            }
            // fallthrough

          default:
            printf("no info for 66 %02x %x\n", addr[1], addr - code_base);
            exit(1);
        }
        break;
      default:
        printf("no info for %02x %x\n", addr[0], addr - code_base);
        exit(1);
    }
    return i;
  }
  
  // impl address/simulated destination.  The first of the pair points to
  // a 4-byte value in implementation code that is a pc-relative jump
  // constant.  That constant should be overwritten with the correct
  // constant that goes to the implementation address corresponding to
  // the simulated destination (the second of the pair).
  vector<pair<byte*,const byte*> > relocations;
  
  // generates simulator code for a block of simulated code starting at addr.
  void genBlock(const byte *addr) {
    while (true) {
      if (addr - code_base < 0 || addr - code_base >= code_size) {
        error("bad map table offset %x\n", addr - code_base);
      }
      
      // we've already generated code for this insn - just jump to it
      if (map_table[addr - code_base] != exit_stub) {
        genByte(0xe9);
        genInt(map_table[addr - code_base] - (buf + 4));
        return;
      }
      
      // save mapping from simulation address to implementation address
      map_table[addr - code_base] = buf;
      
      // check for actions here.
      if (actions.find(addr) != actions.end()) {
        genActionStub(actions[addr]);
        return;
      }
      // also listeners
      if (listeners.find(addr) != listeners.end()) {
        genListenerStub(listeners[addr]);
      }
      
      InstructionInfo info = getInstructionInfo(addr);
      switch (info.kind) {
        case NORMAL:
          // implement the instruction with itself
          gen(addr, info.length);
          break;
        case CALL:
          // push simulated return address
          genByte(0x68); // push constant
          genAddr(addr + info.length);
          if (info.destination == addr + info.length) { // optimization: call next instruction (just push return address)
            break;
          }
          // fallthrough to jump
        case JUMP:
          genByte(0xe9); // jmp constant
          relocations.push_back(make_pair(buf, info.destination));
          genInt(0);
          return;
        case COND_JUMP:
          genByte(0x0f);
          genByte(0x80 + info.condition);
          relocations.push_back(make_pair(buf, info.destination));
          genInt(0);
          break;
        case RET:
          // save eax
          genSaveReg(EAX, &regs[EAX]);
          
          // load target EIP into eax
          genByte(0x58); // pop to eax
          genIndirectJump();
          return;
        case INDIRECT_CALL:
        case INDIRECT_JUMP:
          // save eax
          genSaveReg(EAX, &regs[EAX]);
          
          // load target EIP into eax
          // change "call/jmp *XXX" to "mov XXX,%eax"
          genByte(0x8b);
          genByte(addr[1] & 0xc7);
          gen(addr + 2, info.length - 2);
          
          if (info.kind == INDIRECT_CALL) {
            // push simulated return address
            genByte(0x68); // push constant
            genAddr(addr + info.length);
          }
          
          genIndirectJump();
          return;
      }
      addr += info.length;
    }
  }
  
  // ensure we have code generated for the given address
  void genCode(const byte *addr) {
    relocations.push_back(make_pair((byte*)0, addr));
    while (relocations.size() > 0) {
      pair<byte*,const byte*> r = relocations.back();
      relocations.pop_back();
      byte *impl = r.first;
      const byte *block = r.second;
      if (map_table[block - code_base] == exit_stub) {
        genBlock(block);
      }
      if (impl) *(uint32_t*)impl = map_table[block - code_base] - (impl + 4);
    }
  }
  
  // run the simulator until we reach the stop address
  void go(const byte *stop_addr) {
    while (true) {
      genCode(eip);
      eip_impl = map_table[eip - code_base];
      ((void(*)())enter_stub)();
      if (eip == stop_addr) return;
    }
  }
  
  void add_action(const byte *addr, void (*action)(X86Sim *)) {
    actions[addr] = action;
  }
  void add_listener(const byte *addr, void (*listener)(X86Sim *)) {
    listeners[addr] = listener;
  }
};

X86Sim *X86Sim::create(const byte *code, int size) {
  return new X86SimImpl(code, size);
}
