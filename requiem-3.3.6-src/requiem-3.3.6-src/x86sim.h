//NOTE: compile with -m32
#include <stdint.h>

typedef unsigned char byte;

#define EAX 0
#define ECX 1
#define EDX 2
#define EBX 3
#define ESP 4
#define EBP 5
#define ESI 6
#define EDI 7

class X86Sim {
public:
  // build an x86 simulator where all of the executable code is in the range [code,code+size].
  static X86Sim *create(const byte *code, int size);
  virtual ~X86Sim(){}
  
  // register state of simulated code
  uint32_t regs[8];
  uint32_t eflags;
  const byte *eip;

  // add some code to be done INSTEAD OF the code at addr.
  // actions must modify eip.
  virtual void add_action(const byte *addr, void (*action)(X86Sim *)) = 0;
  
  // add some code to be done IN ADDITION TO (and before) the code at addr.
  // listeners may not modify eip.
  virtual void add_listener(const byte *addr, void (*listener)(X86Sim *)) = 0;
  
  // start simulating the code
  // you must set up the register state (including eip) first.
  virtual void go(const byte *stop_addr) = 0;
};
