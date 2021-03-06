#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <map>
#include <string>
#include "x86sim.h"
#include "bigint/BigIntegerLibrary.hh"
#include "aes.h"

using namespace std;

#define error(args...) { fprintf(stdout, "ERROR "); fprintf(stdout, ## args); exit(1); }

byte *aligned_malloc(size_t size, size_t align) {
  byte *ptr = (byte*)malloc(size + align - 1);
  if (!ptr) error("failed malloc %lu %lu\n", size, align);
  ptr = (byte*)(((uint32_t)ptr + align - 1) / align * align);
  return ptr;
}
void aligned_free(byte *ptr) {
  // memory leak, don't care to record original ptr
}

static bool print_actions = false;

static void (*id_listener_callback)(uint32_t key_id);
static void (*key_listener_callback)(const byte *key);

// Construct a big integer from a big-endian byte array.
static BigUnsigned bigFromBuf(const byte *buf, int n) {
  BigUnsigned r(0);
  for (int i = 0; i < n; i++) {
    r <<= 8;
    r += buf[i];
  }
  return r;
}
// Convert a big integer to a big-endian byte array.
static void bigToBuf(BigUnsigned v, byte *buf, int n) {
  for (int i = n - 1; i >= 0; i--) {
    buf[i] = (v & 0xFF).toInt();
    v >>= 8;
  }
}

static uint32_t byteswap32(uint32_t x) {
  return (x << 24) + ((x & 0xff00) << 8) + ((x >> 8) & 0xff00) + (x >> 24);
}
static uint64_t byteswap64(uint64_t x) {
  return (x << 56) + ((x & 0xff00) << 40) + ((x & 0xff0000) << 24) + ((x & 0xff000000) << 8) + ((x >> 8) & 0xff000000) + ((x >> 24) & 0xff0000) + ((x >> 40) & 0xff00) + (x >> 56);
}

static void returnAction(X86Sim *s, uint32_t pop, uint32_t value) {
  // set return value
  s->regs[EAX] = value;
  // pop return address
  s->eip = *(byte**)s->regs[ESP];
  s->regs[ESP] += 4 + pop;
}

static uint32_t handle_id = 1;

static void GetProcessHeap_action(X86Sim *s) {
  if (print_actions) printf("GetProcessHeap_action %x\n", handle_id);
  returnAction(s, 0, handle_id++);
}
static void HeapAlloc_action(X86Sim *s) {
  uint32_t size = *(uint32_t*)(s->regs[ESP] + 12);
  void *ptr = malloc(size);
  if (print_actions) printf("HeapAlloc_action %p/%x\n", ptr, size);
  returnAction(s, 12, (uint32_t)ptr);
}
static void HeapFree_action(X86Sim *s) {
  void *ptr = *(void**)(s->regs[ESP] + 12);
  if (print_actions) printf("HeapFree_action %p\n", ptr);
  free(ptr);
  returnAction(s, 12, 1);
}
static void CreateMutexA_action(X86Sim *s) {
  if (print_actions) printf("CreateMutexA_action %x\n", handle_id);
  returnAction(s, 12, handle_id++);
}
static void CreateEventA_action(X86Sim *s) {
  if (print_actions) printf("CreateEventA_action %x\n", handle_id);
  returnAction(s, 16, handle_id++);
}

static void CryptAcquireContext_action(X86Sim *s) {
  byte **p = *(byte***)(s->regs[ESP] + 4);
  if (print_actions) printf("CryptAcquireContext_action %x\n", handle_id);
  *p = (byte*)handle_id++;
  returnAction(s, 20, 1);
}
static void CryptGenRandom_action(X86Sim *s) {
  uint32_t n = *(uint32_t*)(s->regs[ESP] + 8);
  byte *p = *(byte**)(s->regs[ESP] + 12);
  if (print_actions) printf("CryptGenRandom_action %x\n", n);
  for (int i = 0; i < n; i++) p[i] = 0xaa;
  returnAction(s, 12, 1);
}
static void CryptReleaseContext_action(X86Sim *s) {
  if (print_actions) printf("CryptReleaseContext_action %x\n", *(uint32_t*)(s->regs[ESP] + 4));
  returnAction(s, 8, 1);
}

static void WaitForSingleObject_action(X86Sim *s) {
  if (print_actions) printf("WaitForSingleObject_action %x\n", *(uint32_t*)(s->regs[ESP] + 4));
  returnAction(s, 8, 0);
}
static void ResetEvent_action(X86Sim *s) {
  if (print_actions) printf("ResetEvent_action %x\n", *(uint32_t*)(s->regs[ESP] + 4));
  returnAction(s, 4, 0);
}
static void ReleaseMutex_action(X86Sim *s) {
  if (print_actions) printf("ReleaseMutex_action %x\n", *(uint32_t*)(s->regs[ESP] + 4));
  returnAction(s, 4, 1);
}
static void InterlockedCompareExchange_action(X86Sim *s) {
  if (print_actions) printf("InterlockedCompareExchange_action\n");
  uint32_t *p = *(uint32_t**)(s->regs[ESP] + 4);
  uint32_t oldval = *p;
  uint32_t newval = *(uint32_t*)(s->regs[ESP] + 8);
  uint32_t comp = *(uint32_t*)(s->regs[ESP] + 12);
  if (oldval == comp) *p = newval;
  returnAction(s, 12, oldval);
}
static void GetCurrentThreadId_action(X86Sim *s) {
  if (print_actions) printf("GetCurrentThreadId_action\n");
  returnAction(s, 0, 1);
}

struct FileData {
  const byte *data;
  size_t size;
  int attr;
  FileData() : data(0), size(0), attr(0x22) {}
  FileData(const byte *data, size_t size) : data(data), size(size), attr(0x22) {
  }
};
map<string,FileData> file_data;
map<uint32_t,FileData> open_files;

static void GetFileAttributesA_action(X86Sim *s) {
  char *path = *(char**)(s->regs[ESP] + 4);
  if (print_actions) printf("GetFileAttributesA_action %s\n", path);
  FileData info = file_data[path];
  if (!info.data) {
    if (print_actions) printf("  doesn't exist\n");
    returnAction(s, 4, (uint32_t)-1);
  } else {
    returnAction(s, 4, info.attr);
  }
}
static void SetFileAttributesA_action(X86Sim *s) {
  char *path = *(char**)(s->regs[ESP] + 4);
  int attr = *(int*)(s->regs[ESP] + 8);
  if (print_actions) printf("SetFileAttributesA_action %s %x\n", path, attr);
  file_data[path].attr = attr;
  returnAction(s, 8, 0);
}
static void FindFirstFileA_action(X86Sim *s) {
  char *path = *(char**)(s->regs[ESP] + 4);
  uint32_t *p = *(uint32_t**)(s->regs[ESP] + 8);
  if (print_actions) printf("FindFirstFileA_action %s %p\n", path, p);
  FileData info = file_data[path];
  if (!info.data) {
    returnAction(s, 8, (uint32_t)-1);
  } else {
    p[0] = info.attr;
    p[1] = p[3] = p[5] = 0x20827000;
    p[2] = p[4] = p[6] = 0x1cc83aa;
    p[7] = 0;
    p[8] = info.size;
    returnAction(s, 8, handle_id++);
  }
}
static void FindNextFileA_action(X86Sim *s) {
  if (print_actions) printf("FindNextFileA_action\n");
  int handle = *(int*)(s->regs[ESP] + 4);
  int attr = *(int*)(s->regs[ESP] + 8);
  returnAction(s, 8, (uint32_t)-1);
}
static void FindClose_action(X86Sim *s) {
  uint32_t handle = *(int*)(s->regs[ESP] + 4);
  if (print_actions) printf("FindClose_action %d\n", handle);
  returnAction(s, 4, 1);
}

static void CreateFileA_action(X86Sim *s) {
  char *path = *(char**)(s->regs[ESP] + 4);
  if (print_actions) printf("CreateFileA_action %s\n", path);
  open_files[handle_id] = file_data[path];
  returnAction(s, 28, handle_id++);
}
static void ReadFile_action(X86Sim *s) {
  uint32_t handle = *(uint32_t*)(s->regs[ESP] + 4);
  byte *buf = *(byte**)(s->regs[ESP] + 8);
  int size = *(int*)(s->regs[ESP] + 12);
  int *sizep = *(int**)(s->regs[ESP] + 16);
  if (print_actions) printf("ReadFile_action %d %p %x %p\n", handle, buf, size, sizep);
  FileData info = open_files[handle];
  if (size > info.size) {
    printf("read too much %d %ld\n", size, info.size);
    size = info.size;
  }
  memcpy(buf, info.data, size);
  *sizep = size;
  returnAction(s, 20, 1);
}
static void CloseHandle_action(X86Sim *s) {
  uint32_t handle = *(uint32_t*)(s->regs[ESP] + 4);
  if (print_actions) printf("CloseHandle_action %d\n", handle);
  returnAction(s, 4, 0);
}
static void DeleteFileA_action(X86Sim *s) {
  // CoreFP calls this if it has trouble decrypting the
  // sidb/sidd files.  It means error for us...
  char *path = *(char**)(s->regs[ESP] + 4);
  printf("unlink of %s detected\n", path);
  error("Unable to decrypt iTunes key files.  You need a new version of Requiem.\n");
}

static void add_actions(X86Sim *s, byte *base) {
  s->add_action(base + 0xdc6568, GetProcessHeap_action);
  s->add_action(base + 0xdc6570, HeapAlloc_action);
  s->add_action(base + 0xdc6560, HeapFree_action);
  s->add_action(base + 0xdc64c8, CreateMutexA_action);
  s->add_action(base + 0xdc64d8, CreateEventA_action);
  s->add_action(base + 0xdc65d0, CryptAcquireContext_action);
  s->add_action(base + 0xdc65d8, CryptGenRandom_action);
  s->add_action(base + 0xdc65e0, CryptReleaseContext_action);
  s->add_action(base + 0xdc64b0, WaitForSingleObject_action);
  s->add_action(base + 0xdc64e0, ResetEvent_action);
  s->add_action(base + 0xdc64c0, ReleaseMutex_action);
  s->add_action(base + 0xdc6498, InterlockedCompareExchange_action);
  s->add_action(base + 0xdc6510, GetCurrentThreadId_action);
  s->add_action(base + 0xdc64a0, GetFileAttributesA_action);
  s->add_action(base + 0xdc64a8, SetFileAttributesA_action);
  s->add_action(base + 0xdc64f0, FindFirstFileA_action);
  s->add_action(base + 0xdc6580, FindNextFileA_action);
  s->add_action(base + 0xdc6508, FindClose_action);
  s->add_action(base + 0xdc6588, CreateFileA_action);
  s->add_action(base + 0xdc6590, ReadFile_action);
  s->add_action(base + 0xdc64d0, CloseHandle_action);
  s->add_action(base + 0xdc65a0, DeleteFileA_action);
}

// load CoreFP, 1.13.37
static byte *loadCoreFP(const byte *corefp) {
  byte *base = aligned_malloc(0x139a000, 0x1000);
  memset(base, 0, 0x139a000);
  
  // header
  memcpy(base, corefp, 0x1000);
  // text segment
  memcpy(base + 0x1000, corefp + 0x1000, 0xdc5600);
  // read data segment
  memcpy(base + 0xdc7000, corefp + 0xdc7000, 0x595790);
  // read rdata segment
  memcpy(base + 0x135d000, corefp + 0x135d000, 0x3b278);
  
  // relocations
  uint32_t delta = (uint32_t)base - 0x7c800000;
  
  for (const byte *reloc = corefp + 0x139c000; reloc < corefp + 0x139c000 + 0x3d510;) {
    const byte *block_addr = base + *(uint32_t*)reloc;
    uint32_t nreloc = *(uint32_t*)(reloc + 4) / 2 - 4;
    for (int i = 0; i < nreloc; i++) {
      uint16_t r = *(uint16_t*)(reloc + 8 + 2 * i);
      switch (r >> 12) {
        case 0:
          // NOP
          break;
        case 3:
          *(uint32_t*)(block_addr + (r & 0xfff)) += delta;
          break;
        default: error("unknown reloc type %d\n", r >> 12);
      }
    }
    reloc += 8 + 2 * nreloc;
  }
  
  return base;
}

static int YlCJ3lgCall7(X86Sim *s, uint32_t op, uint32_t *argvals, int arglen, const byte *code, const uint32_t token8[2]) {
  // build info
  byte info[33] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  
  info[0] = 0;
  info[1] = 33;
  info[2] = 6;

  info[9] = 5;
  info[10] = 0;
  info[11] = 1;
  info[12] = 1;
  info[13] = 4;
  *(uint32_t*)(&info[14]) = byteswap32(argvals[0]);
  info[18] = 4;
  *(uint32_t*)(&info[19]) = byteswap32(argvals[1]);
  info[23] = 4;
  *(uint32_t*)(&info[24]) = byteswap32(argvals[2]);
  info[28] = 4;
  *(uint32_t*)(&info[29]) = byteswap32(argvals[3]);
  
  // build check array
  byte check[16];
  for (int i = 0; i < 16; i++) check[i] = ((byte*)info + 2)[i];
  
  // final obfuscation
  *(uint32_t*)((byte*)info + 6) ^= byteswap32(op);

  // secondary output
  byte output2[16];
  
  uint32_t *args = (uint32_t*)s->regs[ESP];
  const byte *retaddr = code;
  args[-1] = (uint32_t)retaddr;
  args[0] = 7;
  args[1] = token8[0];
  args[2] = token8[1];
  args[3] = op;
  args[4] = 0;
  args[5] = (uint32_t)check;
  args[6] = (uint32_t)info;
  args[7] = (uint32_t)output2;

  s->regs[ESP] -= 4;
  s->eip = code + 0x1f2f0; // YlCJ3lg
  s->go(retaddr);
  printf("eax: %x\n", s->regs[EAX]);
  return s->regs[EAX];
}

static const int iTunesPublicKeyLen = 1064;
static byte iTunesPublicKey[iTunesPublicKeyLen] = {
  0x30, 0x82, 0x04, 0x24, 0x30, 0x82, 0x03, 0x8d, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0d, 0x33,
  0x33, 0xaf, 0x11, 0x05, 0x06, 0xaf, 0x00, 0x02, 0xaf, 0x00, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x7f, 0x31, 0x0b, 0x30,
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
  0x55, 0x04, 0x0a, 0x13, 0x0a, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31,
  0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1d, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20,
  0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75,
  0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31, 0x33, 0x30, 0x31, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x13, 0x2a, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20, 0x46, 0x61, 0x69, 0x72, 0x50, 0x6c, 0x61, 0x79,
  0x20, 0x41, 0x41, 0x41, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
  0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1e, 0x17, 0x0d,
  0x31, 0x31, 0x30, 0x35, 0x30, 0x36, 0x30, 0x31, 0x31, 0x33, 0x31, 0x39, 0x5a, 0x17, 0x0d, 0x31,
  0x36, 0x30, 0x35, 0x30, 0x34, 0x30, 0x31, 0x31, 0x33, 0x31, 0x39, 0x5a, 0x30, 0x67, 0x31, 0x0b,
  0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06,
  0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e,
  0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0e, 0x41, 0x70, 0x70, 0x6c, 0x65,
  0x20, 0x46, 0x61, 0x69, 0x72, 0x50, 0x6c, 0x61, 0x79, 0x31, 0x2a, 0x30, 0x28, 0x06, 0x03, 0x55,
  0x04, 0x03, 0x13, 0x21, 0x69, 0x54, 0x75, 0x6e, 0x65, 0x73, 0x2e, 0x33, 0x33, 0x33, 0x33, 0x41,
  0x46, 0x31, 0x31, 0x30, 0x35, 0x30, 0x36, 0x41, 0x46, 0x30, 0x30, 0x30, 0x32, 0x41, 0x46, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x31, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81,
  0x81, 0x00, 0xbe, 0x72, 0xc9, 0x01, 0x90, 0xdd, 0xde, 0x88, 0x4f, 0xb5, 0x65, 0x8a, 0xf3, 0x8e,
  0xc7, 0x76, 0x73, 0x6a, 0x06, 0xe0, 0xdb, 0x51, 0x8e, 0xdb, 0xf6, 0x4b, 0x43, 0x97, 0xd0, 0xf2,
  0x1a, 0x16, 0xb8, 0x74, 0xf2, 0xb5, 0x80, 0x11, 0xdf, 0x02, 0x39, 0x74, 0x0c, 0x68, 0xca, 0xdd,
  0xfb, 0xdb, 0xc7, 0xfb, 0xc0, 0x22, 0x98, 0x75, 0x97, 0x86, 0x12, 0xf2, 0x7d, 0x76, 0x46, 0x3a,
  0xe3, 0x5a, 0x8b, 0x9c, 0x56, 0x03, 0x97, 0xcf, 0x6d, 0xa6, 0x45, 0x5e, 0x23, 0x93, 0xe5, 0x3b,
  0x85, 0x87, 0x0e, 0x81, 0xd9, 0x92, 0xec, 0xd4, 0x4d, 0x44, 0x9b, 0x8a, 0xfd, 0xdb, 0x23, 0x20,
  0xe5, 0x9e, 0xd3, 0x83, 0x3e, 0xf5, 0x45, 0xcd, 0xa0, 0xd9, 0x70, 0x00, 0x23, 0xcd, 0x91, 0xe3,
  0xd6, 0x67, 0x1d, 0xd6, 0xe4, 0x0a, 0x89, 0x44, 0x8e, 0x63, 0xae, 0xbb, 0x85, 0x8d, 0x5c, 0xd6,
  0x42, 0xdd, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0xba, 0x30, 0x82, 0x01, 0xb6, 0x30,
  0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x03, 0xb8, 0x30,
  0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x06,
  0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xcc, 0x72, 0xcb, 0xfc, 0x82, 0x7b, 0xea, 0x07,
  0x06, 0xca, 0x4d, 0x5e, 0xb0, 0x7a, 0x6a, 0x69, 0xf9, 0x2c, 0x84, 0xa6, 0x30, 0x1f, 0x06, 0x03,
  0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x56, 0xd9, 0x1d, 0x0a, 0x8c, 0x1b, 0x4e,
  0xc8, 0x00, 0x8c, 0x59, 0x51, 0x65, 0xbe, 0x9f, 0x9c, 0xa3, 0xe4, 0x2b, 0xf0, 0x30, 0x82, 0x01,
  0x54, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x07, 0x01, 0x02, 0x04, 0x82, 0x01,
  0x44, 0x00, 0x00, 0x00, 0x01, 0x09, 0xdc, 0x30, 0xb0, 0x13, 0x5b, 0xab, 0x3f, 0x13, 0x5d, 0xe3,
  0x45, 0x15, 0x47, 0x8f, 0x41, 0x15, 0x63, 0xf8, 0x3b, 0x16, 0x94, 0x69, 0x2a, 0x19, 0x47, 0xb1,
  0xf3, 0x1a, 0x61, 0x96, 0x47, 0x1b, 0xfe, 0xd9, 0x0b, 0x1f, 0xd3, 0x85, 0x92, 0x24, 0x20, 0xce,
  0x1d, 0x27, 0xfb, 0xdb, 0x6b, 0x2b, 0x5c, 0xf4, 0xf9, 0x2e, 0x30, 0x41, 0x54, 0x2f, 0x78, 0x1e,
  0xd4, 0x3a, 0x44, 0x65, 0x6b, 0x3f, 0xe4, 0x46, 0xac, 0x40, 0xae, 0x80, 0x63, 0x44, 0x96, 0x1c,
  0x21, 0x46, 0xc3, 0x96, 0x10, 0x46, 0xf7, 0xb8, 0xf6, 0x48, 0x92, 0xb6, 0x91, 0x4a, 0x74, 0x42,
  0x4f, 0x4b, 0x44, 0x71, 0x42, 0x50, 0x7c, 0x41, 0x97, 0x51, 0xbd, 0x2e, 0x4f, 0x52, 0xce, 0x54,
  0x2b, 0x53, 0xba, 0x39, 0x63, 0x5b, 0xa9, 0x9d, 0x93, 0x5c, 0x10, 0xc8, 0x73, 0x5c, 0xe4, 0x6c,
  0xe9, 0x5c, 0xe7, 0x27, 0xbe, 0x5d, 0xfb, 0x9f, 0xa1, 0x5f, 0x39, 0xc8, 0xe0, 0x62, 0x9b, 0xb2,
  0x70, 0x66, 0xfa, 0x6d, 0x20, 0x6b, 0xe9, 0x55, 0x35, 0x6c, 0xce, 0x7f, 0xc0, 0x70, 0xd1, 0xe0,
  0x55, 0x72, 0x69, 0x4d, 0x76, 0x80, 0x9f, 0xc3, 0xfc, 0x86, 0xad, 0xbd, 0x76, 0x88, 0x2c, 0x65,
  0x9b, 0x88, 0x72, 0xcb, 0xad, 0x8c, 0x2c, 0xce, 0x9c, 0x91, 0xf4, 0x27, 0xdf, 0xa2, 0x64, 0xf0,
  0xc1, 0xa2, 0x93, 0xe1, 0xa0, 0xa3, 0xe5, 0x37, 0x7e, 0xa5, 0x36, 0xdf, 0xee, 0xa5, 0xf3, 0x3c,
  0x3e, 0xa9, 0x14, 0x86, 0x47, 0xaa, 0x95, 0x45, 0x54, 0xab, 0xc5, 0xfa, 0x16, 0xb4, 0x96, 0xbd,
  0xc1, 0xb5, 0x65, 0x8e, 0xd7, 0xbb, 0x43, 0x60, 0xc2, 0xbc, 0x76, 0x23, 0x9a, 0xc4, 0xa3, 0x43,
  0x32, 0xc6, 0xb2, 0x8c, 0xd7, 0xc7, 0xed, 0x79, 0x51, 0xc9, 0x13, 0xbf, 0x87, 0xcb, 0xb6, 0x3e,
  0x38, 0xcc, 0x46, 0xf7, 0xa0, 0xcd, 0x75, 0x2c, 0xf5, 0xcd, 0xa4, 0xb2, 0x84, 0xd0, 0x66, 0x8f,
  0x66, 0xd1, 0x3f, 0xe0, 0x45, 0xd1, 0xb5, 0xc2, 0x24, 0xd3, 0x69, 0x6e, 0x94, 0xd4, 0x83, 0x31,
  0x44, 0xd4, 0xf5, 0xf8, 0xf5, 0xe0, 0xe0, 0xf2, 0x9f, 0xe2, 0x18, 0x18, 0x64, 0xe4, 0x73, 0x0c,
  0xe5, 0xe9, 0xf6, 0x53, 0xe1, 0xed, 0x9f, 0x97, 0xd3, 0xed, 0xe4, 0xd3, 0x8e, 0xf4, 0x41, 0x9e,
  0x34, 0xfa, 0xf7, 0x22, 0x97, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
  0x01, 0x05, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x3e, 0x6d, 0x99, 0x7e, 0xed, 0xc2, 0x69, 0x54,
  0x37, 0x35, 0xd5, 0x88, 0x17, 0x66, 0x7c, 0xc6, 0xf9, 0x13, 0x56, 0x1a, 0xe3, 0x9c, 0x7a, 0xa8,
  0x7b, 0x15, 0x89, 0x34, 0x6a, 0x83, 0x9c, 0xf0, 0xff, 0xaa, 0x05, 0x4f, 0xad, 0xb7, 0x9b, 0x95,
  0x58, 0x55, 0xcc, 0xd3, 0xf2, 0xb7, 0xef, 0xa1, 0x52, 0xb5, 0x1d, 0x23, 0x21, 0x05, 0x1f, 0x58,
  0xff, 0x03, 0x6b, 0x7f, 0x20, 0x7e, 0x9f, 0xd7, 0x01, 0x95, 0x8b, 0x77, 0x59, 0x6c, 0xeb, 0x12,
  0x58, 0xd9, 0x8e, 0xbb, 0x48, 0x6b, 0x84, 0xb1, 0xa5, 0x36, 0xe8, 0x8f, 0xb7, 0x0a, 0x44, 0x42,
  0x6d, 0x2c, 0x5d, 0x08, 0x61, 0xa9, 0xc3, 0x8c, 0xaf, 0xdb, 0xbd, 0xba, 0x0b, 0x61, 0xbc, 0x10,
  0x85, 0xef, 0x79, 0x6c, 0x09, 0x66, 0x4b, 0x73, 0xeb, 0x14, 0xe2, 0x31, 0x8d, 0x9e, 0xcc, 0x43,
  0xfa, 0x3e, 0xd6, 0xdd, 0x96, 0xb4, 0xb8, 0xd1,
};

byte handshake[128];
void handshake_listener(X86Sim *s) {
  byte *h = ((byte**)s->regs[EAX])[4];
  memcpy(handshake, h, 128);
}

void keyid_listener(X86Sim *s) {
  uint32_t key_id = s->regs[ECX];
  id_listener_callback(key_id);
}

void key_listener(X86Sim *s) {
  byte *p = *(byte**)s->regs[ESP];
  byte key[16];
  for (int i = 0; i < 16; i++) key[i] = p[i] * 0x3b + 0x95;
  key_listener_callback(key); // overwrites key from hdkey_listener
}

extern byte keysubHD_table[16*256]; // from tables.cc
extern byte keysubHDWin_table[16*256];
void hdkey_listener(X86Sim *s) {
  byte *p = (*(byte***)s->regs[ESP])[2];
  byte key[16];
  for (int i = 0; i < 16; i++) key[i] = p[i + 20] + 0xa0;
  for (int i = 0; i < 16; i++) key[i] = keysubHDWin_table[256*i + key[i]];
  for (int i = 0; i < 16; i++) key[i] = keysubHD_table[i*256 + key[i]];
  aes_context ctx;
  byte fixedkey[16] = {0x54,0x97,0x1f,0xac,0x02,0x1e,0x71,0x9c,0xc0,0xfd,0x80,0x5c,0xdb,0x89,0x61,0x11};
  aes_set_key(&ctx, fixedkey, 128);
  aes_decrypt(&ctx, key, key);
  key_listener_callback(key);
}

int extractKeys(const byte *corefp, const byte *macaddr, const byte *sidb, uint32_t sidb_len, const byte *sidd, uint32_t sidd_len, uint32_t user_id, void (*id_callback)(uint32_t key_id), void (*key_callback)(const byte *key)) {
  id_listener_callback = id_callback;
  key_listener_callback = key_callback;
  
  byte *code = loadCoreFP(corefp);
  X86Sim *s = X86Sim::create(code, 0xdc6600);
  add_actions(s, code);

  // set up data files
  file_data["/Users/Shared/SC Info\\SC Info.sidb"] = FileData(sidb, sidb_len);
  file_data["/Users/Shared/SC Info\\SC Info.sidd"] = FileData(sidd, sidd_len);

  // listen for clear handshake
  s->add_listener(code + 0x78a1, handshake_listener);
  s->add_listener(code + 0x37ef93, key_listener);
  s->add_listener(code + 0x26f1c2, keyid_listener);
  s->add_listener(code + 0x2f3210, hdkey_listener);
  
  // set up call
  byte *stackmem = aligned_malloc(1048576, 16);
  memset(stackmem, 0, 1048576);
  byte *stack = stackmem + 1048576 - 0x1000;
  s->regs[ESP] = (uint32_t)stack;
  uint32_t *args = (uint32_t*)stack;
  
  byte *retaddr = code;
  uint32_t token8[2];
  uint32_t two = 2; 
  byte encrypted_handshake[128];
  byte *CoreFPPublicKey;
  uint32_t CoreFPPublicKeyLen;
  
  args[-1] = (uint32_t)retaddr;
  args[0] = 7;
  args[1] = (uint32_t)token8;
  args[2] = (uint32_t)&two;
  args[3] = (uint32_t)iTunesPublicKey;
  args[4] = iTunesPublicKeyLen;
  args[5] = (uint32_t)encrypted_handshake;
  args[6] = (uint32_t)&CoreFPPublicKey;
  args[7] = (uint32_t)&CoreFPPublicKeyLen;
  
  s->regs[ESP] -= 4;
  s->eip = code + 0x2ce0; // WIn9UJ86JKdV4dM
  s->go(retaddr);
  printf("eax: %x\n", s->regs[EAX]);
  if (s->regs[EAX]) return 1;
  
  // use same handshake in the opposite direction
  byte *handshake2 = handshake;
  
  // encrypt using CoreFP public key
  // don't bother parsing it, just hardcode it.
  byte modulus[128] = {
    0xce,0xe9,0x41,0xe2,0x5f,0x8a,0xb9,0xbe,0x10,0x0a,0xcf,0x6f,0xbf,0x1b,
    0xbf,0xaa,0xbc,0xb8,0xf7,0xc6,0x7d,0x78,0xb5,0x24,0x78,0xa1,0x4f,0x91,0x65,
    0x05,0xc4,0x64,0xd5,0x8e,0xd1,0xc0,0x85,0xe2,0x73,0xb7,0x8a,0x3f,0x39,0x13,
    0x85,0xe2,0x4b,0xe1,0xd0,0x37,0x32,0x47,0x22,0x4d,0x19,0x9a,0x6a,0x83,0x45,
    0x78,0x5e,0x91,0x5a,0x8a,0xe6,0xc0,0xf5,0x22,0x63,0xf7,0xa7,0x2e,0x2f,0x17,
    0xed,0x4b,0x01,0xca,0x02,0xe7,0xba,0xd3,0x84,0xa4,0xd1,0x66,0x0c,0x58,0xa6,
    0x7b,0x44,0xaa,0xed,0x26,0xf4,0x25,0xbc,0x91,0x52,0xda,0x51,0x4a,0x2e,0x5f,
    0x88,0x96,0x99,0x02,0xf5,0xfb,0x5a,0xa0,0x93,0xde,0xf0,0xa9,0x70,0x92,0xb2,
    0x7a,0xeb,0x2b,0xb1,0x09,0x95,0xd0,0xd5,0x8f,
  };
  BigUnsigned N = bigFromBuf(modulus, 128);
  BigUnsigned M = bigFromBuf(handshake2, 128);
  BigUnsigned X = modexp(M, BigUnsigned(0x10001), N);
  byte encrypted_handshake2[128];
  bigToBuf(X, encrypted_handshake2, 128);
  
  args[-1] = (uint32_t)retaddr;
  args[0] = 7;
  args[1] = token8[0];
  args[2] = token8[1];
  args[3] = (uint32_t)encrypted_handshake2;
  
  s->regs[ESP] -= 4;
  s->eip = code + 0xb170; // X46O5IeS
  s->go(retaddr);
  printf("eax: %x\n", s->regs[EAX]);
  if (s->regs[EAX]) return 1;
  
  struct {
    uint32_t size;
    byte data[6];
  } mac = {
    6,
  };
  for (int i = 0; i < 6; i++) mac.data[i] = macaddr[i];
  byte output[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  byte unk[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  
  // read sidb
  uint32_t argvals[4] = {
    (uint32_t)unk,
    (uint32_t)&mac,
    (uint32_t)"/Users/Shared/SC Info",
    (uint32_t)output
  };
  int err = YlCJ3lgCall7(s, 0xf4419e34, argvals, 4, code, token8);
  if (err) return 1;

  struct {
    uint32_t junk[9];
    uint32_t udid_size;
    byte udid_data[20];
    uint32_t lots[256];
  } context = {
    {0,0x5eb9581a,0x462e4780,0,0x77206ab0,0x833426a8,0x9a64a200,0x5eb95818,0xdd},
    20, // udid length
    {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, // arbitrary udid
  };
  *(uint32_t*)((uint32_t)&context + 0x154) = 0x41b39731;
  struct {
    uint32_t junk[17];
    uint32_t context_ptr;
  } metacontext = {
    {0xc7b1ceb,0xc582e6a7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    ((uint32_t)&context + 0x44a16aa0) ^ 0x44a16aa0,
  };
  {
    byte check[16];
    byte output[16];
    uint64_t info[8];
    
    info[0] = byteswap64(6);
    info[1] = 0;
    info[2] = byteswap64(1);
    info[3] = byteswap64(((uint32_t)&metacontext + 0x737c3980) ^ 0x737c3980);
    info[4] = 0;
    info[5] = 0;
    info[6] = 0;
    info[7] = 0;

    // 1a619647 call
    args[-1] = (uint32_t)retaddr;
    args[0] = 5;
    args[1] = token8[0];
    args[2] = token8[1];
    args[3] = 0x1a619647;
    args[4] = 0;
    args[5] = (uint32_t) check;
    args[6] = (uint32_t) info;
    args[7] = (uint32_t) output;
    
    s->regs[ESP] -= 4;
    s->eip = code + 0x1f2f0; // YlCJ3lg
    s->go(retaddr);
    printf("eax: %x\n", s->regs[EAX]);
    if (s->regs[EAX]) return 1;
  }

  uint64_t info[6];
  info[0] = 4;
  info[1] = 0;
  info[2] = 2;
  info[3] = ((uint32_t)&metacontext + 0x737c3980) ^ 0x737c3980;
  info[4] = user_id;
  info[5] = 0;
  for (int i = 0; i < 6; i++) info[i] = byteswap64(info[i]);
  byte check[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  byte output2[16];
  
  args[-1] = (uint32_t)retaddr;
  args[0] = 5;
  args[1] = token8[0];
  args[2] = token8[1];
  args[3] = 0x629bb270;
  args[4] = 0;
  args[5] = (uint32_t)check;
  args[6] = (uint32_t)info;
  args[7] = (uint32_t)output2;

  s->regs[ESP] -= 4;
  s->eip = code + 0x1f2f0; // YlCJ3lg
  s->go(retaddr);
  printf("eax: %x\n", s->regs[EAX]);
  if (s->regs[EAX]) return 1;
  
  delete s;
  free(stackmem);
  return 0;
}
