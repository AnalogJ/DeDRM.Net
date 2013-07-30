#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <string>
#include "x86sim.h"
#include "bigint/BigIntegerLibrary.hh"
#include "aes.h"

using namespace std;

#define error(args...) { fprintf(stdout, "ERROR "); fprintf(stdout, ## args); exit(1); }

byte *aligned_malloc(size_t size, size_t align) {
  byte *ptr;
  if (posix_memalign((void**)&ptr, align, size)) error("failed malloc %lu %lu\n", size, align);
  return ptr;
}
void aligned_free(byte *ptr) {
  free(ptr);
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

void returnAction(X86Sim *s, uint32_t value) {
  // set return value
  s->regs[EAX] = value;
  // pop return address
  s->eip = *(byte**)s->regs[ESP];
  s->regs[ESP] += 4;
}
void pthread_mutex_lock_action(X86Sim *s) {
  if (print_actions) printf("pthread_mutex_lock\n");
  returnAction(s, 0);
}
void pthread_mutex_unlock_action(X86Sim *s) {
  if (print_actions) printf("pthread_mutex_unlock_action\n");
  returnAction(s, 0);
}
void pthread_rwlock_init_action(X86Sim *s) {
  if (print_actions) printf("pthread_rwlock_init_action\n");
  returnAction(s, 0);
}
void pthread_rwlock_rdlock_action(X86Sim *s) {
  if (print_actions) printf("pthread_rwlock_rdlock_action\n");
  returnAction(s, 0);
}
void pthread_rwlock_wrlock_action(X86Sim *s) {
  if (print_actions) printf("pthread_rwlock_wrlock_action\n");
  returnAction(s, 0);
}
void pthread_rwlock_unlock_action(X86Sim *s) {
  if (print_actions) printf("pthread_rwlock_unlock_action\n");
  returnAction(s, 0);
}
void pthread_once_action(X86Sim *s) {
  if (print_actions) printf("pthread_once_action\n");
  uint32_t *control = *(uint32_t**)(s->regs[ESP] + 4);
  byte *routine = *(byte**)(s->regs[ESP] + 8);
  int magic = *control;
  if (magic == 0x30b1bcba) { // hasn't been called yet
    *control = 0; // mark as already called
    s->eip = routine; // jump to routine - it will return to pthread_once's caller
    if (print_actions) printf("  calling %p\n", routine);
    // TODO: this doesn't return the correct value from pthread_once, but CoreFP doesn't seem to care...
  } else { // already called - just return 0
    returnAction(s, 0);
  }
}
void pthread_self_action(X86Sim *s) {
  returnAction(s, 1);
}
void OSAtomicCompareAndSwap32Barrier_action(X86Sim *s) {
  uint32_t oldValue = *(uint32_t*)(s->regs[ESP] + 4);
  uint32_t newValue = *(uint32_t*)(s->regs[ESP] + 8);
  uint32_t *ptr = *(uint32_t**)(s->regs[ESP] + 12);
  if (print_actions) printf("OSAtomicCompareAndSwap32Barrier_action %p %x %x\n", ptr, oldValue, newValue);
  if (oldValue == *ptr) {
    *ptr = newValue;
    returnAction(s, 1);
  } else {
    returnAction(s, 0);
  }
}

static char *current_bundle = NULL;
void CFStringCreateWithCStringNoCopy_action(X86Sim *s) {
  char *p = *(char**)(s->regs[ESP] + 8);
  if (print_actions) printf("CFStringCreateWithCStringNoCopy_action %s\n", p);
  current_bundle = p;
  returnAction(s, 1);
}
void CFBundleGetMainBundle_action(X86Sim *s) {
  if (print_actions) printf("CFBundleGetMainBundle_action\n");
  returnAction(s, 1);
}
void CFBundleGetBundleWithIdentifier_action(X86Sim *s) {
  if (print_actions) printf("CFBundleGetBundleWithIdentifier_action\n");
  returnAction(s, 1);
}
void CFBundleCopyResourcesDirectoryURL_action(X86Sim *s) {
  if (print_actions) printf("CFBundleCopyResourcesDirectoryURL_action\n");
  returnAction(s, 1);
}
void CFBundleCopyPrivateFrameworksURL_action(X86Sim *s) {
  if (print_actions) printf("CFBundleCopyPrivateFrameworksURL_action\n");
  returnAction(s, 1);
}
void CFRelease_action(X86Sim *s) {
  if (print_actions) printf("CFRelease_action\n");
  returnAction(s, 0);
}
void CFURLGetFileSystemRepresentation_action(X86Sim *s) {
  if (print_actions) printf("CFURLGetFileSystemRepresentation_action\n");
  char *p = *(char**)(s->regs[ESP] + 12);
  if (!strcmp(current_bundle, "com.apple.CoreFP")) {
    strcpy(p, "/System/Library/PrivateFrameworks/CoreFP.framework/Resources");
  } else if (!strcmp(current_bundle, "com.apple.CoreFP1")) {
    strcpy(p, "/System/Library/PrivateFrameworks/CoreFP1.framework/Resources");
  } else {
    error("unknown bundle %s\n", current_bundle);
  }
  returnAction(s, 1);
}

void malloc_action(X86Sim *s) {
  uint32_t size = *(uint32_t*)(s->regs[ESP] + 4);
  void *ptr = malloc(size);
  if (!ptr) error("malloc %x failed\n", size);
  if (print_actions) printf("malloc_action %p/%x\n", ptr, size);
  returnAction(s, (uint32_t)ptr);
}
void free_action(X86Sim *s) {
  void *ptr = *(void**)(s->regs[ESP] + 4);
  if (print_actions) printf("free_action %p\n", ptr);
  free(ptr);
  returnAction(s, 0);
}
void memset_action(X86Sim *s) {
  void *ptr = *(void**)(s->regs[ESP] + 4);
  uint32_t c = *(uint32_t*)(s->regs[ESP] + 8);
  uint32_t len = *(uint32_t*)(s->regs[ESP] + 12);
  if (print_actions) printf("memset_action %p %x %x\n", ptr, c, len);
  memset(ptr, c, len);
  returnAction(s, (uint32_t)ptr);
}
void memcpy_action(X86Sim *s) {
  byte *dst = *(byte**)(s->regs[ESP] + 4);
  byte *src = *(byte**)(s->regs[ESP] + 8);
  uint32_t len = *(uint32_t*)(s->regs[ESP] + 12);
  if (print_actions) printf("memcpy action %p %p %x\n", dst, src, len);
  memcpy(dst, src, len);
  returnAction(s, 0);
}
void strncmp_action(X86Sim *s) {
  uint32_t p1 = *(uint32_t*)(s->regs[ESP] + 4);
  uint32_t p2 = *(uint32_t*)(s->regs[ESP] + 8);
  uint32_t len = *(uint32_t*)(s->regs[ESP] + 12);
  if (print_actions) printf("strncmp action %x %x %x\n", p1, p2, len);
  for (uint32_t i = 0; i < len; i++) {
    byte c1 = *(byte*)(p1 + i);
    byte c2 = *(byte*)(p2 + i);
    if (c1 != c2) {
      returnAction(s, c1 < c2 ? -1 : 1);
      return;
    }
  }
  returnAction(s, 0);
}

struct FileData {
  const byte *data;
  size_t size;
  FileData() : data(0), size(0) {}
  FileData(const byte *data, size_t size) : data(data), size(size) {
  }
};
map<string,FileData> file_data;
uint32_t next_fd = 3;
map<uint32_t,FileData> open_files;
void open_action(X86Sim *s) {
  char *name = *(char**)(s->regs[ESP] + 4);
  if (print_actions) printf("open_action %s\n", name);
  FileData info = file_data[name];
  if (!info.data) {
    if (print_actions) printf("open failed %s\n", name);
    returnAction(s, (uint32_t)-1);
    // see error_action for error code
  } else {
    if (print_actions) printf("open succeeded %s %x\n", name, next_fd);
    open_files[next_fd] = info;
    returnAction(s, next_fd++);
  }
}
void read_action(X86Sim *s) {
  uint32_t fd = *(uint32_t*)(s->regs[ESP] + 4);
  byte *buf = *(byte**)(s->regs[ESP] + 8);
  uint32_t size = *(uint32_t*)(s->regs[ESP] + 12);
  if (print_actions) printf("read_action %x %p %x\n", fd, buf, size);
  FileData info = open_files[fd];
  if (size > info.size) error("read too much %d %ld\n", size, info.size);
  memcpy(buf, info.data, size);
  returnAction(s, size);
}
void close_action(X86Sim *s) {
  uint32_t fd = *(uint32_t*)(s->regs[ESP] + 4);
  if (print_actions) printf("close_action %x\n", fd);
  open_files.erase(fd);
  returnAction(s, 0);
}
void lstat_action(X86Sim *s) {
  char *path = (char*)*(uint32_t*)(s->regs[ESP] + 4);
  if (print_actions) printf("lstat_action %s\n", path);
  uint32_t buf = *(uint32_t*)(s->regs[ESP] + 8);
  FileData info = file_data[path];
  if (!info.data) {
    if (print_actions) printf("  doesn't exist\n");
    returnAction(s, (uint32_t)-1);
  } else {
    *(time_t*)(buf + 32) = 1317852000; // modification time
    *(size_t*)(buf + 48) = info.size;
    returnAction(s, 0);
  }
}
void error_action(X86Sim *s) {
  static uint32_t two = 2; // ENOENT (no such file or directory)
  if (print_actions) printf("error_action\n");
  returnAction(s, (uint32_t)&two);
}
void fstat_action(X86Sim *s) {
  uint32_t fd = *(uint32_t*)(s->regs[ESP] + 4);
  if (print_actions) printf("fstat_action %d\n", fd);
  uint32_t buf = *(uint32_t*)(s->regs[ESP] + 8);
  FileData info = open_files[fd];
  *(time_t*)(buf + 32) = 1317852000; // modification time
  *(size_t*)(buf + 48) = info.size;
  returnAction(s, 0);
}
const byte *err_return;
void unlink_action(X86Sim *s) {
  // CoreFP calls this if it has trouble decrypting the
  // sidb/sidd files.  It means error for us...
  char *path = (char*)*(uint32_t*)(s->regs[ESP] + 4);
  printf("unlink of %s detected\n", path);
  s->regs[EAX] = 1;
  s->eip = err_return;
}

void arc4random_action(X86Sim *s) {
  if (print_actions) printf("arc4random_action\n");
  returnAction(s, 0xaaaaaaaa);
}

void umoddi3_action(X86Sim *s) {
  uint64_t x = *(uint64_t*)(s->regs[ESP] + 4);
  uint64_t y = *(uint64_t*)(s->regs[ESP] + 12);
  //if (print_actions) printf("umoddi3_action %llx %llx\n", x, y);
  uint64_t z = x % y;
  s->regs[EAX] = z;
  s->regs[EDX] = z >> 32;
  // pop return address
  s->eip = *(byte**)s->regs[ESP];
  s->regs[ESP] += 4;
}

void dlopen_action(X86Sim *s) {
  char *filename = *(char**)(s->regs[ESP] + 4);
  if (print_actions) printf("dlopen %s\n", filename);
  returnAction(s, 1);
}

byte *symbol_DFjn2fjk;
byte *symbol_PPFdkjq4nb;
byte *symbol_Zmdjk32jjoap;
byte *symbol_P1Pfodajk24n;
byte *symbol_p320tjnag329na;
byte *symbol_pPrj293naokbS1;

void dlsym_action(X86Sim *s) {
  char *symbol = *(char**)(s->regs[ESP] + 8);
  if (print_actions) printf("dlsym %s\n", symbol);
  if (!strcmp(symbol, "DFjn2fjk")) {
    returnAction(s, (uint32_t)symbol_DFjn2fjk);
  } else if (!strcmp(symbol, "PPFdkjq4nb")) {
    returnAction(s, (uint32_t)symbol_PPFdkjq4nb);
  } else if (!strcmp(symbol, "Zmdjk32jjoap")) {
    returnAction(s, (uint32_t)symbol_Zmdjk32jjoap);
  } else if (!strcmp(symbol, "P1Pfodajk24n")) {
    returnAction(s, (uint32_t)symbol_P1Pfodajk24n);
  } else if (!strcmp(symbol, "p320tjnag329na")) {
    returnAction(s, (uint32_t)symbol_p320tjnag329na);
  } else if (!strcmp(symbol, "pPrj293naokbS1")) {
    returnAction(s, (uint32_t)symbol_pPrj293naokbS1);
  } else {
    error("unknown symbol %s\n", symbol);
  }
}

void add_actions(X86Sim *s, byte *base) {
  // CoreFP
  s->add_action(base + 0x2ffb4c, pthread_mutex_lock_action);
  s->add_action(base + 0x2ffb52, pthread_mutex_unlock_action);
  s->add_action(base + 0x2ffb64, pthread_rwlock_init_action);
  s->add_action(base + 0x2ffb6a, pthread_rwlock_rdlock_action);
  s->add_action(base + 0x2ffb76, pthread_rwlock_wrlock_action);
  s->add_action(base + 0x2ffb70, pthread_rwlock_unlock_action);
  s->add_action(base + 0x2ffb58, pthread_once_action);
  s->add_action(base + 0x2ffae6, OSAtomicCompareAndSwap32Barrier_action);
  s->add_action(base + 0x2ffa6e, CFStringCreateWithCStringNoCopy_action);
  s->add_action(base + 0x2ffa3e, CFBundleGetMainBundle_action);
  s->add_action(base + 0x2ffa38, CFBundleGetBundleWithIdentifier_action);
  s->add_action(base + 0x2ffa32, CFBundleCopyResourcesDirectoryURL_action);
  s->add_action(base + 0x2ffa86, CFURLGetFileSystemRepresentation_action);
  s->add_action(base + 0x2ffa2c, CFBundleCopyPrivateFrameworksURL_action);
  s->add_action(base + 0x2ffa68, CFRelease_action);
  s->add_action(base + 0x2ffb34, malloc_action);
  s->add_action(base + 0x2ffb1c, free_action);
  s->add_action(base + 0x2ffb40, memset_action);
  s->add_action(base + 0x2ffb46, open_action);
  s->add_action(base + 0x2ffb82, read_action);
  s->add_action(base + 0x2ffb0a, close_action);
  s->add_action(base + 0x2ffb2e, lstat_action);
  s->add_action(base + 0x2ffaec, error_action);
  s->add_action(base + 0x2ffb94, unlink_action);
  s->add_action(base + 0x2ffb04, arc4random_action);
  s->add_action(base + 0x2ffb10, dlopen_action);
  s->add_action(base + 0x2ffb16, dlsym_action);
  
  // CoreFP1
  byte *base1 = base + 0x45c000;
  s->add_action(base1 + 0xd40bb2, pthread_mutex_lock_action);
  s->add_action(base1 + 0xd40bb8, pthread_mutex_unlock_action);
  s->add_action(base1 + 0xd40bca, pthread_rwlock_init_action);
  s->add_action(base1 + 0xd40bd0, pthread_rwlock_rdlock_action);
  s->add_action(base1 + 0xd40bdc, pthread_rwlock_wrlock_action);
  s->add_action(base1 + 0xd40bd6, pthread_rwlock_unlock_action);
  s->add_action(base1 + 0xd40bbe, pthread_once_action);
  s->add_action(base1 + 0xd40be2, pthread_self_action);
  s->add_action(base1 + 0xd40b0a, OSAtomicCompareAndSwap32Barrier_action);
  s->add_action(base1 + 0xd40aec, CFStringCreateWithCStringNoCopy_action);
  s->add_action(base1 + 0xd40ae0, CFBundleGetMainBundle_action);
  s->add_action(base1 + 0xd40ada, CFBundleGetBundleWithIdentifier_action);
  s->add_action(base1 + 0xd40ad4, CFBundleCopyResourcesDirectoryURL_action);
  s->add_action(base1 + 0xd40af2, CFURLGetFileSystemRepresentation_action);
  s->add_action(base1 + 0xd40ae6, CFRelease_action);
  s->add_action(base1 + 0xd40b94, malloc_action);
  s->add_action(base1 + 0xd40b5e, free_action);
  s->add_action(base1 + 0xd40b9a, memcpy_action);
  s->add_action(base1 + 0xd40c06, strncmp_action);
  s->add_action(base1 + 0xd40ba6, open_action);
  s->add_action(base1 + 0xd40be8, read_action);
  s->add_action(base1 + 0xd40b28, close_action);
  s->add_action(base1 + 0xd40b8e, lstat_action);
  s->add_action(base1 + 0xd40b6a, fstat_action);
  s->add_action(base1 + 0xd40c0c, unlink_action);
  s->add_action(base1 + 0xd40b22, arc4random_action);
  s->add_action(base1 + 0xd40b1c, umoddi3_action);
}

// load CoreFP, 1.13.35
byte *loadCoreFP(const byte *corefp, const byte *corefp1) {
  byte *base = aligned_malloc(0x45c000 + 0x1234000, 0x1000);
  memset(base, 0, 0x45c000 + 0x1234000);
  byte *base1 = base + 0x45c000;
  
  // text segment
  memcpy(base, corefp, 0x300000);
  // read data segment
  memcpy(base + 0x300000, corefp + 0x300000, 0x4000);
  // read linkedit segment
  memcpy(base + 0x453000, corefp + 0x304000, 0x8020);

  // modify __nl_symbol_ptr section
  for (int i = 0; i < 0x2a0; i += 4) {
    *(uint32_t*)(base + 0x300008 + i) += (uint32_t)base;
  }
  
  // apply local relocations
  for (int i = 0; i < 0x174; i++) {
    uint32_t addr = *(uint32_t*)(base + 0x4538b4 + 8 * i);
    *(uint32_t*)(base + addr) += (uint32_t)base;
  }

  memcpy(base1, corefp1, 0xd41000);
  memcpy(base1 + 0xd41000, corefp1 + 0xd41000, 0xd000);
  memcpy(base1 + 0x121b000, corefp1 + 0xd4e000, 0x18140);
  for (int i = 0; i < 0xb2c; i += 4) {
    *(uint32_t*)(base1 + 0xd41008 + i) += (uint32_t)base1;
  }
  for (int i = 0; i < 0x2c6; i++) {
    uint32_t addr = *(uint32_t*)(base1 + 0x121b6ec + 8 * i);
    *(uint32_t*)(base1 + addr) += (uint32_t)base1;
  }
  
  // save address of some routines in CoreFP1
  symbol_DFjn2fjk = base1 + 0xa9bd00;
  symbol_PPFdkjq4nb = base1 + 0xa61380;
  symbol_Zmdjk32jjoap = base1 + 0x39c0;
  symbol_P1Pfodajk24n = base1 + 0xc04c20;
  symbol_p320tjnag329na = base1 + 0xa27560;
  symbol_pPrj293naokbS1 = base1 + 0xad93f0;
  
  return base;
}

byte handshake[128];
void handshake_listener(X86Sim *s) {
  byte *h = (*(byte***)(s->regs[ESP] + 4))[6];
  memcpy(handshake, h, 128);
}

void keyid_listener(X86Sim *s) {
  uint32_t key_id = s->regs[ESI];
  id_listener_callback(key_id);
}

void key_listener(X86Sim *s) {
  byte *p = *(byte**)(s->regs[ESP] + 4);
  byte key[16];
  for (int i = 0; i < 16; i++) key[i] = p[i] * 0x3b + 0x95;
  key_listener_callback(key);
}

extern byte keysubHD_table[16*256]; // from tables.cc
void hdkey_listener(X86Sim *s) {
  byte *p = *(byte**)(s->regs[EBP] - 0x18ce4);
  byte key[16];
  for (int i = 0; i < 16; i++) key[i] = p[i] + 0xb2;
  for (int i = 0; i < 16; i++) key[i] = keysubHD_table[i*256 + key[i]];
  aes_context ctx;
  byte fixedkey[16] = {0x54,0x97,0x1f,0xac,0x02,0x1e,0x71,0x9c,0xc0,0xfd,0x80,0x5c,0xdb,0x89,0x61,0x11};
  aes_set_key(&ctx, fixedkey, 128);
  aes_decrypt(&ctx, key, key);
  key_listener_callback(key);
}

int YlCJ3lgCall7(X86Sim *s, uint32_t op, uint32_t *argvals, int arglen, const byte *code, const uint32_t token8[2]) {
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
  s->eip = code + 0x1910; // YlCJ3lg
  s->go(retaddr);
  printf("eax: %x\n", s->regs[EAX]);
  return s->regs[EAX];
}

const int iTunesPublicKeyLen = 1064;
byte iTunesPublicKey[iTunesPublicKeyLen] = {
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

int extractKeys(const byte *corefp, const byte *corefp1, const byte *icxs, const byte *icxs1, const byte *macaddr, const byte *sidb, uint32_t sidb_len, const byte *sidd, uint32_t sidd_len, uint32_t user_id, void (*id_callback)(uint32_t key_id), void (*key_callback)(const byte *key)) {
  id_listener_callback = id_callback;
  key_listener_callback = key_callback;
  
  byte *code = loadCoreFP(corefp, corefp1);
  X86Sim *s = X86Sim::create(code, 0x45c000 + 0x1234000);
  add_actions(s, code);
  err_return = code;

  // set up data files
  file_data["/System/Library/PrivateFrameworks/CoreFP.framework/Resources/../CoreFP.icxs"] = FileData(icxs, 1368752);
  file_data["/System/Library/PrivateFrameworks/CoreFP1.framework/Resources/../CoreFP1.icxs"] = FileData(icxs1, 5083776);
  file_data["/Users/Shared/SC Info/SC Info.sidb"] = FileData(sidb, sidb_len);
  file_data["/Users/Shared/SC Info/SC Info.sidd"] = FileData(sidd, sidd_len);

  // listen for clear handshake
  s->add_listener(code + 0x265880, handshake_listener);
  
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
  s->eip = code + 0x1f84d0; // WIn9UJ86JKdV4dM
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
  s->eip = code + 0x2322c0; // X46O5IeS
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
    uint32_t junk[7];
    uint32_t udid_size;
    byte udid_data[20];
    uint32_t lots[256];
  } context = {
    {0xfe50144a,0x4643853f,0x2eef8520,0,0x3017af50,0x4643855a,0x60},
    20, // udid length
    {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, // arbitrary udid
  };
  *(uint32_t*)((uint32_t)&context + 0x14c) = 0x0;
  struct {
    uint32_t junk[17];
    uint32_t context_ptr;
  } metacontext = {
    {0x47883ab9,0xa720bc96,0,1,0,0,0,0,0,0,0,0x30e75a3,0,0,0,0,0},
    (uint32_t)&context + 0x20258bd0 ^ 0x20258bd0,
  };
  {
    byte check[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    byte output[16];
    uint64_t info[8];
    
    info[0] = byteswap64(6);
    info[1] = 0;
    info[2] = byteswap64(1);
    info[3] = byteswap64((uint32_t)&metacontext + 0x161f4e10 ^ 0x161f4e10);
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
    s->eip = code + 0x1910; // YlCJ3lg
    s->go(retaddr);
    printf("eax: %x\n", s->regs[EAX]);
    if (s->regs[EAX]) return 1;
  }

  uint64_t info[6];
  info[0] = 4;
  info[1] = 0;
  info[2] = 2;
  info[3] = ((uint32_t)&metacontext + 0x161f4e10) ^ 0x161f4e10;
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

  s->add_listener(code + 0x45c000 + 0x11a0, key_listener);
  s->add_listener(code + 0x45c000 + 0x2e47c3, keyid_listener);
  s->add_listener(code + 0x45c000 + 0x2eab40, hdkey_listener);

  s->regs[ESP] -= 4;
  s->eip = code + 0x1910; // YlCJ3lg
  s->go(retaddr);
  printf("eax: %x\n", s->regs[EAX]);
  if (s->regs[EAX]) return 1;
  
  delete s;
  free(stackmem);
  return 0;
}
