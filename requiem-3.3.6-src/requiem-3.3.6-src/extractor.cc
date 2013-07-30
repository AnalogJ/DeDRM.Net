#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <map>
using namespace std;

typedef unsigned char byte;

#define error(args...) { fprintf(stdout, "ERROR "); fprintf(stdout, ## args); exit(1); }

// from simphone.cc (mac) or winphone.cc (Windows)
#if WINDOWS
int extractKeys(const byte *corefp, const byte *macaddr, const byte *sidb, uint32_t sidb_len, const byte *sidd, uint32_t sidd_len, uint32_t user_id, void (*id_callback)(uint32_t key_id), void (*key_callback)(const byte *key));
#else
int extractKeys(const byte *corefp, const byte *corefp1, const byte *icxs, const byte *icxs1, const byte *macaddr, const byte *sidb, uint32_t sidb_len, const byte *sidd, uint32_t sidd_len, uint32_t user_id, void (*id_callback)(uint32_t key_id), void (*key_callback)(const byte *key));
#endif

static uint32_t current_id;
static map<uint32_t,byte*> keys;
static void id_callback(uint32_t key_id) {
  keys[key_id] = NULL;
  current_id = key_id;
}
static void key_callback(const byte *key) {
  byte *k = (byte*)malloc(16);
  memcpy(k, key, 16);
  keys[current_id] = k;
}

struct FileData {
  byte *data;
  uint32_t length;
  FileData(byte *data, uint32_t length) : data(data), length(length) {}
};
static FileData read(const char *name) {
  FILE *f = fopen(name, "rb");
  fseek(f, 0, SEEK_END);
  int len = ftell(f);
  fseek(f, 0, SEEK_SET);
  byte *data = (byte*)malloc(len);
  if (fread(data, 1, len, f) != len) error("can't read whole file %s\n", name);
  fclose(f);
  return FileData(data, len);
}

static byte *parse_mac(const char *str) {
  byte *mac = (byte*)malloc(6);
  for (int i = 0; i < 6; i++) {
    char s[3] = {str[2 * i], str[2 * i + 1], 0};
    mac[i] = strtol(s, NULL, 16);
  }
  return mac;
}

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IOLBF, 0); // line buffer stdout
  printf("entered native code\n");
  uint32_t user_id = (uint32_t)strtoll(argv[1], NULL, 16);
  FileData sidb = read(argv[2]);
  FileData sidd = read(argv[3]);
  byte *macaddr = parse_mac(argv[4]);
  FileData corefp = read(argv[5]);
#if !WINDOWS
  FileData corefp1 = read(argv[6]);
  FileData icxs = read(argv[7]);
  FileData icxs1 = read(argv[8]);
#endif
  
#if WINDOWS
  int err = extractKeys(corefp.data, macaddr, sidb.data, sidb.length, sidd.data, sidd.length, user_id, id_callback, key_callback);
#else
  int err = extractKeys(corefp.data, corefp1.data, icxs.data, icxs1.data, macaddr, sidb.data, sidb.length, sidd.data, sidd.length, user_id, id_callback, key_callback);
#endif
  
  for (map<uint32_t,byte*>::const_iterator i = keys.begin(); i != keys.end(); ++i) {
    uint32_t key_id = i->first;
    byte *key = i->second;
    if (key) {
      printf("KEY %x", key_id);
      for (int i = 0; i < 16; i++) {
        printf(" %02x", key[i]);
      }
      printf("\n");
      free(key);
    } else {
      printf("NOKEY %x\n", key_id);
    }
  }
  printf("leaving native code\n");
  return err;
}
