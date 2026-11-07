/* Compile with -I pointing at src/phobos-obfuscator from Phobos
 * 22aedefda053062dc58c036072d2da6e216d5a34. No upstream source is vendored.
 * Usage: reference encode|decode key partial hex
 */
#include <stdio.h>
#include <stdlib.h>
#include "obfuscation.h"
int main(int argc, char **argv) {
 if (argc != 5) return 2;
 uint8_t b[65536]; int n=0; unsigned byte;
 for (const char *p=argv[4]; *p; p+=2) {
  if (n >= 64000 || !p[1] || sscanf(p,"%2x", &byte)!=1) return 2;
  b[n++]=(uint8_t)byte;
 }
 uint8_t version=1;
 if (!strcmp(argv[1],"encode")) n=encode(b,n,argv[2],strlen(argv[2]),1,4,atoi(argv[3]));
 else n=decode(b,n,argv[2],strlen(argv[2]),&version,atoi(argv[3]));
 if (n<0 || n>65536) return 3;
 for(int i=0;i<n;i++) printf("%02x",b[i]);
 puts(""); return 0;
}
