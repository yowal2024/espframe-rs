// SPDX-License-Identifier: GPL-2.0
/* Compiler-generated struct copies in freestanding plugins. */
typedef __SIZE_TYPE__ size_t;
void *memcpy(void *d,const void *s,size_t n)
{ unsigned char *a=d;const unsigned char *b=s;while(n--)*a++=*b++;return d; }
void *memset(void *d,int c,size_t n)
{ unsigned char *a=d;while(n--)*a++=c;return d; }
int memcmp(const void *a,const void *b,size_t n)
{ const unsigned char *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0; }
