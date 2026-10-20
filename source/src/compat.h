#ifndef JIPSTATS_COMPAT_H
#define JIPSTATS_COMPAT_H
#include <features.h>
#include <sys/stat.h>
#if defined(__x86_64__) && defined(__GLIBC__)
__asm__(".symver dlsym,dlsym@GLIBC_2.2.5");
__asm__(".symver dladdr,dladdr@GLIBC_2.2.5");
/* Build-host glibc redirects C23 integer parsers. We use no C23-only syntax. */
__asm__(".symver __isoc23_sscanf,__isoc99_sscanf@GLIBC_2.7");
__asm__(".symver __isoc23_strtol,strtol@GLIBC_2.2.5");
__asm__(".symver __isoc23_strtoull,strtoull@GLIBC_2.2.5");
extern int __xstat(int,const char*,struct stat*);
extern int __fxstat(int,int,struct stat*);
static inline int js_compat_stat(const char *p,struct stat *s){return __xstat(1,p,s);}
static inline int js_compat_fstat(int fd,struct stat*s){return __fxstat(1,fd,s);}
#define stat(p,s) js_compat_stat((p),(s))
#define fstat(fd,s) js_compat_fstat((fd),(s))
#endif
#endif
