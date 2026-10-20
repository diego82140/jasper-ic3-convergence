/* The producer's vendor archive may call the post-2.33 stat64 entrypoint.
 * x86-64's legacy version-1 ABI has the same layout and works on glibc 2.17.
 * --wrap=stat64 redirects archive references, independent of its build host.
 */
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <sys/stat.h>
extern int __xstat64 (int, const char *, struct stat64 *);
int __wrap_stat64 (const char *path, struct stat64 *result)
{
  return __xstat64 (1, path, result);
}
