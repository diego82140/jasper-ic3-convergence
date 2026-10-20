/* Preserve this extension for the selected Jasper installation only.
 * Some supplied Jasper wrapper scripts unset LD_PRELOAD for library isolation.
 * The extension itself targets glibc 2.17 and is restored at execve, without
 * editing the wrapper or restoring arbitrary third-party preloads it removed.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int (*next_execve)(const char *,char *const[],char *const[]);
static char library_path[PATH_MAX];
static char *root;
static const char *keys[]={"JIPSTATS_ROOT","JIPSTATS_IMAGE","JIPSTATS_PROFILE","JIPSTATS_QUERIES","JIPSTATS_DIAGNOSTICS","JIPSTATS_EVIDENCE_DIR","JIPSTATS_SINK","JIPSTATS_CAPTURE_MODE","JIPSTATS_MAX_RECORDS","JIPSTATS_CUBES","JIPSTATS_COMPRESSION"};
static char *settings[11];

__attribute__((constructor)) static void launch_init(void){
 void *p=dlsym(RTLD_NEXT,"execve");memcpy(&next_execve,&p,sizeof p);
 const char *r=getenv("JIPSTATS_ROOT");
 if(!r || *r!='/')return;
 Dl_info info;
 if(!dladdr((void*)&launch_init,&info)||!info.dli_fname||!realpath(info.dli_fname,library_path))return;
 root=strdup(r);if(!root){library_path[0]=0;return;}
 for(unsigned i=0;i<11;i++){
  const char *value=getenv(keys[i]);
  if(value && asprintf(&settings[i],"%s=%s",keys[i],value)<0)settings[i]=NULL;
 }
}
static int in_installation(const char *p){
 size_t n=root?strlen(root):0;
 return n && p && !strncmp(root,p,n) && (p[n]=='/'||p[n]==0);
}
static int equal_key(const char *entry,const char *key){
 size_t n=strlen(key);return !strncmp(entry,key,n)&&entry[n]=='=';
}
__attribute__((visibility("default")))
int execve(const char *path,char *const argv[],char *const envp[]){
 if(!next_execve){void*p=dlsym(RTLD_NEXT,"execve");memcpy(&next_execve,&p,sizeof p);}
 if(!next_execve){errno=ENOSYS;return -1;}
 if(!root||!library_path[0])return next_execve(path,argv,envp);
 int target=in_installation(path);
 for(unsigned i=0;!target && i<128 && argv[i];i++)target=in_installation(argv[i]);
 if(!target)return next_execve(path,argv,envp);

 /* All allocation happened at load time; exec path uses bounded stack storage. */
 char *replacement[4096];unsigned count=0;unsigned seen=0;
 const char *preload=NULL;
 for(unsigned i=0;envp && envp[i];i++){
  if(i>=4080)return next_execve(path,argv,envp);
  if(equal_key(envp[i],"LD_PRELOAD")){preload=envp[i]+11;continue;}
  for(unsigned j=0;j<11;j++)if(equal_key(envp[i],keys[j]))seen|=1u<<j;
  replacement[count++]=envp[i];
 }
 for(unsigned j=0;j<11;j++)if(!(seen&(1u<<j)) && settings[j])replacement[count++]=settings[j];
 char preload_value[16384];int n;
 if(preload && strstr(preload,library_path))n=snprintf(preload_value,sizeof preload_value,"LD_PRELOAD=%s",preload);
 else n=snprintf(preload_value,sizeof preload_value,"LD_PRELOAD=%s%s%s",library_path,preload&&*preload?":":"",preload?preload:"");
 if(n<0||(size_t)n>=sizeof preload_value){errno=E2BIG;return -1;}
 replacement[count++]=preload_value;replacement[count]=NULL;
 return next_execve(path,argv,replacement);
}
