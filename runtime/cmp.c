#define _GNU_SOURCE // for non-POSIX RTLD_NEXT
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <fenv.h>
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <execinfo.h>
#include <immintrin.h>
#include <setjmp.h>
#include <execinfo.h>
#include <wchar.h>
#include <pthread.h>
#include <sys/mman.h>

#define TARGET "run_base" // use "run_base" for SPEC
#define JULIET "CWE"      // use "CWE" for Juliet

#define REDZONE_SIZE 16 // bytes
#define REDZONE_JUMP (REDZONE_SIZE/sizeof(float))

#define FAULT_ERROR_CODE  1

#define FLOAT_MODE 1
#define CMP_1_LOOP 0
#define CMP_4_LOOP 0
#define CMP_8_LOOP 0

void * g_null = NULL;
static uint8_t process = 0;

//0x0b8b8b8a
#define FLOAT_MAGIC_ADD ((float)(5.375081e-32))

static inline __attribute__((always_inline)) void fpadd_magic(void *mem) {
    asm volatile (
    "vaddss %0, %1, %%xmm15"
    :
    :"p"(mem), "v"(FLOAT_MAGIC_ADD)
    :"xmm15");
}

static inline __attribute__((always_inline)) void check_poison(void* src, size_t size)
{
    size_t src_b = (size_t)src;

    //Always check leftmost byte (first iteration) and
    //then check every REDZONE_SIZE
    //TODO verify properly that we need REDZONE_SIZE/2 steps
    for(size_t ptr=src_b; ptr<src_b+size; ptr+=REDZONE_SIZE/2) {
#if FLOAT_MODE == 1
        fpadd_magic((char *) ptr);
#elif CMP_1_LOOP == 1
        if(*((unsigned char*)ptr) == 0x8b){
            free(g_null);
        }
#elif CMP_4_LOOP == 1
        if(*((uint32_t*)ptr) == 0x8b8b8b8b){
            free(g_null);
        }
#elif CMP_8_LOOP == 1
        if(*((uint64_t*)ptr) == 0x8b8b8b8b8b8b8b8b){
            free(g_null);
        }
#endif
    }

    //Always check rightmost bytes
#if FLOAT_MODE == 1
        fpadd_magic((char *) (src_b + size - 1));
#elif CMP_1_LOOP == 1
        if(*((unsigned char*)(src_b + size - 1)) == 0x8b){
            free(g_null);
        }
#elif CMP_4_LOOP == 1
        if(*((uint32_t*)(src_b + size - 1)) == 0x8b8b8b8b){
            free(g_null);
        }
#elif CMP_8_LOOP == 1
        if(*((uint64_t*)(src_b + size - 1)) == 0x8b8b8b8b8b8b8b8b){
            free(g_null);
        }
#endif
}

void *cmp_memcpy(void *dest, const void * src, size_t n)
{
    if(process){
        // naive pre-memcpy checks (instead of inter-memcpy)
        if(n != 0){
            check_poison((void*)src, n);
            check_poison(dest, n);
        }
        return memcpy(dest, src, n);
    }
    return memcpy(dest, src, n);
}

void* cmp_memset(void *str, int c, size_t n)
{
    if(process){
        // naive pre-memset checks (instead of inter-memset)
        if(n != 0){
            check_poison(str, n);
        }
        void* res = memset(str, c, n);
        return res;
    }
    return memset(str, c, n);
}

void* cmp_memmove(void *str1, const void *str2, size_t n)
{
    if(process){
        // naive pre-memmove checks (instead of inter-memmove)
        if(n != 0){
            check_poison((void*)str2, n);
            check_poison(str1, n);
        }
        void* res = memmove(str1, str2, n);
        return res;
    }
    return memmove(str1, str2, n);
}

size_t cmp_strlen(const char *s)
{
    if(process){
        size_t size = strlen(s);
        if(size != 0){
            check_poison((void*)s, size);
        }
        return size;
    }
    return strlen(s);
}

size_t cmp_strnlen(const char *s, size_t maxlen)
{
    if(process){
        if(maxlen != 0){
            check_poison((void*)s, maxlen);
        }
        return strnlen(s, maxlen);
    }
    return strnlen(s, maxlen);
}


char* cmp_strcpy(char* dest, const char* src)
{
    if(process){
        return cmp_memcpy(dest, src, strlen(src) + 1);
    }
    return strcpy(dest, src);
}

char* cmp_strcat(char *restrict dest, const char *restrict src) {
    if(process){
        cmp_memcpy(dest + strlen(dest), src, strlen(src) + 1);
        return dest;
    }
    return strcat(dest, src);
}

char* cmp_strncat(char *restrict dest, const char *restrict src, size_t n) {
    if(process){
        char *s = dest;
        dest += strlen(dest);
        size_t ss = strnlen(src, n);
        dest[ss] = '\0';
        cmp_memcpy(dest, src, ss);
        return s;
    }
    return strncat(dest, src, n);
}

char* cmp_strncpy(char *restrict dest, const char *restrict src, size_t n) {
    if(process){
        size_t size = strnlen(src, n);
        if(size != n){
            cmp_memset(dest + size, '\0', n - size);
        }
        return cmp_memcpy(dest, src, size);
    }
    return strncpy(dest, src, n);
}

wchar_t* cmp_wcscpy(wchar_t *dst, const wchar_t *src) {
    if(process){
        return (wchar_t *) cmp_memcpy ((char *) dst, (char *) src, (wcslen(src)+1)*sizeof(wchar_t));
    }
    return wcscpy(dst, src);
}

int cmp_snprintf(char *restrict s, size_t maxlen, const char *restrict format, ...){
    if(process){
        if(maxlen != 0){
            check_poison(s, maxlen);
        }
    }

    // glibc code
    va_list arg;
    int done;
    va_start (arg, format);
    done = vsnprintf(s, maxlen, format, arg);
    va_end (arg);
    return done;
}

//We care only about %s because is the only one causing printf
//to derefernce memory
//TODO we are currently only supporting printf("%s", ...) for
//implementation simplicity
int cmp_printf(const char *restrict format, ...){
    va_list ap;

    if(process){
      if(strstr(format, "%s") != NULL) {
        //Check how many format strings we have
        int c = 0;
        const char *fmt = format;
        while(*fmt != '\0') {
          if(*fmt++ == '%') c++;
        }
        //If we have a single %s, then we instrument
        if(c == 1) {
            va_start(ap, format);
            char *s = va_arg(ap, char*);
            size_t len = strlen(s);
            if(len != 0){
                check_poison(s, len);
            }
            va_end(ap);
        }
      }
    }

    //Do original printf
    int done;
    va_start(ap, format);
    done = vfprintf(stdout, format, ap);
    va_end(ap);
    return done;
}

int cmp_puts(const char *str){
    if(process){
        size_t len = strlen(str);
        if(len != 0){
            check_poison((void*)str, len);
        }
    }
    return puts(str);
}

void __attribute__((destructor)) exit_unload()
{
    if(process){
        // clean up
    }
}

typedef int (*main_t)(int, char, char);
typedef int (*libc_start_main_t)(main_t main, int argc, char** ubp_av,
        void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void* stack_end);
int __libc_start_main(main_t main, int argc, char** ubp_av,
        void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void* stack_end)
{
    libc_start_main_t og_libc_start_main = (libc_start_main_t)dlsym(RTLD_NEXT, "__libc_start_main");

     // resolve malloc_usable_size early to avoid xsave register spill
     malloc_usable_size(NULL);

    if(strstr(ubp_av[0], TARGET) || strstr(ubp_av[0], JULIET)){
        process = 1;
    }

    return og_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

