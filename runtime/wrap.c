/*
FloatZone runtime wrapper. Used to perform the following tasks:
 - Add SIGFPE handler
 - Handle SIGFPE to confirm the presence of memory violations
 - Manage redzone insertion/deletion for heap + Quarantine
 - Intercept libc functions (e.g. memcpy, memset, etc.) to perform the
   sanitzer checks 

TODO we do not intercept all libc functions, but we cover the most important:
 - memcmp
 - memcpy
 - memmove
 - memset
 - printf (partially supported)
 - puts
 - snprintf
 - strcat
 - strcmp
 - strcpy
 - strlen
 - strncat
 - strncmp
 - strncpy
 - strnlen
 - wcscpy
*/


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
#include "xed-interface.h"

#define TARGET "run_base" // use "run_base" for SPEC
#define JULIET "CWE"      // use "CWE" for Juliet

#define REDZONE_SIZE 16 // bytes
#define REDZONE_JUMP (REDZONE_SIZE/sizeof(float))

#define FAULT_ERROR_CODE  1

#define FLOAT_MAGIC_POISON_PRE        (0x8b8b8b89U)
#define FLOAT_MAGIC_POISON_PRE_BYTE   (0x89U)
#define FLOAT_MAGIC_POISON            (0x8b8b8b8bU)
#define FLOAT_MAGIC_POISON_BYTE       (0x8bU)
//0x0b8b8b8a
#define FLOAT_MAGIC_ADD             ((float)(5.375081e-32))

// MODE: count exceptions handled
#define COUNT_EXCEPTIONS 0
// MODE: enable float underflow exceptions
#define ENABLE_EXCEPTIONS 1
// MODE: allow surviving exceptions (recover)
#define SURVIVE_EXCEPTIONS 0
// MODE: heap quarantine
#define ENABLE_QUARANTINE 1
// MODE: catch segmentation faults (Juliet)
#define CATCH_SEGFAULT 0
// MODE: AFL++ requires abort() for bugs
#define FUZZ_MODE 1
#define QUARANTINE_SIZE_BYTES 268435456 // 256 MB
// quarantine max bytes / min. size of alloc == upper bound
#define MIN_ALLOC_SIZE 40

static uint8_t process = 0;

struct redzone {
  char vals[16];
} redzone_s = {{ 0x89, 0x8b, 0x8b, 0x8b,
  0x8b, 0x8b, 0x8b, 0x8b,
  0x8b, 0x8b, 0x8b, 0x8b,
  0x8b, 0x8b, 0x8b, 0x8b}};


#if COUNT_EXCEPTIONS == 1
static uint32_t except_cnt_vaddss_skip = 0; // FP from vaddss but no redzone
static uint32_t except_cnt_vaddss_rz = 0; // FP from vaddss and looks like redzone
static uint32_t except_cnt_underflow = 0; // generic underflow
extern const char *__progname;
#endif

// stack redzones (exceptions/longjmps)
uintptr_t g_stored_sp = 0;

// glibc symbols
void* __libc_malloc(size_t size);
void* __libc_calloc(size_t nmemb, size_t size);
void* __libc_realloc(void* ptr, size_t size);
void* __libc_free(void* ptr);


// quarantine
#if ENABLE_QUARANTINE == 1
typedef struct Ring Ring;
struct Ring {
  void* ptr;
  size_t size;
};

#define MAX_RING_ELEMS (QUARANTINE_SIZE_BYTES/MIN_ALLOC_SIZE)
Ring ring[MAX_RING_ELEMS];
// 5000 elements -> 256 MB allocated memory -> start clearing
size_t front = 0;
size_t rear = 0;
uint64_t quarantine_size = 0; // in bytes
pthread_mutex_t ring_lock;

void append_to_list(void *ptr, size_t size)
{
  // enqueue
  pthread_mutex_lock(&ring_lock);
  ring[rear].ptr = ptr;
  ring[rear].size = size;
  rear = rear + 1;
  if(rear == MAX_RING_ELEMS) rear = 0;
  // apply the poison (the first REDZONE_SIZE bytes (underflow) can be skipped)
  // the last 15 bytes are also guaranteed to be 0x8b
  // update quarantine size
  quarantine_size += size;
  pthread_mutex_unlock(&ring_lock);

  memset(((uint8_t*)ptr)+REDZONE_SIZE, FLOAT_MAGIC_POISON_BYTE, size-REDZONE_SIZE-(REDZONE_SIZE-1));
}

void pop_last_from_list()
{
  void *ptr_to_clean;
  size_t size_to_clean;

  pthread_mutex_lock(&ring_lock);
  // dequeue
  if(front != rear){
    ptr_to_clean = ring[front].ptr;
    size_to_clean = ring[front].size;
    quarantine_size -= ring[front].size;

    front = (front + 1);
    if(front == MAX_RING_ELEMS) front = 0;

    pthread_mutex_unlock(&ring_lock);

    memset(ptr_to_clean, 0, size_to_clean);
    __libc_free(ptr_to_clean);
  }
  else{
    // empty: set to zero
    quarantine_size = 0;
    pthread_mutex_unlock(&ring_lock);
  }
}

void add_to_quarantine(void* ptr, size_t size)
{
  append_to_list(ptr, size);

  //TODO: lock to read quarantine_size?
  while(quarantine_size > QUARANTINE_SIZE_BYTES){
    pop_last_from_list();
  }
}
#endif

//Override signal handling function to avoid that our SIGFPE handler get replaced
void handler(int sig, siginfo_t* si, void* vcontext); // declare
typedef sighandler_t (*proto_signal)(int signum, sighandler_t handler);
proto_signal __signal;
typedef int (*proto_sigaction)(int signum, const struct sigaction *act, struct sigaction *oldact);
proto_sigaction ___sigaction;
typedef sighandler_t (*proto_sysv_signal)(int signum, sighandler_t handler);
proto_sysv_signal ___sysv_signal;

sighandler_t signal(int signum, sighandler_t hndlr) {
    if(process){
        if(signum == SIGFPE){
            // return without registering
            return 0;
        }
    }
    return __signal(signum, hndlr);
}

// 600.perlbench calls __sysv_signal with signum==SIGFPE (depending on glibc)
sighandler_t __sysv_signal(int signum, sighandler_t hndlr) {
    if(process){
        if(signum == SIGFPE){
            // return without registering
            return 0;
        }
    }
    return ___sysv_signal(signum, hndlr);
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    if(process){
        if(signum == SIGFPE){
            if(act != NULL && act->sa_sigaction != &handler){
                // return without registering
                return 0;
            }
        }
    }
    return ___sigaction(signum, act, oldact);
}


// longjmp override
typedef void (*proto_longjmp)(jmp_buf env, int val);
typedef void (*proto_siglongjmp)(sigjmp_buf env, int val);
proto_longjmp __longjmp;
proto_siglongjmp __siglongjmp;

void __attribute__((noreturn)) longjmp(jmp_buf env, int val)
{
    if(process){
        // store sp in g_stored_sp before jmp
        asm volatile("movq %%rsp, %0\n" : "=r"(g_stored_sp));
    }
    __longjmp(env, val);
    exit(-1);
}

void __attribute__((noreturn)) siglongjmp(sigjmp_buf env, int val)
{
    if(process){
        // store sp in g_stored_sp before jmp
        asm volatile("movq %%rsp, %0\n" : "=r"(g_stored_sp));
    }
    __siglongjmp(env, val);
    exit(-1);
}

// exceptions override
typedef void (*proto_cxa_throw)(void *, void *, void (*) (void *));
proto_cxa_throw __og_cxa_throw;

void __cxa_throw (void *thrown_exception, void *pvtinfo, void (*dest)(void *))
{
    if(process){
        // store sp in g_stored_sp before throw exception
        asm volatile("movq %%rsp, %0\n" : "=r"(g_stored_sp));
    }
    __og_cxa_throw(thrown_exception, pvtinfo, dest);
}

// current_sp = sp before call
// we do sp-8 to make sure the return address of clear_stack_on_jump remains intact
void __attribute__ ((noinline, disable_sanitizer_instrumentation)) clear_stack_on_jump(unsigned long current_sp)
{
    memset((void*)g_stored_sp, 0, current_sp-g_stored_sp-8);
}

static inline __attribute__((always_inline)) void fpadd_magic(void *mem) {
    asm volatile (
    "vaddss %0, %1, %%xmm15"
    :
    :"p"(mem), "v"(FLOAT_MAGIC_ADD)
    :"xmm15");
}

static inline __attribute__((always_inline)) void apply_poison(void* ptr, size_t size)
{
    void* poison = (void*) (((uint8_t *)ptr) + size);
    *((struct redzone*)poison) = redzone_s;
}

// FloatZone double-sided redzones on heap
static inline __attribute__((always_inline)) void apply_poison_underflow(void* ptr)
{
    *((struct redzone*)ptr) = redzone_s;
}

static inline __attribute__((always_inline)) void apply_poison_overflow_delta(void* ptr, size_t offset, size_t delta)
{
    void* poison = (void*) (((uint8_t *)ptr) + offset);
    *((struct redzone*)poison) = redzone_s;
    memset(poison+REDZONE_SIZE, 0x8b, delta);
}

static inline __attribute__((always_inline)) void remove_poison_scan(void* ptr) 
{
    // assume ptr is already shifted back to the original start of the obj
    size_t sz = malloc_usable_size(ptr);

    // clear underflow redzone
    memset(ptr, 0, REDZONE_SIZE);

    // find the start of the overflow redzone
    uint8_t* b = ((uint8_t*)ptr) + sz;
    size_t i;
    for(i = REDZONE_SIZE; i < sz; i++){
        if(*(b-i) != 0x8b){
            break;
        }
    }
    // here *b-i == 0x89. clear overflow redzone
    memset(b-i, 0, i);
}

// check_poison externally visible
void __attribute__ ((noinline)) check_poison_visible(void* src, size_t size)
{
    // these calls do not check the size as pre-condition
    if(size == 0) return;

    size_t src_b = (size_t)src;

    for(size_t ptr=src_b; ptr<src_b+size; ptr+=REDZONE_SIZE/2) {
        fpadd_magic((char *) ptr);
    }

    //Always check rightmost 4 bytes
    fpadd_magic((char *) (src_b + size - 1));
}

static inline __attribute__((always_inline)) void check_poison(void* src, size_t size)
{
    size_t src_b = (size_t)src;

    //Always check leftmost byte (first iteration) and
    //then check every REDZONE_SIZE
    //TODO verify properly that we need REDZONE_SIZE/2 steps
    for(size_t ptr=src_b; ptr<src_b+size; ptr+=REDZONE_SIZE/2) {
        fpadd_magic((char *) ptr);
    }

    //Always check rightmost 4 bytes
    fpadd_magic((char *) (src_b + size - 1));
}

void* malloc(size_t size)
{
    if(process){
        if(size == 0) return NULL;

        size_t padded_size = REDZONE_SIZE + size + REDZONE_SIZE;
        uint8_t* ptr = __libc_malloc(padded_size);
        if(ptr == NULL) return NULL;

        apply_poison_underflow(ptr);
        size_t allocated_size = malloc_usable_size(ptr);

        ptr = ptr + REDZONE_SIZE; // shift by underflow redzone
        apply_poison_overflow_delta(ptr, size, allocated_size-padded_size);

        return (void *)ptr;
    }
    return __libc_malloc(size);
}

void* calloc(size_t nmemb, size_t size)
{
    if(process){
        // easier to pad calloc by relying on malloc
        size_t total_size = nmemb * size;

        size_t padded_size = REDZONE_SIZE + total_size + REDZONE_SIZE;
        uint8_t* ptr = __libc_malloc(padded_size);
        if(ptr == NULL) return NULL;

        apply_poison_underflow(ptr);
        size_t allocated_size = malloc_usable_size(ptr);

        ptr = ptr + REDZONE_SIZE; // shift by underflow redzone
        memset(ptr, 0, total_size); // zero out (calloc)
        apply_poison_overflow_delta(ptr, total_size, allocated_size-padded_size);

        return (void *)ptr;
    }
    return __libc_calloc(nmemb, size);
}

void* realloc(void *ptr, size_t size)
{
    if(process){
        if(ptr == NULL){
            return malloc(size);
        }

        if(size == 0){
            free(ptr);
            return NULL;
        }

        // recover original address
        ptr = ptr - REDZONE_SIZE;

        // make sure the old redzone does not get copied to the new object
        remove_poison_scan(ptr);

        size_t padded_size = REDZONE_SIZE + size + REDZONE_SIZE;
        void* reptr = __libc_realloc(ptr, padded_size);
        if(reptr == NULL) return NULL;

        apply_poison_underflow(reptr);
        size_t allocated_size = malloc_usable_size(reptr);

        reptr = reptr + REDZONE_SIZE; // shift by underflow redzone
        apply_poison_overflow_delta(reptr, size, allocated_size-padded_size);

        return reptr;
    }
    return __libc_realloc(ptr, size);
}

void free(void* ptr)
{
    if(process){
        if(ptr == NULL) return;

        // double free check
        fpadd_magic(ptr);

        // recover original address
        ptr = ptr - REDZONE_SIZE;

#if ENABLE_QUARANTINE == 1
        size_t sz = malloc_usable_size(ptr);
        add_to_quarantine(ptr, sz);
#else
        remove_poison_scan(ptr);
        __libc_free(ptr);
#endif
        return;
    }
    __libc_free(ptr);
}

typedef int (*proto_posix_memalign)(void **memptr, size_t alignment, size_t size);
proto_posix_memalign __posix_memalign;

int __attribute__((disable_sanitizer_instrumentation)) posix_memalign(void **memptr, size_t alignment, size_t size)
{
    if(process){
		    *memptr = malloc(size);
		    if(*memptr != NULL) return 0;
		    return 12; // ENOMEM
	  }
	  return __posix_memalign(memptr, alignment, size);
}

void __attribute__((disable_sanitizer_instrumentation)) *floatzone_memcpy(void *dest, const void * src, size_t n)
{
    if(process){
        // naive pre-memcpy checks (instead of inter-memcpy)
        if(n != 0){
            check_poison((void*)src, n);
            check_poison(dest, n);
        }
    }
    return memcpy(dest, src, n);
}

void* __attribute__((disable_sanitizer_instrumentation)) floatzone_memset(void *str, int c, size_t n)
{
    if(process){
        // naive pre-memset checks (instead of inter-memset)
        if(n != 0){
            check_poison(str, n);
        }
    }
    return memset(str, c, n);
}

void* __attribute__((disable_sanitizer_instrumentation)) floatzone_memmove(void *str1, const void *str2, size_t n)
{
    if(process){
        // naive pre-memmove checks (instead of inter-memmove)
        if(n != 0){
            check_poison((void*)str2, n);
            check_poison(str1, n);
        }
    }
    return memmove(str1, str2, n);
}

int __attribute__((disable_sanitizer_instrumentation)) floatzone_strcmp(const char *s1, const char *s2)
{
    if(process){
        // ASan code
        unsigned char c1, c2;
        size_t i;
        for (i = 0;; i++) {
            c1 = (unsigned char)s1[i];
            c2 = (unsigned char)s2[i];
            if (c1 != c2 || c1 == '\0') break;
        }
        if(i != 0){
            check_poison((void*)s1, i);
            check_poison((void*)s2, i);
        }
    }
    return strcmp(s1, s2);
}

int __attribute__((disable_sanitizer_instrumentation)) floatzone_strncmp(const char *s1, const char *s2, size_t n)
{
    if(process){
        // ASan code
        unsigned char c1, c2;
        size_t i;
        for (i = 0; i < n; i++) {
            c1 = (unsigned char)s1[i];
            c2 = (unsigned char)s2[i];
            if (c1 != c2 || c1 == '\0') break;
        }
        size_t min = n;
        if(i+1 < n) min = i+1;
        if(n != 0){
            check_poison((void*)s1, min);
            check_poison((void*)s2, min);
        }
    }
    return strncmp(s1, s2, n);
}

int __attribute__((disable_sanitizer_instrumentation)) floatzone_memcmp(const void *s1, const void *s2, size_t n)
{
    if(process){
        if(n != 0){
            check_poison((void*)s1, n);
            check_poison((void*)s2, n);
        }
    }
    return memcmp(s1, s2, n);
}

size_t __attribute__((disable_sanitizer_instrumentation)) floatzone_strlen(const char *s)
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

size_t __attribute__((disable_sanitizer_instrumentation)) floatzone_strnlen(const char *s, size_t maxlen)
{
    if(process){
        if(maxlen != 0){
            check_poison((void*)s, maxlen);
        }
        return strnlen(s, maxlen);
    }
    return strnlen(s, maxlen);
}

char* __attribute__((disable_sanitizer_instrumentation)) floatzone_strcpy(char* dest, const char* src)
{
    if(process){
        return floatzone_memcpy(dest, src, strlen(src) + 1);
    }
    return strcpy(dest, src);
}

char* __attribute__((disable_sanitizer_instrumentation)) floatzone_strcat(char *restrict dest, const char *restrict src) {
    if(process){
        floatzone_memcpy(dest + strlen(dest), src, strlen(src) + 1);
        return dest;
    }
    return strcat(dest, src);
}

char* __attribute__((disable_sanitizer_instrumentation)) floatzone_strncat(char *restrict dest, const char *restrict src, size_t n) {
    if(process){
        char *s = dest;
        dest += strlen(dest);
        size_t ss = strnlen(src, n);
        dest[ss] = '\0';
        floatzone_memcpy(dest, src, ss);
        return s;
    }
    return strncat(dest, src, n);
}

char* __attribute__((disable_sanitizer_instrumentation)) floatzone_strncpy(char *restrict dest, const char *restrict src, size_t n) {
    if(process){
        size_t size = strnlen(src, n);
        if(size != n){
            floatzone_memset(dest + size, '\0', n - size);
        }
        return floatzone_memcpy(dest, src, size);
    }
    return strncpy(dest, src, n);
}

wchar_t* __attribute__((disable_sanitizer_instrumentation)) floatzone_wcscpy(wchar_t *dst, const wchar_t *src) {
    if(process){
        return (wchar_t *) floatzone_memcpy ((char *) dst, (char *) src, (wcslen(src)+1)*sizeof(wchar_t));
    }
    return wcscpy(dst, src);
}

int __attribute__((disable_sanitizer_instrumentation)) floatzone_snprintf(char *restrict s, size_t maxlen, const char *restrict format, ...){
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
int __attribute__((disable_sanitizer_instrumentation)) floatzone_printf(const char *restrict format, ...){
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

int __attribute__((disable_sanitizer_instrumentation)) floatzone_puts(const char *str){
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
#if COUNT_EXCEPTIONS == 1
        process = 0;
        FILE* fp = fopen("/tmp/floatexception.txt", "a");
        fprintf(fp, "%s\t%u\t%u\t%u\n", __progname, except_cnt_vaddss_skip, except_cnt_underflow, except_cnt_vaddss_rz);
        process = 1;
#endif
    }
}

#define     RAX     0
#define     RCX     1
#define     RDX     2
#define     RBX     3
#define     RSP     4
#define     RBP     5
#define     RSI     6
#define     RDI     7
#define     R8      8
#define     R9      9
#define     R10     10
#define     R11     11
#define     R12     12
#define     R13     13
#define     R14     14
#define     R15     15
#define     RNONE   16

const int regs_map[16] = {
    /* RAX = 0  */[RAX] = REG_RAX,
    /* RCX = 1  */[RCX] = REG_RCX,
    /* RDX = 2  */[RDX] = REG_RDX,
    /* RBX = 3  */[RBX] = REG_RBX,
    /* RSP = 4  */[RSP] = REG_RSP,
    /* RBP = 5  */[RBP] = REG_RBP,
    /* RSI = 6  */[RSI] = REG_RSI,
    /* RDI = 7  */[RDI] = REG_RDI,
    /* R8  = 8  */[R8 ] = REG_R8,
    /* R9  = 9  */[R9 ] = REG_R9,
    /* R10 = 10 */[R10] = REG_R10,
    /* R11 = 11 */[R11] = REG_R11,
    /* R12 = 12 */[R12] = REG_R12,
    /* R13 = 13 */[R13] = REG_R13,
    /* R14 = 14 */[R14] = REG_R14,
    /* R15 = 15 */[R15] = REG_R15
};

//Row: mod
//Column rm
//Element: reg, SIB, offset size
#define     NOTSUPP    {-1U, -1U, -1U}
const uint32_t lut_modrm[4][16][3] =
{
    {//Mod 00
        {RAX, 0, 0}, {RCX, 0, 0}, {RDX, 0, 0}, {RBX, 0, 0}, {RSP, 1, 0}, NOTSUPP,    {RSI, 0, 0}, {RDI, 0, 0}, {R8, 0, 0}, {R9, 0, 0}, {R10, 0, 0}, {R11, 0, 0}, {R12, 1, 0}, NOTSUPP,   {R14, 0, 0}, {R15, 0, 0},
    },

    {//Mod 01
        {RAX, 0, 1}, {RCX, 0, 1}, {RDX, 0, 1}, {RBX, 0, 1}, {RSP, 1, 1}, {RBP, 0, 1}, {RSI, 0, 1}, {RDI, 0, 1}, {R8, 0, 1}, {R9, 0, 1}, {R10, 0, 1}, {R11, 0, 1}, {R12, 1, 1}, {R13, 0, 1}, {R14, 0, 1}, {R15, 0, 1},
    },

    {//Mod 10
        {RAX, 0, 4}, {RCX, 0, 4}, {RDX, 0, 4}, {RBX, 0, 4}, {RSP, 1, 4}, {RBP, 0, 4}, {RSI, 0, 4}, {RDI, 0, 4}, {R8, 0, 4}, {R9, 0, 4}, {R10, 0, 4}, {R11, 0, 4}, {R12, 1, 4}, {R13, 0, 4}, {R14, 0, 4}, {R15, 0, 4},
    },

    {//Mod 11
        NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,     NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,    NOTSUPP,
    },
};

const int scales[4] = {1,2,4,8};

/*  get_fault_addr: decode FP instruction and return faulting memory address.
    e.g. vadds xmm0, xmm1, [rax+rbx*4+1234] -> rax+rbx*4+1234
Arguments:
- op:       input,  pointer to start of faulting FP instruction
- op_len:   output, pointer to return the length of the opcode
- uc:       input,  struct containing the regs saved during exception
Return:
- Pointer to fualting address
- NULL in case of error, (op_len is set to 0)

Note: When I wrote this code only God and I understood what it did,
Now only God knows.
 */
void* get_fault_addr(uint8_t *op, int *op_len, ucontext_t *uc)
{
    uint32_t rex_x, rex_r, rex_b, modrm, mod, reg, rm, scale, index, base, sib, pos;
    int32_t offset;
    uint8_t *ptr;

    //Verify VEX instruction
    if (op[0] != 0xc5 && op[0] != 0xc4) goto get_fault_addr_error;

    base  = 0;
    index = 0;
    scale = 0;
    offset = 0;

    // vex 2 bytes
    if (op[0] == 0xc5) {
        if(op[2] != 0x58) goto get_fault_addr_error;
        rex_r = 1^((op[1]>>7)&1);
        rex_x = 0;
        rex_b = 0;
        pos = 3;    //point to modrm
    }

    // rex 3 bytes
    if (op[0] == 0xc4) {
        if(op[3] != 0x58) goto get_fault_addr_error;
        rex_r = 1^((op[1]>>7)&1);
        rex_x = 1^((op[1]>>6)&1);
        rex_b = 1^((op[1]>>5)&1);
        pos = 4;    //point to modrm
    }

    //mod/rm decode
    modrm = op[pos];
    mod = (modrm>>6)&0x3;
    reg = (rex_r<<3) | ((modrm>>3)&0x7);
    rm  = (rex_b<<3) | (modrm&0x7);
    base = rm;
    pos++;

    //Check for supported mod/rm
    if (lut_modrm[mod][rm][0] == -1U) goto get_fault_addr_error;

    //If SIB
    if(lut_modrm[mod][rm][1]) {
        sib = op[pos];
        scale = scales[(sib>>6) & 0x3];
        index = (rex_x<<3) | ((sib>>3)&0x7);
        base  = (rex_b<<3) | ((sib>>0)&0x7);
        //cursed SIB encoding
        if(mod != 0){
            if (index == RSP) index = RNONE;
        } else {
            if((index == RSP) && (base == RBP || base == R13)) goto get_fault_addr_error;
            if (index == RSP) index = RNONE;
            if (base == RBP || base == R13) {
                base = RNONE;
            }
        }
        pos++;
    }

    //Offset
    if(lut_modrm[mod][rm][2] == 1) {
        offset = (int8_t)op[pos];
        pos++;
    }
    if(lut_modrm[mod][rm][2] == 4) {
        offset = (int32_t)(((op[pos+0]&0xff) << 0) |
                ((op[pos+1]&0xff) << 8) |
                ((op[pos+2]&0xff) << 16) |
                ((op[pos+3]&0xff) << 24));
        pos += 4;
    }

get_fault_addr_success:
    ptr = NULL;
    *op_len = pos;
    if (base != RNONE) ptr += uc->uc_mcontext.gregs[regs_map[base]];
    if (index != RNONE) ptr += uc->uc_mcontext.gregs[regs_map[index]]*scale;
    ptr += offset;
    return (void *) ptr;

get_fault_addr_error:
    *op_len = 0;
    return NULL;
}

void dump(ucontext_t* uc) {
    printf("--------------------\n");
    for(int i=0; i<16; i++) {
        for(int j=0; j<4; j++) {
            printf("%08x ", uc->uc_mcontext.fpregs->_xmm[i].element[j]);
        }
        printf("\n");
    }
}

//push   rax
//push   rbx
//push   rcx
//push   rdx
//push   rdi
//push   rsi
//push   rbp
//push   r8
//push   r9
//push   r10
//push   r11
//push   r12
//push   r13
//push   r14
//push   r15
//movabs rax,0x1111111111111111
//movabs rbx,0x2222222222222222
//movabs rcx,0x3333333333333333
//movabs rdx,0x4444444444444444
//movabs rdi,0x5555555555555555
//movabs rsi,0x6666666666666666
//movabs rbp,0x7777777777777777
//movabs r8,0x8888888888888888
//movabs r9,0x9999999999999999
//movabs r10,0xaaaaaaaaaaaaaaaa
//movabs r11,0xbbbbbbbbbbbbbbbb
//movabs r12,0xcccccccccccccccc
//movabs r13,0xdddddddddddddddd
//movabs r14,0xeeeeeeeeeeeeeeee
//movabs r15,0xfefefefefefefefe
const uint8_t prolog[] = {
    0x50, 0x53, 0x51, 0x52, 0x57, 0x56, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41,
    0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
    0xb8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x48, 0xbb, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x48, 0xb9, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x48, 0xba, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x48, 0xbf, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x48, 0xbe, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x48,
    0xbd, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x49, 0xb8, 0x88,
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x49, 0xb9, 0x99, 0x99, 0x99,
    0x99, 0x99, 0x99, 0x99, 0x99, 0x49, 0xba, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0x49, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0x49, 0xbc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x49,
    0xbd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0x49, 0xbe, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0x49, 0xbf, 0xfe, 0xfe, 0xfe,
    0xfe, 0xfe, 0xfe, 0xfe, 0xfe
};


//pop    r15
//pop    r14
//pop    r13
//pop    r12
//pop    r11
//pop    r10
//pop    r9
//pop    r8
//pop    rbp
//pop    rsi
//pop    rdi
//pop    rdx
//pop    rcx
//pop    rbx
//pop    rax
//ret
const uint8_t epilog[] = {
    0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x41, 0x5b, 0x41, 0x5a,
    0x41, 0x59, 0x41, 0x58, 0x5d, 0x5e, 0x5f, 0x5a, 0x59, 0x5b, 0x58, 0xc3
};

/*
This is a terrible piece of code, but there are no other way around (I guess).
This code disassemble the instruction present at `op` and returns its opcode
length. This is needed since we need to skip the faulting SIGFPE instruction.
To ensure we do not affect original execution, we re-execute the faulting
instruction in an environment without FTZ enabled. This achieved with a
terrible trick of doing some sort of JIT'ing.
*/
int get_ins_len_and_re_execute(uint8_t *op, ucontext_t *uc) {
    static uint8_t *rwx;
    static int first_time = 1;
    xed_state_t dstate;
    xed_decoded_inst_t xedd;
    const xed_inst_t* xi;
    int noperands;
    const xed_operand_t* operand;
    xed_operand_enum_t opname;
    xed_reg_enum_t reg;
    int op_len;
    void (*fptr)(void);

    static void (*xed_tables_init)(void);
    static void (*xed_decoded_inst_zero_set_mode)(xed_decoded_inst_t* p, const xed_state_t* dstate);
    static xed_error_enum_t (*xed_decode)(xed_decoded_inst_t* xedd, const xed_uint8_t* itext, const unsigned int bytes);
    static const xed_operand_t* (*xed_inst_operand)(const xed_inst_t *p, unsigned int i);
    static xed_reg_enum_t (*xed_decoded_inst_get_reg)(const xed_decoded_inst_t *p, xed_operand_enum_t reg_operand);
    static xed_uint_t (*xed_operand_written)(const xed_operand_t *p);
    void *handle;

    if(first_time) {
        handle = dlopen(LIBXED_SO, RTLD_LAZY);
        if(!handle) {
            printf("Can't open libxed.so\n");
            exit(-1);
        }
        dlerror();
        xed_tables_init = dlsym(handle, "xed_tables_init");
        if(dlerror() != NULL) exit(-37);
        xed_decoded_inst_zero_set_mode = dlsym(handle, "xed_decoded_inst_zero_set_mode");
        if(dlerror() != NULL) exit(-37);
        xed_decode = dlsym(handle, "xed_decode");
        if(dlerror() != NULL) exit(-37);
        xed_inst_operand = dlsym(handle, "xed_inst_operand");
        if(dlerror() != NULL) exit(-37);
        xed_decoded_inst_get_reg = dlsym(handle, "xed_decoded_inst_get_reg");
        if(dlerror() != NULL) exit(-37);
        xed_operand_written = dlsym(handle, "xed_operand_written");
        if(dlerror() != NULL) exit(-37);

        xed_tables_init();
        first_time = 0;
        rwx = (uint8_t *) mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    }

    //Get instruction length
    dstate.mmode=XED_MACHINE_MODE_LONG_64;
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    xed_decode(&xedd, op, XED_MAX_INSTRUCTION_BYTES);
    xi = xed_decoded_inst_inst(&xedd);
    op_len = xed_decoded_inst_get_length(&xedd);


    //Copy the assembly wrapper to re-execute the faulty instr
    fptr = (void(*)(void))rwx;
    memcpy(rwx, prolog, sizeof(prolog));
    memcpy(rwx+sizeof(prolog), op, op_len);
    memcpy(rwx+sizeof(prolog)+op_len, epilog, sizeof(epilog));

    //Patch the opcodes to restore the original registers
    memcpy(&rwx[0x17+ 0+2] ,  &uc->uc_mcontext.gregs[REG_RAX], 8);
    memcpy(&rwx[0x17+10+2] ,  &uc->uc_mcontext.gregs[REG_RBX], 8);
    memcpy(&rwx[0x17+20+2] ,  &uc->uc_mcontext.gregs[REG_RCX], 8);
    memcpy(&rwx[0x17+30+2] ,  &uc->uc_mcontext.gregs[REG_RDX], 8);
    memcpy(&rwx[0x17+40+2] ,  &uc->uc_mcontext.gregs[REG_RDI], 8);
    memcpy(&rwx[0x17+50+2] ,  &uc->uc_mcontext.gregs[REG_RSI], 8);
    memcpy(&rwx[0x17+60+2] ,  &uc->uc_mcontext.gregs[REG_RBP], 8);
    memcpy(&rwx[0x17+70+2] ,  &uc->uc_mcontext.gregs[REG_R8 ], 8);
    memcpy(&rwx[0x17+80+2] ,  &uc->uc_mcontext.gregs[REG_R9 ], 8);
    memcpy(&rwx[0x17+90+2] ,  &uc->uc_mcontext.gregs[REG_R10], 8);
    memcpy(&rwx[0x17+100+2],  &uc->uc_mcontext.gregs[REG_R11], 8);
    memcpy(&rwx[0x17+110+2],  &uc->uc_mcontext.gregs[REG_R12], 8);
    memcpy(&rwx[0x17+120+2],  &uc->uc_mcontext.gregs[REG_R13], 8);
    memcpy(&rwx[0x17+130+2],  &uc->uc_mcontext.gregs[REG_R14], 8);
    memcpy(&rwx[0x17+140+2],  &uc->uc_mcontext.gregs[REG_R15], 8);
    
    asm volatile("lfence"); //Avoid MC.SMC

    //Disable FTZ, and re-execute the faulty instruction after restoring all XMM registers
    _MM_SET_FLUSH_ZERO_MODE(_MM_FLUSH_ZERO_OFF);
    asm volatile("movdqu (%0), %%xmm0" ::"r"(&uc->uc_mcontext.fpregs->_xmm[0]):);
    asm volatile("movdqu (%0), %%xmm1" ::"r"(&uc->uc_mcontext.fpregs->_xmm[1]):);
    asm volatile("movdqu (%0), %%xmm2" ::"r"(&uc->uc_mcontext.fpregs->_xmm[2]):);
    asm volatile("movdqu (%0), %%xmm3" ::"r"(&uc->uc_mcontext.fpregs->_xmm[3]):);
    asm volatile("movdqu (%0), %%xmm4" ::"r"(&uc->uc_mcontext.fpregs->_xmm[4]):);
    asm volatile("movdqu (%0), %%xmm5" ::"r"(&uc->uc_mcontext.fpregs->_xmm[5]):);
    asm volatile("movdqu (%0), %%xmm6" ::"r"(&uc->uc_mcontext.fpregs->_xmm[6]):);
    asm volatile("movdqu (%0), %%xmm7" ::"r"(&uc->uc_mcontext.fpregs->_xmm[7]):);
    asm volatile("movdqu (%0), %%xmm8" ::"r"(&uc->uc_mcontext.fpregs->_xmm[8]):);
    asm volatile("movdqu (%0), %%xmm9" ::"r"(&uc->uc_mcontext.fpregs->_xmm[9]):);
    asm volatile("movdqu (%0), %%xmm10"::"r"(&uc->uc_mcontext.fpregs->_xmm[10]):);
    asm volatile("movdqu (%0), %%xmm11"::"r"(&uc->uc_mcontext.fpregs->_xmm[11]):);
    asm volatile("movdqu (%0), %%xmm12"::"r"(&uc->uc_mcontext.fpregs->_xmm[12]):);
    asm volatile("movdqu (%0), %%xmm13"::"r"(&uc->uc_mcontext.fpregs->_xmm[13]):);
    asm volatile("movdqu (%0), %%xmm14"::"r"(&uc->uc_mcontext.fpregs->_xmm[14]):);
    asm volatile("movdqu (%0), %%xmm15"::"r"(&uc->uc_mcontext.fpregs->_xmm[15]):);
    fptr();
    asm volatile("movdqu %%xmm0, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[0]):);
    asm volatile("movdqu %%xmm1, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[1]):);
    asm volatile("movdqu %%xmm2, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[2]):);
    asm volatile("movdqu %%xmm3, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[3]):);
    asm volatile("movdqu %%xmm4, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[4]):);
    asm volatile("movdqu %%xmm5, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[5]):);
    asm volatile("movdqu %%xmm6, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[6]):);
    asm volatile("movdqu %%xmm7, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[7]):);
    asm volatile("movdqu %%xmm8, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[8]):);
    asm volatile("movdqu %%xmm9, (%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[9]):);
    asm volatile("movdqu %%xmm10,(%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[10]):);
    asm volatile("movdqu %%xmm11,(%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[11]):);
    asm volatile("movdqu %%xmm12,(%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[12]):);
    asm volatile("movdqu %%xmm13,(%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[13]):);
    asm volatile("movdqu %%xmm14,(%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[14]):);
    asm volatile("movdqu %%xmm15,(%0)" ::"r"(&uc->uc_mcontext.fpregs->_xmm[15]):);
    _MM_SET_FLUSH_ZERO_MODE(_MM_FLUSH_ZERO_ON);

    return op_len;
}

void handler(int sig, siginfo_t* si, void* vcontext)
{
    int op_len;
    ucontext_t *uc = (ucontext_t *)vcontext;
    void *fault_rip = (void *) si->si_addr;
    void *fault_addr = get_fault_addr((uint8_t*)fault_rip, &op_len, uc);
    uint8_t *fault_ptr = (uint8_t *) fault_addr;

    //fprintf(stderr, "Exception caught: fault_addr: %p\n", fault_addr);
    //fflush(stderr);

    //If our decoder fails
    if(fault_addr == NULL) {
        //Damn we got a SIGFPE from a non vaddss. Let's disassemble and skip the fault
#if COUNT_EXCEPTIONS == 1
        except_cnt_underflow++;
#endif
        op_len = get_ins_len_and_re_execute(fault_rip, uc);
        goto false_positive;
    }
    
    //Probably useless
    if( (*(uint32_t *)fault_ptr) != FLOAT_MAGIC_POISON && 
        (*(uint32_t *)fault_ptr) != FLOAT_MAGIC_POISON_PRE) goto false_positive;

    uint8_t *ptr = fault_ptr;

    // New Improved Addition: if the fault value is 0x8b8b8b89, we should scan right to confirm a redzone
    // not left, since the 89 has to mark the start of a redzone (this way we avoid reading a prepended underflow zone)
    if(*((uint32_t *)fault_ptr) == FLOAT_MAGIC_POISON_PRE){ // i = {0,1,2,3} == {89 8b 8b 8b}
        int found = 0;
        for(int i = 4; i < REDZONE_SIZE; i++){
            if(*(ptr+i) != FLOAT_MAGIC_POISON_BYTE){
                // the right of a 0x898b8b8b8b is not a redzone (no 8b)
#if COUNT_EXCEPTIONS == 1
                except_cnt_vaddss_skip++;
#endif
                goto false_positive;
            }
        }
    }
    else {
        //Let's go left until we find something that is not 8b
        //if it is 89 -> true positive, or false positive containing 89 8b 8b 8b 8b ...
        //if it is not 89 false positive
        //also make sure we have at least 15 8b on the right

        int found = 0;
        while(*ptr == FLOAT_MAGIC_POISON_BYTE) { 
            ptr--;
            found++;
        }

        //Now ptr pointing to something that is not 8b
        if(*ptr == FLOAT_MAGIC_POISON_PRE_BYTE) {
            //Ok we need 15 8b on the right from current ptr
            for(int i = 1; i < REDZONE_SIZE; i++) {
                if (*(ptr+i) != FLOAT_MAGIC_POISON_BYTE) {
#if COUNT_EXCEPTIONS == 1
                    except_cnt_vaddss_skip++;
#endif
                    goto false_positive;
                }
            }
        } else {
#if COUNT_EXCEPTIONS == 1
            except_cnt_vaddss_skip++;
#endif
            goto false_positive;
        }
    }

    // fault
#if COUNT_EXCEPTIONS == 1
    except_cnt_vaddss_rz++;
#endif

#if SURVIVE_EXCEPTIONS == 0
    fprintf(stderr, "\n!!!! [FLOATZONE] Fault addr = %p !!!!\n", fault_addr);

    for(int i=-64; i<64; i+=4) {
        fprintf(stderr, "%p: %02x %02x %02x %02x ", &fault_ptr[i], fault_ptr[i], fault_ptr[i+1], fault_ptr[i+2], fault_ptr[i+3]);
        if((void *)&fault_ptr[i] == fault_addr) fprintf(stderr, " <-----");
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    void **buf = malloc(128*sizeof(void *));
    int ret = backtrace(buf, 128);
    char **names = backtrace_symbols(buf, ret);
    fprintf(stderr, "Fault RIP = %p\nBacktrace:\n", fault_rip);
    for(int i=2; i<ret; i++) {
        fprintf(stderr, " - [%d] %s\n", i-2, names[i]);
    }

#if FUZZ_MODE == 1
    abort();
#else
    exit(FAULT_ERROR_CODE);
#endif
#endif

false_positive:
    uc->uc_mcontext.gregs[REG_RIP] += op_len;

    //Remove the presence of spurious redzone from the stack.
    //This was a nasty bug where the SIGFPE exception handler was leaving dangling redzone
    //when returning from a false positive
    for(int i=0; i<16; i++) {
        if(memcmp(&uc->uc_mcontext.fpregs->_xmm[i], &redzone_s, REDZONE_SIZE) == 0) {
            memset(&uc->uc_mcontext.fpregs->_xmm[i], 0, REDZONE_SIZE);
        }
    }

    return;
}

#if CATCH_SEGFAULT == 1
static void segfault_handler(int sig, siginfo_t *si, void *vcontext){
#if FUZZ_MODE == 1
    abort();
#else
    exit(FAULT_ERROR_CODE);
#endif
}
#endif

/// Disables the process so we don't do quarantine checking
/// on malloc'd memory from pre-init libc/libdl.
static void disable_process() {
  process = 0;
}

typedef int (*main_t)(int, char, char);
typedef int (*libc_start_main_t)(main_t main, int argc, char** ubp_av,
        void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void* stack_end);
int __libc_start_main(main_t main, int argc, char** ubp_av,
        void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void* stack_end)
{
    libc_start_main_t og_libc_start_main = (libc_start_main_t)dlsym(RTLD_NEXT, "__libc_start_main");
    __signal = (proto_signal) dlsym(RTLD_NEXT, "signal");
    ___sigaction = (proto_sigaction) dlsym(RTLD_NEXT, "sigaction");
    ___sysv_signal = (proto_sysv_signal) dlsym(RTLD_NEXT, "__sysv_signal");

    __longjmp = (proto_longjmp) dlsym(RTLD_NEXT, "longjmp");
    __siglongjmp = (proto_siglongjmp) dlsym(RTLD_NEXT, "siglongjmp");
    __og_cxa_throw = (proto_cxa_throw) dlsym(RTLD_NEXT, "__cxa_throw");
    __posix_memalign = (proto_posix_memalign) dlsym(RTLD_NEXT, "posix_memalign");

#if FUZZ_MODE == 1
    // avoid shutdown free() calls in some glibc versions on uninstrumented memory
    if (atexit(disable_process) != 0) {
        fprintf(stderr, "Failed to set atexit\n");
        abort();
    }
#endif

    if(strstr(ubp_av[0], TARGET) || strstr(ubp_av[0], JULIET)){
        // register signal handler
        struct sigaction action;
        memset(&action, 0, sizeof(struct sigaction));
        action.sa_flags = SA_SIGINFO;
        action.sa_sigaction = handler;

#if ENABLE_EXCEPTIONS == 1
        // enable Flush To Zero to allow Underflow
        _MM_SET_FLUSH_ZERO_MODE(_MM_FLUSH_ZERO_ON);

        ___sigaction(SIGFPE, &action, NULL);

        // enable FP underflow exceptions
        feenableexcept(FE_UNDERFLOW);
#endif

#if ENABLE_QUARANTINE == 1
        pthread_mutex_init(&ring_lock, NULL);
#endif

#if CATCH_SEGFAULT == 1
        memset(&action, 0, sizeof(struct sigaction));
        sigemptyset(&action.sa_mask);
        action.sa_flags     = SA_NODEFER;
        action.sa_sigaction = segfault_handler;
        sigaction(SIGSEGV, &action, NULL); // Segmentation fault
#endif

        process = 1;
    }

    return og_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

