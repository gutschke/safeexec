#define _GNU_SOURCE

#include <asm/ioctls.h>
#include <asm/unistd.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "safeexec.h"


#if __SIZEOF_SIZE_T__ == 4
#define ELF(x) Elf32_##x
#define ELFCLASS ELFCLASS32
#else
#define ELF(x) Elf64_##x
#define ELFCLASS ELFCLASS64
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ELF_DATA ELFDATA2LSB
#else
#define ELF_DATA ELFDATA2MSB
#endif

#ifdef __i386
#define EM_CURRENT EM_386
#elif defined(__x86_64)
#define EM_CURRENT EM_X86_64
#elif defined(__ARM_ARCH_ISA_A64)
#define EM_CURRENT EM_AARCH64
#elif defined(__ARM_ARCH)
#define EM_CURRENT EM_ARM
#endif

/*
 * SECTIONS {
 *   .ephemeralBinary : {
 *     _start_ephemeralBinary = .;
 *     KEEP(*(.ephemeralBinary))
 *     KEEP(*(.ephemeralBinaryRO))
 *     _end_ephemeralBinary = .;
 *   }
 * } INSERT AFTER .text;
 */
extern char _start_ephemeralBinary, _end_ephemeralBinary;
#define EPHEMERAL(x) \
  static x __attribute__((section(".ephemeralBinary"), \
                          no_instrument_function, \
                          no_stack_protector, \
                          no_stack_limit)); \
  static  x
#define EPHEMERALRO(x) \
  static const x __attribute__((section(".ephemeralBinaryRO")))
#define ALIGN(x) ((typeof(x))(((off_t)(x) + 15) & -16))


typedef struct {
  const char *path;
  const char * const *argv;
  const char * const *envp;
  const struct safeexec_action *actions;
  const size_t nActions;
} EphemeralArgs;


EPHEMERAL(ssize_t sysenter(int num, ...)) {
  va_list ap;
  va_start(ap, num);
  #if EM_CURRENT == EM_386
  unsigned long res;
  const void *args[] = { va_arg(ap, void *), va_arg(ap, void *),
                         va_arg(ap, void *), va_arg(ap, void *),
                         va_arg(ap, void *), va_arg(ap, void *) };
  const struct { const int num; const void *a1, *a6; } s = { num, args[0], args[5] };
  __asm__ volatile("push %%ebp\n"
                   "push %%ebx\n"
                   "movl 8(%1), %%ebp\n"
                   "movl 4(%1), %%ebx\n"
                   "movl 0(%1), %%eax\n"
                   "int $0x80\n"
                   "pop %%ebx\n"
                   "pop %%ebp"
                   : "=a" (res)
                   : "0" (&s),
                     "c" (args[1]), "d" (args[2]),
                     "S" (args[3]), "D" (args[4])
                   : "memory");
  #elif EM_CURRENT == EM_X86_64
  unsigned long res;
  __asm__ volatile("movq %5, %%r10\n"
                   "movq %6, %%r8\n"
                   "movq %7, %%r9\n"
                   "syscall"
                   : "=a" (res)
                   : "0" (num),
                     "D" (va_arg(ap, void *)),
                     "S" (va_arg(ap, void *)),
                     "d" (va_arg(ap, void *)),
                     "r" (va_arg(ap, void *)),
                     "r" (va_arg(ap, void *)),
                     "r" (va_arg(ap, void *))
                   : "rcx", "r8", "r9", "r10", "r11", "memory");
  #elif EM_CURRENT == EM_AARCH64
  register void *res __asm__("x0") = va_arg(ap, void *);
  register void *x1  __asm__("x1") = va_arg(ap, void *);
  register void *x2  __asm__("x2") = va_arg(ap, void *);
  register void *x3  __asm__("x3") = va_arg(ap, void *);
  register void *x4  __asm__("x4") = va_arg(ap, void *);
  register void *x5  __asm__("x5") = va_arg(ap, void *);
  __asm__ volatile("mov x8, %1\n"
                   "svc 0"
                   : "=r" (res)
                   : "r" (num), "r" (res), "r" (x1), "r"(x2),
                     "r" (x3), "r" (x4), "r" (x5)
                   : "x8", "memory");
  #elif EM_CURRENT == EM_ARM
  register void *res __asm__("r0") = va_arg(ap, void *);
  register void *r1  __asm__("r1") = va_arg(ap, void *);
  register void *r2  __asm__("r2") = va_arg(ap, void *);
  register void *r3  __asm__("r3") = va_arg(ap, void *);
  register void *r4  __asm__("r4") = va_arg(ap, void *);
  register void *r5  __asm__("r5") = va_arg(ap, void *);
  __asm__ volatile("push {r7}\n"
                   "mov r7, %1\n"
                   "swi 0\n"
                   "pop {r7}"
                   : "=r" (res)
                   : "r" (num), "r" (res), "r" (r1), "r" (r2),
                      "r" (r3), "r" (r4), "r" (r5)
                   : "lr", "memory");
  #endif
  va_end(ap);
  return (ssize_t)res;
}


EPHEMERAL(void ephemeralBinary(void)) {
  #if EM_CURRENT == EM_386
  #elif EM_CURRENT == EM_X86_64
  asm __volatile__ ("lea -8(%rsp), %rsp");
  #elif EM_CURRENT == EM_AARCH64
  #elif EM_CURRENT == EM_ARM
  #endif
  const EphemeralArgs *args =
    (EphemeralArgs *)ALIGN(&_end_ephemeralBinary);
  for (int i = 0; i < args->nActions; i++) {
    const struct safeexec_action *action = &args->actions[i];
    switch (action->op) {
    case SE_OPEN:
      int fd = sysenter(__NR_openat, (size_t)AT_FDCWD, action->path,
                        (size_t)action->flags, (size_t)action->mode);
      if (fd != action->fd) {
        sysenter(__NR_dup3, (size_t)fd, (size_t)action->fd, NULL);
        sysenter(__NR_close, (size_t)fd);
      }
      break;
    case SE_CLOSE:
      sysenter(__NR_close, (size_t)action->fd);
      break;
    case SE_DUP2:
      sysenter(__NR_dup3, (size_t)action->src, (size_t)action->dst, NULL);
      break;
    case SE_CHDIR:
      sysenter(__NR_chdir, action->path);
      break;
    case SE_FCHDIR:
      sysenter(__NR_fchdir, (size_t)action->fd);
      break;
    case SE_CLOSE_FROM:
      sysenter(__NR_close_range, (size_t)action->fd, (ssize_t)-1, NULL);
      break;
    case SE_TCSETPGRP:
      pid_t pid = sysenter(__NR_getpgid, 0);
      sysenter(__NR_ioctl, (size_t)action->fd, TIOCSPGRP, &pid);
      break;
    case SE_CLOSE_ALL_BUT:
      EPHEMERALRO(char procPath[]) = "/proc/self/fd";
      int proc = sysenter(__NR_openat, (size_t)AT_FDCWD, procPath,
                          (size_t)O_RDONLY, NULL);
      for (;;) {
        char buf[1024];
        ssize_t rc = sysenter(__NR_getdents64, (size_t)proc,
                              buf, sizeof(buf));
        if (rc <= 0)
          break;
        for (const char *ptr = buf; ptr < &buf[rc]; ) {
          struct linux_dirent64 {
            ino64_t d_ino;
            off64_t d_off;
            unsigned short d_reclen;
            unsigned char d_type;
            char d_name[];
          } entry;
          memcpy((char *)&entry, ptr, sizeof(entry));
          const char *name = ((struct linux_dirent64 *)ptr)->d_name;
          int fd = 0;
          for (; *name; name++) {
            if (*name < '0' || *name > '9')
              goto next;
            fd = 10*fd + *name - '0';
          }
          if (fd == proc)
            goto next;
          for (int idx = action->nFds; idx-- > 0; ) {
            if (action->fds[idx] == fd)
              goto next;
          }
          sysenter(__NR_close, (size_t)fd);
        next:
          ptr += entry.d_reclen;
        }
      }
      sysenter(__NR_close, (size_t)proc);
      break;
    default:
      break;
    }
  }
  sysenter(__NR_execve, args->path, args->argv, args->envp);
  sysenter(__NR_exit_group, (size_t)1);
}


static int makeEphemeralBinary(const char *path,
                               size_t nActions,
                               const struct safeexec_action *actions,
                               char * const argv[],
                               char * const envp[]) {
  struct Header {
      ELF(Ehdr) ehdr;
      ELF(Phdr) phdr;
  };
  const size_t ephemeralBinarySize =
    &_end_ephemeralBinary - &_start_ephemeralBinary;
  const size_t pageSize = sysconf(_SC_PAGESIZE);
  const off_t binaryVirtPage =
    ((off_t)ephemeralBinary - sizeof(struct Header)) & -pageSize;
  const size_t textSegmentSize =
    (off_t)&_end_ephemeralBinary - binaryVirtPage;
  const EphemeralArgs *argsPtr =
    (EphemeralArgs *)ALIGN(&_end_ephemeralBinary);
  const struct safeexec_action *actionsPtr =
    (struct safeexec_action *)ALIGN(&argsPtr[1]);
  off_t excludedFds = 0;
  size_t pathsLen = 0;
  for (int i = 0; i < nActions; i++)
    switch (actions[i].op) {
    case SE_OPEN:
    case SE_CHDIR:
      pathsLen += strlen(actions[i].path) + 1;
      break;
    case SE_CLOSE_ALL_BUT:
      excludedFds += actions[i].nFds;
      break;
    default:
      break;
    }
  const int *excludedFdsPtr = (int *)ALIGN(&actionsPtr[nActions]);
  const char *pathsPtr = (char *)&excludedFdsPtr[excludedFds];
  const char *execPathPtr = &pathsPtr[pathsLen];
  const size_t execPathLen = strlen(path) + 1;
  pathsLen += execPathLen;
  const char * const *argvPtr = (const char **)ALIGN(&pathsPtr[pathsLen]);
  size_t argc = 0, envc = 0, stringsLen = 0;
  for (; argv && argv[argc]; argc++) {
    stringsLen += strlen(argv[argc]) + 1;
  }
  for (; envp && envp[envc]; envc++) {
    stringsLen += strlen(envp[envc]) + 1;
  }
  const EphemeralArgs args = {
    .path = execPathPtr,
    .argv = argvPtr,
    .envp = &argvPtr[argc + 1],
    .actions = actionsPtr,
    .nActions = nActions,
  };
  const char *stringsPtr = (char *)&args.envp[envc + 1];
  const size_t dataSegmentSize =
    stringsPtr + stringsLen - &_end_ephemeralBinary;
  const struct Header header = {
    {
      .e_ident = { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
                   ELFCLASS, ELF_DATA, EV_CURRENT, ELFOSABI_LINUX },
      .e_type = ET_EXEC,
      .e_machine = EM_CURRENT,
      .e_version = EV_CURRENT,
      .e_entry = (ELF(Addr))&ephemeralBinary,
      .e_phoff = sizeof(ELF(Ehdr)),
      .e_ehsize = sizeof(ELF(Ehdr)),
      .e_phentsize = sizeof(ELF(Phdr)),
      .e_phnum = 1,
      .e_shentsize = sizeof(ELF(Shdr))
    },
    {
      .p_type = PT_LOAD,
      .p_flags = PF_X | PF_R,
      .p_offset = 0,
      .p_vaddr = binaryVirtPage,
      .p_paddr = binaryVirtPage,
      .p_filesz = textSegmentSize + dataSegmentSize,
      .p_memsz = textSegmentSize + dataSegmentSize,
      .p_align = pageSize
    }
  };
  const int fd = memfd_create(path, MFD_CLOEXEC);
  if (fd < 0 ||
      write(fd, &header, sizeof(header)) != sizeof(header) ||
      lseek(fd, textSegmentSize - ephemeralBinarySize, SEEK_SET) < 0 ||
      write(fd, &_start_ephemeralBinary,
            ephemeralBinarySize) != ephemeralBinarySize ||
      lseek(fd, (char *)argsPtr - (char *)&_end_ephemeralBinary,
            SEEK_CUR) < 0 ||
      write(fd, &args, sizeof(args)) != sizeof(args) ||
      lseek(fd, (char *)actionsPtr - (char *)&argsPtr[1], SEEK_CUR) < 0) {
  err:
    if (fd >= 0) close(fd);
    return -1;
  }
  off_t fdsIdx = 0;
  off_t pathIdx = 0;
  for (int i = 0; i < nActions; i++) {
    struct safeexec_action action = actions[i];
    switch (action.op) {
    case SE_OPEN:
    case SE_CHDIR:
      action.path = (char *)&pathsPtr[pathIdx];
      pathIdx += strlen(actions[i].path) + 1;
      break;
    case SE_CLOSE_ALL_BUT:
      action.fds = (int *)&excludedFdsPtr[fdsIdx];
      fdsIdx += action.nFds;
      break;
    default:
      break;
    }
    if (write(fd, &action, sizeof(action)) != sizeof(action))
      goto err;
  }
  if (lseek(fd, (char *)excludedFdsPtr - (char *)&actionsPtr[nActions],
            SEEK_CUR) < 0)
    goto err;
  for (int i = 0; i < nActions; i++)
    if (actions[i].op == SE_CLOSE_ALL_BUT &&
        write(fd, actions[i].fds,
              actions[i].nFds*sizeof(*actions[i].fds)) !=
          actions[i].nFds*sizeof(*actions[i].fds))
      goto err;
  for (int i = 0; i < nActions; i++)
    switch (actions[i].op) {
    case SE_OPEN:
    case SE_CHDIR:
      const char *path = actions[i].path;
      const size_t len = strlen(path) + 1;
      if (write(fd, path, len) != len)
        goto err;
      break;
    default:
      break;
    }
  if (write(fd, path, execPathLen) != execPathLen ||
      lseek(fd, (char *)argvPtr - &pathsPtr[pathsLen], SEEK_CUR) < 0)
    goto err;
  const char *ptrs[256];
  char * const *ptr = argv;
  const char *entry = NULL;
  int n = 0, i = 0;
  for (int state = 0; state < 2;) {
    if (!ptr || !(entry = ptr[i++])) {
      entry = NULL;
      ++state;
      ptr = envp;
      i = 0;
    } else {
      const char *val = entry;
      entry = stringsPtr;
      stringsPtr += strlen(val) + 1;
    }
    ptrs[n++] = entry;
    if (n == sizeof(ptrs)/sizeof(*ptrs) || state == 2) {
      if (write(fd, ptrs, n*sizeof(*ptrs)) != n*sizeof(*ptrs))
        goto err;
      n = 0;
    }
  }
  struct iovec iov[64];
  ptr = argv;
  i = 0;
  size_t bytes = 0;
  for (int state = 0; state < 2;) {
    if (!ptr || !(entry = ptr[i++])) {
      entry = NULL;
      ++state;
      ptr = envp;
      i = 0;
    } else {
      iov[n].iov_base = (char *)entry;
      bytes += iov[n++].iov_len = strlen(entry) + 1;
    }
    if (n == sizeof(iov)/sizeof(*iov) || state == 2) {
      if (writev(fd, iov, n) != bytes)
        goto err;
      bytes = 0;
      n = 0;
    }
  }
  return fd;
}


int safeexec(pid_t *pid, const char *path,
             size_t nActions, const struct safeexec_action *actions,
             char * const argv[], char * const envp[]) {
  const int fd = makeEphemeralBinary(path, nActions, actions, argv, envp);
  if (fd < 0)
    return -1;

  const pid_t newPid = vfork();
  if (newPid == 0) {
    fexecve(fd, argv, envp);
    _exit(1);
  }

  close(fd);
  if (newPid < 0) {
    return newPid;
  } else {
    *pid = newPid;
    return 0;
  }
}
