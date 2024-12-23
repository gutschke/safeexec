#ifndef __SAFEEXEC_H__
#define __SAFEEXEC_H__

#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>


enum safeexec_operation {
  SE_OPEN, SE_CLOSE, SE_DUP2, SE_CHDIR, SE_FCHDIR, SE_CLOSE_FROM,
  SE_TCSETPGRP, SE_CLOSE_ALL_BUT
};

struct safeexec_action {
  enum safeexec_operation op;
  union {
    struct {
      int fd;
      char *path;
      int flags;
      mode_t mode;
    };
    struct {
      int src, dst;
    };
    struct {
      int *fds;
      int nFds;
    };
  };
};

int safeexec(pid_t *pid, const char *path,
             size_t nActions, const struct safeexec_action *actions,
             char * const argv[], char * const envp[]);

#endif
