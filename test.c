#define _GNU_SOURCE

#include <unistd.h>

#include "safeexec.h"


int main(int argc, char *argv[]) {
  pid_t pid;
  safeexec(&pid, "/bin/true",
           5,
           (struct safeexec_action []) {
             { .op = SE_OPEN,
               .fd = 0, .path = "/dev/null", .flags = O_RDONLY },
             { .op = SE_OPEN,
               .fd = 1, .path = "/dev/null", .flags = O_WRONLY },
             { .op = SE_DUP2, .src = 1, .dst = 2 },
             { .op = SE_CHDIR, .path = "/" },
             { .op = SE_CLOSE_ALL_BUT, .nFds = 3,
               .fds = (int []){ 0, 1, 2 } },
           },
           (char * const []){ "true", NULL }, environ);
  return 0;
}
