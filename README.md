safeexec
========

These days, many programs are multi-threaded. Sometimes, that isn't
even under the control of the developer, and threads are started by
third-party libraries from within their load-time constructors.

Unfortunately, the presence of threads makes the familiar fork()/exec()
pattern very difficult to use. There are race conditions that can
trigger dead-locks in library-owned locks as -- for instance -- found
in glibc. There also is a chance that the dynamic link loader could
hang. And there is the potential to leak file descriptors.

Furthermore, if invoking a subprocess from a very large parent process
that has lots of memory mappings,fork() can turn into a prohibitively
expensive operation.

A discussion at https://lwn.net/Articles/1002371/ suggested using
vfork()/memfd_create()/execat() instead. The code in this project is
a proof-of-concept to validate that idea.

It turns out that this is in principle a viable option, and it avoids
a lot of the problems mentioned earlier.

It also has proven somewhat fragile, as we have to create a new ELF
image on the fly. We copy the executable code from our parent process
to create a small and emphemeral helper process. This is complicated
by the fact that compilers don't always honor __attribute__((section()))
for all the code that they generate.

There are look up tables and other read-only data that can be put into
the wrong section by the compiler. Position-indepent-code also
generates references outside of the named section.

All the data that the helper process needs must be serialized, which
results in complex code.

We cannot rely on library functions and have to directly invoke system
calls. This requires the use of architecture-specific assembly
code. And we have to tell the compiler to disable built-ins, as it will
otherwise attempt to recognize common open-coded functions and replace
the compiler's prefered library function.

Finally, all of this only works with modern kernel versions that have
the required system calls that we need.


Current Status
==============

The current code has been lightly tested on x86_64, i386 and
ARM (32bit and 64bit). It shouldn't be too difficult to port to other
architectures.

The API isn't quite complete yet, the code should be cleaned up and
documented, and error handling has to be added throughout.

But while the code isn't ready for production use in its current form,
it shows the viability of this technique and could form the foundation of
a general-purpose library that finally solves the problem of thread-safe
creation of sub processes.
