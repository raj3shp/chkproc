# chkproc
Python script to find Linux processes that are hidden from ps output

Hiding processes is a common technique used by rootkits to stay hidden for long periods of time. By using Loadable kernel modules (LKM), syscalls such as `getdents` can be altered to not include malware's process directory in the output. With this simple approach we can identify potentially hidden processes.

This is a simple python implementatin of chkproc.c from [chkrootkit](https://www.chkrootkit.org/)
