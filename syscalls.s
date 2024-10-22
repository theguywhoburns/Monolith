;long read(unsigned int fd, char __user *buf, size_t count);
.global _read
_read:
	ret
;long write(unsigned int fd, const char __user *buf, size_t count);
.global _write
_write:
	ret
;long open(const char __user *filename, int flags, umode_t mode);
.global _open
_open:
	ret
;long close(unsigned int fd);
.global _close
_close:
	ret
;long newstat(const char __user *filename, struct stat __user *statbuf);
.global _newstat
_newstat:
	ret
;long newfstat(unsigned int fd, struct stat __user *statbuf);
.global _newfstat
_newfstat:
	ret
;long newlstat(const char __user *filename, struct stat __user *statbuf);
.global _newlstat
_newlstat:
	ret
;long poll(struct pollfd __user *ufds, unsigned int nfds, int timeout);
.global _poll
_poll:
	ret
;long lseek(unsigned int fd, off_t offset, unsigned int whence);
.global _lseek
_lseek:
	ret
;long mmap( unsigned long addr, unsigned long len, int prot, int flags, int fd, long off);
.global _mmap
_mmap:
	ret
;long mprotect(unsigned long start, size_t len, unsigned long prot);
.global _mprotect
_mprotect:
	ret
;long munmap(unsigned long addr, size_t len);
.global _munmap
_munmap:
	ret
;long brk(unsigned long brk);
.global _brk
_brk:
	ret
;long rt_sigaction(int, const struct sigaction __user *, struct sigaction __user *, size_t);
.global _rt_sigaction
_rt_sigaction:
	ret
;long rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize);
.global _rt_sigprocmask
_rt_sigprocmask:
	ret
;long rt_sigreturn(struct pt_regs *regs);
.global _rt_sigreturn
_rt_sigreturn:
	ret
;long ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
.global _ioctl
_ioctl:
	ret
;long pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);
.global _pread64
_pread64:
	ret
;long pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
.global _pwrite64
_pwrite64:
	ret
;long readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
.global _readv
_readv:
	ret
;long writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
.global _writev
_writev:
	ret
;long access(const char __user *filename, int mode);
.global _access
_access:
	ret
;long pipe(int __user *fildes);
.global _pipe
_pipe:
	ret
;long select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct __kernel_old_timeval __user *tvp);
.global _select
_select:
	ret
;long sched_yield(void);
.global _sched_yield
_sched_yield:
	ret
;long mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);
.global _mremap
_mremap:
	ret
;long msync(unsigned long start, size_t len, int flags);
.global _msync
_msync:
	ret
;long mincore(unsigned long start, size_t len, unsigned char __user * vec);
.global _mincore
_mincore:
	ret
;long madvise(unsigned long start, size_t len, int behavior);
.global _madvise
_madvise:
	ret
;long shmget(key_t key, size_t size, int flag);
.global _shmget
_shmget:
	ret
;long shmat(int shmid, char __user *shmaddr, int shmflg);
.global _shmat
_shmat:
	ret
;long shmctl(int shmid, int cmd, struct shmid_ds __user *buf);
.global _shmctl
_shmctl:
	ret
;long dup(unsigned int fildes);
.global _dup
_dup:
	ret
;long dup2(unsigned int oldfd, unsigned int newfd);
.global _dup2
_dup2:
	ret
;long pause(void);
.global _pause
_pause:
	ret
;long nanosleep(struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);
.global _nanosleep
_nanosleep:
	ret
;long getitimer(int which, struct __kernel_old_itimerval __user *value);
.global _getitimer
_getitimer:
	ret
;long alarm(unsigned int seconds);
.global _alarm
_alarm:
	ret
;long setitimer(int which, struct __kernel_old_itimerval __user *value, struct __kernel_old_itimerval __user *ovalue);
.global _setitimer
_setitimer:
	ret
;long getpid(void);
.global _getpid
_getpid:
	ret
;long sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count);
.global _sendfile64
_sendfile64:
	ret
;long socket(int, int, int);
.global _socket
_socket:
	ret
;long connect(int, struct sockaddr __user *, int);
.global _connect
_connect:
	ret
;long accept(int, struct sockaddr __user *, int __user *);
.global _accept
_accept:
	ret
;long sendto(int, void __user *, size_t, unsigned, struct sockaddr __user *, int);
.global _sendto
_sendto:
	ret
;long recvfrom(int, void __user *, size_t, unsigned, struct sockaddr __user *, int __user *);
.global _recvfrom
_recvfrom:
	ret
;long sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags);
.global _sendmsg
_sendmsg:
	ret
;long recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags);
.global _recvmsg
_recvmsg:
	ret
;long shutdown(int, int);
.global _shutdown
_shutdown:
	ret
;long bind(int, struct sockaddr __user *, int);
.global _bind
_bind:
	ret
;long listen(int, int);
.global _listen
_listen:
	ret
;long getsockname(int, struct sockaddr __user *, int __user *);
.global _getsockname
_getsockname:
	ret
;long getpeername(int, struct sockaddr __user *, int __user *);
.global _getpeername
_getpeername:
	ret
;long socketpair(int, int, int, int __user *);
.global _socketpair
_socketpair:
	ret
;long setsockopt(int fd, int level, int optname, char __user *optval, int optlen);
.global _setsockopt
_setsockopt:
	ret
;long getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen);
.global _getsockopt
_getsockopt:
	ret
;long clone(unsigned long, unsigned long, int __user *, unsigned long, int __user *);
.global _clone
_clone:
	ret
;long fork(void);
.global _fork
_fork:
	ret
;long vfork(void);
.global _vfork
_vfork:
	ret
;long execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
.global _execve
_execve:
	ret
;long exit(int error_code);
.global _exit
_exit:
	ret
;long wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru);
.global _wait4
_wait4:
	ret
;long kill(pid_t pid, int sig);
.global _kill
_kill:
	ret
;long newuname(struct new_utsname __user *name);
.global _newuname
_newuname:
	ret
;long semget(key_t key, int nsems, int semflg);
.global _semget
_semget:
	ret
;long semop(int semid, struct sembuf __user *sops, unsigned nsops);
.global _semop
_semop:
	ret
;long semctl(int semid, int semnum, int cmd, unsigned long arg);
.global _semctl
_semctl:
	ret
;long shmdt(char __user *shmaddr);
.global _shmdt
_shmdt:
	ret
;long msgget(key_t key, int msgflg);
.global _msgget
_msgget:
	ret
;long msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg);
.global _msgsnd
_msgsnd:
	ret
;long msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg);
.global _msgrcv
_msgrcv:
	ret
;long msgctl(int msqid, int cmd, struct msqid_ds __user *buf);
.global _msgctl
_msgctl:
	ret
;long fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
.global _fcntl
_fcntl:
	ret
;long flock(unsigned int fd, unsigned int cmd);
.global _flock
_flock:
	ret
;long fsync(unsigned int fd);
.global _fsync
_fsync:
	ret
;long fdatasync(unsigned int fd);
.global _fdatasync
_fdatasync:
	ret
;long truncate(const char __user *path, long length);
.global _truncate
_truncate:
	ret
;long ftruncate(unsigned int fd, unsigned long length);
.global _ftruncate
_ftruncate:
	ret
;long getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
.global _getdents
_getdents:
	ret
;long getcwd(char __user *buf, unsigned long size);
.global _getcwd
_getcwd:
	ret
;long chdir(const char __user *filename);
.global _chdir
_chdir:
	ret
;long fchdir(unsigned int fd);
.global _fchdir
_fchdir:
	ret
;long rename(const char __user *oldname, const char __user *newname);
.global _rename
_rename:
	ret
;long mkdir(const char __user *pathname, umode_t mode);
.global _mkdir
_mkdir:
	ret
;long rmdir(const char __user *pathname);
.global _rmdir
_rmdir:
	ret
;long creat(const char __user *pathname, umode_t mode);
.global _creat
_creat:
	ret
;long link(const char __user *oldname, const char __user *newname);
.global _link
_link:
	ret
;long unlink(const char __user *pathname);
.global _unlink
_unlink:
	ret
;long symlink(const char __user *old, const char __user *new);
.global _symlink
_symlink:
	ret
;long readlink(const char __user *path, char __user *buf, int bufsiz);
.global _readlink
_readlink:
	ret
;long chmod(const char __user *filename, umode_t mode);
.global _chmod
_chmod:
	ret
;long fchmod(unsigned int fd, umode_t mode);
.global _fchmod
_fchmod:
	ret
;long chown(const char __user *filename, uid_t user, gid_t group);
.global _chown
_chown:
	ret
;long fchown(unsigned int fd, uid_t user, gid_t group);
.global _fchown
_fchown:
	ret
;long lchown(const char __user *filename, uid_t user, gid_t group);
.global _lchown
_lchown:
	ret
;long umask(int mask);
.global _umask
_umask:
	ret
;long gettimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);
.global _gettimeofday
_gettimeofday:
	ret
;long getrlimit(unsigned int resource, struct rlimit __user *rlim);
.global _getrlimit
_getrlimit:
	ret
;long getrusage(int who, struct rusage __user *ru);
.global _getrusage
_getrusage:
	ret
;long sysinfo(struct sysinfo __user *info);
.global _sysinfo
_sysinfo:
	ret
;long times(struct tms __user *tbuf);
.global _times
_times:
	ret
;long ptrace(long request, long pid, unsigned long addr, unsigned long data);
.global _ptrace
_ptrace:
	ret
;long getuid(void);
.global _getuid
_getuid:
	ret
;long syslog(int type, char __user *buf, int len);
.global _syslog
_syslog:
	ret
;long getgid(void);
.global _getgid
_getgid:
	ret
;long setuid(uid_t uid);
.global _setuid
_setuid:
	ret
;long setgid(gid_t gid);
.global _setgid
_setgid:
	ret
;long geteuid(void);
.global _geteuid
_geteuid:
	ret
;long getegid(void);
.global _getegid
_getegid:
	ret
;long setpgid(pid_t pid, pid_t pgid);
.global _setpgid
_setpgid:
	ret
;long getppid(void);
.global _getppid
_getppid:
	ret
;long getpgrp(void);
.global _getpgrp
_getpgrp:
	ret
;long setsid(void);
.global _setsid
_setsid:
	ret
;long setreuid(uid_t ruid, uid_t euid);
.global _setreuid
_setreuid:
	ret
;long setregid(gid_t rgid, gid_t egid);
.global _setregid
_setregid:
	ret
;long getgroups(int gidsetsize, gid_t __user *grouplist);
.global _getgroups
_getgroups:
	ret
;long setgroups(int gidsetsize, gid_t __user *grouplist);
.global _setgroups
_setgroups:
	ret
;long setresuid(uid_t ruid, uid_t euid, uid_t suid);
.global _setresuid
_setresuid:
	ret
;long getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);
.global _getresuid
_getresuid:
	ret
;long setresgid(gid_t rgid, gid_t egid, gid_t sgid);
.global _setresgid
_setresgid:
	ret
;long getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);
.global _getresgid
_getresgid:
	ret
;long getpgid(pid_t pid);
.global _getpgid
_getpgid:
	ret
;long setfsuid(uid_t uid);
.global _setfsuid
_setfsuid:
	ret
;long setfsgid(gid_t gid);
.global _setfsgid
_setfsgid:
	ret
;long getsid(pid_t pid);
.global _getsid
_getsid:
	ret
;long capget(cap_user_header_t header, cap_user_data_t dataptr);
.global _capget
_capget:
	ret
;long capset(cap_user_header_t header, const cap_user_data_t data);
.global _capset
_capset:
	ret
;long rt_sigpending(sigset_t __user *set, size_t sigsetsize);
.global _rt_sigpending
_rt_sigpending:
	ret
;long rt_sigtimedwait(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct __kernel_timespec __user *uts, size_t sigsetsize);
.global _rt_sigtimedwait
_rt_sigtimedwait:
	ret
;long rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo);
.global _rt_sigqueueinfo
_rt_sigqueueinfo:
	ret
;long rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize);
.global _rt_sigsuspend
_rt_sigsuspend:
	ret
;long sigaltstack(const struct sigaltstack __user *uss, struct sigaltstack __user *uoss);
.global _sigaltstack
_sigaltstack:
	ret
;long utime(char __user *filename, struct utimbuf __user *times);
.global _utime
_utime:
	ret
;long mknod(const char __user *filename, umode_t mode, unsigned dev);
.global _mknod
_mknod:
	ret
;long personality(unsigned int personality);
.global _personality
_personality:
	ret
;long ustat(unsigned dev, struct ustat __user *ubuf);
.global _ustat
_ustat:
	ret
;long statfs(const char __user * path, struct statfs __user *buf);
.global _statfs
_statfs:
	ret
;long fstatfs(unsigned int fd, struct statfs __user *buf);
.global _fstatfs
_fstatfs:
	ret
;long sysfs(int option, unsigned long arg1, unsigned long arg2);
.global _sysfs
_sysfs:
	ret
;long getpriority(int which, int who);
.global _getpriority
_getpriority:
	ret
;long setpriority(int which, int who, int niceval);
.global _setpriority
_setpriority:
	ret
;long sched_setparam(pid_t pid, struct sched_param __user *param);
.global _sched_setparam
_sched_setparam:
	ret
;long sched_getparam(pid_t pid, struct sched_param __user *param);
.global _sched_getparam
_sched_getparam:
	ret
;long sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param);
.global _sched_setscheduler
_sched_setscheduler:
	ret
;long sched_getscheduler(pid_t pid);
.global _sched_getscheduler
_sched_getscheduler:
	ret
;long sched_get_priority_max(int policy);
.global _sched_get_priority_max
_sched_get_priority_max:
	ret
;long sched_get_priority_min(int policy);
.global _sched_get_priority_min
_sched_get_priority_min:
	ret
;long sched_rr_get_interval(pid_t pid, struct __kernel_timespec __user *interval);
.global _sched_rr_get_interval
_sched_rr_get_interval:
	ret
;long mlock(unsigned long start, size_t len);
.global _mlock
_mlock:
	ret
;long munlock(unsigned long start, size_t len);
.global _munlock
_munlock:
	ret
;long mlockall(int flags);
.global _mlockall
_mlockall:
	ret
;long munlockall(void);
.global _munlockall
_munlockall:
	ret
;long vhangup(void);
.global _vhangup
_vhangup:
	ret
;long pivot_root(const char __user *new_root, const char __user *put_old);
.global _pivot_root
_pivot_root:
	ret
;long ni_syscall(void);
.global _ni_syscall
_ni_syscall:
	ret
;long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
.global _prctl
_prctl:
	ret
;long adjtimex(struct __kernel_timex __user *txc_p);
.global _adjtimex
_adjtimex:
	ret
;long setrlimit(unsigned int resource, struct rlimit __user *rlim);
.global _setrlimit
_setrlimit:
	ret
;long chroot(const char __user *filename);
.global _chroot
_chroot:
	ret
;long sync(void);
.global _sync
_sync:
	ret
;long acct(const char __user *name);
.global _acct
_acct:
	ret
;long settimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);
.global _settimeofday
_settimeofday:
	ret
;long mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data);
.global _mount
_mount:
	ret
;long umount(char __user *name, int flags);
.global _umount
_umount:
	ret
;long swapon(const char __user *specialfile, int swap_flags);
.global _swapon
_swapon:
	ret
;long swapoff(const char __user *specialfile);
.global _swapoff
_swapoff:
	ret
;long reboot(int magic1, int magic2, unsigned int cmd, void __user *arg);
.global _reboot
_reboot:
	ret
;long sethostname(char __user *name, int len);
.global _sethostname
_sethostname:
	ret
;long setdomainname(char __user *name, int len);
.global _setdomainname
_setdomainname:
	ret
;long _;
._global 
:
	ret
;long ioperm(unsigned long from, unsigned long num, int on);
.global _ioperm
_ioperm:
	ret
;long init_module(void __user *umod, unsigned long len, const char __user *uargs);
.global _init_module
_init_module:
	ret
;long delete_module(const char __user *name_user, unsigned int flags);
.global _delete_module
_delete_module:
	ret
;long quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr);
.global _quotactl
_quotactl:
	ret
;long gettid(void);
.global _gettid
_gettid:
	ret
;long readahead(int fd, loff_t offset, size_t count);
.global _readahead
_readahead:
	ret
;long setxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);
.global _setxattr
_setxattr:
	ret
;long lsetxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);
.global _lsetxattr
_lsetxattr:
	ret
;long fsetxattr(int fd, const char __user *name, const void __user *value, size_t size, int flags);
.global _fsetxattr
_fsetxattr:
	ret
;long getxattr(const char __user *path, const char __user *name, void __user *value, size_t size);
.global _getxattr
_getxattr:
	ret
;long lgetxattr(const char __user *path, const char __user *name, void __user *value, size_t size);
.global _lgetxattr
_lgetxattr:
	ret
;long fgetxattr(int fd, const char __user *name, void __user *value, size_t size);
.global _fgetxattr
_fgetxattr:
	ret
;long listxattr(const char __user *path, char __user *list, size_t size);
.global _listxattr
_listxattr:
	ret
;long llistxattr(const char __user *path, char __user *list, size_t size);
.global _llistxattr
_llistxattr:
	ret
;long flistxattr(int fd, char __user *list, size_t size);
.global _flistxattr
_flistxattr:
	ret
;long removexattr(const char __user *path, const char __user *name);
.global _removexattr
_removexattr:
	ret
;long lremovexattr(const char __user *path, const char __user *name);
.global _lremovexattr
_lremovexattr:
	ret
;long fremovexattr(int fd, const char __user *name);
.global _fremovexattr
_fremovexattr:
	ret
;long tkill(pid_t pid, int sig);
.global _tkill
_tkill:
	ret
;long time(__kernel_old_time_t __user *tloc);
.global _time
_time:
	ret
;long futex(u32 __user *uaddr, int op, u32 val, const struct __kernel_timespec __user *utime, u32 __user *uaddr2, u32 val3);
.global _futex
_futex:
	ret
;long sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
.global _sched_setaffinity
_sched_setaffinity:
	ret
;long sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
.global _sched_getaffinity
_sched_getaffinity:
	ret
;long io_setup(unsigned nr_reqs, aio_context_t __user *ctx);
.global _io_setup
_io_setup:
	ret
;long io_destroy(aio_context_t ctx);
.global _io_destroy
_io_destroy:
	ret
;long io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout);
.global _io_getevents
_io_getevents:
	ret
;long io_submit(aio_context_t, long, struct iocb __user * __user *);
.global _io_submit
_io_submit:
	ret
;long io_cancel(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result);
.global _io_cancel
_io_cancel:
	ret
;long lookup_dcookie(u64 cookie64, char __user *buf, size_t len);
.global _lookup_dcookie
_lookup_dcookie:
	ret
;long epoll_create(int size);
.global _epoll_create
_epoll_create:
	ret
;long remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);
.global _remap_file_pages
_remap_file_pages:
	ret
;long getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
.global _getdents64
_getdents64:
	ret
;long set_tid_address(int __user *tidptr);
.global _set_tid_address
_set_tid_address:
	ret
;long restart_syscall(void);
.global _restart_syscall
_restart_syscall:
	ret
;long semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct __kernel_timespec __user *timeout);
.global _semtimedop
_semtimedop:
	ret
;long fadvise64(int fd, loff_t offset, size_t len, int advice);
.global _fadvise64
_fadvise64:
	ret
;long timer_create(clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id);
.global _timer_create
_timer_create:
	ret
;long timer_settime(timer_t timer_id, int flags, const struct __kernel_itimerspec __user *new_setting, struct __kernel_itimerspec __user *old_setting);
.global _timer_settime
_timer_settime:
	ret
;long timer_gettime(timer_t timer_id, struct __kernel_itimerspec __user *setting);
.global _timer_gettime
_timer_gettime:
	ret
;long timer_getoverrun(timer_t timer_id);
.global _timer_getoverrun
_timer_getoverrun:
	ret
;long timer_delete(timer_t timer_id);
.global _timer_delete
_timer_delete:
	ret
;long clock_settime(clockid_t which_clock, const struct __kernel_timespec __user *tp);
.global _clock_settime
_clock_settime:
	ret
;long clock_gettime(clockid_t which_clock, struct __kernel_timespec __user *tp);
.global _clock_gettime
_clock_gettime:
	ret
;long clock_getres(clockid_t which_clock, struct __kernel_timespec __user *tp);
.global _clock_getres
_clock_getres:
	ret
;long clock_nanosleep(clockid_t which_clock, int flags, const struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);
.global _clock_nanosleep
_clock_nanosleep:
	ret
;long exit_group(int error_code);
.global _exit_group
_exit_group:
	ret
;long epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout);
.global _epoll_wait
_epoll_wait:
	ret
;long epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event);
.global _epoll_ctl
_epoll_ctl:
	ret
;long tgkill(pid_t tgid, pid_t pid, int sig);
.global _tgkill
_tgkill:
	ret
;long utimes(char __user *filename, struct __kernel_old_timeval __user *utimes);
.global _utimes
_utimes:
	ret
;long mbind(unsigned long start, unsigned long len, unsigned long mode, const unsigned long __user *nmask, unsigned long maxnode, unsigned flags);
.global _mbind
_mbind:
	ret
;long set_mempolicy(int mode, const unsigned long __user *nmask, unsigned long maxnode);
.global _set_mempolicy
_set_mempolicy:
	ret
;long get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);
.global _get_mempolicy
_get_mempolicy:
	ret
;long mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr);
.global _mq_open
_mq_open:
	ret
;long mq_unlink(const char __user *name);
.global _mq_unlink
_mq_unlink:
	ret
;long mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec __user *abs_timeout);
.global _mq_timedsend
_mq_timedsend:
	ret
;long mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct __kernel_timespec __user *abs_timeout);
.global _mq_timedreceive
_mq_timedreceive:
	ret
;long mq_notify(mqd_t mqdes, const struct sigevent __user *notification);
.global _mq_notify
_mq_notify:
	ret
;long mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat);
.global _mq_getsetattr
_mq_getsetattr:
	ret
;long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags);
.global _kexec_load
_kexec_load:
	ret
;long waitid(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru);
.global _waitid
_waitid:
	ret
;long add_key(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid);
.global _add_key
_add_key:
	ret
;long request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid);
.global _request_key
_request_key:
	ret
;long keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
.global _keyctl
_keyctl:
	ret
;long ioprio_set(int which, int who, int ioprio);
.global _ioprio_set
_ioprio_set:
	ret
;long ioprio_get(int which, int who);
.global _ioprio_get
_ioprio_get:
	ret
;long inotify_init(void);
.global _inotify_init
_inotify_init:
	ret
;long inotify_add_watch(int fd, const char __user *path, u32 mask);
.global _inotify_add_watch
_inotify_add_watch:
	ret
;long inotify_rm_watch(int fd, __s32 wd);
.global _inotify_rm_watch
_inotify_rm_watch:
	ret
;long migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to);
.global _migrate_pages
_migrate_pages:
	ret
;long openat(int dfd, const char __user *filename, int flags, umode_t mode);
.global _openat
_openat:
	ret
;long mkdirat(int dfd, const char __user * pathname, umode_t mode);
.global _mkdirat
_mkdirat:
	ret
;long mknodat(int dfd, const char __user * filename, umode_t mode, unsigned dev);
.global _mknodat
_mknodat:
	ret
;long fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);
.global _fchownat
_fchownat:
	ret
;long futimesat(int dfd, const char __user *filename, struct __kernel_old_timeval __user *utimes);
.global _futimesat
_futimesat:
	ret
;long newfstatat(int dfd, const char __user *filename, struct stat __user *statbuf, int flag);
.global _newfstatat
_newfstatat:
	ret
;long unlinkat(int dfd, const char __user * pathname, int flag);
.global _unlinkat
_unlinkat:
	ret
;long renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname);
.global _renameat
_renameat:
	ret
;long linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);
.global _linkat
_linkat:
	ret
;long symlinkat(const char __user * oldname, int newdfd, const char __user * newname);
.global _symlinkat
_symlinkat:
	ret
;long readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz);
.global _readlinkat
_readlinkat:
	ret
;long fchmodat(int dfd, const char __user *filename, umode_t mode);
.global _fchmodat
_fchmodat:
	ret
;long faccessat(int dfd, const char __user *filename, int mode);
.global _faccessat
_faccessat:
	ret
;long pselect6(int, fd_set __user *, fd_set __user *, fd_set __user *, struct __kernel_timespec __user *, void __user *);
.global _pselect6
_pselect6:
	ret
;long ppoll(struct pollfd __user *, unsigned int, struct __kernel_timespec __user *, const sigset_t __user *, size_t);
.global _ppoll
_ppoll:
	ret
;long unshare(unsigned long unshare_flags);
.global _unshare
_unshare:
	ret
;long set_robust_list(struct robust_list_head __user *head, size_t len);
.global _set_robust_list
_set_robust_list:
	ret
;long get_robust_list(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr);
.global _get_robust_list
_get_robust_list:
	ret
;long splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);
.global _splice
_splice:
	ret
;long tee(int fdin, int fdout, size_t len, unsigned int flags);
.global _tee
_tee:
	ret
;long sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags);
.global _sync_file_range
_sync_file_range:
	ret
;long vmsplice(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags);
.global _vmsplice
_vmsplice:
	ret
;long move_pages(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags);
.global _move_pages
_move_pages:
	ret
;long utimensat(int dfd, const char __user *filename, struct __kernel_timespec __user *utimes, int flags);
.global _utimensat
_utimensat:
	ret
;long epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize);
.global _epoll_pwait
_epoll_pwait:
	ret
;long signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask);
.global _signalfd
_signalfd:
	ret
;long timerfd_create(int clockid, int flags);
.global _timerfd_create
_timerfd_create:
	ret
;long eventfd(unsigned int count);
.global _eventfd
_eventfd:
	ret
;long fallocate(int fd, int mode, loff_t offset, loff_t len);
.global _fallocate
_fallocate:
	ret
;long timerfd_settime(int ufd, int flags, const struct __kernel_itimerspec __user *utmr, struct __kernel_itimerspec __user *otmr);
.global _timerfd_settime
_timerfd_settime:
	ret
;long timerfd_gettime(int ufd, struct __kernel_itimerspec __user *otmr);
.global _timerfd_gettime
_timerfd_gettime:
	ret
;long accept4(int, struct sockaddr __user *, int __user *, int);
.global _accept4
_accept4:
	ret
;long signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);
.global _signalfd4
_signalfd4:
	ret
;long eventfd2(unsigned int count, int flags);
.global _eventfd2
_eventfd2:
	ret
;long epoll_create1(int flags);
.global _epoll_create1
_epoll_create1:
	ret
;long dup3(unsigned int oldfd, unsigned int newfd, int flags);
.global _dup3
_dup3:
	ret
;long pipe2(int __user *fildes, int flags);
.global _pipe2
_pipe2:
	ret
;long inotify_init1(int flags);
.global _inotify_init1
_inotify_init1:
	ret
;long preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
.global _preadv
_preadv:
	ret
;long pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
.global _pwritev
_pwritev:
	ret
;long rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, siginfo_t __user *uinfo);
.global _rt_tgsigqueueinfo
_rt_tgsigqueueinfo:
	ret
;long perf_event_open( struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags);
.global _perf_event_open
_perf_event_open:
	ret
;long recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct __kernel_timespec __user *timeout);
.global _recvmmsg
_recvmmsg:
	ret
;long fanotify_init(unsigned int flags, unsigned int event_f_flags);
.global _fanotify_init
_fanotify_init:
	ret
;long fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char __user *pathname);
.global _fanotify_mark
_fanotify_mark:
	ret
;long prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim);
.global _prlimit64
_prlimit64:
	ret
;long name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag);
.global _name_to_handle_at
_name_to_handle_at:
	ret
;long open_by_handle_at(int mountdirfd, struct file_handle __user *handle, int flags);
.global _open_by_handle_at
_open_by_handle_at:
	ret
;long clock_adjtime(clockid_t which_clock, struct __kernel_timex __user *tx);
.global _clock_adjtime
_clock_adjtime:
	ret
;long syncfs(int fd);
.global _syncfs
_syncfs:
	ret
;long sendmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags);
.global _sendmmsg
_sendmmsg:
	ret
;long setns(int fd, int nstype);
.global _setns
_setns:
	ret
;long getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);
.global _getcpu
_getcpu:
	ret
;long process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
.global _process_vm_readv
_process_vm_readv:
	ret
;long process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
.global _process_vm_writev
_process_vm_writev:
	ret
;long kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
.global _kcmp
_kcmp:
	ret
;long finit_module(int fd, const char __user *uargs, int flags);
.global _finit_module
_finit_module:
	ret
;long sched_setattr(pid_t pid, struct sched_attr __user *attr, unsigned int flags);
.global _sched_setattr
_sched_setattr:
	ret
;long sched_getattr(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags);
.global _sched_getattr
_sched_getattr:
	ret
;long renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);
.global _renameat2
_renameat2:
	ret
;long seccomp(unsigned int op, unsigned int flags, void __user *uargs);
.global _seccomp
_seccomp:
	ret
;long getrandom(char __user *buf, size_t count, unsigned int flags);
.global _getrandom
_getrandom:
	ret
;long memfd_create(const char __user *uname_ptr, unsigned int flags);
.global _memfd_create
_memfd_create:
	ret
;long kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user *cmdline_ptr, unsigned long flags);
.global _kexec_file_load
_kexec_file_load:
	ret
;long bpf(int cmd, union bpf_attr *attr, unsigned int size);
.global _bpf
_bpf:
	ret
;long execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);
.global _execveat
_execveat:
	ret
;long userfaultfd(int flags);
.global _userfaultfd
_userfaultfd:
	ret
;long membarrier(int cmd, unsigned int flags, int cpu_id);
.global _membarrier
_membarrier:
	ret
;long mlock2(unsigned long start, size_t len, int flags);
.global _mlock2
_mlock2:
	ret
;long copy_file_range(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);
.global _copy_file_range
_copy_file_range:
	ret
;long preadv2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
.global _preadv2
_preadv2:
	ret
;long pwritev2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
.global _pwritev2
_pwritev2:
	ret
;long pkey_mprotect(unsigned long start, size_t len, unsigned long prot, int pkey);
.global _pkey_mprotect
_pkey_mprotect:
	ret
;long pkey_alloc(unsigned long flags, unsigned long init_val);
.global _pkey_alloc
_pkey_alloc:
	ret
;long pkey_free(int pkey);
.global _pkey_free
_pkey_free:
	ret
;long statx(int dfd, const char __user *path, unsigned flags, unsigned mask, struct statx __user *buffer);
.global _statx
_statx:
	ret
;long io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout, const struct __aio_sigset *sig);
.global _io_pgetevents
_io_pgetevents:
	ret
;long rseq(struct rseq __user *rseq, uint32_t rseq_len, int flags, uint32_t sig);
.global _rseq
_rseq:
	ret
;long pidfd_send_signal(int pidfd, int sig, siginfo_t __user *info, unsigned int flags);
.global _pidfd_send_signal
_pidfd_send_signal:
	ret
;long io_uring_setup(u32 entries, struct io_uring_params __user *p);
.global _io_uring_setup
_io_uring_setup:
	ret
;long io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void __user *argp, size_t argsz);
.global _io_uring_enter
_io_uring_enter:
	ret
;long io_uring_register(unsigned int fd, unsigned int op, void __user *arg, unsigned int nr_args);
.global _io_uring_register
_io_uring_register:
	ret
;long open_tree(int dfd, const char __user *path, unsigned flags);
.global _open_tree
_open_tree:
	ret
;long move_mount(int from_dfd, const char __user *from_path, int to_dfd, const char __user *to_path, unsigned int ms_flags);
.global _move_mount
_move_mount:
	ret
;long fsopen(const char __user *fs_name, unsigned int flags);
.global _fsopen
_fsopen:
	ret
;long fsconfig(int fs_fd, unsigned int cmd, const char __user *key, const void __user *value, int aux);
.global _fsconfig
_fsconfig:
	ret
;long fsmount(int fs_fd, unsigned int flags, unsigned int ms_flags);
.global _fsmount
_fsmount:
	ret
;long fspick(int dfd, const char __user *path, unsigned int flags);
.global _fspick
_fspick:
	ret
;long pidfd_open(pid_t pid, unsigned int flags);
.global _pidfd_open
_pidfd_open:
	ret
;long clone3(struct clone_args __user *uargs, size_t size);
.global _clone3
_clone3:
	ret
;long close_range(unsigned int fd, unsigned int max_fd, unsigned int flags);
.global _close_range
_close_range:
	ret
;long openat2(int dfd, const char __user *filename, struct open_how *how, size_t size);
.global _openat2
_openat2:
	ret
;long pidfd_getfd(int pidfd, int fd, unsigned int flags);
.global _pidfd_getfd
_pidfd_getfd:
	ret
;long faccessat2(int dfd, const char __user *filename, int mode, int flags);
.global _faccessat2
_faccessat2:
	ret
;long process_madvise(int pidfd, const struct iovec __user *vec, size_t vlen, int behavior, unsigned int flags);
.global _process_madvise
_process_madvise:
	ret
;long epoll_pwait2(int epfd, struct epoll_event __user *events, int maxevents, const struct __kernel_timespec __user *timeout, const sigset_t __user *sigmask, size_t sigsetsize);
.global _epoll_pwait2
_epoll_pwait2:
	ret
;long mount_setattr(int dfd, const char __user *path, unsigned int flags, struct mount_attr __user *uattr, size_t usize);
.global _mount_setattr
_mount_setattr:
	ret
;long quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id, void __user *addr);
.global _quotactl_fd
_quotactl_fd:
	ret
;long landlock_create_ruleset(const struct landlock_ruleset_attr __user *attr, size_t size, __u32 flags);
.global _landlock_create_ruleset
_landlock_create_ruleset:
	ret
;long landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void __user *rule_attr, __u32 flags);
.global _landlock_add_rule
_landlock_add_rule:
	ret
;long landlock_restrict_self(int ruleset_fd, __u32 flags);
.global _landlock_restrict_self
_landlock_restrict_self:
	ret
;long memfd_secret(unsigned int flags);
.global _memfd_secret
_memfd_secret:
	ret
;long process_mrelease(int pidfd, unsigned int flags);
.global _process_mrelease
_process_mrelease:
	ret
;long futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes, unsigned int flags, struct __kernel_timespec __user *timeout, clockid_t clockid);
.global _futex_waitv
_futex_waitv:
	ret
;long set_mempolicy_home_node(unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags);
.global _set_mempolicy_home_node
_set_mempolicy_home_node:
	ret
;long cachestat(unsigned int fd, struct cachestat_range __user *cstat_range, struct cachestat __user *cstat, unsigned int flags);
.global _cachestat
_cachestat:
	ret
;long fchmodat2(int dfd, const char __user *filename, umode_t mode, unsigned int flags);
.global _fchmodat2
_fchmodat2:
	ret
;long map_shadow_stack(unsigned long addr, unsigned long size, unsigned int flags);
.global _map_shadow_stack
_map_shadow_stack:
	ret
;long compat_rt_sigaction(int, const struct compat_sigaction __user *, struct compat_sigaction __user *, compat_size_t);
.global _compat_rt_sigaction
_compat_rt_sigaction:
	ret
;long compat_ioctl(unsigned int fd, unsigned int cmd, compat_ulong_t arg);
.global _compat_ioctl
_compat_ioctl:
	ret
;long readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
.global _readv
_readv:
	ret
;long writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
.global _writev
_writev:
	ret
;long compat_recvfrom(int fd, void __user *buf, compat_size_t len, unsigned flags, struct sockaddr __user *addr, int __user *addrlen);
.global _compat_recvfrom
_compat_recvfrom:
	ret
;long compat_sendmsg(int fd, struct compat_msghdr __user *msg, unsigned flags);
.global _compat_sendmsg
_compat_sendmsg:
	ret
;long compat_recvmsg(int fd, struct compat_msghdr __user *msg, unsigned int flags);
.global _compat_recvmsg
_compat_recvmsg:
	ret
;long compat_execve(const char __user *filename, const compat_uptr_t __user *argv, const compat_uptr_t __user *envp);
.global _compat_execve
_compat_execve:
	ret
;long compat_ptrace(compat_long_t request, compat_long_t pid, compat_long_t addr, compat_long_t data);
.global _compat_ptrace
_compat_ptrace:
	ret
;long compat_rt_sigpending(compat_sigset_t __user *uset, compat_size_t sigsetsize);
.global _compat_rt_sigpending
_compat_rt_sigpending:
	ret
;long compat_rt_sigtimedwait_time64(compat_sigset_t __user *uthese, struct compat_siginfo __user *uinfo, struct __kernel_timespec __user *uts, compat_size_t sigsetsize);
.global _compat_rt_sigtimedwait_time64
_compat_rt_sigtimedwait_time64:
	ret
;long compat_rt_sigqueueinfo(compat_pid_t pid, int sig, struct compat_siginfo __user *uinfo);
.global _compat_rt_sigqueueinfo
_compat_rt_sigqueueinfo:
	ret
;long compat_sigaltstack(const compat_stack_t __user *uss_ptr, compat_stack_t __user *uoss_ptr);
.global _compat_sigaltstack
_compat_sigaltstack:
	ret
;long compat_timer_create(clockid_t which_clock, struct compat_sigevent __user *timer_event_spec, timer_t __user *created_timer_id);
.global _compat_timer_create
_compat_timer_create:
	ret
;long compat_mq_notify(mqd_t mqdes, const struct compat_sigevent __user *u_notification);
.global _compat_mq_notify
_compat_mq_notify:
	ret
;long compat_kexec_load(compat_ulong_t entry, compat_ulong_t nr_segments, struct compat_kexec_segment __user *, compat_ulong_t flags);
.global _compat_kexec_load
_compat_kexec_load:
	ret
;long compat_waitid(int, compat_pid_t, struct compat_siginfo __user *, int, struct compat_rusage __user *);
.global _compat_waitid
_compat_waitid:
	ret
;long compat_set_robust_list(struct compat_robust_list_head __user *head, compat_size_t len);
.global _compat_set_robust_list
_compat_set_robust_list:
	ret
;long compat_get_robust_list(int pid, compat_uptr_t __user *head_ptr, compat_size_t __user *len_ptr);
.global _compat_get_robust_list
_compat_get_robust_list:
	ret
;long vmsplice(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags);
.global _vmsplice
_vmsplice:
	ret
;long move_pages(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags);
.global _move_pages
_move_pages:
	ret
;long compat_preadv64(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, loff_t pos);
.global _compat_preadv64
_compat_preadv64:
	ret
;long compat_pwritev64(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, loff_t pos);
.global _compat_pwritev64
_compat_pwritev64:
	ret
;long compat_rt_tgsigqueueinfo(compat_pid_t tgid, compat_pid_t pid, int sig, struct compat_siginfo __user *uinfo);
.global _compat_rt_tgsigqueueinfo
_compat_rt_tgsigqueueinfo:
	ret
;long compat_recvmmsg_time64(int fd, struct compat_mmsghdr __user *mmsg, unsigned vlen, unsigned int flags, struct __kernel_timespec __user *timeout);
.global _compat_recvmmsg_time64
_compat_recvmmsg_time64:
	ret
;long compat_sendmmsg(int fd, struct compat_mmsghdr __user *mmsg, unsigned vlen, unsigned int flags);
.global _compat_sendmmsg
_compat_sendmmsg:
	ret
;long process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
.global _process_vm_readv
_process_vm_readv:
	ret
;long process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
.global _process_vm_writev
_process_vm_writev:
	ret
;long setsockopt(int fd, int level, int optname, char __user *optval, int optlen);
.global _setsockopt
_setsockopt:
	ret
;long getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen);
.global _getsockopt
_getsockopt:
	ret
;long compat_io_setup(unsigned nr_reqs, u32 __user *ctx32p);
.global _compat_io_setup
_compat_io_setup:
	ret
;long compat_io_submit(compat_aio_context_t ctx_id, int nr, u32 __user *iocb);
.global _compat_io_submit
_compat_io_submit:
	ret
;long compat_execveat(int dfd, const char __user *filename, const compat_uptr_t __user *argv, const compat_uptr_t __user *envp, int flags);
.global _compat_execveat
_compat_execveat:
	ret
;long compat_preadv64v2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, loff_t pos, rwf_t flags);
.global _compat_preadv64v2
_compat_preadv64v2:
	ret
;long compat_pwritev64v2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, loff_t pos, rwf_t flags);
.global _compat_pwritev64v2
_compat_pwritev64v2:
	ret
