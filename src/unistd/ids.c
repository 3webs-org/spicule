/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* There is one user as far as this library is concerned: an NT access
 * token has no real/effective/saved triple for anything here to differ
 * from, so every id below is one fixed number.
 *
 * Process groups and sessions are not that, and used to be: every one
 * of getpgrp/getpgid/setpgrp/setsid/getsid answered a hardcoded 1.  The
 * fiction cost more than it saved.  setsid.html's DESCRIPTION and its
 * "[EPERM] The calling process is already a process group leader"
 * together describe a state machine -- the first call sets the process
 * group ID to the process ID, which is exactly the precondition that
 * makes the second one fail -- and a constant can neither enter that
 * state nor report it.  setpgrp.html is starker still: "No errors are
 * defined", so its one specified effect ("sets the process group ID of
 * the calling process to the process ID of the calling process") is the
 * entire call, and it did not happen.
 *
 * So the two ids live in statics below.  NT has no process-group or
 * session object to hang them on -- a console process group
 * (CREATE_NEW_PROCESS_GROUP) is the nearest thing and cannot be joined;
 * src/process/posix_spawn.c's banner has that argument in full -- so
 * this is per-process bookkeeping and nothing more.  It is also exactly
 * as much of the model as a process can observe about *itself*, which
 * is all these six calls specify once there is no second process to
 * name (the clauses that do need one stay N/A; test/posix-unistd-ids.c
 * records which).
 *
 * The initial value, 1, is load-bearing twice over.  POSIX starts a
 * process in the group and session of whoever started it, so it is not
 * a group leader and its first setsid() succeeds; leadership is asked
 * here as `pgid == getpid()` rather than kept as a flag, and 1 is a
 * number no process can answer getpid() with -- NT process ids are
 * multiples of four (0 is the idle process, 4 is System) -- so that
 * comparison is false at startup for every process by construction
 * rather than by luck.  Reading 1 back as one *shared* group would be
 * the wrong reading: nothing here can name another process's group --
 * getpgid()/getsid() validate their pid (pid_exists() below answers the
 * [ESRCH] both pages make a shall-fail) but have no per-pid group to
 * report once it exists, so what comes back is always this process's
 * own.  1 therefore means "the group this process was born into, whose
 * other members this library cannot see".
 *
 * fork() needs no fixup for any of this and gets it right for free: the
 * clone carries these statics over with the rest of the address space
 * (src/process/fork.c), which is fork.html's "the child process shall
 * inherit the process group ID and session membership of the parent"
 * -- and because leadership is a comparison against getpid() rather
 * than a stored flag, a child of a leader correctly stops being one the
 * moment its own pid differs.  __spawn (src/process/spawn.c) cannot do
 * the same: the child is a fresh image with fresh statics, so it starts
 * in the born-into group rather than the caller's.  That divergence
 * from exec.html's inheritance rule is left standing deliberately --
 * closing it means widening the RuntimeData block crt1 reads back, for
 * a value no call in this library can report about another process. */
#include <unistd.h>
#include <errno.h>
#include "libc.h"

uid_t getuid(void) { return 1000; }
uid_t geteuid(void) { return 1000; }
gid_t getgid(void) { return 1000; }
gid_t getegid(void) { return 1000; }
int setuid(uid_t u) { (void)u; return 0; }
int seteuid(uid_t u) { (void)u; return 0; }
int setgid(gid_t g) { (void)g; return 0; }
int setegid(gid_t g) { (void)g; return 0; }
int setreuid(uid_t r, uid_t e) { (void)r; (void)e; return 0; }
int setregid(gid_t r, gid_t e) { (void)r; (void)e; return 0; }
/* The supplementary group list this library reports is one entry long
 * and holds the effective group ID -- getgroups.html leaves it
 * implementation-defined whether the effective gid appears there, and
 * with one identity there is nothing else to put in it.  gidsetsize is
 * an argument, though, and gets read as one: [EINVAL] is a *shall*-fail
 * for a gidsetsize "non-zero and less than the number of group IDs that
 * would have been returned", which every negative value is, given a
 * count of 1.  gidsetsize 0 asks for the count alone and must not touch
 * grouplist -- callers pass a null pointer for that form. */
int getgroups(int n, gid_t *g)
{
	const int held = 1;
	if (n != 0 && n < held) { errno = EINVAL; return -1; }
	if (n != 0) g[0] = getegid();
	return held;
}
/* The group and session this process is in; see the banner for why they
 * start at 1 and why a plain static is the whole of the model. */
static pid_t pgid = 1;
static pid_t sid = 1;

pid_t getpgrp(void) { return pgid; }

/* Does a process with this process ID exist, as far as this process can
 * tell?  getpgid.html and getsid.html both make "[ESRCH] There is no
 * process with a process ID equal to pid" a *shall*-fail, and that
 * clause is about the existence of a process rather than about
 * sessions: it binds a one-session implementation exactly as much as
 * any other, which is why the two getters below answer a fixed 1 (the
 * single process group / single session this platform has) but only
 * for a pid that names something.
 *
 * Existence is decided the way kill() and getpriority() already decide
 * it (src/signal/signal.c, src/misc/resource.c), in three steps:
 *
 *   - pid 0 and this process's own pid are the caller, which exists by
 *     construction -- "If pid is equal to 0, getpgid() shall return the
 *     process group ID of the calling process".  Answered without an NT
 *     call, so the common form of both calls stays free of one.
 *   - a pid in the child table (src/process/children.c) is a process
 *     this one created and has not yet reaped.  This arm is not an
 *     optimisation of the NtOpenProcess below, because the two answer
 *     different questions: POSIX existence lasts until wait() collects
 *     the pid -- an exited-but-unreaped child is still a process, and
 *     the table entry src/process/wait.c holds open is precisely that
 *     state -- while openability by CLIENT_ID is a property of the NT
 *     process *object*, which the two platforms disagree about once it
 *     has exited (see wait.c's reopen-by-pid discussion: Wine and
 *     Windows differ on whether an exited pid can be opened at all).
 *     Consulting the table first is what keeps a zombie child from
 *     being reported nonexistent on the platform that says no.
 *   - anything else is put to the object manager by CLIENT_ID.
 *     STATUS_INVALID_CID -- and any other failure that is not a refusal
 *     -- means there is no such process.  STATUS_ACCESS_DENIED means
 *     the process is there and merely not ours to open, which is
 *     existence, not [ESRCH]; it cannot become [EPERM] here either,
 *     since that clause of both pages is about a process in a
 *     *different session* and there is only the one.
 *
 * A negative pid names no process (kill() answers ESRCH for one too),
 * and is rejected without troubling NT: NtOpenProcess takes an unsigned
 * CLIENT_ID, so sign-extending -1 into it would ask about pid
 * 0xffffffffffffffff instead of reporting the error.
 */
static int pid_exists(pid_t p)
{
	HANDLE h;
	NTSTATUS st;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;

	if (p == 0 || p == getpid()) return 1;
	if (p < 0) return 0;
	if (__child_find((int)p)) return 1;

	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
	cid.UniqueProcess = (HANDLE)(ULONG_PTR)p;
	cid.UniqueThread = 0;
	st = NtOpenProcess(&h, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
	if (!NT_SUCCESS(st)) return st == STATUS_ACCESS_DENIED;
	NtClose(h);
	return 1;
}

pid_t getpgid(pid_t p)
{
	if (!pid_exists(p)) { errno = ESRCH; return -1; }
	return pgid;
}
int setpgid(pid_t a, pid_t b) { (void)a; (void)b; return 0; }

/* setpgrp.html DESCRIPTION: "If the calling process is not already a
 * session leader, setpgrp() sets the process group ID of the calling
 * process to the process ID of the calling process."  RETURN VALUE:
 * "Upon completion, setpgrp() shall return the process group ID."
 * ERRORS: "No errors are defined."
 *
 * Only the process-group half is done.  The page permits the System V
 * reading in which the call creates a session too ("If setpgrp()
 * creates a new session, then the new session has no controlling
 * terminal"), and that reading loses here: it would make setpgrp() a
 * setsid() that cannot fail, spending the one group-leadership
 * transition setsid()'s [EPERM] is defined in terms of, for an effect
 * the DESCRIPTION does not require of it. */
pid_t setpgrp(void)
{
	pid_t self = getpid();
	if (sid != self) pgid = self;
	return pgid;
}

/* setsid.html DESCRIPTION: "The setsid() function shall create a new
 * session, if the calling process is not a process group leader.  Upon
 * return the calling process shall be the session leader of this new
 * session, shall be the process group leader of a new process group,
 * and shall have no controlling terminal.  The process group ID of the
 * calling process shall be set equal to the process ID of the calling
 * process."  ERRORS: "[EPERM] The calling process is already a process
 * group leader ..."
 *
 * "Already a process group leader" is pgid == pid, false for a fresh
 * process and true of every process that has been through here once, so
 * the second call fails -- which is the whole of what the clause can
 * mean where no other process's group can be named.
 *
 * "Shall have no controlling terminal" is not modelled: the console is
 * the only terminal on this platform and nothing in src/termios/ or
 * src/unistd/isatty.c distinguishes a controlling one from any other,
 * so there is no state to drop.  tcgetsid()/tcgetpgrp() keep answering
 * for it, and follow this session and group rather than a constant. */
pid_t setsid(void)
{
	pid_t self = getpid();
	if (pgid == self) { errno = EPERM; return -1; }
	sid = pgid = self;
	return pgid;
}

pid_t getsid(pid_t p)
{
	if (!pid_exists(p)) { errno = ESRCH; return -1; }
	return sid;
}

int chown(const char *p, uid_t u, gid_t g) { (void)p; (void)u; (void)g; return 0; }
int fchown(int f, uid_t u, gid_t g) { (void)f; (void)u; (void)g; return 0; }
int lchown(const char *p, uid_t u, gid_t g) { (void)p; (void)u; (void)g; return 0; }
int fchownat(int d, const char *p, uid_t u, gid_t g, int f) { (void)d; (void)p; (void)u; (void)g; (void)f; return 0; }
/* nice() used to be `(void)incr; return 0;` here, among identity calls it
 * has nothing to do with.  It moved to src/misc/resource.c, beside the
 * one piece of state getpriority()/setpriority() already keep this
 * process's nice value in, so that the two interfaces cannot disagree
 * about it. */
int chroot(const char *p) { (void)p; errno = EPERM; return -1; }
int issetugid(void) { return 0; }
char *getlogin(void)
{
	extern char *getenv(const char *);
	char *u = getenv("USERNAME");
	return u ? u : getenv("USER");
}
int getlogin_r(char *buf, size_t n)
{
	char *l = getlogin();
	size_t i;
	if (!l) return ENXIO;
	for (i = 0; l[i] && i + 1 < n; i++) buf[i] = l[i];
	if (l[i]) return ERANGE;
	buf[i] = 0;
	return 0;
}
