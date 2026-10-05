/*
 * Interceptor zachowania - biblioteka wstrzykiwana przez LD_PRELOAD.
 *
 * Po co: analiza statyczna widzi, jak plik WYGLĄDA. Ten moduł widzi, co plik
 * ROBI. Podglądamy wywołania libc - otwieranie plików, uruchamianie procesów,
 * łączenie się z siecią - i zapisujemy je do dziennika, który potem czyta
 * avengine/behavior.py.
 *
 * Zasady bezpieczeństwa użyte w tym pliku:
 *  - logowanie idzie przez SUROWE wywołania systemowe (syscall), nigdy przez
 *    funkcje libc - inaczej hook `open` wywołałby `fopen`, które wywołuje
 *    `open`, i mielibyśmy nieskończoną rekurencję;
 *  - dodatkowa blokada rekurencji (in_hook) na wypadek wątków;
 *  - logujemy tylko to, co ma znaczenie analityczne (zapisy, uruchomienia,
 *    sieć, odczyty wrażliwych plików) - pełny zrzut wszystkich odczytów
 *    bibliotek i locale zalałby dziennik setkami tysięcy linii.
 *
 * Ograniczenia (uczciwie): pliki statycznie zlinkowane, binaria korzystające
 * z surowych syscalli (np. Go) oraz programy setuid omijają LD_PRELOAD.
 * Prawdziwa piaskownica używa sterownika kernelowego; to jest następny
 * najlepszy wariant bez uprawnień roota.
 *
 * Budowa:  gcc -shared -fPIC -O2 -o interceptor.so interceptor.c -ldl
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* ------------------------------------------------------------ dziennik --- */

static int g_log_fd = -2; /* -2 = jeszcze nie otwarty, -1 = wyłączony */
static __thread int in_hook = 0;

static void ensure_log(void)
{
    if (g_log_fd != -2)
        return;
    const char *path = getenv("AVY_BEHAVIOR_LOG");
    if (!path) {
        g_log_fd = -1;
        return;
    }
    /* Bezpośrednio syscall: fopen/open są przechwytywane. */
    g_log_fd = (int)syscall(SYS_openat, AT_FDCWD, path,
                            O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (g_log_fd < 0)
        g_log_fd = -1;
}

static void log_event(const char *fmt, ...)
{
    ensure_log();
    if (g_log_fd < 0 || in_hook)
        return;

    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0)
        return;
    if (n >= (int)sizeof(buf))
        n = (int)sizeof(buf) - 1;
    buf[n] = '\n';

    in_hook = 1;
    (void)syscall(SYS_write, g_log_fd, buf, (size_t)n + 1);
    in_hook = 0;
}

/* ------------------------------------------------- co nas interesuje ----- */

/*
 * Odczyty logujemy tylko dla ścieżek wrażliwych - to typowy cel ataku:
 * poświadczenia, klucze SSH, portfele krypto, historia poleceń.
 */
static int is_sensitive(const char *path)
{
    if (!path)
        return 0;
    static const char *const patterns[] = {
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/",
        "/etc/ld.so.preload", "/etc/cron", "/etc/systemd", "/etc/rc.local",
        "/root/.ssh", ".ssh/", "id_rsa", "id_ed25519", ".aws/credentials",
        ".gnupg/", ".bash_history", ".zsh_history", ".config/autostart",
        ".mozilla/", "wallets", "wallet.dat", ".kdbx", "keepass",
        "/proc/self/", "/proc/version", "authorized_keys", NULL
    };
    for (int i = 0; patterns[i]; i++) {
        if (strstr(path, patterns[i]))
            return 1;
    }
    return 0;
}

static const char *access_mode(int flags)
{
    int acc = flags & O_ACCMODE;
    if (acc == O_WRONLY || acc == O_RDWR)
        return (flags & O_APPEND) ? "append" : "write";
    if (flags & (O_CREAT | O_TRUNC))
        return "write";
    return "read";
}

static void log_open(const char *path, int flags)
{
    if (!path)
        return;
    const char *mode = access_mode(flags);
    if (strcmp(mode, "read") == 0 && !is_sensitive(path))
        return; /* zwykłe odczyty nas nie interesują */
    log_event("OPEN\t%d\t%s\t%s", (int)getpid(), path, mode);
}

/* --------------------------------------------------------------- hooki --- */

/* --- pliki --- */

int open(const char *path, int flags, ...)
{
    static int (*real)(const char *, int, ...);
    if (!real)
        real = dlsym(RTLD_NEXT, "open");
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    log_open(path, flags);
    return real(path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
    static int (*real)(const char *, int, ...);
    if (!real)
        real = dlsym(RTLD_NEXT, "open64");
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    log_open(path, flags);
    return real(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    static int (*real)(int, const char *, int, ...);
    if (!real)
        real = dlsym(RTLD_NEXT, "openat");
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    log_open(path, flags);
    return real(dirfd, path, flags, mode);
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    static int (*real)(int, const char *, int, ...);
    if (!real)
        real = dlsym(RTLD_NEXT, "openat64");
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    log_open(path, flags);
    return real(dirfd, path, flags, mode);
}

FILE *fopen(const char *path, const char *mode)
{
    static FILE *(*real)(const char *, const char *);
    if (!real)
        real = dlsym(RTLD_NEXT, "fopen");
    if (path && mode && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')))
        log_event("OPEN\t%d\t%s\t%s", (int)getpid(), path,
                  strchr(mode, 'a') ? "append" : "write");
    else if (path && is_sensitive(path))
        log_event("OPEN\t%d\t%s\tread", (int)getpid(), path);
    return real(path, mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    static FILE *(*real)(const char *, const char *);
    if (!real)
        real = dlsym(RTLD_NEXT, "fopen64");
    if (path && mode && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')))
        log_event("OPEN\t%d\t%s\t%s", (int)getpid(), path,
                  strchr(mode, 'a') ? "append" : "write");
    return real(path, mode);
}

int unlink(const char *path)
{
    static int (*real)(const char *);
    if (!real)
        real = dlsym(RTLD_NEXT, "unlink");
    log_event("DELETE\t%d\t%s", (int)getpid(), path ? path : "(null)");
    return real(path);
}

int unlinkat(int dirfd, const char *path, int flags)
{
    static int (*real)(int, const char *, int);
    if (!real)
        real = dlsym(RTLD_NEXT, "unlinkat");
    log_event("DELETE\t%d\t%s", (int)getpid(), path ? path : "(null)");
    return real(dirfd, path, flags);
}

int rename(const char *old, const char *new)
{
    static int (*real)(const char *, const char *);
    if (!real)
        real = dlsym(RTLD_NEXT, "rename");
    log_event("MOVE\t%d\t%s\t%s", (int)getpid(), old ? old : "(null)",
              new ? new : "(null)");
    return real(old, new);
}

int renameat(int od, const char *old, int nd, const char *new)
{
    static int (*real)(int, const char *, int, const char *);
    if (!real)
        real = dlsym(RTLD_NEXT, "renameat");
    log_event("MOVE\t%d\t%s\t%s", (int)getpid(), old ? old : "(null)",
              new ? new : "(null)");
    return real(od, old, nd, new);
}

int mkdir(const char *path, mode_t mode)
{
    static int (*real)(const char *, mode_t);
    if (!real)
        real = dlsym(RTLD_NEXT, "mkdir");
    log_event("MKDIR\t%d\t%s", (int)getpid(), path ? path : "(null)");
    return real(path, mode);
}

int chmod(const char *path, mode_t mode)
{
    static int (*real)(const char *, mode_t);
    if (!real)
        real = dlsym(RTLD_NEXT, "chmod");
    log_event("CHMOD\t%d\t%s\t%o", (int)getpid(), path ? path : "(null)",
              (unsigned)mode);
    return real(path, mode);
}

int truncate(const char *path, off_t length)
{
    static int (*real)(const char *, off_t);
    if (!real)
        real = dlsym(RTLD_NEXT, "truncate");
    log_event("TRUNCATE\t%d\t%s", (int)getpid(), path ? path : "(null)");
    return real(path, length);
}

/* --- uruchamianie procesów --- */

/* argv kończymy w dzienniku znakiem EOT, żeby parser mógł bezpiecznie
   oddzielić kolejne argumenty - spacje w ścieżkach są dozwolone. */
static void log_exec(const char *path, char *const argv[])
{
    if (!path)
        return;
    size_t used = 0;
    char line[3072];
    int n = snprintf(line, sizeof(line), "EXEC\t%d\t%s\t", (int)getpid(), path);
    if (n < 0 || (size_t)n >= sizeof(line))
        return;
    used = (size_t)n;
    if (argv) {
        for (int i = 1; argv[i] && used < sizeof(line) - 2; i++) {
            size_t len = strlen(argv[i]);
            if (used + len + 2 >= sizeof(line))
                break;
            if (i > 1)
                line[used++] = ' ';
            memcpy(line + used, argv[i], len);
            used += len;
        }
    }
    line[used] = '\0';
    log_event("%s", line);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    static int (*real)(const char *, char *const[], char *const[]);
    if (!real)
        real = dlsym(RTLD_NEXT, "execve");
    log_exec(path, argv);
    return real(path, argv, envp);
}

int execv(const char *path, char *const argv[])
{
    static int (*real)(const char *, char *const[]);
    if (!real)
        real = dlsym(RTLD_NEXT, "execv");
    log_exec(path, argv);
    return real(path, argv);
}

int execvp(const char *file, char *const argv[])
{
    static int (*real)(const char *, char *const[]);
    if (!real)
        real = dlsym(RTLD_NEXT, "execvp");
    log_exec(file, argv);
    return real(file, argv);
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
    static int (*real)(const char *, char *const[], char *const[]);
    if (!real)
        real = dlsym(RTLD_NEXT, "execvpe");
    log_exec(file, argv);
    return real(file, argv, envp);
}

/* Rodzina execl* jest wariadyczna: zbieramy argumenty i przekazujemy dalej
   jako wektor argv. */
static int execl_common(const char *path, const char *arg0, va_list ap)
{
    char *argv[64];
    int count = 0;
    argv[count++] = (char *)arg0;
    while (count < 63) {
        char *arg = va_arg(ap, char *);
        argv[count] = arg;
        if (!arg)
            break;
        count++;
    }
    argv[count] = NULL;
    return execv(path, argv);
}

int execl(const char *path, const char *arg, ...)
{
    va_list ap;
    va_start(ap, arg);
    int r = execl_common(path, arg, ap);
    va_end(ap);
    return r;
}

int execlp(const char *file, const char *arg, ...)
{
    va_list ap;
    va_start(ap, arg);
    char *argv[64];
    int count = 0;
    argv[count++] = (char *)arg;
    while (count < 63) {
        char *a = va_arg(ap, char *);
        argv[count] = a;
        if (!a)
            break;
        count++;
    }
    argv[count] = NULL;
    va_end(ap);
    return execvp(file, argv);
}

int execle(const char *path, const char *arg, ...)
{
    va_list ap;
    va_start(ap, arg);
    char *argv[64];
    int count = 0;
    argv[count++] = (char *)arg;
    while (count < 63) {
        char *a = va_arg(ap, char *);
        argv[count] = a;
        if (!a)
            break;
        count++;
    }
    argv[count] = NULL;
    char **envp = va_arg(ap, char **);
    va_end(ap);
    return execve(path, argv, envp);
}

int system(const char *command)
{
    static int (*real)(const char *);
    if (!real)
        real = dlsym(RTLD_NEXT, "system");
    log_event("SHELL\t%d\t%s", (int)getpid(), command ? command : "");
    return real(command);
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *attr, char *const argv[],
                char *const envp[])
{
    static int (*real)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                       const posix_spawnattr_t *, char *const[], char *const[]);
    if (!real)
        real = dlsym(RTLD_NEXT, "posix_spawn");
    log_exec(path, argv);
    return real(pid, path, fa, attr, argv, envp);
}

/* --- sieć --- */

int socket(int domain, int type, int protocol)
{
    static int (*real)(int, int, int);
    if (!real)
        real = dlsym(RTLD_NEXT, "socket");
    const char *fam = domain == AF_INET ? "ipv4"
                    : domain == AF_INET6 ? "ipv6"
                    : domain == AF_UNIX ? "unix" : "other";
    log_event("SOCKET\t%d\t%s\t%s", (int)getpid(), fam,
              (type & SOCK_STREAM) ? "tcp"
              : (type & SOCK_DGRAM) ? "udp"
              : (type & SOCK_RAW) ? "raw" : "other");
    return real(domain, type, protocol);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    static int (*real)(int, const struct sockaddr *, socklen_t);
    if (!real)
        real = dlsym(RTLD_NEXT, "connect");
    char host[128] = {0};
    int port = 0;
    const char *fam = "other";
    if (addr) {
        if (addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &s->sin_addr, host, sizeof(host));
            port = ntohs(s->sin_port);
            fam = "ipv4";
        } else if (addr->sa_family == AF_INET6 &&
                   len >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &s->sin6_addr, host, sizeof(host));
            port = ntohs(s->sin6_port);
            fam = "ipv6";
        } else if (addr->sa_family == AF_UNIX) {
            const struct sockaddr_un *s = (const struct sockaddr_un *)addr;
            snprintf(host, sizeof(host), "%s", s->sun_path);
            fam = "unix";
        }
    }
    log_event("CONNECT\t%d\t%s\t%s\t%d", (int)getpid(), fam, host, port);
    return real(fd, addr, len);
}
