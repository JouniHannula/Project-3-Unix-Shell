/**********************************************************************
 * wish.c — simple Unix shell per OSTEP spec (LUT variant)
 *
 * Build (verbose errors per LUT rubric):
 *   gcc -std=c99 -Wall -Wextra -Werror -O2 -o wish wish.c
 *
 * Build (strict OSTEP single-error message):
 *   gcc -std=c99 -Wall -Wextra -Werror -O2 -DOSTEP_SINGLE_ERROR=1 -o wish wish.c
 *
 * Features
 *  - Interactive and batch modes
 *  - Built-ins: exit, cd, path
 *  - Search path (defaults to /bin; path overwrites; empty path disables external commands)
 *  - Output redirection: cmd > file  (both stdout and stderr -> file; overwrite)
 *  - Parallel commands with &:  cmd1 & cmd2 args & cmd3
 *  - Differentiated error messages to stderr (toggle via OSTEP_SINGLE_ERROR)
 *
 * Known limitations (as per assignment scope)
 *  - Does not treat absolute ("/bin/ls") or relative ("./prog") as special; use path
 *  - No pipes, globbing, quoting, environment variables, or job control
 * 
 * Jouni Hannula
 **********************************************************************/

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------- small low-level I/O helper ------------------- */
/* write_all: write the entire buffer, handling short writes / EINTR.
 * Returns 0 on success, -1 on failure (errno set). */
static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* ------------------- error handling ------------------- */

static const char ERR_MSG[] = "An error has occurred\n";

#ifndef OSTEP_SINGLE_ERROR
#define OSTEP_SINGLE_ERROR 0
#endif

/* Always-available generic error (matches original OSTEP requirement) */
static void shell_error(void) {
    (void)write_all(STDERR_FILENO, ERR_MSG, sizeof(ERR_MSG) - 1);
}

/* Verbose, typed errors (default). If OSTEP_SINGLE_ERROR=1, collapse to generic. */
static void shell_errorf(const char *fmt, ...) {
#if OSTEP_SINGLE_ERROR
    (void)fmt;
    shell_error();
#else
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    /* Ensure each error line ends with '\n' in call sites */
#endif
}

/* ------------------- small helpers ------------------- */

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) { shell_error(); exit(1); }
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (!q) { shell_error(); exit(1); }
    return q;
}

static char *xstrdup(const char *s) {
    char *p = strdup(s);
    if (!p) { shell_error(); exit(1); }
    return p;
}

/* trim leading/trailing spaces, tabs, and newlines, in place */
static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    if (*s == 0) return s;
    char *e = s + strlen(s) - 1;
    while (e > s && (*e == ' ' || *e == '\t' || *e == '\n' || *e == '\r')) {
        *e-- = '\0';
    }
    return s;
}

/* ------------------- PATH handling ------------------- */

typedef struct {
    char **dirs;
    size_t n;
    size_t cap;
} path_t;

static void path_init(path_t *p) {
    p->cap = 4;
    p->n = 1;
    p->dirs = xmalloc(p->cap * sizeof(char *));
    p->dirs[0] = xstrdup("/bin");   /* default */
}

static void path_clear(path_t *p) {
    for (size_t i = 0; i < p->n; i++) free(p->dirs[i]);
    p->n = 0;
}

static void path_set(path_t *p, char **dirs, int ndirs) {
    path_clear(p);
    if ((size_t)(ndirs > 0 ? ndirs : 1) > p->cap) {
        p->cap = (size_t)(ndirs > 0 ? ndirs : 1);
        p->dirs = xrealloc(p->dirs, p->cap * sizeof(char *));
    }
    for (int i = 0; i < ndirs; i++) {
        p->dirs[p->n++] = xstrdup(dirs[i]);
    }
}

static void path_destroy(path_t *p) {
    path_clear(p);
    free(p->dirs);
}

static char *join2(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    int need_slash = (la > 0 && a[la - 1] == '/') ? 0 : 1;
    char *res = xmalloc(la + need_slash + lb + 1);
    memcpy(res, a, la);
    if (need_slash) res[la++] = '/';
    memcpy(res + la, b, lb + 1);
    return res;
}

static char *find_exec(const path_t *path, const char *cmd) {
    for (size_t i = 0; i < path->n; i++) {
        char *full = join2(path->dirs[i], cmd);
        if (access(full, X_OK) == 0) {
            return full; /* caller frees */
        }
        free(full);
    }
    return NULL;
}

/* ------------------- tokenization ------------------- */

/* tokenize s by delimiters, return array of pointers INTO s (s is modified).
 * Returns argc via *argc_out, argv is NULL-terminated. */
static char **tokenize(char *s, const char *delims, int *argc_out) {
    int cap = 8, argc = 0;
    char **argv = xmalloc(cap * sizeof(char *));
    char *saveptr = NULL;
    char *tok = strtok_r(s, delims, &saveptr);
    while (tok) {
        if (argc == cap) {
            cap *= 2;
            argv = xrealloc(argv, cap * sizeof(char *));
        }
        argv[argc++] = tok;
        tok = strtok_r(NULL, delims, &saveptr);
    }
    if (argc == cap) argv = xrealloc(argv, (cap + 1) * sizeof(char *));
    argv[argc] = NULL;
    if (argc_out) *argc_out = argc;
    return argv;
}

/* split a line into jobs by '&' (parallel). Returns array of pointers into line. */
static char **split_parallel(char *line, int *njobs) {
    int cap = 4, n = 0;
    char **jobs = xmalloc(cap * sizeof(char *));
    char *save = NULL;
    char *tok = strtok_r(line, "&", &save);
    while (tok) {
        char *t = trim(tok);
        if (*t) {
            if (n == cap) {
                cap *= 2;
                jobs = xrealloc(jobs, cap * sizeof(char *));
            }
            jobs[n++] = t;
        }
        tok = strtok_r(NULL, "&", &save);
    }
    *njobs = n;
    return jobs;
}

/* parse redirection: command ... > file
 * returns:
 *   argv    : vector of strings (pointers into cmd), NULL-terminated
 *   argc    : count
 *   out     : malloc'd filename or NULL
 *   rc: 0 on success, -1 on syntax error
 */
static int parse_command(char *cmd, char ***argv, int *argc, char **out) {
    *out = NULL;
    *argv = NULL;
    *argc = 0;

    /* find '>' */
    char *redir = strchr(cmd, '>');
    if (redir) {
        *redir = '\0';
        redir++;
        redir = trim(redir);
        if (*redir == '\0') return -1;
        /* single file only */
        int rargc = 0;
        char **rargv = tokenize(redir, " \t\n", &rargc);
        if (rargc != 1) {
            free(rargv);
            return -1;
        }
        *out = xstrdup(rargv[0]);
        free(rargv);
    }

    cmd = trim(cmd);
    if (*cmd == '\0') {
        /* empty command is ok (e.g., " & cmd") */
        return 0;
    }

    *argv = tokenize(cmd, " \t\n", argc);
    return 0;
}

/* ------------------- built-ins ------------------- */

static int is_builtin(const char *cmd) {
    return strcmp(cmd, "exit") == 0 ||
           strcmp(cmd, "cd")   == 0 ||
           strcmp(cmd, "path") == 0;
}

static void builtin_exit(char **argv, int argc) {
    (void)argv;
    if (argc != 1) { shell_errorf("error: exit takes no arguments\n"); return; }
    exit(0);
}

static void builtin_cd(char **argv, int argc) {
    if (argc != 2) { shell_errorf("error: cd expects 1 argument\n"); return; }
    if (chdir(argv[1]) != 0) {
        shell_errorf("error: cd: %s: %s\n", argv[1], strerror(errno));
    }
}

static void builtin_path(char **argv, int argc, path_t *path) {
    /* overwrite path with argv[1..] */
    if (argc <= 1) { path_set(path, NULL, 0); return; }
    path_set(path, argv + 1, argc - 1);
}

/* ------------------- run one command ------------------- */

static pid_t run_command(char **argv, int argc, const char *redir, path_t *path) {
    if (argc == 0) return -1;

    if (is_builtin(argv[0])) {
        if (redir) { shell_errorf("error: redirection not supported for built-ins\n"); return -1; }
        if (strcmp(argv[0], "exit") == 0)  builtin_exit(argv, argc);
        else if (strcmp(argv[0], "cd") == 0)   builtin_cd(argv, argc);
        else                                   builtin_path(argv, argc, path);
        return -1;
    }

    /* external command */
    char *exe = find_exec(path, argv[0]);
    if (!exe) {
        shell_errorf("error: command not found: %s\n", argv[0]);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        shell_errorf("error: fork failed: %s\n", strerror(errno));
        free(exe);
        return -1;
    }

    if (pid == 0) {
        /* child */
        if (redir) {
            int fd = open(redir, O_CREAT | O_WRONLY | O_TRUNC, 0666);
            if (fd < 0) {
                shell_errorf("error: cannot open output file '%s': %s\n", redir, strerror(errno));
                _exit(1);
            }
            if (dup2(fd, STDOUT_FILENO) == -1 || dup2(fd, STDERR_FILENO) == -1) {
                shell_errorf("error: dup2 failed: %s\n", strerror(errno));
                _exit(1);
            }
            (void)close(fd);
        }
        execv(exe, argv);
        shell_errorf("error: exec failed for '%s': %s\n", exe, strerror(errno));
        _exit(1);
    }

    free(exe);
    return pid;
}

/* ------------------- main loop ------------------- */

#define PROMPT "wish> "

int main(int argc, char *argv[])
{
    FILE *in = stdin;
    int interactive = 1;

    if (argc > 2) {
        shell_errorf("error: usage: %s [batch_file]\n", argv[0]);
        exit(1);
    }
    if (argc == 2) {
        in = fopen(argv[1], "r");
        if (!in) {
            shell_errorf("error: cannot open batch file '%s': %s\n", argv[1], strerror(errno));
            exit(1);
        }
        interactive = 0;
    }

    path_t path;
    path_init(&path);

    char *line = NULL;
    size_t n = 0;

    while (1) {
        if (interactive) {
            (void)write_all(STDOUT_FILENO, PROMPT, sizeof(PROMPT) - 1);
        }

        ssize_t len = getline(&line, &n, in);
        if (len == -1) break;  /* EOF */

        /* strip trailing newline to keep parsing simple */
        if (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[len-1] = '\0';

        /* split by '&' for parallel commands */
        int njobs = 0;
        char **jobs = split_parallel(line, &njobs);

        pid_t *pids = xmalloc((size_t)(njobs > 0 ? njobs : 1) * sizeof(pid_t));
        int npids = 0;

        for (int j = 0; j < njobs; j++) {
            char **argvv = NULL;
            int    argcv = 0;
            char *redir = NULL;

            if (parse_command(jobs[j], &argvv, &argcv, &redir) != 0) {
                shell_errorf("error: redirection syntax\n");
                free(argvv);
                free(redir);
                continue;
            }

            if (argcv > 0) {
                pid_t pid = run_command(argvv, argcv, redir, &path);
                if (pid > 0) pids[npids++] = pid;
            }

            free(argvv);
            free(redir);
        }

        /* wait for all started children on this line */
        for (int i = 0; i < npids; i++) {
            int status;
            (void)waitpid(pids[i], &status, 0);
        }

        free(pids);
        free(jobs);
    }

    free(line);
    if (in != stdin) fclose(in);
    path_destroy(&path);
    return 0;
}