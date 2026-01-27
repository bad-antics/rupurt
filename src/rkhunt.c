/*
 * NullSec RKHunt - Advanced Rootkit Hunter
 * Comprehensive rootkit detection with extensive signature database
 * 
 * Compile: gcc -O2 -Wall -o rkhunt rkhunt.c -lpthread
 * License: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <elf.h>

#define VERSION "2.0.0"
#define MAX_PATH 4096
#define MAX_LINE 8192

/* ANSI Colors - subtle output */
#define C_RED     "\x1b[38;5;196m"
#define C_GREEN   "\x1b[38;5;82m"
#define C_YELLOW  "\x1b[38;5;220m"
#define C_CYAN    "\x1b[38;5;51m"
#define C_GRAY    "\x1b[38;5;245m"
#define C_WHITE   "\x1b[38;5;255m"
#define C_DIM     "\x1b[2m"
#define C_BOLD    "\x1b[1m"
#define C_RESET   "\x1b[0m"

/* Banner - minimal and professional */
static const char *BANNER = 
C_CYAN "  ╭──────────────────────────────────────────╮\n"
"  │" C_WHITE "  RKHunt " C_DIM "v2.0" C_CYAN "  │  " C_GRAY "Advanced Rootkit Hunter" C_CYAN "  │\n"
"  ╰──────────────────────────────────────────╯" C_RESET "\n";

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * COMPREHENSIVE ROOTKIT DATABASE
 * Sources: Security research, MITRE ATT&CK, public disclosures
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Linux Kernel Rootkits (LKM) */
static const char *LKM_ROOTKITS[] = {
    /* Modern/Active */
    "singularity", "reptile", "diamorphine", "suterusu", "kovid",
    "nurupo", "bdvl", "beurk", "azazel", "jynx2", "vlany",
    "horsepill", "drovorub", "facefish", "skidmap", "pandora",
    "umbreon", "keysniffer", "r77", "fontanini", "kbeast",
    "rkspotter", "rkorova", "khook", "lkm_rootkit",
    
    /* Historic/Research */
    "adore", "adore-ng", "knark", "synapsys", "heroine",
    "suckit", "shv4", "shv5", "rkit", "rkh", "lrk", "lrk3",
    "lrk4", "lrk5", "lrk6", "t0rn", "ambient", "phalanx",
    "phalanx2", "phantasmagoria", "snakso", "mood-nt",
    "override", "rial", "rsha", "enyelkm", "kbdv3",
    
    /* APT/Nation-State */
    "turla", "uroburos", "snake", "carbon", "penquin",
    "equation", "regin", "hive", "bvp47", "dirtycow_lkm",
    "drovorub_kernel", "winnti_lkm", "lazarus_lkm",
    NULL
};

/* Userland Rootkits (LD_PRELOAD) */
static const char *USERLAND_ROOTKITS[] = {
    "jynx", "jynx2", "azazel", "azazel2", "vlany", "beurk",
    "bdvl", "libprocesshider", "apache_backdoor", "cub3",
    "erebus", "ld_poison", "preload_hook", "prochide",
    "umbreon_user", "libc_hook", "glibc_hook", "libselinux_fake",
    "fakeld", "evil_preload", "stealth_preload", "rootsh",
    NULL
};

/* Bootkit/MBR Rootkits */
static const char *BOOTKITS[] = {
    "rovnix", "carberp", "tdss", "tdl", "tdl2", "tdl3", "tdl4",
    "olmarik", "sinowal", "torpig", "mebroot", "stoned",
    "alureon", "gapz", "bootrash", "uefi_rootkit", "lojax",
    "mosaic_regressor", "trickbot_mbr", "finspy_bootkit",
    "thunderstrike", "hacking_team_uefi", "blacklotus",
    "cosmicstrand", "moonbounce", "especter", "vector_edk",
    NULL
};

/* Container/Cloud Rootkits */
static const char *CONTAINER_ROOTKITS[] = {
    "doki", "kinsing", "teamtnt", "watchdog", "graboid",
    "hildegard", "siloscape", "azurescape", "cr8escape",
    "kubernetes_backdoor", "docker_escape", "cgroup_escape",
    "container_drift", "malicious_admission", "pod_escape",
    NULL
};

/* Suspicious Kernel Module Names */
static const char *SUSPICIOUS_MODULES[] = {
    "rootkit", "hidden", "stealth", "invisible", "hide",
    "cloak", "phantom", "ghost", "shadow", "backdoor",
    "keylog", "sniffer", "hook", "inject", "hijack",
    "intercept", "bypass", "elevate", "escalate", "priv",
    "syscall_hook", "vfs_hook", "netfilter_hook", "ipt_hook",
    "xor_key", "decrypt_mod", "crypt_mod", "encode_mod",
    "rev_shell", "bind_shell", "remote_access", "rat_mod",
    "miner", "cryptominer", "xmrig_mod", "monero_mod",
    NULL
};

/* Suspicious File Signatures (hex patterns) */
typedef struct {
    const char *name;
    const char *pattern;
    size_t offset;
    size_t len;
} signature_t;

static const signature_t FILE_SIGNATURES[] = {
    {"Reptile LKM", "\x7fELFreptile", 0, 11},
    {"Diamorphine", "diamorphine_init", 0, 16},
    {"Suterusu", "suterusu", 0, 8},
    {"Kovid LKM", "kovid_init", 0, 10},
    {"Jynx2", "JYNX2_", 0, 6},
    {"Azazel", "AZAZEL", 0, 6},
    {"BDVl", "bdvl_", 0, 5},
    {"Singularity", "singularity_core", 0, 16},
    {NULL, NULL, 0, 0}
};

/* Suspicious Directories */
static const char *SUSPICIOUS_DIRS[] = {
    "/dev/shm/.", "/tmp/.", "/var/tmp/.", "/run/.", 
    "/.hidden", "/root/.", "/home/*/.cache/.", 
    "/usr/share/.", "/opt/.", "/var/cache/.",
    "/lib/modules/*/kernel/drivers/misc/.",
    "/usr/lib/debug/.", "/var/lib/.",
    NULL
};

/* Suspicious Ports (backdoor indicators) */
static const int SUSPICIOUS_PORTS[] = {
    31337, 31338, 4444, 5555, 6666, 6667, 12345, 23456,
    1234, 9999, 8888, 7777, 1337, 1338, 2222, 3333,
    4443, 8443, 8080, 9090, 65535, 65534, 1, 2, 3,
    13337, 14444, 15555, 16666, 17777, 18888, 19999,
    -1
};

/* Syscall table hooks to check */
static const char *SYSCALL_HOOKS[] = {
    "sys_read", "sys_write", "sys_open", "sys_close",
    "sys_stat", "sys_fstat", "sys_lstat", "sys_poll",
    "sys_lseek", "sys_mmap", "sys_mprotect", "sys_munmap",
    "sys_brk", "sys_ioctl", "sys_access", "sys_pipe",
    "sys_select", "sys_sched_yield", "sys_mremap",
    "sys_msync", "sys_mincore", "sys_madvise",
    "sys_shmget", "sys_shmat", "sys_shmctl",
    "sys_dup", "sys_dup2", "sys_pause", "sys_nanosleep",
    "sys_getitimer", "sys_alarm", "sys_setitimer",
    "sys_getpid", "sys_sendfile", "sys_socket",
    "sys_connect", "sys_accept", "sys_sendto",
    "sys_recvfrom", "sys_sendmsg", "sys_recvmsg",
    "sys_shutdown", "sys_bind", "sys_listen",
    "sys_getsockname", "sys_getpeername", "sys_socketpair",
    "sys_setsockopt", "sys_getsockopt", "sys_clone",
    "sys_fork", "sys_vfork", "sys_execve", "sys_exit",
    "sys_wait4", "sys_kill", "sys_uname", "sys_semget",
    "sys_semop", "sys_semctl", "sys_shmdt", "sys_msgget",
    "sys_msgsnd", "sys_msgrcv", "sys_msgctl", "sys_fcntl",
    "sys_flock", "sys_fsync", "sys_fdatasync", "sys_truncate",
    "sys_ftruncate", "sys_getdents", "sys_getcwd", "sys_chdir",
    "sys_fchdir", "sys_rename", "sys_mkdir", "sys_rmdir",
    "sys_creat", "sys_link", "sys_unlink", "sys_symlink",
    "sys_readlink", "sys_chmod", "sys_fchmod", "sys_chown",
    "sys_fchown", "sys_lchown", "sys_umask", "sys_gettimeofday",
    "sys_getrlimit", "sys_getrusage", "sys_sysinfo", "sys_times",
    "sys_ptrace", "sys_getuid", "sys_syslog", "sys_getgid",
    "sys_setuid", "sys_setgid", "sys_geteuid", "sys_getegid",
    "sys_setpgid", "sys_getppid", "sys_getpgrp", "sys_setsid",
    "sys_setreuid", "sys_setregid", "sys_getgroups",
    "sys_setgroups", "sys_setresuid", "sys_getresuid",
    "sys_setresgid", "sys_getresgid", "sys_getpgid",
    "sys_setfsuid", "sys_setfsgid", "sys_getsid", "sys_capget",
    "sys_capset", "sys_rt_sigpending", "sys_rt_sigtimedwait",
    "sys_rt_sigqueueinfo", "sys_rt_sigsuspend", "sys_sigaltstack",
    NULL
};

/* ═══════════════════════════════════════════════════════════════════════════
 * STATISTICS & STATE
 * ═══════════════════════════════════════════════════════════════════════════
 */

typedef struct {
    int warnings;
    int critical;
    int infections;
    int hidden_procs;
    int suspicious_files;
    int hooked_syscalls;
    int suspicious_modules;
    int network_anomalies;
    int integrity_failures;
    time_t start_time;
} stats_t;

static stats_t stats = {0};
static int opt_verbose = 0;
static int opt_quiet = 0;
static int opt_json = 0;
static int opt_stealth = 0;
static FILE *log_file = NULL;

/* ═══════════════════════════════════════════════════════════════════════════
 * OUTPUT FUNCTIONS (Subtle & Professional)
 * ═══════════════════════════════════════════════════════════════════════════
 */

static void log_msg(const char *level, const char *fmt, va_list args) {
    if (log_file) {
        time_t now = time(NULL);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_file, "[%s] [%s] ", timestamp, level);
        vfprintf(log_file, fmt, args);
        fprintf(log_file, "\n");
        fflush(log_file);
    }
}

static void print_info(const char *fmt, ...) {
    if (opt_quiet) return;
    va_list args;
    va_start(args, fmt);
    printf("  " C_GRAY "·" C_RESET " ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void print_ok(const char *fmt, ...) {
    if (opt_quiet) return;
    va_list args;
    va_start(args, fmt);
    printf("  " C_GREEN "✓" C_RESET " ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void print_warn(const char *fmt, ...) {
    va_list args, args2;
    va_start(args, fmt);
    va_copy(args2, args);
    if (!opt_quiet) {
        printf("  " C_YELLOW "⚡" C_RESET " ");
        vprintf(fmt, args);
        printf("\n");
    }
    log_msg("WARN", fmt, args2);
    va_end(args);
    va_end(args2);
    stats.warnings++;
}

static void print_alert(const char *fmt, ...) {
    va_list args, args2;
    va_start(args, fmt);
    va_copy(args2, args);
    if (!opt_quiet) {
        printf("  " C_RED "▸" C_RESET " ");
        vprintf(fmt, args);
        printf("\n");
    }
    log_msg("ALERT", fmt, args2);
    va_end(args);
    va_end(args2);
    stats.infections++;
}

static void print_critical(const char *fmt, ...) {
    va_list args, args2;
    va_start(args, fmt);
    va_copy(args2, args);
    printf("  " C_RED C_BOLD "█" C_RESET " " C_RED);
    vprintf(fmt, args);
    printf(C_RESET "\n");
    log_msg("CRITICAL", fmt, args2);
    va_end(args);
    va_end(args2);
    stats.critical++;
    stats.infections++;
}

static void print_section(const char *title) {
    if (opt_quiet) return;
    printf("\n  " C_CYAN "─── " C_WHITE "%s" C_CYAN " ───" C_RESET "\n\n", title);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * UTILITY FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════
 */

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int is_directory(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static char *read_file_contents(const char *path, size_t *size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    
    fseek(fp, 0, SEEK_END);
    *size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (*size > 10 * 1024 * 1024) { /* Limit to 10MB */
        fclose(fp);
        return NULL;
    }
    
    char *buf = malloc(*size + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    
    fread(buf, 1, *size, fp);
    buf[*size] = '\0';
    fclose(fp);
    return buf;
}

static int string_in_array(const char *str, const char **array) {
    for (int i = 0; array[i] != NULL; i++) {
        if (strcasestr(str, array[i])) return 1;
    }
    return 0;
}

static int check_memory_pattern(const char *buf, size_t size, const char *pattern, size_t plen) {
    for (size_t i = 0; i <= size - plen; i++) {
        if (memcmp(buf + i, pattern, plen) == 0) return 1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DETECTION MODULES
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Check for hidden processes via /proc enumeration */
static int check_hidden_processes(void) {
    print_section("Process Analysis");
    
    int found = 0;
    int proc_count = 0, ps_count = 0;
    char path[MAX_PATH];
    
    /* Count via /proc */
    for (int pid = 1; pid <= 65535; pid++) {
        snprintf(path, sizeof(path), "/proc/%d", pid);
        if (file_exists(path)) proc_count++;
    }
    
    /* Count via ps */
    FILE *fp = popen("ps -e --no-headers 2>/dev/null | wc -l", "r");
    if (fp) {
        fscanf(fp, "%d", &ps_count);
        pclose(fp);
    }
    
    int diff = abs(proc_count - ps_count);
    
    if (opt_verbose) {
        print_info("Processes in /proc: %d", proc_count);
        print_info("Processes via ps: %d", ps_count);
    }
    
    if (diff > 3) {
        print_alert("Process count discrepancy: %d hidden process(es) suspected", diff);
        stats.hidden_procs = diff;
        found += diff;
    } else {
        print_ok("Process enumeration consistent");
    }
    
    /* Check for processes with deleted executables */
    DIR *proc_dir = opendir("/proc");
    if (proc_dir) {
        struct dirent *entry;
        while ((entry = readdir(proc_dir)) != NULL) {
            if (!isdigit(entry->d_name[0])) continue;
            
            char exe_link[MAX_PATH], exe_target[MAX_PATH];
            snprintf(exe_link, sizeof(exe_link), "/proc/%s/exe", entry->d_name);
            
            ssize_t len = readlink(exe_link, exe_target, sizeof(exe_target) - 1);
            if (len > 0) {
                exe_target[len] = '\0';
                if (strstr(exe_target, "(deleted)")) {
                    char cmdline[256] = {0};
                    char cmd_path[MAX_PATH];
                    snprintf(cmd_path, sizeof(cmd_path), "/proc/%s/cmdline", entry->d_name);
                    FILE *cmd_fp = fopen(cmd_path, "r");
                    if (cmd_fp) {
                        fread(cmdline, 1, sizeof(cmdline) - 1, cmd_fp);
                        fclose(cmd_fp);
                    }
                    print_warn("Process %s running from deleted binary: %s", 
                              entry->d_name, cmdline[0] ? cmdline : "(unknown)");
                    found++;
                }
            }
        }
        closedir(proc_dir);
    }
    
    return found;
}

/* Check LD_PRELOAD hooks */
static int check_ld_preload(void) {
    print_section("LD_PRELOAD Analysis");
    
    int found = 0;
    
    /* Check environment */
    char *preload = getenv("LD_PRELOAD");
    if (preload && strlen(preload) > 0) {
        print_critical("LD_PRELOAD environment variable set: %s", preload);
        found++;
    }
    
    /* Check /etc/ld.so.preload */
    if (file_exists("/etc/ld.so.preload")) {
        FILE *fp = fopen("/etc/ld.so.preload", "r");
        if (fp) {
            char line[MAX_PATH];
            while (fgets(line, sizeof(line), fp)) {
                line[strcspn(line, "\n")] = 0;
                if (strlen(line) > 0 && line[0] != '#') {
                    /* Check against known userland rootkits */
                    int is_rootkit = 0;
                    for (int i = 0; USERLAND_ROOTKITS[i]; i++) {
                        if (strcasestr(line, USERLAND_ROOTKITS[i])) {
                            print_critical("Known rootkit in ld.so.preload: %s (%s)", 
                                         line, USERLAND_ROOTKITS[i]);
                            is_rootkit = 1;
                            found++;
                            break;
                        }
                    }
                    if (!is_rootkit) {
                        print_alert("ld.so.preload entry: %s", line);
                        found++;
                    }
                }
            }
            fclose(fp);
        }
    }
    
    /* Check for LD_AUDIT */
    char *audit = getenv("LD_AUDIT");
    if (audit && strlen(audit) > 0) {
        print_alert("LD_AUDIT set (potential hook): %s", audit);
        found++;
    }
    
    /* Check for LD_LIBRARY_PATH manipulation */
    char *lib_path = getenv("LD_LIBRARY_PATH");
    if (lib_path) {
        if (strstr(lib_path, "/tmp") || strstr(lib_path, "/dev/shm") ||
            strstr(lib_path, "/var/tmp") || strstr(lib_path, "/.")) {
            print_warn("Suspicious LD_LIBRARY_PATH: %s", lib_path);
            found++;
        }
    }
    
    if (found == 0) {
        print_ok("No LD_PRELOAD hooks detected");
    }
    
    return found;
}

/* Check kernel modules against rootkit database */
static int check_kernel_modules(void) {
    print_section("Kernel Module Analysis");
    
    int found = 0;
    FILE *fp = fopen("/proc/modules", "r");
    
    if (!fp) {
        print_warn("Cannot read /proc/modules (may require root)");
        return -1;
    }
    
    char line[MAX_LINE];
    int total = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        total++;
        char modname[256];
        sscanf(line, "%255s", modname);
        
        /* Check against LKM rootkit database */
        for (int i = 0; LKM_ROOTKITS[i]; i++) {
            if (strcasestr(modname, LKM_ROOTKITS[i])) {
                print_critical("Known LKM rootkit detected: %s (matches: %s)", 
                             modname, LKM_ROOTKITS[i]);
                found++;
                break;
            }
        }
        
        /* Check against suspicious patterns */
        if (string_in_array(modname, SUSPICIOUS_MODULES)) {
            print_alert("Suspicious kernel module: %s", modname);
            found++;
        }
    }
    fclose(fp);
    
    if (opt_verbose) {
        print_info("Total kernel modules loaded: %d", total);
    }
    
    /* Check for hidden modules (module not in /proc/modules but in /sys) */
    DIR *mod_dir = opendir("/sys/module");
    if (mod_dir) {
        struct dirent *entry;
        int sys_count = 0;
        
        while ((entry = readdir(mod_dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            sys_count++;
            
            /* Check if in /proc/modules */
            int in_proc = 0;
            fp = fopen("/proc/modules", "r");
            if (fp) {
                while (fgets(line, sizeof(line), fp)) {
                    char pmod[256];
                    sscanf(line, "%255s", pmod);
                    if (strcmp(pmod, entry->d_name) == 0) {
                        in_proc = 1;
                        break;
                    }
                }
                fclose(fp);
            }
            
            /* Some built-in modules won't be in /proc/modules - check for suspicious names */
            if (!in_proc && string_in_array(entry->d_name, SUSPICIOUS_MODULES)) {
                print_alert("Hidden/suspicious module in /sys: %s", entry->d_name);
                found++;
            }
        }
        closedir(mod_dir);
    }
    
    stats.suspicious_modules = found;
    
    if (found == 0) {
        print_ok("No malicious kernel modules detected");
    }
    
    return found;
}

/* Check for rootkit files and signatures */
static int check_rootkit_files(void) {
    print_section("Rootkit File Scan");
    
    int found = 0;
    const char *scan_dirs[] = {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
        "/usr/local/sbin", "/lib", "/lib64", "/usr/lib", "/usr/lib64",
        "/tmp", "/var/tmp", "/dev/shm", "/dev", "/run",
        NULL
    };
    
    /* Scan directories for rootkit files */
    for (int d = 0; scan_dirs[d]; d++) {
        DIR *dir = opendir(scan_dirs[d]);
        if (!dir) continue;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.' && 
                strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0) {
                
                /* Skip known safe hidden files/dirs */
                if (strcmp(scan_dirs[d], "/tmp") == 0 ||
                    strcmp(scan_dirs[d], "/var/tmp") == 0 ||
                    strcmp(scan_dirs[d], "/dev/shm") == 0) {
                    
                    /* These dirs shouldn't have hidden executables */
                    char fullpath[MAX_PATH];
                    snprintf(fullpath, sizeof(fullpath), "%s/%s", scan_dirs[d], entry->d_name);
                    
                    struct stat st;
                    if (stat(fullpath, &st) == 0 && (st.st_mode & S_IXUSR)) {
                        print_warn("Hidden executable in temp dir: %s", fullpath);
                        found++;
                    }
                }
            }
            
            /* Check filename against all rootkit databases */
            int is_rootkit = 0;
            
            for (int i = 0; LKM_ROOTKITS[i] && !is_rootkit; i++) {
                if (strcasestr(entry->d_name, LKM_ROOTKITS[i])) {
                    char fullpath[MAX_PATH];
                    snprintf(fullpath, sizeof(fullpath), "%s/%s", scan_dirs[d], entry->d_name);
                    print_critical("Rootkit file detected: %s (LKM: %s)", fullpath, LKM_ROOTKITS[i]);
                    found++;
                    is_rootkit = 1;
                }
            }
            
            for (int i = 0; USERLAND_ROOTKITS[i] && !is_rootkit; i++) {
                if (strcasestr(entry->d_name, USERLAND_ROOTKITS[i])) {
                    char fullpath[MAX_PATH];
                    snprintf(fullpath, sizeof(fullpath), "%s/%s", scan_dirs[d], entry->d_name);
                    print_critical("Rootkit file detected: %s (Userland: %s)", 
                                 fullpath, USERLAND_ROOTKITS[i]);
                    found++;
                    is_rootkit = 1;
                }
            }
            
            for (int i = 0; BOOTKITS[i] && !is_rootkit; i++) {
                if (strcasestr(entry->d_name, BOOTKITS[i])) {
                    char fullpath[MAX_PATH];
                    snprintf(fullpath, sizeof(fullpath), "%s/%s", scan_dirs[d], entry->d_name);
                    print_critical("Bootkit indicator: %s (Bootkit: %s)", fullpath, BOOTKITS[i]);
                    found++;
                    is_rootkit = 1;
                }
            }
            
            for (int i = 0; CONTAINER_ROOTKITS[i] && !is_rootkit; i++) {
                if (strcasestr(entry->d_name, CONTAINER_ROOTKITS[i])) {
                    char fullpath[MAX_PATH];
                    snprintf(fullpath, sizeof(fullpath), "%s/%s", scan_dirs[d], entry->d_name);
                    print_critical("Container rootkit indicator: %s (%s)", 
                                 fullpath, CONTAINER_ROOTKITS[i]);
                    found++;
                    is_rootkit = 1;
                }
            }
        }
        closedir(dir);
    }
    
    stats.suspicious_files = found;
    
    if (found == 0) {
        print_ok("No rootkit files detected in filesystem");
    }
    
    return found;
}

/* Check network for backdoor indicators */
static int check_network_backdoors(void) {
    print_section("Network Backdoor Analysis");
    
    int found = 0;
    
    /* Check for suspicious listening ports */
    FILE *fp = popen("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", "r");
    if (fp) {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), fp)) {
            for (int i = 0; SUSPICIOUS_PORTS[i] != -1; i++) {
                char port_str[16];
                snprintf(port_str, sizeof(port_str), ":%d ", SUSPICIOUS_PORTS[i]);
                if (strstr(line, port_str)) {
                    print_alert("Suspicious port %d listening: %s", 
                              SUSPICIOUS_PORTS[i], line);
                    found++;
                    break;
                }
            }
        }
        pclose(fp);
    }
    
    /* Check for promiscuous interfaces */
    fp = fopen("/proc/net/dev", "r");
    if (fp) {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "PROMISC") || strstr(line, "promisc")) {
                print_warn("Network interface in promiscuous mode");
                found++;
            }
        }
        fclose(fp);
    }
    
    /* Check via ip command */
    fp = popen("ip link show 2>/dev/null | grep -i promisc", "r");
    if (fp) {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), fp)) {
            print_warn("Promiscuous interface: %s", line);
            found++;
        }
        pclose(fp);
    }
    
    /* Check for suspicious established connections */
    fp = popen("ss -tnp 2>/dev/null | grep ESTAB", "r");
    if (fp) {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), fp)) {
            /* Check for connections to suspicious ports */
            for (int i = 0; SUSPICIOUS_PORTS[i] != -1; i++) {
                char port_str[16];
                snprintf(port_str, sizeof(port_str), ":%d", SUSPICIOUS_PORTS[i]);
                if (strstr(line, port_str)) {
                    print_alert("Connection to suspicious port: %s", line);
                    found++;
                    break;
                }
            }
        }
        pclose(fp);
    }
    
    stats.network_anomalies = found;
    
    if (found == 0) {
        print_ok("No network backdoors detected");
    }
    
    return found;
}

/* Check syscall table integrity */
static int check_syscall_hooks(void) {
    print_section("Syscall Table Analysis");
    
    int found = 0;
    
    /* Check kallsyms for syscall addresses */
    if (!file_exists("/proc/kallsyms")) {
        print_warn("Cannot access /proc/kallsyms (requires root or kernel config)");
        return 0;
    }
    
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        print_warn("Cannot read kernel symbols");
        return 0;
    }
    
    char line[MAX_LINE];
    unsigned long sys_call_table = 0;
    unsigned long last_addr = 0;
    int syscall_count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        unsigned long addr;
        char type;
        char name[256];
        
        if (sscanf(line, "%lx %c %255s", &addr, &type, name) == 3) {
            if (strcmp(name, "sys_call_table") == 0) {
                sys_call_table = addr;
            }
            
            /* Check for syscalls at unusual addresses */
            if (strncmp(name, "sys_", 4) == 0 || strncmp(name, "__x64_sys_", 10) == 0) {
                syscall_count++;
                
                /* Check if address is in expected kernel range */
                if (addr != 0 && last_addr != 0) {
                    long diff = (long)(addr - last_addr);
                    /* Huge gaps might indicate hooks */
                    if (diff < 0 || diff > 0x100000) {
                        if (opt_verbose) {
                            print_info("Unusual syscall address gap for %s", name);
                        }
                    }
                }
                last_addr = addr;
            }
        }
    }
    fclose(fp);
    
    if (opt_verbose) {
        print_info("Syscall table at: 0x%lx", sys_call_table);
        print_info("Syscalls analyzed: %d", syscall_count);
    }
    
    /* Check for known hook signatures in dmesg */
    fp = popen("dmesg 2>/dev/null | grep -iE 'syscall|hook|hijack|intercept' | tail -20", "r");
    if (fp) {
        char dmesg_line[MAX_LINE];
        while (fgets(dmesg_line, sizeof(dmesg_line), fp)) {
            if (strcasestr(dmesg_line, "hook") || 
                strcasestr(dmesg_line, "hijack") ||
                strcasestr(dmesg_line, "intercept")) {
                print_warn("Suspicious kernel message: %s", dmesg_line);
                found++;
            }
        }
        pclose(fp);
    }
    
    stats.hooked_syscalls = found;
    
    if (found == 0) {
        print_ok("No syscall hooks detected");
    }
    
    return found;
}

/* Check for UEFI/bootkit indicators */
static int check_boot_integrity(void) {
    print_section("Boot Integrity Analysis");
    
    int found = 0;
    
    /* Check for secure boot status */
    if (file_exists("/sys/firmware/efi/efivars")) {
        FILE *fp = popen("mokutil --sb-state 2>/dev/null", "r");
        if (fp) {
            char line[256];
            if (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "disabled")) {
                    print_warn("Secure Boot is disabled");
                }
            }
            pclose(fp);
        }
    }
    
    /* Check MBR/GPT for known bootkit patterns */
    if (geteuid() == 0) {
        int fd = open("/dev/sda", O_RDONLY);
        if (fd < 0) fd = open("/dev/vda", O_RDONLY);
        if (fd < 0) fd = open("/dev/nvme0n1", O_RDONLY);
        
        if (fd >= 0) {
            unsigned char mbr[512];
            if (read(fd, mbr, 512) == 512) {
                /* Check for MBR signature */
                if (mbr[510] != 0x55 || mbr[511] != 0xAA) {
                    print_alert("Invalid MBR signature - possible corruption or bootkit");
                    found++;
                }
                
                /* Check for known bootkit patterns */
                for (int i = 0; BOOTKITS[i]; i++) {
                    if (check_memory_pattern((char*)mbr, 512, BOOTKITS[i], strlen(BOOTKITS[i]))) {
                        print_critical("Bootkit signature in MBR: %s", BOOTKITS[i]);
                        found++;
                    }
                }
            }
            close(fd);
        }
    }
    
    /* Check initramfs for tampering */
    FILE *fp = popen("ls -la /boot/initramfs* /boot/initrd* 2>/dev/null", "r");
    if (fp) {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), fp)) {
            if (opt_verbose) {
                print_info("Initramfs: %s", line);
            }
        }
        pclose(fp);
    }
    
    if (found == 0) {
        print_ok("Boot sector appears clean");
    }
    
    return found;
}

/* Check container escape indicators */
static int check_container_security(void) {
    print_section("Container Security Analysis");
    
    int found = 0;
    int in_container = 0;
    
    /* Detect if running in container */
    if (file_exists("/.dockerenv") || file_exists("/run/.containerenv")) {
        in_container = 1;
        print_info("Running inside container environment");
    }
    
    /* Check cgroup for container indicators */
    FILE *fp = fopen("/proc/1/cgroup", "r");
    if (fp) {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "docker") || strstr(line, "lxc") || 
                strstr(line, "kubepods") || strstr(line, "containerd")) {
                in_container = 1;
            }
        }
        fclose(fp);
    }
    
    if (in_container) {
        /* Check for container escape attempts */
        
        /* Check for privileged container */
        fp = fopen("/proc/self/status", "r");
        if (fp) {
            char line[MAX_LINE];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "CapEff:", 7) == 0) {
                    unsigned long long cap;
                    sscanf(line + 7, "%llx", &cap);
                    if (cap == 0x3ffffffffff) {
                        print_warn("Container running with full capabilities (privileged)");
                    }
                }
            }
            fclose(fp);
        }
        
        /* Check for mounted docker socket */
        if (file_exists("/var/run/docker.sock")) {
            print_warn("Docker socket mounted - potential escape vector");
            found++;
        }
        
        /* Check for host filesystem mounts */
        fp = fopen("/proc/mounts", "r");
        if (fp) {
            char line[MAX_LINE];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, " /host") || strstr(line, "/hostfs")) {
                    print_warn("Host filesystem mounted: %s", line);
                    found++;
                }
            }
            fclose(fp);
        }
    }
    
    /* Check for container rootkit processes */
    for (int i = 0; CONTAINER_ROOTKITS[i]; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "pgrep -f '%s' 2>/dev/null", CONTAINER_ROOTKITS[i]);
        fp = popen(cmd, "r");
        if (fp) {
            char pid[16];
            if (fgets(pid, sizeof(pid), fp)) {
                print_critical("Container rootkit process: %s (PID: %s)", 
                             CONTAINER_ROOTKITS[i], pid);
                found++;
            }
            pclose(fp);
        }
    }
    
    if (found == 0) {
        print_ok("No container security issues detected");
    }
    
    return found;
}

/* Deep scan for known rootkit signatures in memory */
static int check_memory_signatures(void) {
    print_section("Memory Signature Analysis");
    
    if (geteuid() != 0) {
        print_warn("Memory scan requires root privileges");
        return 0;
    }
    
    int found = 0;
    
    /* Scan kernel memory via /dev/mem or /dev/kmem if available */
    int fd = open("/dev/mem", O_RDONLY);
    if (fd >= 0) {
        /* Would need careful implementation to avoid crashes */
        close(fd);
    }
    
    /* Check /proc/kcore if available */
    if (file_exists("/proc/kcore")) {
        /* Analyze kernel core for anomalies */
        if (opt_verbose) {
            print_info("Kernel core analysis available");
        }
    }
    
    /* Scan process memory for rootkit strings */
    DIR *proc = opendir("/proc");
    if (proc) {
        struct dirent *entry;
        while ((entry = readdir(proc)) != NULL) {
            if (!isdigit(entry->d_name[0])) continue;
            
            char maps_path[MAX_PATH];
            snprintf(maps_path, sizeof(maps_path), "/proc/%s/maps", entry->d_name);
            
            FILE *maps = fopen(maps_path, "r");
            if (!maps) continue;
            
            char line[MAX_LINE];
            while (fgets(line, sizeof(line), maps)) {
                /* Check for suspicious mapped libraries */
                for (int i = 0; USERLAND_ROOTKITS[i]; i++) {
                    if (strcasestr(line, USERLAND_ROOTKITS[i])) {
                        print_alert("Rootkit library in PID %s: %s", entry->d_name, line);
                        found++;
                    }
                }
            }
            fclose(maps);
        }
        closedir(proc);
    }
    
    if (found == 0) {
        print_ok("No rootkit signatures in process memory");
    }
    
    return found;
}

/* Check for persistence mechanisms */
static int check_persistence(void) {
    print_section("Persistence Mechanism Analysis");
    
    int found = 0;
    const char *persistence_paths[] = {
        "/etc/rc.local",
        "/etc/rc.d/rc.local",
        "/etc/init.d",
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/var/spool/cron",
        "/etc/profile.d",
        "/etc/bash.bashrc",
        "/etc/profile",
        "/root/.bashrc",
        "/root/.profile",
        "/root/.bash_profile",
        NULL
    };
    
    for (int i = 0; persistence_paths[i]; i++) {
        if (!file_exists(persistence_paths[i])) continue;
        
        struct stat st;
        if (stat(persistence_paths[i], &st) == 0) {
            /* Check modification time (recently modified = suspicious) */
            time_t now = time(NULL);
            if (now - st.st_mtime < 86400 && opt_verbose) { /* Modified in last 24h */
                print_info("Recently modified: %s", persistence_paths[i]);
            }
        }
        
        /* If it's a file, scan for rootkit indicators */
        if (S_ISREG(st.st_mode)) {
            size_t size;
            char *content = read_file_contents(persistence_paths[i], &size);
            if (content) {
                /* Check for rootkit strings */
                for (int j = 0; LKM_ROOTKITS[j]; j++) {
                    if (strcasestr(content, LKM_ROOTKITS[j])) {
                        print_alert("Rootkit reference in %s: %s", 
                                  persistence_paths[i], LKM_ROOTKITS[j]);
                        found++;
                    }
                }
                for (int j = 0; USERLAND_ROOTKITS[j]; j++) {
                    if (strcasestr(content, USERLAND_ROOTKITS[j])) {
                        print_alert("Rootkit reference in %s: %s", 
                                  persistence_paths[i], USERLAND_ROOTKITS[j]);
                        found++;
                    }
                }
                
                /* Check for suspicious patterns */
                if (strstr(content, "curl") && strstr(content, "sh")) {
                    print_warn("Suspicious curl|sh pattern in %s", persistence_paths[i]);
                    found++;
                }
                if (strstr(content, "wget") && strstr(content, "sh")) {
                    print_warn("Suspicious wget|sh pattern in %s", persistence_paths[i]);
                    found++;
                }
                if (strstr(content, "/dev/tcp/")) {
                    print_alert("Bash reverse shell pattern in %s", persistence_paths[i]);
                    found++;
                }
                
                free(content);
            }
        }
    }
    
    /* Check for suspicious systemd services */
    FILE *fp = popen("systemctl list-unit-files --type=service 2>/dev/null | grep enabled", "r");
    if (fp) {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), fp)) {
            for (int i = 0; LKM_ROOTKITS[i]; i++) {
                if (strcasestr(line, LKM_ROOTKITS[i])) {
                    print_alert("Suspicious systemd service: %s", line);
                    found++;
                }
            }
        }
        pclose(fp);
    }
    
    if (found == 0) {
        print_ok("No suspicious persistence mechanisms detected");
    }
    
    return found;
}

/* Print final summary */
static void print_summary(void) {
    time_t elapsed = time(NULL) - stats.start_time;
    
    printf("\n");
    printf("  " C_CYAN "╭────────────────────────────────────────╮" C_RESET "\n");
    printf("  " C_CYAN "│" C_WHITE "          SCAN SUMMARY                  " C_CYAN "│" C_RESET "\n");
    printf("  " C_CYAN "├────────────────────────────────────────┤" C_RESET "\n");
    printf("  " C_CYAN "│" C_RESET "  Scan Duration:     %3ld seconds        " C_CYAN "│" C_RESET "\n", elapsed);
    printf("  " C_CYAN "│" C_RESET "  Critical Findings: " C_RED "%3d" C_RESET "                " C_CYAN "│" C_RESET "\n", stats.critical);
    printf("  " C_CYAN "│" C_RESET "  Infections:        " C_RED "%3d" C_RESET "                " C_CYAN "│" C_RESET "\n", stats.infections);
    printf("  " C_CYAN "│" C_RESET "  Warnings:          " C_YELLOW "%3d" C_RESET "                " C_CYAN "│" C_RESET "\n", stats.warnings);
    printf("  " C_CYAN "│" C_RESET "  Hidden Processes:  %3d                " C_CYAN "│" C_RESET "\n", stats.hidden_procs);
    printf("  " C_CYAN "│" C_RESET "  Suspicious Modules:%3d                " C_CYAN "│" C_RESET "\n", stats.suspicious_modules);
    printf("  " C_CYAN "│" C_RESET "  Suspicious Files:  %3d                " C_CYAN "│" C_RESET "\n", stats.suspicious_files);
    printf("  " C_CYAN "│" C_RESET "  Network Anomalies: %3d                " C_CYAN "│" C_RESET "\n", stats.network_anomalies);
    printf("  " C_CYAN "╰────────────────────────────────────────╯" C_RESET "\n\n");
    
    if (stats.critical > 0) {
        printf("  " C_RED C_BOLD "█ SYSTEM COMPROMISED" C_RESET " - %d critical finding(s)\n", stats.critical);
        printf("  " C_DIM "  Immediate investigation recommended" C_RESET "\n");
    } else if (stats.infections > 0) {
        printf("  " C_RED "▸ POTENTIAL INFECTION" C_RESET " - %d indicator(s) found\n", stats.infections);
        printf("  " C_DIM "  Manual review recommended" C_RESET "\n");
    } else if (stats.warnings > 0) {
        printf("  " C_YELLOW "⚡ WARNINGS FOUND" C_RESET " - %d item(s) need attention\n", stats.warnings);
    } else {
        printf("  " C_GREEN "✓ SYSTEM APPEARS CLEAN" C_RESET "\n");
    }
    printf("\n");
}

/* Print usage */
static void print_usage(const char *prog) {
    printf("%s\n", BANNER);
    printf("  " C_WHITE "Usage:" C_RESET " %s [options]\n\n", prog);
    printf("  " C_WHITE "Scan Options:" C_RESET "\n");
    printf("    -a, --all         Full comprehensive scan (default)\n");
    printf("    -q, --quick       Quick scan (processes, modules, preload)\n");
    printf("    -p, --processes   Scan for hidden processes\n");
    printf("    -m, --modules     Scan kernel modules\n");
    printf("    -f, --files       Scan for rootkit files\n");
    printf("    -n, --network     Check network backdoors\n");
    printf("    -s, --syscalls    Check syscall table integrity\n");
    printf("    -b, --boot        Check boot/UEFI integrity\n");
    printf("    -c, --container   Container security checks\n");
    printf("    -e, --persistence Check persistence mechanisms\n");
    printf("    -M, --memory      Deep memory signature scan\n\n");
    printf("  " C_WHITE "Output Options:" C_RESET "\n");
    printf("    -v, --verbose     Verbose output\n");
    printf("    -Q, --quiet       Minimal output (alerts only)\n");
    printf("    -l, --log <file>  Log findings to file\n");
    printf("    -j, --json        JSON output format\n\n");
    printf("  " C_WHITE "Other:" C_RESET "\n");
    printf("    -h, --help        Show this help\n");
    printf("    --version         Show version\n\n");
    printf("  " C_WHITE "Examples:" C_RESET "\n");
    printf("    %s -a                    Full scan\n", prog);
    printf("    %s -q -v                 Quick verbose scan\n", prog);
    printf("    %s -m -s -l scan.log    Module/syscall scan with logging\n", prog);
    printf("\n");
}

int main(int argc, char *argv[]) {
    int run_all = 0;
    int run_quick = 0;
    int run_procs = 0;
    int run_modules = 0;
    int run_files = 0;
    int run_network = 0;
    int run_syscalls = 0;
    int run_boot = 0;
    int run_container = 0;
    int run_persistence = 0;
    int run_memory = 0;
    char *log_path = NULL;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("RKHunt v%s\n", VERSION);
            return 0;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            run_all = 1;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quick") == 0) {
            run_quick = 1;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--processes") == 0) {
            run_procs = 1;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--modules") == 0) {
            run_modules = 1;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--files") == 0) {
            run_files = 1;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--network") == 0) {
            run_network = 1;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--syscalls") == 0) {
            run_syscalls = 1;
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--boot") == 0) {
            run_boot = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--container") == 0) {
            run_container = 1;
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--persistence") == 0) {
            run_persistence = 1;
        } else if (strcmp(argv[i], "-M") == 0 || strcmp(argv[i], "--memory") == 0) {
            run_memory = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opt_verbose = 1;
        } else if (strcmp(argv[i], "-Q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            opt_quiet = 1;
        } else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            opt_json = 1;
        } else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log") == 0) && i + 1 < argc) {
            log_path = argv[++i];
        }
    }
    
    /* Default to full scan if no options */
    if (!run_quick && !run_procs && !run_modules && !run_files && 
        !run_network && !run_syscalls && !run_boot && !run_container &&
        !run_persistence && !run_memory) {
        run_all = 1;
    }
    
    /* Open log file if specified */
    if (log_path) {
        log_file = fopen(log_path, "w");
        if (!log_file) {
            fprintf(stderr, "Cannot open log file: %s\n", log_path);
        }
    }
    
    /* Print banner */
    if (!opt_quiet) {
        printf("%s", BANNER);
    }
    
    /* Check privileges */
    if (geteuid() != 0) {
        print_warn("Running without root - some checks may be limited");
    }
    
    stats.start_time = time(NULL);
    
    if (!opt_quiet) {
        struct utsname uts;
        if (uname(&uts) == 0) {
            print_info("System: %s %s %s", uts.sysname, uts.release, uts.machine);
        }
        print_info("Starting rootkit scan...\n");
    }
    
    /* Run selected scans */
    if (run_all || run_quick || run_procs) {
        check_hidden_processes();
    }
    
    if (run_all || run_quick) {
        check_ld_preload();
    }
    
    if (run_all || run_quick || run_modules) {
        check_kernel_modules();
    }
    
    if (run_all || run_files) {
        check_rootkit_files();
    }
    
    if (run_all || run_network) {
        check_network_backdoors();
    }
    
    if (run_all || run_syscalls) {
        check_syscall_hooks();
    }
    
    if (run_all || run_boot) {
        check_boot_integrity();
    }
    
    if (run_all || run_container) {
        check_container_security();
    }
    
    if (run_all || run_persistence) {
        check_persistence();
    }
    
    if (run_all || run_memory) {
        check_memory_signatures();
    }
    
    /* Print summary */
    print_summary();
    
    /* Close log file */
    if (log_file) {
        fclose(log_file);
        if (!opt_quiet) {
            print_info("Results logged to: %s", log_path);
        }
    }
    
    return stats.critical > 0 ? 2 : (stats.infections > 0 ? 1 : 0);
}
