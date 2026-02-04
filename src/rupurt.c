/*
 * NullSec Rupurt v2.5 - Advanced Rootkit Hunter
 * Comprehensive rootkit detection with extensive signature database
 * 
 * Compile: gcc -O2 -Wall -D_GNU_SOURCE -o rupurt rupurt.c -lpthread -lcrypto
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
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <linux/netlink.h>
#include <elf.h>
#include <dlfcn.h>
#include <link.h>
#include <glob.h>
#include <sched.h>
#include <sys/resource.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

#define VERSION "2.5.0"
#define MAX_PATH 4096
#define MAX_LINE 8192
#define MAX_SIGS 512
#define HASH_SIZE 64

/* ANSI Colors - subtle output */
#define C_RED     "\x1b[38;5;196m"
#define C_GREEN   "\x1b[38;5;82m"
#define C_YELLOW  "\x1b[38;5;220m"
#define C_CYAN    "\x1b[38;5;51m"
#define C_MAGENTA "\x1b[38;5;201m"
#define C_ORANGE  "\x1b[38;5;208m"
#define C_GRAY    "\x1b[38;5;245m"
#define C_WHITE   "\x1b[38;5;255m"
#define C_DIM     "\x1b[2m"
#define C_BOLD    "\x1b[1m"
#define C_RESET   "\x1b[0m"

/* Severity Levels */
#define SEV_INFO     0
#define SEV_LOW      1
#define SEV_MEDIUM   2
#define SEV_HIGH     3
#define SEV_CRITICAL 4

/* Banner - minimal and professional */
static const char *BANNER = 
C_CYAN "  ╭──────────────────────────────────────────╮\n"
"  │" C_WHITE "  Rupurt " C_DIM "v2.5" C_CYAN "  │  " C_GRAY "Advanced Rootkit Hunter" C_CYAN "  │\n"
"  │" C_DIM "     github.com/bad-antics/nullsec-rupurt" C_CYAN " │\n"
"  ╰──────────────────────────────────────────╯" C_RESET "\n";

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * COMPREHENSIVE ROOTKIT DATABASE v2.5
 * Sources: Security research, MITRE ATT&CK, public disclosures, APT reports
 * Total signatures: 200+
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Linux Kernel Rootkits (LKM) - 70+ signatures */
static const char *LKM_ROOTKITS[] = {
    /* Modern/Active (2020+) */
    "singularity", "reptile", "diamorphine", "suterusu", "kovid",
    "nurupo", "bdvl", "beurk", "azazel", "jynx2", "vlany",
    "horsepill", "drovorub", "facefish", "skidmap", "pandora",
    "umbreon", "keysniffer", "r77", "fontanini", "kbeast",
    "rkspotter", "rkorova", "khook", "lkm_rootkit", "nuk3gh0st",
    "icehide", "brokepkg", "reveng_rtkit", "medusa_lkm",
    "spectre_lkm", "phantom_lkm", "venom_rootkit", "hydra_lkm",
    
    /* Historic/Research */
    "adore", "adore-ng", "knark", "synapsys", "heroine",
    "suckit", "shv4", "shv5", "shv6", "rkit", "rkh", "lrk", "lrk3",
    "lrk4", "lrk5", "lrk6", "t0rn", "ambient", "phalanx",
    "phalanx2", "phantasmagoria", "snakso", "mood-nt",
    "override", "rial", "rsha", "enyelkm", "kbdv3",
    "superkit", "all-root", "kbd-mod", "hp-ux", "solaris_module",
    "kis", "lvtes", "moodnt", "optic_kit", "ramen", "omega",
    
    /* APT/Nation-State */
    "turla", "uroburos", "snake", "carbon", "penquin", "penguin_turla",
    "equation", "equationgroup", "regin", "hive", "bvp47", "dirtycow_lkm",
    "drovorub_kernel", "winnti_lkm", "lazarus_lkm", "apt28_lkm",
    "apt29_lkm", "cozy_duke", "fancy_bear", "sandworm_lkm",
    "sofacy", "grizzly_steppe", "energetic_bear", "palmetto_fusion",
    "lightning_framework", "symbiote", "orbit_lkm", "shikitega",
    
    /* eBPF-based rootkits */
    "ebpfkit", "pamspy", "boopkit", "bad_bpf", "bpf_rootkit",
    "triton_ebpf", "ebpf_exfil", "bpfdoor", "bpf_backdoor",
    NULL
};

/* Userland Rootkits (LD_PRELOAD) - 35+ signatures */
static const char *USERLAND_ROOTKITS[] = {
    "jynx", "jynx2", "jynx3", "azazel", "azazel2", "vlany", "beurk",
    "bdvl", "bdvl2", "libprocesshider", "apache_backdoor", "cub3",
    "erebus", "ld_poison", "preload_hook", "prochide", "processhider",
    "umbreon_user", "libc_hook", "glibc_hook", "libselinux_fake",
    "fakeld", "evil_preload", "stealth_preload", "rootsh",
    "ld_backdoor", "libmimikatz", "pam_backdoor", "nss_backdoor",
    "openssh_backdoor", "libkeyutils_backdoor", "xorddos_preload",
    "chinaz_preload", "setuid_backdoor", "setgid_backdoor",
    NULL
};

/* Bootkits - 35+ signatures */
static const char *BOOTKITS[] = {
    /* Modern UEFI */
    "blacklotus", "cosmicstrand", "moonbounce", "especter", "vector_edk",
    "lojax", "finspy_bootkit", "mosaic_regressor", "trickbot_uefi",
    "thunderstrike", "thunderstrike2", "hacking_team_uefi",
    "lighteater", "dreamboot", "rkloader", "uefi_implant",
    
    /* Legacy MBR/VBR */
    "rovnix", "carberp", "tdss", "tdl", "tdl2", "tdl3", "tdl4",
    "olmarik", "sinowal", "torpig", "mebroot", "stoned", "stone",
    "alureon", "gapz", "bootrash", "bootkit", "vbootkit",
    "grayfish", "finfisher_bootkit", "hdroot", "nemesis",
    "petya_bootkit", "satana", "cidox", "pihar", "zeroaccess",
    NULL
};

/* Container/Cloud Rootkits - 25+ signatures */
static const char *CONTAINER_ROOTKITS[] = {
    /* Cryptomining */
    "kinsing", "teamtnt", "watchdog", "graboid", "pro_ocean",
    "lemon_duck", "z0miner", "xanthe", "cetus", "autom",
    
    /* Backdoors */
    "doki", "hildegard", "siloscape", "azurescape", "cr8escape",
    "kubernetes_backdoor", "docker_escape", "cgroup_escape",
    "container_drift", "malicious_admission", "pod_escape",
    "kube_hunter_exp", "peirates", "kubeletctl_exp",
    
    /* Cloud-specific */
    "awscli_backdoor", "gcp_backdoor", "azure_backdoor",
    "cloud_credential_stealer", "metadata_thief", "imds_exfil",
    NULL
};

/* BPF/eBPF specific detection patterns */
static const char *EBPF_THREATS[] = {
    "bpf_probe_write_user", "bpf_override_return", "bpf_send_signal",
    "bpf_sys_bpf", "tracepoint_probe", "kprobe_hijack",
    "xdp_drop_stealth", "tc_redirect_hidden", "cgroup_skb_hidden",
    "raw_tracepoint_backdoor", "fentry_hook", "fexit_hook",
    "bpf_map_hidden", "ringbuf_exfil", "perfbuf_exfil",
    NULL
};

/* Suspicious Kernel Module Patterns */
static const char *SUSPICIOUS_MODULES[] = {
    "rootkit", "hidden", "stealth", "invisible", "hide", "hider",
    "cloak", "phantom", "ghost", "shadow", "backdoor", "shell",
    "keylog", "sniffer", "hook", "inject", "hijack", "hijacker",
    "intercept", "bypass", "elevate", "escalate", "priv", "privilege",
    "syscall_hook", "vfs_hook", "netfilter_hook", "ipt_hook",
    "xor_key", "decrypt_mod", "crypt_mod", "encode_mod",
    "rev_shell", "bind_shell", "remote_access", "rat_mod", "c2_mod",
    "miner", "cryptominer", "xmrig_mod", "monero_mod", "coin_mod",
    "exfil", "data_steal", "cred_dump", "passwd_grab",
    NULL
};

/* Known backdoor ports */
static const int SUSPICIOUS_PORTS[] = {
    31337, 31338, 12345, 12346, 27374, 27665, 20034, 1243,
    6667, 6666, 6668, 6669,  /* IRC */
    4444, 4445, 5555, 5554,  /* Metasploit default */
    8080, 8443, 9001, 9030,  /* Tor/proxies */
    2222, 2223, 3333, 1337,  /* Alt SSH/misc */
    41524, 55553, 50050,     /* RATs */
    6697, 7000, 9999, 65535, /* Various */
    0
};

/* File signatures for binary detection */
typedef struct {
    const char *name;
    const unsigned char *pattern;
    size_t offset;
    size_t len;
    int severity;
} signature_t;

/* Binary signatures (hex patterns) */
static const signature_t FILE_SIGNATURES[] = {
    {"Reptile LKM", (const unsigned char*)"reptile", 0, 7, SEV_CRITICAL},
    {"Diamorphine", (const unsigned char*)"diamorphine", 0, 11, SEV_CRITICAL},
    {"Suterusu", (const unsigned char*)"suterusu", 0, 8, SEV_CRITICAL},
    {"Kovid LKM", (const unsigned char*)"kovid", 0, 5, SEV_CRITICAL},
    {"Jynx2", (const unsigned char*)"JYNX2", 0, 5, SEV_CRITICAL},
    {"Azazel", (const unsigned char*)"AZAZEL", 0, 6, SEV_CRITICAL},
    {"BDVl", (const unsigned char*)"bdvl", 0, 4, SEV_CRITICAL},
    {"Singularity", (const unsigned char*)"singularity", 0, 11, SEV_CRITICAL},
    {"Drovorub", (const unsigned char*)"drovorub", 0, 8, SEV_CRITICAL},
    {"eBPFkit", (const unsigned char*)"ebpfkit", 0, 7, SEV_CRITICAL},
    {"BPFDoor", (const unsigned char*)"bpfdoor", 0, 7, SEV_CRITICAL},
    {"Symbiote", (const unsigned char*)"symbiote", 0, 8, SEV_CRITICAL},
    {NULL, NULL, 0, 0, 0}
};

/* Suspicious directories */
static const char *SUSPICIOUS_DIRS[] = {
    "/dev/shm/.", "/tmp/.", "/var/tmp/.", "/run/.",
    "/.hidden", "/root/.", "/.cache/.",
    "/dev/.blkid", "/dev/.udev", "/dev/.initramfs",
    "/usr/share/.", "/usr/lib/.", "/lib/.",
    "/etc/.", "/var/lib/.", "/opt/.",
    NULL
};

/* Critical system files to hash-check */
static const char *INTEGRITY_FILES[] = {
    "/bin/ls", "/bin/ps", "/bin/netstat", "/bin/ss",
    "/bin/login", "/bin/su", "/bin/sudo", "/bin/passwd",
    "/usr/bin/ssh", "/usr/bin/sshd", "/usr/bin/top",
    "/usr/bin/find", "/usr/bin/lsof", "/usr/bin/w",
    "/sbin/ifconfig", "/sbin/init", "/sbin/insmod",
    "/sbin/modprobe", "/sbin/rmmod", "/sbin/lsmod",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/lib/x86_64-linux-gnu/libpam.so.0",
    NULL
};

/* Known library hijack targets */
static const char *HIJACK_LIBS[] = {
    "libkeyutils.so", "libselinux.so", "libcrypt.so",
    "libc.so.6", "libdl.so.2", "libpthread.so.0",
    "libpam.so", "libnss_files.so", "libnss_compat.so",
    "libsystemd.so", "libutil.so", "libcap.so",
    NULL
};

/* Process hiding techniques */
static const char *PROC_HIDING_INDICATORS[] = {
    "/proc/sys/kernel/modules_disabled",
    "/proc/sys/kernel/kptr_restrict",
    "/sys/module/*/holders",
    "/sys/kernel/debug/tracing/available_filter_functions",
    NULL
};

/* Global stats */
static struct {
    int total_checks;
    int critical;
    int high;
    int medium;
    int low;
    int infections;
    int warnings;
    int hidden_procs;
    int suspicious_modules;
    int suspicious_files;
    int network_anomalies;
    int integrity_failures;
    int ebpf_threats;
    int persistence_found;
    time_t start_time;
} stats = {0};

/* Options */
static int opt_verbose = 0;
static int opt_quiet = 0;
static int opt_json = 0;
static int opt_hash_check = 0;
static int opt_deep_scan = 0;
static FILE *log_file = NULL;

/* Forward declarations */
static void print_finding(int severity, const char *category, const char *fmt, ...);
static void print_info(const char *fmt, ...);
static void print_warn(const char *fmt, ...);

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * UTILITY FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════
 */

static const char *severity_str(int sev) {
    switch(sev) {
        case SEV_INFO: return C_GRAY "INFO" C_RESET;
        case SEV_LOW: return C_GREEN "LOW" C_RESET;
        case SEV_MEDIUM: return C_YELLOW "MEDIUM" C_RESET;
        case SEV_HIGH: return C_ORANGE "HIGH" C_RESET;
        case SEV_CRITICAL: return C_RED C_BOLD "CRITICAL" C_RESET;
        default: return "UNKNOWN";
    }
}

static void print_finding(int severity, const char *category, const char *fmt, ...) {
    va_list args;
    char msg[MAX_LINE];
    
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    switch(severity) {
        case SEV_CRITICAL: stats.critical++; break;
        case SEV_HIGH: stats.high++; break;
        case SEV_MEDIUM: stats.medium++; break;
        case SEV_LOW: stats.low++; break;
    }
    
    if (severity >= SEV_HIGH) stats.infections++;
    if (severity >= SEV_MEDIUM) stats.warnings++;
    
    if (opt_json) {
        printf("{\"severity\":\"%s\",\"category\":\"%s\",\"message\":\"%s\"}\n",
               severity == SEV_CRITICAL ? "critical" : 
               severity == SEV_HIGH ? "high" :
               severity == SEV_MEDIUM ? "medium" :
               severity == SEV_LOW ? "low" : "info",
               category, msg);
    } else if (!opt_quiet || severity >= SEV_HIGH) {
        const char *icon = severity >= SEV_CRITICAL ? "█" :
                          severity >= SEV_HIGH ? "▸" :
                          severity >= SEV_MEDIUM ? "▹" : "·";
        printf("  %s [%s] %s%s%s: %s\n", 
               severity >= SEV_CRITICAL ? C_RED : 
               severity >= SEV_HIGH ? C_ORANGE :
               severity >= SEV_MEDIUM ? C_YELLOW : C_GRAY,
               category, C_RESET, icon, C_RESET, msg);
    }
    
    if (log_file) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] [%s] %s\n",
                t->tm_year+1900, t->tm_mon+1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec,
                severity == SEV_CRITICAL ? "CRITICAL" : 
                severity == SEV_HIGH ? "HIGH" :
                severity == SEV_MEDIUM ? "MEDIUM" :
                severity == SEV_LOW ? "LOW" : "INFO",
                category, msg);
    }
}

static void print_info(const char *fmt, ...) {
    if (opt_quiet) return;
    
    va_list args;
    va_start(args, fmt);
    printf("  " C_CYAN "▸" C_RESET " ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void print_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("  " C_YELLOW "⚠" C_RESET " ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void print_section(const char *name) {
    if (!opt_quiet && !opt_json) {
        printf("\n  " C_CYAN "─────" C_RESET " %s " C_CYAN "─────" C_RESET "\n", name);
    }
}

static int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static int read_file_content(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, size - 1, f);
    buf[n] = 0;
    fclose(f);
    return n;
}

static int string_in_array(const char *str, const char **arr) {
    for (int i = 0; arr[i]; i++) {
        if (strcasestr(str, arr[i])) return 1;
    }
    return 0;
}

static unsigned long simple_hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * DETECTION MODULES
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Check for hidden processes by comparing /proc enumeration with kill() */
static int check_hidden_processes(void) {
    print_section("Process Analysis");
    stats.total_checks++;
    
    int found_hidden = 0;
    int max_pid = 0;
    char path[MAX_PATH];
    
    /* Get max PID */
    FILE *f = fopen("/proc/sys/kernel/pid_max", "r");
    if (f) {
        fscanf(f, "%d", &max_pid);
        fclose(f);
    }
    if (max_pid <= 0) max_pid = 65536;
    if (max_pid > 400000) max_pid = 400000;  /* Reasonable limit */
    
    int proc_count = 0;
    int kill_count = 0;
    
    /* Count via /proc */
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
                proc_count++;
            }
        }
        closedir(dir);
    }
    
    /* Count via kill(pid, 0) - only sample for performance */
    int sample_step = max_pid > 100000 ? 10 : 1;
    for (int pid = 1; pid < max_pid; pid += sample_step) {
        if (kill(pid, 0) == 0 || errno == EPERM) {
            kill_count++;
            
            /* Check if hidden from /proc */
            snprintf(path, sizeof(path), "/proc/%d", pid);
            if (access(path, F_OK) != 0) {
                found_hidden++;
                stats.hidden_procs++;
                print_finding(SEV_CRITICAL, "HIDDEN_PROC", 
                    "PID %d exists but hidden from /proc", pid);
                
                /* Try to get more info */
                if (opt_verbose) {
                    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
                    char cmdline[256] = {0};
                    if (read_file_content(path, cmdline, sizeof(cmdline)) > 0) {
                        print_finding(SEV_HIGH, "HIDDEN_PROC", "  Cmdline: %s", cmdline);
                    }
                }
            }
        }
    }
    
    if (sample_step > 1) kill_count *= sample_step;
    
    /* Check for significant discrepancy */
    int diff = abs(kill_count - proc_count);
    if (diff > 50) {
        print_finding(SEV_MEDIUM, "PROC_COUNT", 
            "Process count discrepancy: /proc=%d, kill=%d (diff=%d)", 
            proc_count, kill_count, diff);
    } else if (opt_verbose) {
        print_info("Process count: /proc=%d, verified=%d", proc_count, kill_count);
    }
    
    /* Check for process namespace manipulation */
    if (file_exists("/proc/1/ns/pid")) {
        char ns_self[64], ns_init[64];
        ssize_t n1 = readlink("/proc/self/ns/pid", ns_self, sizeof(ns_self)-1);
        ssize_t n2 = readlink("/proc/1/ns/pid", ns_init, sizeof(ns_init)-1);
        if (n1 > 0 && n2 > 0) {
            ns_self[n1] = 0;
            ns_init[n2] = 0;
            if (strcmp(ns_self, ns_init) != 0) {
                print_finding(SEV_LOW, "NAMESPACE", 
                    "Running in different PID namespace than init");
            }
        }
    }
    
    if (found_hidden == 0 && !opt_quiet) {
        print_info("No hidden processes detected");
    }
    
    return found_hidden;
}

/* Check LD_PRELOAD and library injection */
static int check_ld_preload(void) {
    print_section("Library Injection");
    stats.total_checks++;
    
    int threats = 0;
    char buf[MAX_LINE];
    
    /* Check LD_PRELOAD environment */
    char *preload = getenv("LD_PRELOAD");
    if (preload && strlen(preload) > 0) {
        print_finding(SEV_HIGH, "LD_PRELOAD", "LD_PRELOAD is set: %s", preload);
        threats++;
    }
    
    /* Check /etc/ld.so.preload */
    if (file_exists("/etc/ld.so.preload")) {
        FILE *f = fopen("/etc/ld.so.preload", "r");
        if (f) {
            while (fgets(buf, sizeof(buf), f)) {
                buf[strcspn(buf, "\n")] = 0;
                if (strlen(buf) > 0 && buf[0] != '#') {
                    /* Check against known rootkit libraries */
                    if (string_in_array(buf, USERLAND_ROOTKITS)) {
                        print_finding(SEV_CRITICAL, "LD_PRELOAD", 
                            "Known rootkit library in ld.so.preload: %s", buf);
                        threats++;
                    } else {
                        print_finding(SEV_HIGH, "LD_PRELOAD", 
                            "Library in /etc/ld.so.preload: %s", buf);
                        threats++;
                    }
                }
            }
            fclose(f);
        }
    }
    
    /* Check for suspicious libraries in /etc/ld.so.conf.d */
    glob_t globbuf;
    if (glob("/etc/ld.so.conf.d/*.conf", 0, NULL, &globbuf) == 0) {
        for (size_t i = 0; i < globbuf.gl_pathc; i++) {
            FILE *f = fopen(globbuf.gl_pathv[i], "r");
            if (f) {
                while (fgets(buf, sizeof(buf), f)) {
                    buf[strcspn(buf, "\n")] = 0;
                    /* Check for suspicious paths */
                    if (strstr(buf, "/dev/shm") || strstr(buf, "/tmp") ||
                        strstr(buf, "/.") || strstr(buf, "/var/tmp")) {
                        print_finding(SEV_HIGH, "LD_CONF", 
                            "Suspicious library path in %s: %s", 
                            globbuf.gl_pathv[i], buf);
                        threats++;
                    }
                }
                fclose(f);
            }
        }
        globfree(&globbuf);
    }
    
    /* Check loaded libraries in current process */
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        while (fgets(buf, sizeof(buf), maps)) {
            /* Look for suspicious library paths */
            if ((strstr(buf, "/dev/shm/") || strstr(buf, "/tmp/") ||
                 strstr(buf, "/var/tmp/") || strstr(buf, "/.")) &&
                strstr(buf, ".so")) {
                buf[strcspn(buf, "\n")] = 0;
                print_finding(SEV_HIGH, "LIBRARY", 
                    "Suspicious library loaded from temp path");
                threats++;
            }
        }
        fclose(maps);
    }
    
    /* Check for libkeyutils hijacking (common rootkit technique) */
    const char *keyutils_paths[] = {
        "/lib/libkeyutils.so.1",
        "/lib64/libkeyutils.so.1", 
        "/lib/x86_64-linux-gnu/libkeyutils.so.1",
        NULL
    };
    
    for (int i = 0; keyutils_paths[i]; i++) {
        struct stat st;
        if (stat(keyutils_paths[i], &st) == 0) {
            /* Check for unusually small size (backdoor) */
            if (st.st_size < 5000) {
                print_finding(SEV_HIGH, "LIBHIJACK", 
                    "Suspiciously small libkeyutils: %s (%ld bytes)", 
                    keyutils_paths[i], st.st_size);
                threats++;
            }
        }
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("No library injection detected");
    }
    
    return threats;
}

/* Check kernel modules */
static int check_kernel_modules(void) {
    print_section("Kernel Modules");
    stats.total_checks++;
    
    int threats = 0;
    char buf[MAX_LINE];
    char mod_name[256];
    
    /* Read /proc/modules */
    FILE *f = fopen("/proc/modules", "r");
    if (!f) {
        print_warn("Cannot read /proc/modules");
        return 0;
    }
    
    while (fgets(buf, sizeof(buf), f)) {
        if (sscanf(buf, "%255s", mod_name) != 1) continue;
        
        /* Check against known rootkit modules */
        if (string_in_array(mod_name, LKM_ROOTKITS)) {
            print_finding(SEV_CRITICAL, "ROOTKIT_LKM", 
                "Known rootkit module loaded: %s", mod_name);
            stats.suspicious_modules++;
            threats++;
            continue;
        }
        
        /* Check suspicious patterns */
        if (string_in_array(mod_name, SUSPICIOUS_MODULES)) {
            print_finding(SEV_HIGH, "SUSPECT_LKM", 
                "Suspicious kernel module: %s", mod_name);
            stats.suspicious_modules++;
            threats++;
            continue;
        }
        
        /* Check for modules with suspicious characteristics */
        char mod_path[MAX_PATH];
        snprintf(mod_path, sizeof(mod_path), "/sys/module/%s", mod_name);
        
        /* Check if module info is accessible */
        if (access(mod_path, F_OK) != 0) {
            print_finding(SEV_HIGH, "HIDDEN_LKM", 
                "Module loaded but hidden from /sys/module: %s", mod_name);
            stats.suspicious_modules++;
            threats++;
        }
        
        if (opt_verbose) {
            /* Check module parameters for suspicious values */
            snprintf(mod_path, sizeof(mod_path), "/sys/module/%s/parameters", mod_name);
            DIR *dir = opendir(mod_path);
            if (dir) {
                struct dirent *entry;
                while ((entry = readdir(dir))) {
                    if (entry->d_name[0] == '.') continue;
                    char param_path[MAX_PATH];
                    snprintf(param_path, sizeof(param_path), "%s/%s", mod_path, entry->d_name);
                    char param_val[256] = {0};
                    if (read_file_content(param_path, param_val, sizeof(param_val)) > 0) {
                        /* Check for suspicious parameter values */
                        if (strstr(param_val, "hide") || strstr(param_val, "stealth") ||
                            strstr(param_val, "hook") || strstr(param_val, "root")) {
                            print_finding(SEV_MEDIUM, "LKM_PARAM", 
                                "Suspicious module parameter: %s/%s=%s", 
                                mod_name, entry->d_name, param_val);
                        }
                    }
                }
                closedir(dir);
            }
        }
    }
    fclose(f);
    
    /* Check for tainted kernel */
    if (read_file_content("/proc/sys/kernel/tainted", buf, sizeof(buf)) > 0) {
        int tainted = atoi(buf);
        if (tainted & 4096) {  /* Out-of-tree module */
            print_finding(SEV_LOW, "KERNEL", "Kernel tainted with out-of-tree module");
        }
        if (tainted & 8192) {  /* Unsigned module */
            print_finding(SEV_MEDIUM, "KERNEL", "Kernel tainted with unsigned module");
        }
    }
    
    /* Check for module loading disabled */
    if (read_file_content("/proc/sys/kernel/modules_disabled", buf, sizeof(buf)) > 0) {
        if (atoi(buf) == 1 && opt_verbose) {
            print_info("Module loading is disabled (security feature)");
        }
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("No suspicious kernel modules detected");
    }
    
    return threats;
}

/* Check for rootkit files in filesystem */
static int check_rootkit_files(void) {
    print_section("Filesystem Analysis");
    stats.total_checks++;
    
    int threats = 0;
    char path[MAX_PATH];
    
    /* Common rootkit file locations */
    const char *rootkit_paths[] = {
        /* Hidden directories */
        "/dev/.udev.d", "/dev/.static", "/dev/.initramfs",
        "/dev/shm/.x", "/dev/shm/.r", "/dev/shm/.t",
        "/tmp/.ICE-unix/.", "/tmp/.X11-unix/.",
        "/var/tmp/.", "/run/lock/.",
        
        /* Reptile */
        "/reptile", "/dev/.reptile", "/etc/.reptile",
        
        /* Diamorphine */
        "/dev/.diamorphine", "/tmp/.diamorphine",
        
        /* Kovid */
        "/dev/.kovid", "/tmp/.kovid",
        
        /* Suterusu */
        "/dev/.suterusu", "/tmp/.suterusu",
        
        /* Jynx */
        "/etc/.jynx", "/etc/.jynx2", "/tmp/.jynx",
        
        /* Other common */
        "/usr/share/.hidden", "/usr/local/.hidden",
        "/opt/.hidden", "/var/.hidden",
        "/etc/.ssh", "/root/.ssh2",
        "/etc/ld.so.hash", "/lib/.libs",
        
        /* APT-related */
        "/var/run/.uroburos", "/tmp/.turla",
        "/dev/shm/.drovorub", "/var/tmp/.regin",
        
        NULL
    };
    
    for (int i = 0; rootkit_paths[i]; i++) {
        if (file_exists(rootkit_paths[i])) {
            print_finding(SEV_CRITICAL, "ROOTKIT_FILE", 
                "Suspicious rootkit path exists: %s", rootkit_paths[i]);
            stats.suspicious_files++;
            threats++;
        }
    }
    
    /* Check /dev for unexpected files */
    DIR *dir = opendir("/dev");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            /* Skip normal entries */
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            
            /* Check for hidden files in /dev */
            if (entry->d_name[0] == '.' && strlen(entry->d_name) > 1) {
                /* Allow known legitimate hidden entries */
                if (strcmp(entry->d_name, ".udev") == 0) continue;
                
                snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
                struct stat st;
                if (stat(path, &st) == 0) {
                    if (S_ISDIR(st.st_mode)) {
                        print_finding(SEV_HIGH, "HIDDEN_DIR", 
                            "Hidden directory in /dev: %s", path);
                        stats.suspicious_files++;
                        threats++;
                    } else if (S_ISREG(st.st_mode)) {
                        print_finding(SEV_HIGH, "HIDDEN_FILE", 
                            "Hidden file in /dev: %s", path);
                        stats.suspicious_files++;
                        threats++;
                    }
                }
            }
            
            /* Check for executables in /dev (highly suspicious) */
            snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
            struct stat st;
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
                    print_finding(SEV_CRITICAL, "DEV_EXEC", 
                        "Executable file in /dev: %s", path);
                    stats.suspicious_files++;
                    threats++;
                }
            }
        }
        closedir(dir);
    }
    
    /* Check for suspicious setuid/setgid binaries */
    const char *suid_dirs[] = {"/tmp", "/var/tmp", "/dev/shm", "/home", NULL};
    for (int i = 0; suid_dirs[i]; i++) {
        char cmd[MAX_PATH];
        snprintf(cmd, sizeof(cmd), "find %s -perm /6000 -type f 2>/dev/null", suid_dirs[i]);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char result[MAX_PATH];
            while (fgets(result, sizeof(result), fp)) {
                result[strcspn(result, "\n")] = 0;
                print_finding(SEV_CRITICAL, "SUID_TEMP", 
                    "SUID/SGID binary in temp directory: %s", result);
                stats.suspicious_files++;
                threats++;
            }
            pclose(fp);
        }
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("No suspicious rootkit files detected");
    }
    
    return threats;
}

/* Check network for backdoors */
static int check_network_backdoors(void) {
    print_section("Network Analysis");
    stats.total_checks++;
    
    int threats = 0;
    char buf[MAX_LINE];
    
    /* Check /proc/net/tcp and tcp6 */
    const char *net_files[] = {"/proc/net/tcp", "/proc/net/tcp6", NULL};
    
    for (int nf = 0; net_files[nf]; nf++) {
        FILE *f = fopen(net_files[nf], "r");
        if (!f) continue;
        
        /* Skip header */
        fgets(buf, sizeof(buf), f);
        
        while (fgets(buf, sizeof(buf), f)) {
            unsigned int local_port, remote_port;
            int state;
            
            /* Parse: sl local_address rem_address st ... */
            if (sscanf(buf, "%*d: %*x:%x %*x:%x %x", 
                       &local_port, &remote_port, &state) == 3) {
                
                /* Check for listening (state 0A) on suspicious ports */
                if (state == 0x0A) {
                    for (int i = 0; SUSPICIOUS_PORTS[i]; i++) {
                        if (local_port == SUSPICIOUS_PORTS[i]) {
                            print_finding(SEV_HIGH, "BACKDOOR_PORT", 
                                "Suspicious listening port: %d", local_port);
                            stats.network_anomalies++;
                            threats++;
                            break;
                        }
                    }
                }
            }
        }
        fclose(f);
    }
    
    /* Check for raw sockets (often used by rootkits) */
    FILE *f = fopen("/proc/net/raw", "r");
    if (f) {
        fgets(buf, sizeof(buf), f);  /* Skip header */
        int raw_count = 0;
        while (fgets(buf, sizeof(buf), f)) {
            raw_count++;
        }
        fclose(f);
        
        if (raw_count > 0) {
            print_finding(SEV_MEDIUM, "RAW_SOCKET", 
                "Raw sockets detected: %d", raw_count);
            stats.network_anomalies++;
            threats++;
        }
    }
    
    /* Check for packet sockets */
    f = fopen("/proc/net/packet", "r");
    if (f) {
        fgets(buf, sizeof(buf), f);  /* Skip header */
        int packet_count = 0;
        while (fgets(buf, sizeof(buf), f)) {
            packet_count++;
        }
        fclose(f);
        
        if (packet_count > 2) {  /* Some legitimate uses */
            print_finding(SEV_LOW, "PACKET_SOCKET", 
                "Multiple packet sockets detected: %d", packet_count);
        }
    }
    
    /* Check for suspicious established connections */
    f = fopen("/proc/net/tcp", "r");
    if (f) {
        fgets(buf, sizeof(buf), f);
        while (fgets(buf, sizeof(buf), f)) {
            unsigned int local_port, remote_port;
            int state;
            unsigned long remote_addr;
            
            if (sscanf(buf, "%*d: %*x:%x %lx:%x %x", 
                       &local_port, &remote_addr, &remote_port, &state) == 4) {
                
                /* Check for established (state 01) to suspicious ports */
                if (state == 0x01) {
                    for (int i = 0; SUSPICIOUS_PORTS[i]; i++) {
                        if (remote_port == SUSPICIOUS_PORTS[i]) {
                            print_finding(SEV_HIGH, "SUSPICIOUS_CONN", 
                                "Outbound connection to suspicious port: %d", remote_port);
                            stats.network_anomalies++;
                            threats++;
                            break;
                        }
                    }
                }
            }
        }
        fclose(f);
    }
    
    /* Check for netfilter hooks (iptables manipulation) */
    if (opt_deep_scan && file_exists("/proc/net/ip_tables_names")) {
        /* Check for unusual iptables chains */
        char cmd[] = "iptables -L -n 2>/dev/null | grep -c DROP";
        FILE *fp = popen(cmd, "r");
        if (fp) {
            int drop_rules = 0;
            fscanf(fp, "%d", &drop_rules);
            pclose(fp);
            
            if (drop_rules > 100) {
                print_finding(SEV_MEDIUM, "IPTABLES", 
                    "Unusually high number of DROP rules: %d", drop_rules);
            }
        }
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("No network anomalies detected");
    }
    
    return threats;
}

/* Check syscall table integrity */
static int check_syscall_hooks(void) {
    print_section("Syscall Integrity");
    stats.total_checks++;
    
    int threats = 0;
    char buf[MAX_LINE];
    
    /* Check kallsyms for syscall table manipulation */
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        print_warn("Cannot read /proc/kallsyms (try running as root)");
        return 0;
    }
    
    unsigned long sys_call_table = 0;
    unsigned long sys_call_table_end = 0;
    int found_hooks = 0;
    
    while (fgets(buf, sizeof(buf), f)) {
        char addr_str[32], type, name[256];
        if (sscanf(buf, "%31s %c %255s", addr_str, &type, name) == 3) {
            unsigned long addr = strtoul(addr_str, NULL, 16);
            
            if (strcmp(name, "sys_call_table") == 0) {
                sys_call_table = addr;
            }
            
            /* Check for suspicious kernel symbols */
            if (string_in_array(name, LKM_ROOTKITS)) {
                print_finding(SEV_CRITICAL, "ROOTKIT_SYM", 
                    "Rootkit symbol in kernel: %s @ 0x%lx", name, addr);
                threats++;
                found_hooks++;
            }
            
            /* Check for hook-related symbols */
            if (strstr(name, "_hook") || strstr(name, "hijack") ||
                strstr(name, "intercept") || strstr(name, "replace")) {
                if (!strstr(name, "netfilter") && !strstr(name, "security") &&
                    !strstr(name, "ftrace") && !strstr(name, "kprobe")) {
                    if (opt_verbose) {
                        print_finding(SEV_LOW, "HOOK_SYM", 
                            "Hook-related symbol: %s", name);
                    }
                }
            }
        }
    }
    fclose(f);
    
    /* Check kprobes for suspicious hooks */
    if (file_exists("/sys/kernel/debug/kprobes/list")) {
        f = fopen("/sys/kernel/debug/kprobes/list", "r");
        if (f) {
            int kprobe_count = 0;
            while (fgets(buf, sizeof(buf), f)) {
                kprobe_count++;
                
                /* Check for suspicious kprobe targets */
                if (strstr(buf, "sys_") || strstr(buf, "do_") ||
                    strstr(buf, "vfs_") || strstr(buf, "tcp_") ||
                    strstr(buf, "udp_") || strstr(buf, "inet_")) {
                    buf[strcspn(buf, "\n")] = 0;
                    if (opt_verbose) {
                        print_finding(SEV_LOW, "KPROBE", 
                            "System function kprobe: %s", buf);
                    }
                }
            }
            fclose(f);
            
            if (kprobe_count > 50) {
                print_finding(SEV_MEDIUM, "KPROBE", 
                    "High number of kprobes installed: %d", kprobe_count);
                threats++;
            }
        }
    }
    
    /* Check ftrace for suspicious hooks */
    if (file_exists("/sys/kernel/debug/tracing/enabled_functions")) {
        f = fopen("/sys/kernel/debug/tracing/enabled_functions", "r");
        if (f) {
            int ftrace_count = 0;
            while (fgets(buf, sizeof(buf), f)) {
                ftrace_count++;
            }
            fclose(f);
            
            if (ftrace_count > 0 && opt_verbose) {
                print_info("Ftrace hooks active: %d", ftrace_count);
            }
        }
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("No syscall hooks detected");
    }
    
    return threats;
}

/* Check eBPF for malicious programs */
static int check_ebpf_programs(void) {
    print_section("eBPF Analysis");
    stats.total_checks++;
    
    int threats = 0;
    char buf[MAX_LINE];
    
    /* Check for loaded BPF programs via /proc */
    DIR *dir = opendir("/proc");
    if (!dir) return 0;
    
    struct dirent *entry;
    int bpf_progs = 0;
    
    while ((entry = readdir(dir))) {
        if (!isdigit(entry->d_name[0])) continue;
        
        char fdinfo_path[MAX_PATH];
        snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/%s/fdinfo", entry->d_name);
        
        DIR *fddir = opendir(fdinfo_path);
        if (!fddir) continue;
        
        struct dirent *fd_entry;
        while ((fd_entry = readdir(fddir))) {
            if (!isdigit(fd_entry->d_name[0])) continue;
            
            char fd_path[MAX_PATH];
            snprintf(fd_path, sizeof(fd_path), "%s/%s", fdinfo_path, fd_entry->d_name);
            
            FILE *f = fopen(fd_path, "r");
            if (f) {
                while (fgets(buf, sizeof(buf), f)) {
                    if (strstr(buf, "prog_type:")) {
                        bpf_progs++;
                        
                        /* Check for suspicious BPF program types */
                        if (strstr(buf, "kprobe") || strstr(buf, "tracepoint") ||
                            strstr(buf, "raw_tracepoint")) {
                            if (opt_verbose) {
                                print_finding(SEV_LOW, "BPF_PROG", 
                                    "BPF program attached to kernel: PID %s", entry->d_name);
                            }
                        }
                    }
                }
                fclose(f);
            }
        }
        closedir(fddir);
    }
    closedir(dir);
    
    if (bpf_progs > 20) {
        print_finding(SEV_MEDIUM, "BPF_COUNT", 
            "High number of BPF programs loaded: %d", bpf_progs);
        stats.ebpf_threats++;
        threats++;
    } else if (opt_verbose && bpf_progs > 0) {
        print_info("BPF programs detected: %d", bpf_progs);
    }
    
    /* Check for BPF filesystem mounts (potential persistence) */
    FILE *f = fopen("/proc/mounts", "r");
    if (f) {
        while (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "bpf") && strstr(buf, "type bpf")) {
                /* Check mount location */
                if (!strstr(buf, "/sys/fs/bpf")) {
                    buf[strcspn(buf, "\n")] = 0;
                    print_finding(SEV_HIGH, "BPF_MOUNT", 
                        "Non-standard BPF filesystem mount: %s", buf);
                    stats.ebpf_threats++;
                    threats++;
                }
            }
        }
        fclose(f);
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("No suspicious eBPF activity detected");
    }
    
    return threats;
}

/* Check boot integrity */
static int check_boot_integrity(void) {
    print_section("Boot Integrity");
    stats.total_checks++;
    
    int threats = 0;
    
    /* Check for UEFI Secure Boot status */
    if (file_exists("/sys/firmware/efi")) {
        char buf[64];
        if (read_file_content("/sys/firmware/efi/efivars/SecureBoot-*", buf, sizeof(buf)) > 0) {
            if (opt_verbose) {
                print_info("UEFI system detected");
            }
        }
        
        /* Check EFI variables for suspicious entries */
        DIR *dir = opendir("/sys/firmware/efi/efivars");
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir))) {
                /* Check for suspicious EFI variable names */
                if (string_in_array(entry->d_name, BOOTKITS)) {
                    print_finding(SEV_CRITICAL, "EFI_VAR", 
                        "Suspicious EFI variable: %s", entry->d_name);
                    threats++;
                }
            }
            closedir(dir);
        }
    }
    
    /* Check initramfs integrity */
    glob_t globbuf;
    if (glob("/boot/initramfs-*.img", 0, NULL, &globbuf) == 0 ||
        glob("/boot/initrd.img-*", 0, NULL, &globbuf) == 0) {
        
        for (size_t i = 0; i < globbuf.gl_pathc; i++) {
            struct stat st;
            if (stat(globbuf.gl_pathv[i], &st) == 0) {
                /* Check modification time */
                time_t now = time(NULL);
                if (now - st.st_mtime < 86400 && opt_verbose) {
                    print_finding(SEV_LOW, "INITRAMFS", 
                        "Initramfs modified recently: %s", globbuf.gl_pathv[i]);
                }
            }
        }
        globfree(&globbuf);
    }
    
    /* Check kernel command line for suspicious parameters */
    char cmdline[MAX_LINE];
    if (read_file_content("/proc/cmdline", cmdline, sizeof(cmdline)) > 0) {
        /* Check for dangerous parameters */
        if (strstr(cmdline, "init=/bin/") && !strstr(cmdline, "init=/bin/systemd") &&
            !strstr(cmdline, "init=/sbin/init")) {
            print_finding(SEV_HIGH, "CMDLINE", 
                "Suspicious init= parameter in kernel cmdline");
            threats++;
        }
        
        if (strstr(cmdline, "module.sig_enforce=0")) {
            print_finding(SEV_MEDIUM, "CMDLINE", 
                "Module signature enforcement disabled");
            threats++;
        }
    }
    
    /* Check GRUB config for modifications */
    const char *grub_configs[] = {
        "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg",
        "/etc/default/grub", NULL
    };
    
    for (int i = 0; grub_configs[i]; i++) {
        struct stat st;
        if (stat(grub_configs[i], &st) == 0) {
            time_t now = time(NULL);
            if (now - st.st_mtime < 86400) {
                print_finding(SEV_LOW, "GRUB", 
                    "GRUB config modified recently: %s", grub_configs[i]);
            }
        }
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("Boot integrity check passed");
    }
    
    return threats;
}

/* Check container security */
static int check_container_security(void) {
    print_section("Container Security");
    stats.total_checks++;
    
    int threats = 0;
    int in_container = 0;
    char buf[MAX_LINE];
    
    /* Detect if running in container */
    if (file_exists("/.dockerenv") || file_exists("/run/.containerenv")) {
        in_container = 1;
        if (opt_verbose) {
            print_info("Running inside container");
        }
    }
    
    /* Check cgroup for container indicators */
    if (read_file_content("/proc/1/cgroup", buf, sizeof(buf)) > 0) {
        if (strstr(buf, "docker") || strstr(buf, "lxc") || 
            strstr(buf, "kubepods") || strstr(buf, "containerd")) {
            in_container = 1;
        }
    }
    
    /* Check for container escape indicators */
    if (in_container) {
        /* Check for privileged mode */
        if (read_file_content("/proc/self/status", buf, sizeof(buf)) > 0) {
            if (strstr(buf, "CapEff:\t0000003fffffffff")) {
                print_finding(SEV_HIGH, "CONTAINER", 
                    "Container running in privileged mode");
                threats++;
            }
        }
        
        /* Check for dangerous mounts */
        FILE *f = fopen("/proc/mounts", "r");
        if (f) {
            while (fgets(buf, sizeof(buf), f)) {
                if (strstr(buf, "/var/run/docker.sock")) {
                    print_finding(SEV_HIGH, "CONTAINER", 
                        "Docker socket mounted in container");
                    threats++;
                }
                if (strstr(buf, " / ") && strstr(buf, "ext4")) {
                    /* Might have host filesystem access */
                    if (opt_verbose) {
                        print_finding(SEV_MEDIUM, "CONTAINER", 
                            "Container may have host filesystem access");
                    }
                }
            }
            fclose(f);
        }
        
        /* Check for container escape techniques */
        if (file_exists("/host")) {
            print_finding(SEV_CRITICAL, "CONTAINER", 
                "Potential container escape: /host mount detected");
            threats++;
        }
    }
    
    /* Check Docker for infected images (if docker accessible) */
    if (file_exists("/var/run/docker.sock")) {
        /* Check for known malicious container names/images */
        FILE *fp = popen("docker ps --format '{{.Image}}' 2>/dev/null", "r");
        if (fp) {
            while (fgets(buf, sizeof(buf), fp)) {
                buf[strcspn(buf, "\n")] = 0;
                if (string_in_array(buf, CONTAINER_ROOTKITS)) {
                    print_finding(SEV_CRITICAL, "DOCKER", 
                        "Known malicious container image: %s", buf);
                    threats++;
                }
            }
            pclose(fp);
        }
    }
    
    /* Check Kubernetes if available */
    if (file_exists("/var/run/secrets/kubernetes.io")) {
        if (opt_verbose) {
            print_info("Kubernetes environment detected");
        }
        
        /* Check for overly permissive service account */
        char token_path[] = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        if (file_exists(token_path)) {
            struct stat st;
            if (stat(token_path, &st) == 0 && (st.st_mode & 0077)) {
                print_finding(SEV_MEDIUM, "K8S", 
                    "Service account token has loose permissions");
                threats++;
            }
        }
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("Container security check passed");
    }
    
    return threats;
}

/* Check persistence mechanisms */
static int check_persistence(void) {
    print_section("Persistence Mechanisms");
    stats.total_checks++;
    
    int threats = 0;
    char buf[MAX_LINE];
    
    /* Check cron directories */
    const char *cron_dirs[] = {
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
        NULL
    };
    
    for (int i = 0; cron_dirs[i]; i++) {
        DIR *dir = opendir(cron_dirs[i]);
        if (!dir) continue;
        
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (entry->d_name[0] == '.') continue;
            
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "%s/%s", cron_dirs[i], entry->d_name);
            
            /* Check file content for suspicious commands */
            FILE *f = fopen(path, "r");
            if (f) {
                while (fgets(buf, sizeof(buf), f)) {
                    /* Check for common persistence patterns */
                    if (strstr(buf, "curl") && strstr(buf, "| bash")) {
                        print_finding(SEV_CRITICAL, "CRON", 
                            "Suspicious pipe to bash in cron: %s", path);
                        stats.persistence_found++;
                        threats++;
                    }
                    if (strstr(buf, "wget") && (strstr(buf, "| sh") || strstr(buf, "|sh"))) {
                        print_finding(SEV_CRITICAL, "CRON", 
                            "Suspicious wget|sh in cron: %s", path);
                        stats.persistence_found++;
                        threats++;
                    }
                    if (strstr(buf, "/dev/tcp/") || strstr(buf, "nc -e") ||
                        strstr(buf, "ncat -e") || strstr(buf, "bash -i")) {
                        print_finding(SEV_CRITICAL, "CRON", 
                            "Reverse shell pattern in cron: %s", path);
                        stats.persistence_found++;
                        threats++;
                    }
                }
                fclose(f);
            }
        }
        closedir(dir);
    }
    
    /* Check systemd units */
    const char *systemd_dirs[] = {
        "/etc/systemd/system", "/usr/lib/systemd/system",
        "/lib/systemd/system", "/run/systemd/system",
        NULL
    };
    
    for (int i = 0; systemd_dirs[i]; i++) {
        DIR *dir = opendir(systemd_dirs[i]);
        if (!dir) continue;
        
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (!strstr(entry->d_name, ".service")) continue;
            
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "%s/%s", systemd_dirs[i], entry->d_name);
            
            FILE *f = fopen(path, "r");
            if (f) {
                int suspicious = 0;
                while (fgets(buf, sizeof(buf), f)) {
                    /* Check ExecStart for suspicious patterns */
                    if (strstr(buf, "ExecStart=")) {
                        if (strstr(buf, "/dev/shm") || strstr(buf, "/tmp/.") ||
                            strstr(buf, "/var/tmp/.") || strstr(buf, "curl") ||
                            strstr(buf, "wget")) {
                            suspicious = 1;
                        }
                        
                        /* Check for known rootkit patterns */
                        if (string_in_array(buf, LKM_ROOTKITS) ||
                            string_in_array(buf, USERLAND_ROOTKITS)) {
                            print_finding(SEV_CRITICAL, "SYSTEMD", 
                                "Rootkit-related systemd service: %s", entry->d_name);
                            stats.persistence_found++;
                            threats++;
                        }
                    }
                }
                fclose(f);
                
                if (suspicious) {
                    print_finding(SEV_HIGH, "SYSTEMD", 
                        "Suspicious systemd service: %s", entry->d_name);
                    stats.persistence_found++;
                    threats++;
                }
            }
        }
        closedir(dir);
    }
    
    /* Check SSH authorized_keys for backdoors */
    glob_t globbuf;
    if (glob("/home/*/.ssh/authorized_keys", 0, NULL, &globbuf) == 0) {
        for (size_t i = 0; i < globbuf.gl_pathc; i++) {
            FILE *f = fopen(globbuf.gl_pathv[i], "r");
            if (f) {
                int key_count = 0;
                while (fgets(buf, sizeof(buf), f)) {
                    key_count++;
                    /* Check for suspicious key comments */
                    if (strstr(buf, "backdoor") || strstr(buf, "rootkit") ||
                        strstr(buf, "pwned") || strstr(buf, "hacked")) {
                        print_finding(SEV_CRITICAL, "SSH", 
                            "Suspicious SSH key comment in %s", globbuf.gl_pathv[i]);
                        threats++;
                    }
                }
                fclose(f);
                
                /* Warn if many keys */
                if (key_count > 10) {
                    print_finding(SEV_MEDIUM, "SSH", 
                        "Many SSH keys (%d) in %s", key_count, globbuf.gl_pathv[i]);
                }
            }
        }
        globfree(&globbuf);
    }
    
    /* Check /root/.ssh as well */
    if (file_exists("/root/.ssh/authorized_keys")) {
        struct stat st;
        if (stat("/root/.ssh/authorized_keys", &st) == 0) {
            if (st.st_mode & 0077) {
                print_finding(SEV_MEDIUM, "SSH", 
                    "Root authorized_keys has loose permissions");
            }
        }
    }
    
    /* Check rc.local */
    if (file_exists("/etc/rc.local")) {
        FILE *f = fopen("/etc/rc.local", "r");
        if (f) {
            while (fgets(buf, sizeof(buf), f)) {
                if (strstr(buf, "curl") || strstr(buf, "wget") ||
                    strstr(buf, "/tmp/") || strstr(buf, "/dev/shm")) {
                    print_finding(SEV_HIGH, "RC_LOCAL", 
                        "Suspicious command in rc.local");
                    stats.persistence_found++;
                    threats++;
                    break;
                }
            }
            fclose(f);
        }
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("No malicious persistence detected");
    }
    
    return threats;
}

/* Deep memory signature scan */
static int check_memory_signatures(void) {
    print_section("Memory Analysis");
    stats.total_checks++;
    
    int threats = 0;
    char path[MAX_PATH];
    
    /* Scan process maps and memory for rootkit signatures */
    DIR *dir = opendir("/proc");
    if (!dir) return 0;
    
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!isdigit(entry->d_name[0])) continue;
        
        int pid = atoi(entry->d_name);
        
        /* Read maps to find executable regions */
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        FILE *maps = fopen(path, "r");
        if (!maps) continue;
        
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), maps)) {
            /* Look for executable anonymous mappings (common for injected code) */
            unsigned long start, end;
            char perms[8];
            
            if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {
                /* Check for rwx permissions (suspicious) */
                if (strchr(perms, 'r') && strchr(perms, 'w') && strchr(perms, 'x')) {
                    /* Anonymous executable memory */
                    if (strstr(line, "deleted") || 
                        (strstr(line, " 00:00 ") && !strstr(line, "[") && !strstr(line, "/"))) {
                        print_finding(SEV_HIGH, "MEMORY", 
                            "RWX anonymous memory in PID %d @ 0x%lx-0x%lx", 
                            pid, start, end);
                        threats++;
                    }
                }
            }
        }
        fclose(maps);
        
        /* Check cmdline for suspicious patterns */
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        char cmdline[MAX_PATH] = {0};
        if (read_file_content(path, cmdline, sizeof(cmdline)) > 0) {
            /* Replace nulls with spaces for display */
            for (int i = 0; i < sizeof(cmdline) - 1 && cmdline[i]; i++) {
                if (cmdline[i] == '\0') cmdline[i] = ' ';
            }
            
            /* Check for rootkit indicators */
            if (string_in_array(cmdline, LKM_ROOTKITS) ||
                string_in_array(cmdline, USERLAND_ROOTKITS)) {
                print_finding(SEV_CRITICAL, "PROCESS", 
                    "Rootkit-related process: PID %d - %s", pid, cmdline);
                threats++;
            }
        }
        
        /* Check exe link for deleted files (common rootkit technique) */
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        char exe_path[MAX_PATH];
        ssize_t len = readlink(path, exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = 0;
            if (strstr(exe_path, "(deleted)")) {
                print_finding(SEV_HIGH, "PROCESS", 
                    "Process running from deleted executable: PID %d - %s", 
                    pid, exe_path);
                threats++;
            }
        }
    }
    closedir(dir);
    
    if (threats == 0 && !opt_quiet) {
        print_info("No suspicious memory patterns detected");
    }
    
    return threats;
}

/* File integrity check */
static int check_file_integrity(void) {
    print_section("File Integrity");
    stats.total_checks++;
    
    int threats = 0;
    
    for (int i = 0; INTEGRITY_FILES[i]; i++) {
        const char *path = INTEGRITY_FILES[i];
        struct stat st;
        
        if (stat(path, &st) != 0) continue;
        
        /* Check for suspicious modifications */
        
        /* 1. Check if file is a symlink (common replacement technique) */
        char link_target[MAX_PATH];
        ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
        if (len > 0) {
            link_target[len] = 0;
            /* Check if symlink points to suspicious location */
            if (strstr(link_target, "/tmp") || strstr(link_target, "/dev/shm") ||
                strstr(link_target, "/.") || strstr(link_target, "/var/tmp")) {
                print_finding(SEV_CRITICAL, "INTEGRITY", 
                    "System binary symlinked to suspicious location: %s -> %s", 
                    path, link_target);
                stats.integrity_failures++;
                threats++;
            }
        }
        
        /* 2. Check file ownership (should be root) */
        if (st.st_uid != 0) {
            print_finding(SEV_HIGH, "INTEGRITY", 
                "System binary not owned by root: %s (uid=%d)", path, st.st_uid);
            stats.integrity_failures++;
            threats++;
        }
        
        /* 3. Check for unexpected write permissions */
        if (st.st_mode & S_IWOTH) {
            print_finding(SEV_HIGH, "INTEGRITY", 
                "System binary world-writable: %s", path);
            stats.integrity_failures++;
            threats++;
        }
        
        /* 4. Check modification time (shouldn't be recent unless system update) */
        time_t now = time(NULL);
        if (now - st.st_mtime < 3600 && opt_deep_scan) {
            print_finding(SEV_MEDIUM, "INTEGRITY", 
                "System binary modified in last hour: %s", path);
        }
        
        /* 5. Open and check ELF header for tampering */
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            unsigned char elf_header[64];
            if (read(fd, elf_header, sizeof(elf_header)) == sizeof(elf_header)) {
                /* Verify ELF magic */
                if (elf_header[0] != 0x7f || elf_header[1] != 'E' ||
                    elf_header[2] != 'L' || elf_header[3] != 'F') {
                    print_finding(SEV_CRITICAL, "INTEGRITY", 
                        "System binary has corrupted ELF header: %s", path);
                    stats.integrity_failures++;
                    threats++;
                }
            }
            close(fd);
        }
    }
    
    if (threats == 0 && !opt_quiet) {
        print_info("File integrity check passed");
    }
    
    return threats;
}

/* Print summary */
static void print_summary(void) {
    if (opt_json) {
        printf("{\"summary\":{\"critical\":%d,\"high\":%d,\"medium\":%d,\"low\":%d,\"total_checks\":%d}}\n",
               stats.critical, stats.high, stats.medium, stats.low, stats.total_checks);
        return;
    }
    
    time_t elapsed = time(NULL) - stats.start_time;
    
    printf("\n");
    printf("  " C_CYAN "╭────────────────────────────────────────╮" C_RESET "\n");
    printf("  " C_CYAN "│" C_WHITE C_BOLD "           SCAN RESULTS                " C_CYAN "│" C_RESET "\n");
    printf("  " C_CYAN "├────────────────────────────────────────┤" C_RESET "\n");
    printf("  " C_CYAN "│" C_RESET "  Scan Duration:     %3ld seconds        " C_CYAN "│" C_RESET "\n", elapsed);
    printf("  " C_CYAN "│" C_RESET "  Checks Performed:  %3d                " C_CYAN "│" C_RESET "\n", stats.total_checks);
    printf("  " C_CYAN "├────────────────────────────────────────┤" C_RESET "\n");
    printf("  " C_CYAN "│" C_RESET "  " C_RED C_BOLD "Critical:" C_RESET "           %3d                " C_CYAN "│" C_RESET "\n", stats.critical);
    printf("  " C_CYAN "│" C_RESET "  " C_ORANGE "High:" C_RESET "               %3d                " C_CYAN "│" C_RESET "\n", stats.high);
    printf("  " C_CYAN "│" C_RESET "  " C_YELLOW "Medium:" C_RESET "             %3d                " C_CYAN "│" C_RESET "\n", stats.medium);
    printf("  " C_CYAN "│" C_RESET "  " C_GREEN "Low:" C_RESET "                %3d                " C_CYAN "│" C_RESET "\n", stats.low);
    printf("  " C_CYAN "├────────────────────────────────────────┤" C_RESET "\n");
    printf("  " C_CYAN "│" C_RESET "  Hidden Processes:  %3d                " C_CYAN "│" C_RESET "\n", stats.hidden_procs);
    printf("  " C_CYAN "│" C_RESET "  Suspicious Modules:%3d                " C_CYAN "│" C_RESET "\n", stats.suspicious_modules);
    printf("  " C_CYAN "│" C_RESET "  Suspicious Files:  %3d                " C_CYAN "│" C_RESET "\n", stats.suspicious_files);
    printf("  " C_CYAN "│" C_RESET "  Network Anomalies: %3d                " C_CYAN "│" C_RESET "\n", stats.network_anomalies);
    printf("  " C_CYAN "│" C_RESET "  eBPF Threats:      %3d                " C_CYAN "│" C_RESET "\n", stats.ebpf_threats);
    printf("  " C_CYAN "│" C_RESET "  Integrity Fails:   %3d                " C_CYAN "│" C_RESET "\n", stats.integrity_failures);
    printf("  " C_CYAN "│" C_RESET "  Persistence Found: %3d                " C_CYAN "│" C_RESET "\n", stats.persistence_found);
    printf("  " C_CYAN "╰────────────────────────────────────────╯" C_RESET "\n\n");
    
    if (stats.critical > 0) {
        printf("  " C_RED C_BOLD "█████ SYSTEM COMPROMISED █████" C_RESET "\n");
        printf("  " C_RED "%d critical finding(s) detected" C_RESET "\n", stats.critical);
        printf("  " C_DIM "Immediate incident response recommended" C_RESET "\n\n");
    } else if (stats.high > 0) {
        printf("  " C_ORANGE C_BOLD "▸▸▸ HIGH RISK DETECTED ◂◂◂" C_RESET "\n");
        printf("  " C_ORANGE "%d high-severity finding(s)" C_RESET "\n", stats.high);
        printf("  " C_DIM "Investigation strongly recommended" C_RESET "\n\n");
    } else if (stats.medium > 0) {
        printf("  " C_YELLOW "⚡ WARNINGS FOUND" C_RESET " - %d item(s) need attention\n\n", stats.medium);
    } else if (stats.low > 0) {
        printf("  " C_GREEN "✓ System appears clean" C_RESET " - %d minor items noted\n\n", stats.low);
    } else {
        printf("  " C_GREEN C_BOLD "✓ SYSTEM CLEAN" C_RESET "\n");
        printf("  " C_DIM "No rootkit indicators detected" C_RESET "\n\n");
    }
}

/* Print usage */
static void print_usage(const char *prog) {
    printf("%s\n", BANNER);
    printf("  " C_WHITE "Usage:" C_RESET " %s [options]\n\n", prog);
    printf("  " C_WHITE "Scan Options:" C_RESET "\n");
    printf("    -a, --all           Full comprehensive scan (default)\n");
    printf("    -q, --quick         Quick scan (processes, modules, preload)\n");
    printf("    -p, --processes     Scan for hidden processes\n");
    printf("    -m, --modules       Scan kernel modules\n");
    printf("    -f, --files         Scan for rootkit files\n");
    printf("    -n, --network       Check network backdoors\n");
    printf("    -s, --syscalls      Check syscall table integrity\n");
    printf("    -b, --boot          Check boot/UEFI integrity\n");
    printf("    -c, --container     Container security checks\n");
    printf("    -e, --persistence   Check persistence mechanisms\n");
    printf("    -E, --ebpf          eBPF program analysis\n");
    printf("    -I, --integrity     File integrity verification\n");
    printf("    -M, --memory        Deep memory signature scan\n\n");
    printf("  " C_WHITE "Output Options:" C_RESET "\n");
    printf("    -v, --verbose       Verbose output\n");
    printf("    -Q, --quiet         Minimal output (alerts only)\n");
    printf("    -l, --log <file>    Log findings to file\n");
    printf("    -j, --json          JSON output format\n");
    printf("    -d, --deep          Enable deep scanning (slower)\n\n");
    printf("  " C_WHITE "Other:" C_RESET "\n");
    printf("    -h, --help          Show this help\n");
    printf("    --version           Show version\n\n");
    printf("  " C_WHITE "Examples:" C_RESET "\n");
    printf("    %s -a                     Full scan\n", prog);
    printf("    %s -q -v                  Quick verbose scan\n", prog);
    printf("    %s -m -s -E -l scan.log  Module/syscall/eBPF scan with log\n", prog);
    printf("    %s -a -d -j > report.json Deep scan with JSON output\n", prog);
    printf("\n");
    printf("  " C_DIM "Signatures: 200+ rootkits | eBPF/BPF threats | APT implants" C_RESET "\n");
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
    int run_ebpf = 0;
    int run_integrity = 0;
    char *log_path = NULL;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("Rupurt v%s - Advanced Rootkit Hunter\n", VERSION);
            printf("Signatures: 200+ rootkits, bootkits, eBPF threats\n");
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
        } else if (strcmp(argv[i], "-E") == 0 || strcmp(argv[i], "--ebpf") == 0) {
            run_ebpf = 1;
        } else if (strcmp(argv[i], "-I") == 0 || strcmp(argv[i], "--integrity") == 0) {
            run_integrity = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opt_verbose = 1;
        } else if (strcmp(argv[i], "-Q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            opt_quiet = 1;
        } else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            opt_json = 1;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--deep") == 0) {
            opt_deep_scan = 1;
        } else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log") == 0) && i + 1 < argc) {
            log_path = argv[++i];
        }
    }
    
    /* Default to full scan if no options */
    if (!run_quick && !run_procs && !run_modules && !run_files && 
        !run_network && !run_syscalls && !run_boot && !run_container &&
        !run_persistence && !run_memory && !run_ebpf && !run_integrity) {
        run_all = 1;
    }
    
    /* Open log file if specified */
    if (log_path) {
        log_file = fopen(log_path, "w");
        if (!log_file) {
            fprintf(stderr, "Cannot open log file: %s\n", log_path);
        } else {
            time_t now = time(NULL);
            fprintf(log_file, "Rupurt v%s - Scan started at %s\n", VERSION, ctime(&now));
        }
    }
    
    /* Print banner */
    if (!opt_quiet && !opt_json) {
        printf("%s", BANNER);
    }
    
    /* Check privileges */
    if (geteuid() != 0) {
        print_warn("Running without root - some checks may be limited");
    }
    
    stats.start_time = time(NULL);
    
    if (!opt_quiet && !opt_json) {
        struct utsname uts;
        if (uname(&uts) == 0) {
            print_info("System: %s %s %s", uts.sysname, uts.release, uts.machine);
        }
        print_info("Starting rootkit scan...");
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
    
    if (run_all || run_ebpf) {
        check_ebpf_programs();
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
    
    if (run_all || run_integrity) {
        check_file_integrity();
    }
    
    if (run_all || run_memory) {
        check_memory_signatures();
    }
    
    /* Print summary */
    print_summary();
    
    /* Close log file */
    if (log_file) {
        time_t now = time(NULL);
        fprintf(log_file, "\nScan completed at %s", ctime(&now));
        fprintf(log_file, "Summary: %d critical, %d high, %d medium, %d low\n",
                stats.critical, stats.high, stats.medium, stats.low);
        fclose(log_file);
        if (!opt_quiet && !opt_json) {
            print_info("Results logged to: %s", log_path);
        }
    }
    
    return stats.critical > 0 ? 2 : (stats.high > 0 ? 1 : 0);
}
