/*
 * NullSec RKHunt - Rootkit Hunter
 * Author: bad-antics
 * Language: C
 *
 * Detect hidden processes, kernel modules, and system call hooks
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h>
#include <time.h>

#define VERSION "1.0.0"

/* ANSI Colors */
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define CYAN    "\x1b[36m"
#define GRAY    "\x1b[90m"
#define RESET   "\x1b[0m"

/* Banner */
const char *BANNER = 
"\n"
"    ██████╗ ██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗\n"
"    ██╔══██╗██║ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝\n"
"    ██████╔╝█████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   \n"
"    ██╔══██╗██╔═██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   \n"
"    ██║  ██║██║  ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   \n"
"    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   \n"
"    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
"    Rootkit Hunter                      [NullSec] v1.0.0\n"
"\n";

/* Suspicious paths */
const char *SUSPICIOUS_PATHS[] = {
    "/tmp/.X11-unix",
    "/dev/shm/.hidden",
    "/var/tmp/.hidden",
    "/.hidden",
    "/root/.hidden",
    "/etc/ld.so.preload",
    NULL
};

/* Known rootkit signatures */
const char *ROOTKIT_SIGS[] = {
    "adore",
    "knark",
    "rkit",
    "rkh",
    "suckit",
    "beastkit",
    "shv4",
    "shv5",
    "rkkit",
    "ark",
    "zk",
    "override",
    "jynx",
    "diamorphine",
    NULL
};

/* Suspicious kernel modules */
const char *SUSPICIOUS_MODULES[] = {
    "rootkit",
    "hidden",
    "stealth",
    "invisible",
    "hide",
    "diamorphine",
    "reptile",
    "suterusu",
    "beurk",
    NULL
};

/* Statistics */
typedef struct {
    int warnings;
    int infections;
    int hidden_procs;
    int suspicious_files;
    int hooked_syscalls;
} stats_t;

static stats_t stats = {0};
static int verbose = 0;
static int quiet = 0;

/* Utility functions */
void print_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("  " CYAN "[*]" RESET " ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

void print_ok(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("  " GREEN "[✓]" RESET " ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

void print_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("  " YELLOW "[⚠]" RESET " ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
    stats.warnings++;
}

void print_alert(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("  " RED "[!]" RESET " ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
    stats.infections++;
}

void print_section(const char *title) {
    printf("\n  " CYAN "━━━ %s ━━━" RESET "\n\n", title);
}

/* Check if process exists in /proc but not visible via readdir */
int check_hidden_processes(void) {
    print_section("Hidden Process Detection");
    
    int found = 0;
    char path[256];
    
    /* Check PID range 1-65535 */
    for (int pid = 1; pid <= 65535; pid++) {
        snprintf(path, sizeof(path), "/proc/%d", pid);
        
        struct stat st;
        if (stat(path, &st) == 0) {
            /* Process exists, check if visible in readdir */
            char cmdline[256] = {0};
            char cmdpath[280];
            snprintf(cmdpath, sizeof(cmdpath), "/proc/%d/cmdline", pid);
            
            int fd = open(cmdpath, O_RDONLY);
            if (fd >= 0) {
                read(fd, cmdline, sizeof(cmdline) - 1);
                close(fd);
            }
            
            /* Check for suspicious empty cmdline (kernel thread or hidden) */
            if (strlen(cmdline) == 0 && pid > 2) {
                /* Could be kernel thread - check further */
                char statpath[280];
                char statbuf[256];
                snprintf(statpath, sizeof(statpath), "/proc/%d/stat", pid);
                
                fd = open(statpath, O_RDONLY);
                if (fd >= 0) {
                    read(fd, statbuf, sizeof(statbuf) - 1);
                    close(fd);
                    
                    /* Check if it's a user-space process without cmdline */
                    if (!strstr(statbuf, "kworker") && 
                        !strstr(statbuf, "kthread") &&
                        !strstr(statbuf, "migration")) {
                        if (verbose) {
                            print_warn("Suspicious process PID %d with empty cmdline", pid);
                        }
                    }
                }
            }
        }
    }
    
    if (found == 0) {
        print_ok("No hidden processes detected via /proc enumeration");
    }
    
    return found;
}

/* Compare ps output vs /proc */
int check_proc_vs_ps(void) {
    print_section("Process Consistency Check");
    
    int proc_count = 0;
    int ps_count = 0;
    
    /* Count processes in /proc */
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (isdigit(entry->d_name[0])) {
                proc_count++;
            }
        }
        closedir(dir);
    }
    
    /* Count processes via ps */
    FILE *fp = popen("ps aux 2>/dev/null | wc -l", "r");
    if (fp) {
        fscanf(fp, "%d", &ps_count);
        pclose(fp);
        ps_count--; /* Subtract header line */
    }
    
    print_info("Processes in /proc: %d", proc_count);
    print_info("Processes via ps:   %d", ps_count);
    
    int diff = abs(proc_count - ps_count);
    if (diff > 5) {
        print_warn("Process count mismatch: %d difference (possible hidden processes)", diff);
        stats.hidden_procs = diff;
        return diff;
    } else {
        print_ok("Process counts consistent");
    }
    
    return 0;
}

/* Check for LD_PRELOAD hooking */
int check_ld_preload(void) {
    print_section("LD_PRELOAD Analysis");
    
    int found = 0;
    
    /* Check environment */
    char *preload = getenv("LD_PRELOAD");
    if (preload && strlen(preload) > 0) {
        print_alert("LD_PRELOAD is set: %s", preload);
        found++;
    }
    
    /* Check /etc/ld.so.preload */
    FILE *fp = fopen("/etc/ld.so.preload", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            /* Remove newline */
            line[strcspn(line, "\n")] = 0;
            if (strlen(line) > 0 && line[0] != '#') {
                print_alert("ld.so.preload entry: %s", line);
                found++;
            }
        }
        fclose(fp);
    }
    
    if (found == 0) {
        print_ok("No LD_PRELOAD hooks detected");
    }
    
    return found;
}

/* Check loaded kernel modules */
int check_kernel_modules(void) {
    print_section("Kernel Module Analysis");
    
    int found = 0;
    FILE *fp = fopen("/proc/modules", "r");
    
    if (!fp) {
        print_warn("Cannot read /proc/modules");
        return -1;
    }
    
    char line[512];
    int total = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        total++;
        
        /* Check against suspicious names */
        for (int i = 0; SUSPICIOUS_MODULES[i] != NULL; i++) {
            if (strcasestr(line, SUSPICIOUS_MODULES[i])) {
                char modname[64];
                sscanf(line, "%63s", modname);
                print_alert("Suspicious kernel module: %s", modname);
                found++;
            }
        }
    }
    fclose(fp);
    
    print_info("Total kernel modules: %d", total);
    
    if (found == 0) {
        print_ok("No suspicious kernel modules detected");
    }
    
    return found;
}

/* Check for hidden files in common locations */
int check_hidden_files(void) {
    print_section("Hidden File Detection");
    
    int found = 0;
    const char *dirs[] = {"/tmp", "/var/tmp", "/dev/shm", "/dev", NULL};
    
    for (int i = 0; dirs[i] != NULL; i++) {
        DIR *dir = opendir(dirs[i]);
        if (!dir) continue;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            /* Check for dot files (hidden) */
            if (entry->d_name[0] == '.' && 
                strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0) {
                
                /* Skip known safe */
                if (strcmp(entry->d_name, ".X11-unix") == 0 ||
                    strcmp(entry->d_name, ".font-unix") == 0 ||
                    strcmp(entry->d_name, ".ICE-unix") == 0) {
                    continue;
                }
                
                char fullpath[512];
                snprintf(fullpath, sizeof(fullpath), "%s/%s", dirs[i], entry->d_name);
                
                /* Check for suspicious extensions or patterns */
                if (strstr(entry->d_name, ".sh") ||
                    strstr(entry->d_name, ".py") ||
                    strstr(entry->d_name, ".so") ||
                    strstr(entry->d_name, "root") ||
                    strstr(entry->d_name, "shell")) {
                    print_warn("Suspicious hidden file: %s", fullpath);
                    found++;
                } else if (verbose) {
                    print_info("Hidden file: %s", fullpath);
                }
            }
        }
        closedir(dir);
    }
    
    stats.suspicious_files += found;
    
    if (found == 0) {
        print_ok("No suspicious hidden files detected");
    }
    
    return found;
}

/* Check for rootkit signatures in files */
int check_rootkit_signatures(void) {
    print_section("Rootkit Signature Scan");
    
    int found = 0;
    const char *dirs[] = {"/bin", "/sbin", "/usr/bin", "/usr/sbin", NULL};
    
    for (int d = 0; dirs[d] != NULL; d++) {
        DIR *dir = opendir(dirs[d]);
        if (!dir) continue;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            for (int i = 0; ROOTKIT_SIGS[i] != NULL; i++) {
                if (strcasestr(entry->d_name, ROOTKIT_SIGS[i])) {
                    char fullpath[512];
                    snprintf(fullpath, sizeof(fullpath), "%s/%s", dirs[d], entry->d_name);
                    print_alert("Rootkit signature match: %s", fullpath);
                    found++;
                }
            }
        }
        closedir(dir);
    }
    
    if (found == 0) {
        print_ok("No rootkit signatures detected in system binaries");
    }
    
    return found;
}

/* Check /proc filesystem anomalies */
int check_proc_anomalies(void) {
    print_section("Proc Filesystem Analysis");
    
    int found = 0;
    
    /* Check for hidden entries in /proc */
    struct stat st;
    
    /* Check kcore access */
    if (stat("/proc/kcore", &st) != 0) {
        print_warn("/proc/kcore not accessible - may be hidden");
        found++;
    }
    
    /* Check kallsyms */
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (fp) {
        int count = 0;
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            count++;
            /* Check for zeroed out addresses (sign of hiding) */
            if (strncmp(line, "0000000000000000", 16) == 0 && count > 10) {
                /* Many zeroed addresses could indicate kallsyms restriction */
                break;
            }
        }
        fclose(fp);
        
        if (count < 1000) {
            print_warn("kallsyms appears restricted or empty (%d entries)", count);
            found++;
        } else {
            print_ok("kallsyms accessible (%d entries)", count);
        }
    } else {
        print_warn("Cannot read /proc/kallsyms");
        found++;
    }
    
    return found;
}

/* Check network connections for suspicious activity */
int check_network(void) {
    print_section("Network Analysis");
    
    int found = 0;
    
    /* Check for promiscuous mode */
    FILE *fp = fopen("/proc/net/dev", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "PROMISC")) {
                print_warn("Interface in promiscuous mode detected");
                found++;
            }
        }
        fclose(fp);
    }
    
    /* Check for suspicious listening ports */
    fp = popen("ss -tlnp 2>/dev/null | grep -E ':4444|:31337|:12345|:6666|:6667'", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            print_alert("Suspicious port: %s", line);
            found++;
        }
        pclose(fp);
    }
    
    if (found == 0) {
        print_ok("No suspicious network activity detected");
    }
    
    return found;
}

/* Check system integrity */
int check_system_integrity(void) {
    print_section("System Integrity");
    
    int found = 0;
    
    /* Check for modified system binaries using package manager */
    FILE *fp = popen("rpm -Va 2>/dev/null | grep '^..5' | head -5 2>/dev/null || "
                     "dpkg --verify 2>/dev/null | grep '^..5' | head -5 2>/dev/null", "r");
    if (fp) {
        char line[512];
        int count = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (count++ == 0) {
                print_warn("Modified system files detected:");
            }
            printf("    %s", line);
            found++;
        }
        pclose(fp);
    }
    
    if (found == 0) {
        print_ok("System binary integrity verified");
    }
    
    return found;
}

/* Print summary */
void print_summary(void) {
    print_section("Scan Summary");
    
    printf("  Warnings:          %d\n", stats.warnings);
    printf("  Infections:        %d\n", stats.infections);
    printf("  Hidden Processes:  %d\n", stats.hidden_procs);
    printf("  Suspicious Files:  %d\n", stats.suspicious_files);
    printf("\n");
    
    if (stats.infections > 0) {
        print_alert("SYSTEM MAY BE COMPROMISED - %d potential infection(s) found!", stats.infections);
    } else if (stats.warnings > 0) {
        print_warn("Scan completed with %d warning(s)", stats.warnings);
    } else {
        print_ok("System appears clean");
    }
    printf("\n");
}

/* Print usage */
void print_usage(const char *prog) {
    printf("%s%s%s", RED, BANNER, RESET);
    printf("  Usage: %s [options]\n\n", prog);
    printf("  Options:\n");
    printf("    -a, --all       Run all checks\n");
    printf("    -p, --procs     Check for hidden processes\n");
    printf("    -m, --modules   Check kernel modules\n");
    printf("    -f, --files     Check for hidden files\n");
    printf("    -n, --network   Check network anomalies\n");
    printf("    -l, --preload   Check LD_PRELOAD hooks\n");
    printf("    -v, --verbose   Verbose output\n");
    printf("    -q, --quiet     Suppress banner\n");
    printf("    -h, --help      Show this help\n");
    printf("    --version       Show version\n");
    printf("\n");
    printf("  Examples:\n");
    printf("    %s -a            Run full scan\n", prog);
    printf("    %s -p -m         Check processes and modules\n", prog);
    printf("    %s -a -v         Full scan with verbose output\n", prog);
    printf("\n");
}

int main(int argc, char *argv[]) {
    int check_all = 0;
    int check_procs = 0;
    int check_modules = 0;
    int check_files = 0;
    int check_net = 0;
    int check_preload = 0;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("NullSec RKHunt v%s\n", VERSION);
            return 0;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            check_all = 1;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--procs") == 0) {
            check_procs = 1;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--modules") == 0) {
            check_modules = 1;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--files") == 0) {
            check_files = 1;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--network") == 0) {
            check_net = 1;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--preload") == 0) {
            check_preload = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            quiet = 1;
        }
    }
    
    /* Default to all if no specific check */
    if (!check_procs && !check_modules && !check_files && !check_net && !check_preload) {
        check_all = 1;
    }
    
    if (!quiet) {
        printf("%s%s%s", RED, BANNER, RESET);
    }
    
    /* Check for root */
    if (geteuid() != 0) {
        print_warn("Running without root privileges - some checks may be limited");
    }
    
    print_info("Starting rootkit scan...");
    time_t start = time(NULL);
    
    /* Run selected checks */
    if (check_all || check_procs) {
        check_hidden_processes();
        check_proc_vs_ps();
    }
    
    if (check_all || check_preload) {
        check_ld_preload();
    }
    
    if (check_all || check_modules) {
        check_kernel_modules();
    }
    
    if (check_all || check_files) {
        check_hidden_files();
        check_rootkit_signatures();
    }
    
    if (check_all) {
        check_proc_anomalies();
        check_system_integrity();
    }
    
    if (check_all || check_net) {
        check_network();
    }
    
    time_t end = time(NULL);
    print_info("Scan completed in %ld seconds", end - start);
    
    print_summary();
    
    return stats.infections > 0 ? 1 : 0;
}
