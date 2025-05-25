#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <link.h>
#include <time.h>

#define MAX_PATH 4096
#define MAX_LIBS 256

typedef struct {
    char path[MAX_PATH];
    int suspicious;
    char reason[256];
} loaded_lib_t;

void check_preload_env() {
    char *preload = getenv("LD_PRELOAD");
    if (preload) {
        printf("[WARNING] LD_PRELOAD detected: %s\n", preload);
    }
    
    char *library_path = getenv("LD_LIBRARY_PATH");
    if (library_path) {
        printf("[WARNING] LD_LIBRARY_PATH detected: %s\n", library_path);
    }
    
    char *audit = getenv("LD_AUDIT");
    if (audit) {
        printf("[WARNING] LD_AUDIT detected: %s\n", audit);
    }
    
    char *debug = getenv("LD_DEBUG");
    if (debug) {
        printf("[WARNING] LD_DEBUG detected: %s\n", debug);
    }
}

int is_suspicious_path(const char *path) {
    const char *suspicious_dirs[] = {
        "/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/usr/local/bin/",
        "/opt/", "/srv/", "/media/", "/mnt/", "/proc/", "/sys/",
        "/run/", "/var/run/", "/var/lock/", "/var/cache/", "/var/spool/",
        "/var/log/", "/var/backups/", "/var/crash/", "/var/mail/",
        "/usr/local/lib/", "/usr/local/share/", "/usr/games/",
        "/boot/", "/lost+found/", "/cdrom/", "/floppy/",
        "/.snapshots/", "/snap/", "/flatpak/", "/AppImage/",
        "/android_storage/", "/sdcard/", "/storage/",
        "/System/", "/Applications/", "/Library/", "/Users/",
        "/Volumes/", "/Network/", "/cores/", "/private/",
        "/usr/local/Cellar/", "/usr/local/opt/", "/usr/local/var/",
        "/opt/homebrew/", "/opt/local/", "/opt/macports/",
        "/usr/X11R6/", "/usr/openwin/", "/usr/dt/", "/usr/ccs/",
        "/export/", "/net/", "/afs/", "/nfs/", "/cifs/", "/smb/",
        "/mnt/cdrom/", "/mnt/floppy/", "/mnt/usb/", "/mnt/hgfs/",
        "/var/www/", "/var/ftp/", "/var/tftp/", "/var/empty/",
        "/var/db/", "/var/games/", "/var/lib/dpkg/", "/var/lib/rpm/",
        "/usr/local/mysql/", "/usr/local/apache/", "/usr/local/nginx/",
        "/usr/share/pixmaps/", "/usr/share/applications/", "/usr/share/mime/",
        "/usr/libexec/", "/usr/lib64/", "/usr/lib32/", "/lib64/", "/lib32/",
        "/usr/multiarch/", "/usr/cross/", "/usr/target/",
        "/.config/", "/.cache/", "/.local/", "/.wine/", "/.steam/",
        "/.thunderbird/", "/.mozilla/", "/.chromium/", "/.chrome/",
        "/.vscode/", "/.atom/", "/.emacs.d/", "/.vim/",
        "/initrd/", "/initramfs/", "/rescue/", "/recovery/",
        "/android/", "/system/", "/vendor/", "/data/", "/cache/",
        "/apex/", "/odm/", "/product/", "/system_ext/",
        "/Windows/", "/Program Files/", "/Program Files (x86)/",
        "/ProgramData/", "/Users/", "/AppData/", "/Temp/",
        "/Windows/System32/", "/Windows/SysWOW64/", "/Windows/Temp/",
        "/chroot/", "/jail/", "/sandbox/", "/container/", "/docker/",
        "/lxc/", "/systemd-private/", "/snap/", "/squashfs-root/",
        NULL
    };
    
    for (int i = 0; suspicious_dirs[i]; i++) {
        if (strstr(path, suspicious_dirs[i])) {
            return 1;
        }
    }
    
    if (strstr(path, "..") || strstr(path, "./") || 
        strstr(path, "hidden") || strstr(path, "temp") ||
        strstr(path, "cache") || strstr(path, "backup") ||
        strstr(path, "old") || strstr(path, "bak") ||
        strstr(path, "orig") || strstr(path, "copy") ||
        strstr(path, "new") || strstr(path, "test") ||
        strstr(path, "debug") || strstr(path, "dev") ||
        strstr(path, "staging") || strstr(path, "prod") ||
        strstr(path, "local") || strstr(path, "custom") ||
        strstr(path, "modified") || strstr(path, "patched") ||
        strstr(path, "trojan") || strstr(path, "backdoor") ||
        strstr(path, "rootkit") || strstr(path, "malware") ||
        strstr(path, "virus") || strstr(path, "worm") ||
        strstr(path, "bot") || strstr(path, "miner") ||
        strstr(path, "keylog") || strstr(path, "steal") ||
        strstr(path, "inject") || strstr(path, "hook") ||
        strstr(path, "bypass") || strstr(path, "exploit")) {
        return 1;
    }
    
    return 0;
}

int check_lib_permissions(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (st.st_mode & S_IWOTH) return 1;
        if (st.st_mode & S_IWGRP && st.st_gid != getgid()) return 1;
        if (st.st_mode & S_ISUID) return 1;
        if (st.st_mode & S_ISGID) return 1;
        if (st.st_mode & S_ISVTX) return 1;
        if (st.st_size == 0) return 1;
        if (st.st_size > 100*1024*1024) return 1;
        if (st.st_mtime > time(NULL) - 3600) return 1;
    }
    return 0;
}

void scan_proc_maps(loaded_lib_t *libs, int *count) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return;
    
    char line[MAX_PATH];
    *count = 0;
    
    while (fgets(line, sizeof(line), maps) && *count < MAX_LIBS) {
        if (strstr(line, ".so")) {
            char *path = strchr(line, '/');
            if (path) {
                char *newline = strchr(path, '\n');
                if (newline) *newline = '\0';
                
                int found = 0;
                for (int i = 0; i < *count; i++) {
                    if (strcmp(libs[i].path, path) == 0) {
                        found = 1;
                        break;
                    }
                }
                
                if (!found) {
                    strncpy(libs[*count].path, path, MAX_PATH - 1);
                    libs[*count].suspicious = 0;
                    strcpy(libs[*count].reason, "");
                    
                    if (is_suspicious_path(path)) {
                        libs[*count].suspicious = 1;
                        strcat(libs[*count].reason, "suspicious_location ");
                    }
                    
                    if (check_lib_permissions(path)) {
                        libs[*count].suspicious = 1;
                        strcat(libs[*count].reason, "suspicious_permissions ");
                    }
                    
                    (*count)++;
                }
            }
        }
    }
    fclose(maps);
}

int dl_iterate_callback(struct dl_phdr_info *info, size_t size, void *data) {
    if (info->dlpi_name && strlen(info->dlpi_name) > 0) {
        int suspicious = 0;
        char reason[256] = "";
        
        if (is_suspicious_path(info->dlpi_name)) {
            suspicious = 1;
            strcat(reason, "suspicious_location ");
        }
        
        if (check_lib_permissions(info->dlpi_name)) {
            suspicious = 1;
            strcat(reason, "suspicious_permissions ");
        }
        
        if (suspicious) {
            printf("[SUSPICIOUS] %s (%s)\n", info->dlpi_name, reason);
            (*(int*)data)++;
        }
    }
    return 0;
}

void check_loaded_libraries() {
    printf("[INFO] Analyzing loaded libraries via dl_iterate_phdr...\n");
    int threats = 0;
    dl_iterate_phdr(dl_iterate_callback, &threats);
    if (threats == 0) {
        printf("[INFO] No suspicious libraries found via dl_iterate_phdr\n");
    }
}

void analyze_library_functions() {
    const char *critical_funcs[] = {
        "execve", "system", "popen", "dlopen", "mmap", 
        "ptrace", "kill", "socket", "connect", "open",
        "read", "write", "close", "fork", "clone",
        "pipe", "dup", "dup2", "fcntl", "ioctl",
        "mprotect", "munmap", "mremap", "msync",
        "shmget", "shmat", "shmdt", "semget", "msgget",
        "accept", "bind", "listen", "recv", "send",
        "sendto", "recvfrom", "getsockopt", "setsockopt",
        "chroot", "setuid", "setgid", "seteuid", "setegid",
        "capset", "capget", "prctl", "ptrace", "personality",
        "mount", "umount", "pivot_root", "chdir", "fchdir",
        "chmod", "fchmod", "chown", "fchown", "lchown",
        "stat", "lstat", "fstat", "access", "readlink",
        "symlink", "link", "unlink", "rename", "mkdir",
        "rmdir", "opendir", "readdir", "closedir",
        "getpid", "getppid", "getuid", "getgid", "geteuid",
        "getegid", "getgroups", "setgroups", "getpgrp",
        "setpgrp", "setsid", "getpgid", "setpgid",
        "signal", "sigaction", "sigprocmask", "sigsuspend",
        "sigpending", "alarm", "pause", "sleep", "usleep",
        "select", "poll", "epoll_create", "epoll_ctl", "epoll_wait",
        "kqueue", "kevent", "eventfd", "signalfd", "timerfd_create",
        "inotify_init", "inotify_add_watch", "inotify_rm_watch",
        "fanotify_init", "fanotify_mark", "perf_event_open",
        "bpf", "seccomp", "landlock_create_ruleset", "landlock_add_rule",
        "memfd_create", "copy_file_range", "splice", "vmsplice",
        "tee", "fallocate", "posix_fadvise", "readahead",
        "sync", "fsync", "fdatasync", "syncfs", "flock",
        "getrlimit", "setrlimit", "getrusage", "times",
        "sysinfo", "uname", "gethostname", "sethostname",
        "getdomainname", "setdomainname", "reboot", "kexec_load",
        NULL
    };
    
    printf("[INFO] Checking for hooked critical functions...\n");
    
    for (int i = 0; critical_funcs[i]; i++) {
        void *func_ptr = dlsym(RTLD_DEFAULT, critical_funcs[i]);
        if (func_ptr) {
            Dl_info info;
            if (dladdr(func_ptr, &info)) {
                if (info.dli_fname && is_suspicious_path(info.dli_fname)) {
                    printf("[SUSPICIOUS] %s() hooked by %s\n", 
                           critical_funcs[i], info.dli_fname);
                }
            }
        }
    }
}

void check_unusual_mount_points() {
    FILE *mounts = fopen("/proc/mounts", "r");
    if (!mounts) return;
    
    printf("[INFO] Checking mount points for suspicious filesystems...\n");
    char line[MAX_PATH];
    
    while (fgets(line, sizeof(line), mounts)) {
        if (strstr(line, "tmpfs") || strstr(line, "ramfs") || 
            strstr(line, "overlay") || strstr(line, "aufs") ||
            strstr(line, "fuse") || strstr(line, "squashfs") ||
            strstr(line, "iso9660") || strstr(line, "udf") ||
            strstr(line, "ntfs") || strstr(line, "fat") ||
            strstr(line, "exfat") || strstr(line, "hfs") ||
            strstr(line, "btrfs") || strstr(line, "zfs") ||
            strstr(line, "nfs") || strstr(line, "cifs") ||
            strstr(line, "sshfs") || strstr(line, "ftpfs")) {
            
            char *mount_point = strtok(line, " ");
            mount_point = strtok(NULL, " ");
            if (mount_point && is_suspicious_path(mount_point)) {
                printf("[SUSPICIOUS] Unusual mount: %s", line);
            }
        }
    }
    fclose(mounts);
}

void check_process_cmdline() {
    FILE *cmdline = fopen("/proc/self/cmdline", "r");
    if (!cmdline) return;
    
    printf("[INFO] Checking process command line...\n");
    char buffer[MAX_PATH];
    size_t len = fread(buffer, 1, sizeof(buffer) - 1, cmdline);
    buffer[len] = '\0';
    
    for (size_t i = 0; i < len; i++) {
        if (buffer[i] == '\0') buffer[i] = ' ';
    }
    
    if (strstr(buffer, "LD_PRELOAD") || strstr(buffer, "LD_LIBRARY_PATH") ||
        strstr(buffer, "faketime") || strstr(buffer, "strace") ||
        strstr(buffer, "ltrace") || strstr(buffer, "gdb") ||
        strstr(buffer, "valgrind") || strstr(buffer, "perf")) {
        printf("[WARNING] Suspicious command line: %s\n", buffer);
    }
    
    fclose(cmdline);
}

int main() {
    loaded_lib_t libraries[MAX_LIBS];
    int lib_count = 0;
    int threats_found = 0;
    
    printf("Enhanced LD_PRELOAD Malware Detector\n");
    printf("Beginning comprehensive scan...\n\n");
    
    check_preload_env();
    check_process_cmdline();
    check_unusual_mount_points();
    
    printf("[INFO] Scanning loaded libraries...\n");
    scan_proc_maps(libraries, &lib_count);
    
    for (int i = 0; i < lib_count; i++) {
        if (libraries[i].suspicious) {
            printf("[SUSPICIOUS] %s (%s)\n", 
                   libraries[i].path, libraries[i].reason);
            threats_found++;
        }
    }
    
    check_loaded_libraries();
    analyze_library_functions();
    
    printf("\n[SUMMARY] Scanned %d libraries\n", lib_count);
    
    if (threats_found > 0) {
        printf("[RESULT] %d potential threats detected!\n", threats_found);
        return 1;
    } else {
        printf("[RESULT] No obvious LD_PRELOAD malware detected\n");
        return 0;
    }
}
