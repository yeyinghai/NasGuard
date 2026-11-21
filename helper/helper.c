#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    const char *ok[] = {"start", "stop", "restart", "status", NULL};
    int i, good = 0;
    if (argc != 2) { fprintf(stderr, "usage: nasguard-helper start|stop|restart|status\n"); return 2; }
    for (i = 0; ok[i]; i++) if (strcmp(argv[1], ok[i]) == 0) good = 1;
    if (!good) { fprintf(stderr, "bad action\n"); return 2; }
    if (setgid(0) != 0 || setuid(0) != 0) { perror("setuid"); return 1; }
    clearenv();
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/syno/sbin:/usr/syno/bin", 1);
    setenv("LANG", "en_US.UTF-8", 1);
    execl("/bin/sh", "sh", "/var/packages/NasGuard/target/bin/ctl.sh", argv[1], (char *)NULL);
    perror("exec");
    return 1;
}
