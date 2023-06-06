#ifndef A3_BPF_INSN_H
#define A3_BPF_INSN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>

static __always_inline void err_print(const char *msg)
{
    printf("\033[31m\033[1m[x] Run eBPF error: \033[0m%s\n", msg);
}

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)          \
    ((struct bpf_insn) {                                \
        .code        = CODE,                            \
        .dst_reg     = DST,                             \
        .src_reg     = SRC,                             \
        .off         = OFF,                             \
        .imm         = IMM                              \
})

#define BPF_ALU64_REG(OP, DST, SRC)                     \
        BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_X, DST, SRC, 0, 0)

#define BPF_ALU32_REG(OP, DST, SRC)                     \
        BPF_RAW_INSN(BPF_ALU | BPF_OP(OP) | BPF_X, DST, SRC, 0, 0)

#define BPF_ALU64_IMM(OP, DST, IMM)                     \
        BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)

#define BPF_ALU32_IMM(OP, DST, IMM)                     \
        BPF_RAW_INSN(BPF_ALU | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)

#define BPF_MOV64_REG(DST, SRC)                         \
        BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, DST, SRC, 0, 0)

#define BPF_MOV32_REG(DST, SRC)                         \
        BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_X, DST, SRC, 0, 0)

#define BPF_MOV64_IMM(DST, IMM)                         \
        BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)

#define BPF_MOV32_IMM(DST, IMM)                         \
        BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_K, DST, 0, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)                 \
        BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, DST, SRC, 0, (uint32_t) (IMM)),\
        BPF_RAW_INSN(0, 0, 0, 0, ((uint64_t) (IMM)) >> 32)

#define BPF_LD_IMM64(DST, IMM)                          \
        BPF_LD_IMM64_RAW(DST, 0, IMM)

#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD	1
#endif

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)                      \
        BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */
#define BPF_LD_ABS(SIZE, IMM)                           \
        BPF_RAW_INSN(BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, 0, 0, 0, IMM)

/* dst_reg = *(uint *) (src_reg + off16) */
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                \
        BPF_RAW_INSN(BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)

/* *(uint *) (dst_reg + off16) = src_reg */
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)                \
        BPF_RAW_INSN(BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)

#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)          \
        BPF_RAW_INSN(BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC, DST, SRC, OFF, OP)

#define BPF_STX_XADD(SIZE, DST, SRC, OFF)               \
        BPF_ATOMIC_OP(SIZE, BPF_ADD, DST, SRC, OFF)

/* *(uint *) (dst_reg + off16) = imm */
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                 \
        BPF_RAW_INSN(BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, DST, 0, OFF, IMM)

#define BPF_JMP_REG(OP, DST, SRC, OFF)                  \
        BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)

#define BPF_JMP32_REG(OP, DST, SRC, OFF)                \
        BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)

#define BPF_JMP_IMM(OP, DST, IMM, OFF)                  \
        BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)                \
        BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)

#define BPF_EXIT_INSN()                                 \
        BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

#define BPF_READ_ARRAY_MAP_IDX(__idx, __map_fd, __dst_reg)                   \
        /* get a pointer to bpf_array */                \
        BPF_LD_MAP_FD(BPF_REG_9, __map_fd),             \
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),            \
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),           \
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),          \
        BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, __idx),        \
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), \
        /* if success, r0 will be ptr to value, 0 for failed */              \
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),          \
        BPF_EXIT_INSN(),                                \
        /* mov the result back and clear R0 */          \
        BPF_MOV64_REG(__dst_reg, BPF_REG_0),            \
        BPF_MOV64_IMM(BPF_REG_0, 0)

#ifndef __user
#define __user 
#endif

#ifndef __rcu
#define __rcu 
#endif

struct bpf_map;
struct btf;
struct btf_type;
struct bpf_prog;
struct bpf_prog_aux;
struct poll_table_struct;
struct vm_area_struct;
struct bpf_local_storage_map;

/* map is generic key/value storage optionally accesible by eBPF programs */
struct bpf_map_ops {
	/* funcs callable from userspace (via syscall) */
	int (*map_alloc_check)(union bpf_attr *attr);
	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
	void (*map_release)(struct bpf_map *map, struct file *map_file);
	void (*map_free)(struct bpf_map *map);
	int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
	void (*map_release_uref)(struct bpf_map *map);
	void *(*map_lookup_elem_sys_only)(struct bpf_map *map, void *key);
	int (*map_lookup_batch)(struct bpf_map *map, const union bpf_attr *attr,
				union bpf_attr __user *uattr);
	int (*map_lookup_and_delete_batch)(struct bpf_map *map,
					   const union bpf_attr *attr,
					   union bpf_attr __user *uattr);
	int (*map_update_batch)(struct bpf_map *map, const union bpf_attr *attr,
				union bpf_attr __user *uattr);
	int (*map_delete_batch)(struct bpf_map *map, const union bpf_attr *attr,
				union bpf_attr __user *uattr);

	/* funcs callable from userspace and from eBPF programs */
	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
	int (*map_update_elem)(struct bpf_map *map, void *key, void *value, 
        		       uint64_t flags);
	int (*map_delete_elem)(struct bpf_map *map, void *key);
	int (*map_push_elem)(struct bpf_map *map, void *value, uint64_t flags);
	int (*map_pop_elem)(struct bpf_map *map, void *value);
	int (*map_peek_elem)(struct bpf_map *map, void *value);

	/* funcs called by prog_array and perf_event_array map */
	void *(*map_fd_get_ptr)(struct bpf_map *map, struct file *map_file,
				int fd);
	void (*map_fd_put_ptr)(void *ptr);
	int (*map_gen_lookup)(struct bpf_map *map, struct bpf_insn *insn_buf);
	uint32_t (*map_fd_sys_lookup_elem)(void *ptr);
	void (*map_seq_show_elem)(struct bpf_map *map, void *key,
				  struct seq_file *m);
	int (*map_check_btf)(const struct bpf_map *map,
			     const struct btf *btf,
			     const struct btf_type *key_type,
			     const struct btf_type *value_type);

	/* Prog poke tracking helpers. */
	int (*map_poke_track)(struct bpf_map *map, struct bpf_prog_aux *aux);
	void (*map_poke_untrack)(struct bpf_map *map, struct bpf_prog_aux *aux);
	void (*map_poke_run)(struct bpf_map *map, uint32_t key, 
			     struct bpf_prog *old, struct bpf_prog *new);

	/* Direct value access helpers. */
	int (*map_direct_value_addr)(const struct bpf_map *map,
				     uint64_t *imm, uint32_t off);
	int (*map_direct_value_meta)(const struct bpf_map *map,
				     uint64_t imm, uint32_t *off);
	int (*map_mmap)(struct bpf_map *map, struct vm_area_struct *vma);
	__poll_t (*map_poll)(struct bpf_map *map, struct file *filp,
			     struct poll_table_struct *pts);

	/* Functions called by bpf_local_storage maps */
	int (*map_local_storage_charge)(struct bpf_local_storage_map *smap,
					void *owner, uint32_t size);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *smap,
					   void *owner, uint32_t size);
	struct bpf_local_storage __rcu ** (*map_owner_storage_ptr)(void *owner);

	/* map_meta_equal must be implemented for maps that can be
	 * used as an inner map.  It is a runtime check to ensure
	 * an inner map can be inserted to an outer map.
	 *
	 * Some properties of the inner map has been used during the
	 * verification time.  When inserting an inner map at the runtime,
	 * map_meta_equal has to ensure the inserting map has the same
	 * properties that the verifier has used earlier.
	 */
	int (*map_meta_equal)(const struct bpf_map *meta0,
			      const struct bpf_map *meta1);

	/* BTF name and id of struct allocated by map_alloc */
	const char * const map_btf_name;
	int *map_btf_id;

	/* bpf_iter info used to open a seq_file */
	const struct bpf_iter_seq_info *iter_seq_info;
};

static __always_inline int bpf(int cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static __always_inline int
bpf_load_prog(unsigned int prog_type, struct bpf_insn *insns, uint64_t insn_cnt,
              char *log_buf, unsigned int log_buf_sz, unsigned int log_level)
{
    union bpf_attr attr = {
        .prog_type = prog_type,
        .insns = (uint64_t) insns,
        .insn_cnt = insn_cnt,
        .license = (uint64_t) "GPL",
        .log_level = log_level,
        .log_buf = (uint64_t) log_buf,
        .log_size = log_buf_sz,
    };

    return bpf(BPF_PROG_LOAD, &attr);
}

static __always_inline int
bpf_map_create(unsigned int map_type, unsigned int key_size, 
               unsigned int value_size, unsigned int max_entries)
{
    union bpf_attr attr = {
        .map_type = map_type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };

    return bpf(BPF_MAP_CREATE, &attr);
}

static __always_inline int
bpf_map_lookup_elem(int map_fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) key,
        .value = (uint64_t) value,
    };

    return bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

static __always_inline int
bpf_map_update_elem(int map_fd,const void *key,const void *value,uint64_t flags)
{
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) key,
        .value = (uint64_t) value,
        .flags = flags,
    };

    return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

static __always_inline int
bpf_map_delete_elem(int map_fd, const void *key)
{
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) key,
    };

    return bpf(BPF_MAP_DELETE_ELEM, &attr);
}

static __always_inline int
bpf_map_get_next_key(int map_fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) key,
        .next_key = (uint64_t) value,
    };

    return bpf(BPF_MAP_GET_NEXT_KEY, &attr);
}

#define BPF_LOG_BUF_SZ 0x100000
static char bpf_log_buf[BPF_LOG_BUF_SZ] = { '\0' };

/**
 * @brief Run a bpf prog by attaching to a pair of sockets and sending packets
 * 
 * @param insns bpf program to be run
 * @param insn_cnt number of bpf instructions
 * @return int 0 for success, others for failure
 */
static int
run_bpf_prog(struct bpf_insn *insns, uint64_t insn_cnt, unsigned int log_level, 
             unsigned int print_log)
{
    char *err_msg = NULL;
    int sock_fd[2], prog_fd;
    int ret;

    /* socket pair to trigger eBPF prog */
    ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, sock_fd);
    if (ret < 0) {
        err_msg = "FAILED to creat socket pair!";
        goto err_socket;
    }

    memset(bpf_log_buf, 0, sizeof(bpf_log_buf));

    /* load bpf prog into kernel */
    prog_fd = bpf_load_prog(BPF_PROG_TYPE_SOCKET_FILTER, insns, insn_cnt, 
                            bpf_log_buf, BPF_LOG_BUF_SZ, log_level);
    if (prog_fd < 0) {
        ret = prog_fd;
        err_msg = "FAILED to load bpf program!";
        goto err_bpf_load;
    }

    /* attach bpf prog to a socket */
    ret = setsockopt(sock_fd[0],SOL_SOCKET,SO_ATTACH_BPF, &prog_fd,sizeof(int));
    if (ret < 0) {
        err_msg = "FAILED to attach the bpf program!";
        goto err_bpf_attach;
    }

    /* send a packet to trigger bpf */
    write(sock_fd[1], "arttnba3", 8);

    /* output the log */
    if (print_log != 0) {
        puts(bpf_log_buf);
    }

    /* recycle resource */
    close(prog_fd);
    close(sock_fd[1]);
    close(sock_fd[0]);

    return 0;

err_bpf_attach:
    close(prog_fd);
err_bpf_load:
    puts(bpf_log_buf);
    close(sock_fd[1]);
    close(sock_fd[0]);
err_socket:
    err_print(err_msg);
    return ret;
}

#endif
