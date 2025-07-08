# D^3CTF 2025 - Pwn - d3kshrm

You know what? Sharing is always a good moral quality. That's the reason why I'm going to share some of my precious memories with all of you!

> Copyright(c) 2025 <ディーキューブ・シーティーエフ カーネル Pwn 製作委員会>
>
> Author: arttnba3 @ L-team x El3ctronic x D^3CTF

## 0x00. Introduction

In this challenge we created a kernel module named `d3kshrm.ko` , which can provide users with functionalities to create shared memory. Through the `ioctl()` interface we have the following capabilities:

- Create a new shared memory with specific size
- Bind to an existed shared memory
- Unbind from current shared memory
- Delete an existed shared memory

And to access the shared memory, we can map the file descriptor after binding it, where the vulnerability locates. Due to the lack of checking on the bound of  `d3kshrm::pages`, an attacker can treat the next 8 bytes next to the `d3kshrm::pages` as a pointer to `struct page` and map it to the user address space.

```c
static vm_fault_t d3kshrm_vm_fault(struct vm_fault *vmf)
{
    struct d3kshrm_struct *d3kshrm;
    struct vm_area_struct *vma;
    vm_fault_t res;

    vma = vmf->vma;
    d3kshrm = (struct d3kshrm_struct *) vma->vm_private_data;

    spin_lock(&d3kshrm->lock);

    /* vulnerability here */
    // if (vmf->pgoff >= d3kshrm->page_nr) {
    if (vmf->pgoff > d3kshrm->page_nr) {
        res = VM_FAULT_SIGBUS;
        goto ret;
    }

    get_page(d3kshrm->pages[vmf->pgoff]);
    vmf->page = d3kshrm->pages[vmf->pgoff];
    res = 0;

ret:
    spin_unlock(&d3kshrm->lock);

    return res;
}
```

## 0x01. Exploitation

As the `d3kshrm::pages` will be allocated from an isolated `kmem_cache`, we have to use page-level heap fengshui to manipulate page-level memory to try to map page pointers outside the challenge functionalities, which is because we can not exploit pages directly by double-mapping as the reference number exists as guard to prevent us to create page-level double free directly. Hence our available exploitation strategy is to map those pages originally with read-only permissions to the user space, which will remind us of the [CVE-2023-2008](https://github.com/arttnba3/Linux-kernel-exploitation/tree/main/CVE/CVE-2023-2008) that also abusing out-of-bound page mapping to do the DirtyPage-like attack. Here comes our exploitation strategy:

- Use page-level heap fengshui to re-arrange page-level memory to put the SLUB pages of the isolated `kmem_cache` of the challenge between two SLUB pages of the victim objects. Here we chose the `pipe_buffer` as the victim as it has a pointer to the `struct page` at the start of the structure, which makes us possible to do the out-of-bound mapping.
- Open the file with read-only permission and use `splice()` function to store the first page of the target file into the `pipe_buffer`.
- Exploit the vulnerability to do the out-of-bound page mapping to map the page originally with read-only permission to the user space with read & write permissions. Hence the power of overwriting read-only file will be granted to us.

I finally chose the `/sbin/poweroff` (which is the symbolic to the `busybox`) as our victim file, as the final line of the `/etc/init.d/rcS` is to execute the `/sbin/poweroff` with root privilege, which will grant us with the power to execute arbitrary code with root privilege. The final exploitation is in `exo.c` in this repository, whose successful rate is at approximately `84.63%` (result after more than 2048 times automatic local test), and I'm convinced that there must be a room to rise it to over `95%+` as I hadn't adopt complex and advanced page-level heap fengshui procedure yet.

## 0x02. Unintended Solution

I'm so sorry that I didn't configure the file system well, which have caused an unintended solution as a result. Before we start I'd like to thank [Qanux](https://9anux.org/2025/06/02/d3kshrm/) from [W&M](https://wm-team.cn/) who has found this issue by chance. To be honest the reason why unintended solution could be happened is that **I configured the file system too normally.**

A minimal proof-of-concept function to **stably** trigger the unintended solution **without the challenge kernel module** is as follow (for helper functions like `prepare_pgv_system()` and `alloc_page()` please refer to the `exp.c`):

```c
void unintended_exploit(void)
{
    int errno;
    prepare_pgv_system();

    for (int i = 0; i < 1000; i++) {
        if ((errno = create_pgv_socket(i)) < 0) {
            printf(ERROR_MSG("[x] Failed to allocate socket: ") "%d\n", i);
            err_exit("FAILED to allocate socket!");
        }

        if ((errno = alloc_page(i, 0x1000 * 64, 64)) < 0) {
            printf(ERROR_MSG("[x] Failed to alloc pages on socket: ")"%d\n", i);
            err_exit("FAILED to allocate pages!");
        }

        printf("[*] No.%d times\n", i);
        fflush(stdout);
    }

    puts("Done!?");
}
```

While executing the proof-of-concept, we can notice that our process just terminated suddenly. Then we just got a root shell with no reasons:

![image.png](https://s2.loli.net/2025/06/03/YIoRTKiwm8bCe19.png)

**How and why?** To figure out what is happening during this procedure, let's take a brief look at our proof-of-concept, who just simply **keeps doing the memory allocation** via the `setsockopt()` of `packet socket`. We all know that if the memory of a process keeps growing and occupies too much memory, there will be no enough available free memory for the system to use, thus the [OOM Killer](https://www.kernel.org/doc/gorman/html/understand/understand016.html) will be waken up to see whether the system have to kill a process for reclaiming its memory back. 

Which process will be chosen to be killed? As we know that there are only several user land processes running in the environment, there is no doubt that the one to be possible to be killed can only comes from `rcS` , `sh`, and `exploit` . But who will be the guy to be chosen as the unlucky sheep? Well, the  [OOM Killer](https://www.kernel.org/doc/gorman/html/understand/understand016.html) determines the victim target depending on multiple factors including the resource consumption, and we can check that by examining the `/proc/[pid]/oom_score` . The result we need is as follow (reading by a simple C function):

![image.png](https://s2.loli.net/2025/06/04/x7Vgjsch31p9XRm.png)

As we can see that the `rcS` and `sh` have the same OOM scores, the unlucky guy will be one of them as the `exploit` has a lower score. And as the `rcS` is a root process while `sh` is not, it seems that killing the `sh` does make sense? The answer is **YES, BUT NOT ONLY YES**. Let us see what really happened:

![](https://s2.loli.net/2025/06/04/gerH8pOMsDUf2uy.png)

**ALL OF THEM ARE KILLED for reclaiming the memory!** But why? An important reason is that after killing one specific victim process, there may still not be enough spare memory to be allocated. This may due to the asynchronous memory reclaiming, memory fragments and so on. What is more is that _we are keeping doing the memory allocation._ Therefore the OOM killer was invoked for multiple times (even if in one allocation procedure), killed the `sh` and `rcS` according to its high `oom_score` and orderd by privilege, and finally killed the `exploit` in the end.

**What will happen if all these processes are killed?** As the `ttyS0` was occupied by these processes and finally get free at the moment, the `init` will re-get its control and detect that it's free now. Note that our initialization system is using the `busybox-init`, as we can see that the `/sbin/init` is a symbol link to the `busybox`. The `busybox-init` will use the `/etc/inittab` as its configuration file, so let's see what I've written in this file at a very long time ago, which is referred to the [official example from the busybox](https://git.busybox.net/busybox/tree/examples/inittab?h=1_37_stable):

```
::sysinit:/etc/init.d/rcS
::askfirst:/bin/ash
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
```

Let's take a look at `::askfirst:` option whose value points to the `/bin/ash`. What is that and in what condition it will be executed? **When there is no process running on the TTY, the program specified by the askfirst option will be executed by the /sbin/init with root privilege** (just like [getty](https://en.wikipedia.org/wiki/Getty_(software))). 

Therefore we can get to know the reason why we can get a root shell: At the very beginning the `/etc/init.d/rcS` is running on the `ttyS0` and spawn a user shell for us to interact. When we try to do the unlimited memory allocation in kernel space to occupy almost all the free memory, the [OOM Killer](https://www.kernel.org/doc/gorman/html/understand/understand016.html) will be waken up to kill the `/etc/init.d/rcS` . As there is no process running on the `ttyS0`, **the /bin/ash specified by ::askfirst: in will be executed to provide us with a root shell**.

That is also how  [Qanux](https://9anux.org/2025/06/02/d3kshrm/) from [W&M](https://wm-team.cn/) solved the `d3kshrm` by accident: he just do the memory allocation directly from functionalities provided by the `d3kshrm.ko` , and due to my misconfiguration and wrong design, the expected allocatable memory is much larger than the memory of the virtual machine. Therefore the OOM killer was waken multiple times to kill all the user land processes except for `init`. After that the `ttyS0` goes idle again the `busybox-init` just throw a root shell out directly to the `ttyS0` he used. 

Hence, here comes another question: **Can we just simply do the memory allocation directly instead of directly exploit the memory-allocation APIs in the kernel?** The answer is almost definitely **NO**. An important reason is that if we allocate memory directly into our process (like doing tons of `malloc()` to expand your heap segment), **our OOM score will grow as well, and we will always be the first one to be killed.** As we were killed, the memory allocation will stop and no need to invoke OOM killer to kill anyone else.

When I got this report during the competition, I quickly realized that this must be caused by the OOM killer after reviewing pictures provided by the player. What I didn't expect is that everyone including the `rcS` will be killed as it never happened in any of CTF challenges I made before. My old expectation is that the kernel will panic due to the OOM, and the result told me that kernel does not always panic (lol the kernel is afraid of dying as well?). The report from the player who discovered this unintended solution says that his successful rate is at least `30%`. However, the POC I wrote above is beyond `99%`, I think this may be caused by the different API we called. As the `packet_set_ring()` calls the `vzalloc_noprof()`, it does only requires the kernel to allocate the memory region that is continuous only required on the virtual memory, which means that it can split the memory allocation from high-order one to low-order ones. However the function in `d3kshrm.ko` just calls the `alloc_pages()` to allocate high-order memory directly, thus the kernel will be more easy to get panic as we may not be able to reclaim required continuous high-order  physical memory.

How I finally fix that? I create a revenge version of this challenge, with the `/etc/inittab` modified. I changed the `::askfirst:` from `/bin/ash` to `/sbin/poweroff` to fix this unexpected vulnerability temporarily. But I think a better version might be changing that to the `login` ? Anyway this had taught me a lesson: **a well-crafted environment might not be the most suitable one**, and I should always **double check everything in the environment**.

## 0xFF. Last but not least...

The introduction and the flag is modified from one of [my favourite advertisement created by the Halo Top](https://www.youtube.com/watch?v=0Kio3t3nXJo). Although this video might just be created for fun, but it does give me some special feelings that I can't describe simply with words. So I chose that as the base and modified a lot to give you some meaningless sentences as the introduction and the flag : )

My innovation of creating this challenge comes from the [CVE-2023-2008](https://github.com/arttnba3/Linux-kernel-exploitation/tree/main/CVE/CVE-2023-2008) whose vulnerability is also the out-of-bound memory mapping. So to be honest it is not a pwn challenge that is hard and creative enough as my expectation and I'm so sorry about that because I'm always wanting to show you something cool and hadn't present anything that is really cool this time. 

An important reason why I chose to modified an existed vulnerability is that _I did not have too much time on completing these challenges._ As I've graduated from my undergraduate, I did not pay too much attention on how my junior schoolmates prepared for this year's D^3CTF, and get to know that almost no pwn challenges were created **just at about 10 days before the competition started** . Therefore I have to stand out to rush to create the pwn challenges with almost nothing new in research in my mind to make sure the competition can be held normally as past years. **Sorry and I apologize that I didn't bring something that is as same cool as the d3kcache in 2023.** 

And if you pay enough attention to the kernel module itself, you may notice that I've wrote another unexpected vulnerability in calculating the reference count of the `vm_area`: I FORGOT TO WRITE THE `vm_open()` TO ADD COUNT BUT HAD REMEMBER TO WRITE THE `vm_close()` TO DEC COUNT! This had made confusion for many of players and made them waste lots of time on trying to exploit that, and to be honest it's not easy to exploit as the page is hard to be use as both the user-land mapping page and SLUB page (but if you're interested enough, maybe you can check for the [CVE-2024-0582](https://github.com/arttnba3/Linux-kernel-exploitation/tree/main/CVE/CVE-2024-0582) which is in a similar situation, but I'm not sure whether it also works for the `d3kshrm` so good luck). I'm sincerely sorry about that because this challenge is also a rush-made one so I didn't check that too well. 

For the whole competition, only the player `Tplus` from the [MNGA](https://ctftime.org/team/19208/) team had solved that with the expected solution. CONGRATULATIONS FOR HIM WHO IS THE ONLY ONE SOLVE THAT DURING THE COMPETITION! And [Qanux](https://9anux.org/2025/06/02/d3kshrm/) from [W&M](https://wm-team.cn/) also succeeded to exploit that with expected solution after the competition ended (because he didn't predict the `-revenge` version would be created for fixing and went out for a big big meal after solved with unintended solution). Anyway I think we should all clap and cheer for them.

And another interesting point all of you may ignore is that **new SLUB pages will be allocated during the kmem\_cache is being created,** which means that our heap fengshui will always need to be focusing on the **NEXT NEW ALLOCATED SLUB PAGES**. I think that is the core reason why both `Tplus` and `Qanux` have a low successful rate in their exploitation as this key point is missing: they're focusing on the first SLUB while my official solution is focusing on the second one. Therefore my successful rate to exploit with page-level heap fengshui is beyond `80%` and almost no need to try multiple times while attacking the remote.

Though I still have many thoughts about the Linux kernel exploitation, but it seems that this passage has become too long at this moment, so let's just stop here. Anyway I would like to thank everyone who has participated in this CTF and has tried to solve my challenge, no matter you've got the flag or not. I'm still so sorry that I did not present you with something as cool as the [d3kcache](https://github.com/arttnba3/D3CTF2023_d3kcache) due to multiple reasons including limited time, hope that you will not mind : )
