AFL的编译插桩是在afl-as部分完成的。本部分主要介绍afl-as以及相关编译插桩的内容。
[TOC]
# 开始之前
本篇是afl源码阅读的第二篇，在上一篇我没有主要介绍插桩相关的内容，放在这一章来简单讲一下。

在本篇之后还会有最后一篇第三篇来介绍AFL的 LLVM 优化的相关内容。
# 一个afl-gcc编译出来的程序是什么样的
首先我们不去看源码，直接先看一下插桩后的样子。
我们使用一个很简单的程序
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

int vuln(char *str)
{
    int len = strlen(str);
    if(str[0] == 'A' && len == 66)
    {
        raise(SIGSEGV);
        //如果输入的字符串的首字符为A并且长度为66，则异常退出
    }
    else if(str[0] == 'F' && len == 6)
    {
        raise(SIGSEGV);
        //如果输入的字符串的首字符为F并且长度为6，则异常退出
    }
    else
    {
        printf("it is good!\n");
    }
    return 0;
}

int main(int argc, char *argv[])
{
    char buf[100]={0};
    gets(buf);//存在栈溢出漏洞
    printf(buf);//存在格式化字符串漏洞
    vuln(buf);

    return 0;
}
```
![](https://s3.ax1x.com/2021/02/07/yNwMVA.png)
可以看到这里已经显示了 ```Instrumented 10 locations```
![](https://s3.ax1x.com/2021/02/07/yNwG28.png)
我们将其拉入IDA看一下。
![](https://s3.ax1x.com/2021/02/07/yNwWZ9.png)
![](https://s3.ax1x.com/2021/02/07/yNwqqH.png)
可以看到afl在代码段进行了插桩，主要是 ```__afl_maybe_log``` 函数，用来探测、反馈程序此时的状态。
# afl-as.c源码分析
## main函数
main函数主要做了一下几步
- 通过调用```edit_params(argc, argv)```编辑了参数。
- 调用```add_instrumentation()```进行插桩。
- fork出一个子进程，在子进程中执行我们编辑好的参数。
- 等待子进程执行完退出的信号。
- 退出，exit参数为```WEXITSTATUS(status)```
## edit_params(int argc, char **argv)
- 首先获取环境变量```TMPDIR```、```AFL_AS```
- 如果设置了clang_mode，且由环境变量获取的afl_as为空
  - 设置use_clang_as = 1
  - afl_as为环境变量```"AFL_CC"```的值
  - 如果还是没有获取到  afl_as，令afl_as为环境变量```"AFL_CXX"```的值
  - 如果还是没有获取到  afl_as，令afl_as为```"clang"```
- 获取tmp目录的位置，跟上一步类似
  - ```getenv("TEMP")```
  - ```getenv("TMP")```
  - 若前两个环境变量都没有获取到，直接令其为```"/tmp"```
- 给```as_params```分配空间。
- 接下来处理```as_params[0]```
  - 如果afl_as不空的话，```as_params[0]=afl_as```
  - 否则指定为```"as"```
- 令```as_params[argc]```为0.
- 接下来扫描argv中的参数。
  - 如果设置了```"--64"```，令```use_64bit = 1```
  - 如果是32为，那么```use_64bit = 0```
  - 如果是macos。
    - 若```"-arch"```指定了```"i386"```，那么abort。
        ```Sorry, 32-bit Apple platforms are not supported.```
    - 若在clang mode下，并且当前的argv[i]不是q或Q，那么跳过这个参数，直接continue掉。
  - 否则直接将当前的```argv[i]```放入```as_params[]```参数数组中
- 如果是macos且使用的```use_clang_as```
  - 向参数数组```as_params[]```中依次添加：```-c -x assembler```
- ```argv[argc - 1]```为input_file
- 如果input_file以```'-'```开头
  - 如果是```"-version"```
    - 设置just_version = 1
    - modified_file = input_file
    - 直接跳转到```wrap_things_up```
  - 如果```input_file[1]```还有其他值，告知用户使用错误，abort
  - 否则```input_file = NULL```
- 否则比较当前input_file是否以```tmp_dir```或```"/var/tmp/"```或```"/tmp/"```开头。
  - 若均不是，则令pass_thru = 1
- 设置```modified_file```
  ```modified_file = alloc_printf("%s/afl-%u-%u.s", tmp_dir, getpid(),(u32) time(NULL))```
- 最后到达```wrap_things_up:```
  - 令```as_params[]```最后一个有效参数为```modified_file```
  - 向```as_params[]```最后一个位置补NULL，标志结束。
## 插桩函数 add_instrumentation(void)
在编辑完```as_params[]```参数数组后进入了此插桩函数。
*Process input file, generate modified_file. Insert instrumentation in all the appropriate places.*
- 如果设置了input_file
  - 只读打开input_file，fd为inf
    ```input_file:/Users/apple/Desktop/AFL/AFL/cmake-build-debug/tmp/test-instr.s```
- 否则inf为stdin
- 打开modified_file，返回out_fd
- 接下来通过while循环每次从input_file(test-instr.s)中读取一行到line中（大小为8192）```static u8 line[MAX_LINE];```
![](https://s3.ax1x.com/2021/02/08/yUV2w9.png)

到了真正插桩的部分了，首先明确，afl只在.text段插桩。所以先要找到.text的位置，并在对应的位置设置```instr_ok = 1```代表找到了一个位置。

首先我们跳过所有的标签、宏、注释。

```c
        if (line[0] == '\t' && line[1] == '.') {

            /* OpenBSD puts jump tables directly inline with the code, which is
               a bit annoying. They use a specific format of p2align directives
               around them, so we use that as a signal. */

            if (!clang_mode && instr_ok && !strncmp(line + 2, "p2align ", 8) &&
                isdigit(line[10]) && line[11] == '\n')
                skip_next_label = 1;

            if (!strncmp(line + 2, "text\n", 5) ||
                !strncmp(line + 2, "section\t.text", 13) ||
                !strncmp(line + 2, "section\t__TEXT,__text", 21) ||
                !strncmp(line + 2, "section __TEXT,__text", 21)) {
                instr_ok = 1;
                continue;
            }

            if (!strncmp(line + 2, "section\t", 8) ||
                !strncmp(line + 2, "section ", 8) ||
                !strncmp(line + 2, "bss\n", 4) ||
                !strncmp(line + 2, "data\n", 5)) {
                instr_ok = 0;
                continue;
            }

        }
```
在这里我们判断读入的这一行line是否以"\t."开头。（即尝试匹配.s中声明的段）
  - 如果是的话进入更深的判断。
    - 首先检查是否是```".p2align "```指令，如果是的话设置```skip_next_label = 1```
    - 接下来尝试匹配：```text\n``` ```"section\t.text"``` ```"section\t__TEXT,__text"``` ```"section __TEXT,__text"```
        - 如果匹配到了设置```instr_ok = 1```，代表我们此时正在.text段。
        - 然后直接continue跳本次循环
    - 尝试匹配：```"section\t"``` ```"section "``` ```"bss\n"``` ```"data\n"```
        - 如果匹配到了说明我们在其他段中。设置```instr_ok = 0```然后continue

接下来判断一些其他信息，比如att汇编还是intel汇编，设置对应标志位。

AFL尝试抓住一些能标志程序变化的重要的部分：
```
           If we're in the right mood for instrumenting, check for function
           names or conditional labels. This is a bit messy, but in essence,
           we want to catch:

             ^main:      - function entry point (always instrumented)
             ^.L0:       - GCC branch label
             ^.LBB0_0:   - clang branch label (but only in clang mode)
             ^\tjnz foo  - conditional branches

           ...but not:

             ^# BB#0:    - clang comments
             ^ # BB#0:   - ditto
             ^.Ltmp0:    - clang non-branch labels
             ^.LC0       - GCC non-branch labels
             ^.LBB0_0:   - ditto (when in GCC mode)
             ^\tjmp foo  - non-conditional jumps

           Additionally, clang and GCC on MacOS X follow a different convention
           with no leading dots on labels, hence the weird maze of #ifdefs
           later on.
```
稍微总结一下就是，AFL试图抓住：```_main:```(这是必然会插桩的位置)、以及gcc和clang下的分支标记，并且还有条件跳转分支。这几个关键的位置是其着重关注的。

```c
/* Conditional branch instruction (jnz, etc). We append the instrumentation
           right after the branch (to instrument the not-taken path) and at the
           branch destination label (handled later on). */

        if (line[0] == '\t') {

            if (line[1] == 'j' && line[2] != 'm' && R(100) < inst_ratio) {

                fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
                        R(MAP_SIZE));

                ins_lines++;

            }

            continue;

        }
```
如果是形如：```\tj[^m].```的指令，即条件跳转指令，并且```R(100)```产生的随机数小于插桩密度```inst_ratio```，那么直接使用```fprintf```将```trampoline_fmt_64```(插桩部分的指令)写入文件。写入大小为小于MAP_SIZE的随机数。```R(MAP_SIZE)```

然后插桩计数```ins_lines```加一。continue

接下来也是对于label的相关评估，有一些label可能是一些分支的目的地，需要自己的评判。
```c
 /* Label of some sort. This may be a branch destination, but we need to
           tread carefully and account for several different formatting
           conventions. */

        /* Apple: L<whatever><digit>: */

        if ((colon_pos = strstr(line, ":"))) {

            if (line[0] == 'L' && isdigit(*(colon_pos - 1))) {
                /* .L0: or LBB0_0: style jump destination */

                 /* Apple: L<num> / LBB<num> */

                if ((isdigit(line[1]) || (clang_mode && !strncmp(line, "LBB", 3)))
                    && R(100) < inst_ratio) {

                        if (!skip_next_label) instrument_next = 1; else skip_next_label = 0;

                }

            } else {

                /* Function label (always instrumented, deferred mode). */

                instrument_next = 1;

            }
```
首先判断line中是否有形如类似：```^L.*\d(:$)```的字符串（比如"Ltext0:"）
  -  接下来更进一步的判断L之后是否为为数字 或者 是否满足在clang mode下，line为"LBB"。（```L\<num> / LBB\<num>```）
    - 如果匹配到了，那么在满足插桩密度以及未设置skip_next_label的情况下。
      - 令```instrument_next = 1```（defer mode）
      - 否则令```skip_next_label = 0```

而如果只匹配到了line中存在```":"```但line并非以L开头。那么说明是```Function label```。
此时设置```instrument_next = 1```进行插桩。

这一切进行完之后，回到while函数的下一个循环中。而在下一个循环的开头，对于以```deferred mode```进行插桩的位置进行了真正的插桩处理。

```c
      /* In some cases, we want to defer writing the instrumentation trampoline
           until after all the labels, macros, comments, etc. If we're in this
           mode, and if the line starts with a tab followed by a character, dump
           the trampoline now. */

        if (!pass_thru && !skip_intel && !skip_app && !skip_csect && instr_ok &&
            instrument_next && line[0] == '\t' && isalpha(line[1])) {

            fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
                    R(MAP_SIZE));

            instrument_next = 0;
            ins_lines++;

        }
```
这里关键的两个判断：```instr_ok && instrument_next```，如果在代码段中，且设置了以```deferred mode```进行插桩，那么就在这个地方进行插桩，写入```trampoline_fmt_64```。

插桩完毕后生成的.s文件如图：
![](https://s3.ax1x.com/2021/02/08/yUMXDK.png)
可以看到已经被插桩了。这里也就是我们一开始看到的：```__afl_maybe_log```

## 收尾工作
在插桩结束后，我们把参数打印一下：
![](https://s3.ax1x.com/2021/02/08/yUQK8s.png)
可以看到这里在用汇编器as来将我们插桩好的.s文件生成可执行文件。
而真正的汇编过程是fork出一个子进程来执行的。
```c
    if (!(pid = fork())) {
        execvp(as_params[0], (char **) as_params);
        FATAL("Oops, failed to execute '%s' - check your PATH", as_params[0]);
    }
```
main函数中等待子进程执行完毕后退出。

**至此整个插桩过程就结束了。**
    
# instrumentation trampoline究竟是什么？
在上一部分我们已经知道了，64位下AFL将```trampoline_fmt_64```写入.s文件的指定位置作为插桩。

本部分主要来讨论AFL究竟插进去了什么东西。

## trampoline_fmt_64
我们直接看ida中的内容，非常直观，```trampoline_fmt_64```就是如下汇编：
```c
lea     rsp, [rsp-98h]
mov     [rsp+98h+var_98], rdx
mov     [rsp+98h+var_90], rcx
mov     [rsp+98h+var_88], rax
mov     rcx, 46A1h          ;注意这里46A1h就是在fptintf插桩的时候R(MAP_SIZE)产生的随机数，可以用于区分每个桩
call    __afl_maybe_log
mov     rax, [rsp+98h+var_88]
mov     rcx, [rsp+98h+var_90]
mov     rdx, [rsp+98h+var_98]
lea     rsp, [rsp+98h]
```
## __afl_maybe_log
大体流程如下：
![](https://s3.ax1x.com/2021/02/08/yU4jU0.png)

在这之前我们首先要关注几个位于bss段的变量：
```c
.AFL_VARS:

  .comm   __afl_area_ptr, 8
  .comm   __afl_prev_loc, 8
  .comm   __afl_fork_pid, 4
  .comm   __afl_temp, 4
  .comm   __afl_setup_failure, 1
  .comm    __afl_global_area_ptr, 8, 8
```
- __afl_area_ptr：共享内存的地址。
- __afl_prev_loc：上一个插桩位置（R(100)随机数的值）
- __afl_fork_pid：由fork产生的子进程的pid
- __afl_temp：缓冲区
- __afl_setup_failure：标志位，如果置位则直接退出。
- __afl_global_area_ptr：一个全局指针。

```c
__afl_maybe_log:

  lahf
  seto  %al

  /* Check if SHM region is already mapped. */

  movq  __afl_area_ptr(%rip), %rdx
  testq %rdx, %rdx
  je    __afl_setup
```
首先```lahf```用于将标志寄存器的低八位送入AH，即将标志寄存器FLAGS中的SF、ZF、AF、PF、CF五个标志位分别传送到累加器AH的对应位（八位中有三位是无效的）。
![](https://s3.ax1x.com/2021/02/08/yUJWRg.png)

接下来```seto```溢出置位。

然后检查共享内存是否已经被设置了。即```__afl_area_ptr```是否为空？
- 如果为NULL则说明还没有被设置，跳转到```__afl_setup```进行设置。
- 否则继续运行。

## __afl_setup
在```__afl_setup:```中用于初始化```__afl_area_ptr```，只有在运行到第一个桩时会进行本次初始化。

```c
__afl_setup:

  /* Do not retry setup if we had previous failures. */

  cmpb $0, __afl_setup_failure(%rip)
  jne __afl_return

  /* Check out if we have a global pointer on file. */

  movq  __afl_global_area_ptr(%rip), %rdx
  testq %rdx, %rdx
  je    __afl_setup_first

  movq %rdx, __afl_area_ptr(%rip)
  jmp  __afl_store
```
如果__afl_setup_failure不为0的话，直接跳转到__afl_return返回。

接下来检查__afl_global_area_ptr文件指针是否为NULL，如果为空则跳转到```__afl_setup_first```。

否则将__afl_global_area_ptr的值赋给__afl_area_ptr后跳转到```__afl_store```


## __afl_setup_first
```c
__afl_setup_first:

  /* Save everything that is not yet saved and that may be touched by
     getenv() and several other libcalls we'll be relying on. */

  leaq -352(%rsp), %rsp

  movq %rax,   0(%rsp)
  movq %rcx,   8(%rsp)
  movq %rdi,  16(%rsp)
  movq %rsi,  32(%rsp)
  movq %r8,   40(%rsp)
  movq %r9,   48(%rsp)
  movq %r10,  56(%rsp)
  movq %r11,  64(%rsp)

  movq %xmm0,  96(%rsp)
  movq %xmm1,  112(%rsp)
  movq %xmm2,  128(%rsp)
  movq %xmm3,  144(%rsp)
  movq %xmm4,  160(%rsp)
  movq %xmm5,  176(%rsp)
  movq %xmm6,  192(%rsp)
  movq %xmm7,  208(%rsp)
  movq %xmm8,  224(%rsp)
  movq %xmm9,  240(%rsp)
  movq %xmm10, 256(%rsp)
  movq %xmm11, 272(%rsp)
  movq %xmm12, 288(%rsp)
  movq %xmm13, 304(%rsp)
  movq %xmm14, 320(%rsp)
  movq %xmm15, 336(%rsp)

  /* Map SHM, jumping to __afl_setup_abort if something goes wrong. */

  /* The 64-bit ABI requires 16-byte stack alignment. We'll keep the
     original stack ptr in the callee-saved r12. */

  pushq %r12
  movq  %rsp, %r12
  subq  $16, %rsp
  andq  $0xfffffffffffffff0, %rsp

  leaq .AFL_SHM_ENV(%rip), %rdi
call _getenv

  testq %rax, %rax
  je    __afl_setup_abort

  movq  %rax, %rdi
call _atoi

  xorq %rdx, %rdx   /* shmat flags    */
  xorq %rsi, %rsi   /* requested addr */
  movq %rax, %rdi   /* SHM ID         */
call _shmat

  cmpq $-1, %rax
  je   __afl_setup_abort

  /* Store the address of the SHM region. */

  movq %rax, %rdx
  movq %rax, __afl_area_ptr(%rip)

  movq %rax, __afl_global_area_ptr(%rip)
  movq %rax, %rdx
```
1.在```__afl_setup_first```中，首先保存寄存器的值（包括xmm寄存器组）

2.接下来进行rsp对齐操作。

3.获取环境变量```"__AFL_SHM_ID"```的值（共享内存的id）。如果获取失败，那么跳转到```__afl_setup_abort```，说明获取失败。

4.获取成功后调用```shmat```启用对共享内存的访问。如果启用失败，跳转到```__afl_setup_abort```。

5.将```shmat```返回的共享内存的地址存储在 ```__afl_area_ptr``` 与 ```__afl_global_area_ptr```全局变量中。

6.一切顺利的话，接下来运行 ```__afl_forkserver```

## __afl_forkserver
```c
  /* Enter the fork server mode to avoid the overhead of execve() calls. We
     push rdx (area ptr) twice to keep stack alignment neat. */

  pushq %rdx
  pushq %rdx

  /* Phone home and tell the parent that we're OK. (Note that signals with
     no SA_RESTART will mess it up). If this fails, assume that the fd is
     closed because we were execve()d from an instrumented binary, or because
     the parent doesn't want to use the fork server. */

  movq $4, %rdx               /* length    */
  leaq __afl_temp(%rip), %rsi /* data      */
  movq $(198 + 1), %rdi       /* file desc */
call _write

  cmpq $4, %rax
  jne  __afl_fork_resume
```
首先向FORKSRV_FD+1即199号描述符（即状态管道）中写出__afl_temp中的四个字节，来通知afl我们的fork server已经启动成功。
顺带一提，这里的向状态管道中写的值，在afl-fuzz.c中的这个位置被读出来：
![](https://s3.ax1x.com/2021/02/08/yUd5yF.png)
**这样我们整个过程就串连起来了。**

接下来进入：```__afl_fork_wait_loop:```

## __afl_fork_wait_loop:
```c
__afl_fork_wait_loop:

  /* Wait for parent by reading from the pipe. Abort if read fails. */

  movq $4, %rdx               /* length    */
  leaq __afl_temp(%rip), %rsi /* data      */
  movq $198, %rdi             /* file desc */
call _read
  cmpq $4, %rax
  jne  __afl_die

  /* Once woken up, create a clone of our process. This is an excellent use
     case for syscall(__NR_clone, 0, CLONE_PARENT), but glibc boneheadedly
     caches getpid() results and offers no way to update the value, breaking
     abort(), raise(), and a bunch of other things :-( */

call _fork
  cmpq $0, %rax
  jl   __afl_die
  je   __afl_fork_resume

  /* In parent process: write PID to pipe, then wait for child. */

  movl %eax, __afl_fork_pid(%rip)

  movq $4, %rdx                   /* length    */
  leaq __afl_fork_pid(%rip), %rsi /* data      */
  movq $(198 + 1), %rdi             /* file desc */
call _write

  movq $0, %rdx                   /* no flags  */
  leaq __afl_temp(%rip), %rsi     /* status    */
  movq __afl_fork_pid(%rip), %rdi /* PID       */
call _waitpid
  cmpq $0, %rax
  jle  __afl_die

  /* Relay wait status to pipe, then loop back. */

  movq $4, %rdx               /* length    */
  leaq __afl_temp(%rip), %rsi /* data      */
  movq $(198 + 1), %rdi         /* file desc */
call _write

  jmp  __afl_fork_wait_loop
```

1.首先我们等待parent（fuzz）通过控制管道发来的命令，读入__afl_temp中。

2.如果读取失败，那么跳到 ```__afl_die```，break出循环。

3.```_fork```出一个子进程，子进程跳入执行：```__afl_fork_resume```

4.将fork出来的子进程pid赋值给```__afl_fork_pid```

5.向状态管道中写出子进程pid，告知parent。此时```__afl_maybe_log```中的父进程作为forksrever与我们的fuzz进行通信。

6.等待我们fork出的子进程执行完毕。然后写入状态管道告知fuzz。

7.重新执行下一轮 ```__afl_fork_wait_loop```进行测试。

## __afl_fork_resume 与
```c
/* In child process: close fds, resume execution. */

  movq $198, %rdi
call _close

  movq $(198 + 1), %rdi
call _close

  popq %rdx
  popq %rdx

  movq %r12, %rsp
  popq %r12

  movq  0(%rsp), %rax
  movq  8(%rsp), %rcx
  movq 16(%rsp), %rdi
  movq 32(%rsp), %rsi
  movq 40(%rsp), %r8
  movq 48(%rsp), %r9
  movq 56(%rsp), %r10
  movq 64(%rsp), %r11

  movq  96(%rsp), %xmm0
  movq 112(%rsp), %xmm1
  movq 128(%rsp), %xmm2
  movq 144(%rsp), %xmm3
  movq 160(%rsp), %xmm4
  movq 176(%rsp), %xmm5
  movq 192(%rsp), %xmm6
  movq 208(%rsp), %xmm7
  movq 224(%rsp), %xmm8
  movq 240(%rsp), %xmm9
  movq 256(%rsp), %xmm10
  movq 272(%rsp), %xmm11
  movq 288(%rsp), %xmm12
  movq 304(%rsp), %xmm13
  movq 320(%rsp), %xmm14
  movq 336(%rsp), %xmm15

  leaq 352(%rsp), %rsp

  jmp  __afl_store
```

1.首先关闭子进程中的文件描述符。

2.恢复子进程的寄存器状态。

3.跳转执行```__afl_store```

## __afl_store:
```c
__afl_store:

  /* Calculate and store hit for the code location specified in rcx. */

  xorq __afl_prev_loc(%rip), %rcx
  xorq %rcx, __afl_prev_loc(%rip)
  shrq $1, __afl_prev_loc(%rip)

  incb (%rdx, %rcx, 1)
```
这一部分反编译出来如下：
```c
  tmp = _afl_prev_loc ^ a2;
  _afl_prev_loc ^= tmp;
  _afl_prev_loc = _afl_prev_loc >> 1;
  ++*(share_mem_addr + tmp);
```
而这个a2就是我们在调用_afl_maybe_log时传入的参数rcx
```char __usercall _afl_maybe_log@<al>(char a1@<of>, __int64 a2@<rcx>```。

 ```c
mov     rcx, 46A1h          ;注意这里46A1h就是在fptintf插桩的时候R(MAP_SIZE)产生的随机数，可以用于区分每个桩
call    __afl_maybe_log
```
**可以看到这个rcx实际就是我们此时用于标记当前这个桩的随机数，而_afl_prev_loc就是上一个桩的随机数**

两次异或之后_afl_prev_loc=a2，然后将_afl_prev_loc右移1位为新的_afl_prev_loc。

**最后在共享内存中存储当前插桩位置的地方计数加一**，相当于：```share_mem[_afl_prev_loc ^ a2]++```，实际上是存入一个64k大小的哈希表，存在碰撞几率，但是问题不大。而这个索引是通过异或得到的。

更进一步的，关于为什么要对```_afl_prev_loc = _afl_prev_loc >> 1;```进行右移1位。

AFL主要考虑如下情况：如果此分支是```A->A```和```B->B```这样的情况那么异或之后就会都变成0，进而使得无法区分。亦或者考虑：```A->B```与```B->A```的情况，异或后的key也是一样的，难以区分。


**至此，AFL的插桩就基本分析的差不多了。下一篇会着重讲llvm mode**


