# AFL源码阅读笔记(1)
**本部分主要是对于整个项目的执行流程进行大体的阅读，目标在于掌握大致的流程与功能，但此部分笔记仍留有一些细节问题，会在后面的笔记/随着本人理解的加深进行补充解释**

*Writen by: ScUpax0s/初号机*

特别感谢Sakura师傅和花花姐姐～
[TOC]
# 开始之前
AFL(American Fuzzy Loop)可以说是市面上用的最多的fuzzer之一了，趁着寒假时间从0到1学习并调试一下AFL的源码，对以后的深入研究Fuzz、漏洞挖掘、安全研究进阶很有帮助。

在Fuzz这个领域来说，我真的是非常小白的了，前一阵期末考试的时候只是环境搭好照着跑过几个demo，跟大师傅们完全不能比，不过好处大概就是能从一个基本可以说对fuzz了解很少的新手角度出发来去记录学习过程，希望对后来的同学有所帮助。

关于如何搭建环境我就不赘述了，可以看：https://xz.aliyun.com/t/4314
# alf-gcc.c(a GCC wrapper)
## 概述
alf-gcc是gcc的一个封装（wrapper），能够实现对于一些关键节点进行插桩，从而记录一些程序执行路径之类的信息，方便对程序的一些运行情况进行反馈。

## main函数
/* Main entry point */
在alf-gcc.c的main中主要有如下三个函数的调用：
- ```find_as(argv[0])``` 主要来查找汇编器
- ```edit_params(argc, argv)``` 通过我们传入编译的参数来进行参数处理，将确定好的参数放入 ```cc_params[]``` 数组。
- 在以上的步骤都完成之后，调用```execvp(cc_params[0], (char **) cc_params)``` 执行afl-gcc。
![](https://s3.ax1x.com/2021/01/25/sLvS7q.png)
## find_as
在函数开头有这样一条注释。

*Try to find our "fake" GNU assembler in AFL_PATH or at the location derived from argv[0]. If that fails, abort.*

这个函数是想通过argv[0]（也就是当前文件的路径）来去寻找对应的汇编器as（Linux上as是很常用的一个汇编器，负责把生成的汇编代码翻译到二进制）。

- 首先获取环境中的 ```AFL_PATH``` 变量。如果获取成功，接着通过 ```alloc_printf``` 来动态的分配一段空间存储对应的路径。之后检查这段路径是否可访问，如果可访问的话赋值给 ```as_path``` ，然后free，return。不可访问的话直接free掉。 

- 如果没有读取成功 ```AFL_PATH``` 则通过对argv[0]的匹配，提取当前路径 ```dir```，然后将 ```{dir}/afl-as``` 在可访问情况下赋值给 ```as_path``` ，然后free，return。不可访问的话直接free掉。 
- 如果以上两种情况因为种种原因都没有成功，那么直接找as，找到了且可访问赋值，没找到就通过 ```FATAL```输出错误信息然后exit(1)

## edit_params
这个函数主要是来设置 CC 的参数。

首先给 ```cc_params``` 分配空间。接下来通过找到最后一个 / 取出此时对应的什么编译器（比如afl-gcc）。将这个名字赋值给 ```name```

首先我们看一下整个函数的结构：
```c
if (!strncmp(name, "afl-clang", 9)){
    
}else{
    
    #ifdef __APPLE__
    ......
    #else
    ......
    #endif /* __APPLE__ */
}
    while(argc--){
        
    }
  
    if (getenv("AFL_HARDEN")){
        
    }
    if (asan_set) {
        
    }else if (getenv("AFL_USE_ASAN")) {

    }else if (getenv("AFL_USE_MSAN")) {

    }

    if (!getenv("AFL_DONT_OPTIMIZE")) {

    }

    if (getenv("AFL_NO_BUILTIN")) {

    }

// over :-)
```


- 如果是afl-clang开头的话，设置 ```clang_mode=1``` 。接下来看究竟是 ```afl-clang++``` 还是 ```afl-clang``` 。并根据环境变量设置，具体表现为，以 ```afl-clang``` 举例。首先获取环境变量 ```AFL_CC``` 如果获取到了，那么设置 ```cc_params[0]=getenv("AFL_CC")``` ；反过来如果没有获取到 那么直接设置为 ```"clang"``` 。```cc_params[]```是我们保存编译参数的数组。

- 如果不是afl-clang开头。并且是Apple平台的话话会进入 ```#ifdef __APPLE__``` 
  + 在Apple平台下，开始对 ```name``` 进行对比，并通过 ```cc_params[0] = getenv("")``` 对cc_params的首项进行赋值。在我这里是 ```cc_params[0] = gcc-9``` 

- 接下来我们进入一个While循环。在循环中我们扫描 argv[] 数组。并将参数放入 ```cc_params```
  - 如果扫描到 ```-B``` ，-B 选项用于设置编译器的搜索路径。这里直接跳过。（因为我们之前已经处理过as_path了）
  - 如果扫描到 ```-integrated-as``` 跳过
  - 如果扫描到 ```-pipe``` 跳过
  - 如果扫描到 ```-fsanitize=address``` 和 ```-fsanitize=memory``` 告诉gcc检查内存访问的错误，比如数组越界之类的。如果扫描到了，就设置 ```asan_set = 1``` 
  - 如果扫描到 ```FORTIFY_SOURCE``` ，设置 ```fortify_set = 1``` FORTIFY_SOURCE在使用各种字符串和内存操作功能时执行一些轻量级检查，以检测一些缓冲区溢出错误。比如strcpy这种。

- 当我们跳出循环后，我们向 ```cc_params``` 中加上 -B 以及对应的 as_path。之后检查 clang_mode 如果是clang的话设置：```-no-integrated-as``` 。（加入 ```cc_params[]``` 中）
- 接下来取环境变量中的 ```AFL_HARDEN``` 如果有的话，添加编译选项 ```-fstack-protector-all``` 到数组中，紧接着如果没有设置 ```fortify_set``` 那么添加 ```-D_FORTIFY_SOURCE=2```选项。
***
接下来进入多个if中。
- 如果通过 ```-fsanitize=```设置了asan_set，那么设置环境变量 ```AFL_USE_ASAN = 1```。
- 如果设置了 ```AFL_USE_ASAN```
  - 继续检测 ```AFL_USE_MSAN``` 与 ```AFL_HARDEN``` 是否设置。如果设置则 abort，因为他们是互斥的；如果没有设置的话，添加 ```-U_FORTIFY_SOURCE``` 与 ```-fsanitize=address``` 到编译选项中。
- 如果设置了 ```AFL_USE_MSAN```
  - 继续检测 ```AFL_USE_ASAN``` 与 ```AFL_HARDEN``` 是否设置。如果设置则 abort，因为他们是互斥的；如果没有设置的话，添加 ```-U_FORTIFY_SOURCE``` 与 ```-fsanitize=memory``` 到编译选项中。
***
接下来对于优化选项进行判断。
- 如果没有设置 ```AFL_DONT_OPTIMIZE``` ，也就是允许进行优化。
  - 向储存编译选项的数组中加入：```-g -O3 -funroll-loops -D__AFL_COMPILER=1 -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1```
***
- 最后，如果设置了 ```AFL_NO_BUILTIN``` ,那么连续添加如下编译选项：```-fno-builtin-strcmp -fno-builtin-strncmp -fno-builtin-strcasecmp -fno-builtin-strncasecmp -fno-builtin-memcmp -fno-builtin-strstr -fno-builtin-strcasestr``` 
- 最后的最后在 ```cc_params[]``` 补一个NULL标志结束，return。

# alf-fuzz.c(Main fuzz .c file)
alf-fuzz.c一共四舍五入8000行～
![](https://i.loli.net/2020/03/25/fu6R7AJe4KGE8ND.png)
## Main函数
首先调用 ```gettimeofday``` 获取当前的准确时间。接着用srandom根据这个时间与当前进程的pid做亦或之后设定了种子。保证了随机性
- 接下来进入一个大While循环，通过 ```getopt``` 扫描我们 argv 里的参数。我们打印出来如下：```/Users/apple/Desktop/AFL/AFL/cmake-build-debug/afl-fuzz -i input -o output -- ./test``` 
  - 首先扫描到 -i ， 将我们 -i 后面的 input 赋值给 in_dir。如果此时的 ```in_dir = "-"```，那么设置  - ```in_place_resume = 1```
  - 接下来扫描到 -o ， 将我们的 -o 的参数output赋值给out_dir， ```out_dir = optarg```
- 参数准备完毕后，调用 ```setup_signal_handlers()``` 设置信号处理的句柄。
- 然后调用 ```check_asan_opts()``` 检测asan设置是否正确。
- 如果设置了 sync_id = N ，那么在 fix_up_sync 中检测是否有互斥的参数、N是否过大。拼接out_dir, sync_id为新的out_dir。最后，如果force_deterministic没有设置，那么skip_deterministic和use_splicing为1.
- 如果设置了dumb_mode，那么不能设置互斥的crash_mode和qemu_mode。
- 获取环境变量：AFL_NO_FORKSRV、AFL_NO_CPU_RED、FL_NO_ARITH、AFL_SHUFFLE_QUEUE、AFL_FAST_CAL，设置对应的：no_forkserver、no_cpu_meter_red、no_arith、shuffle_queue、fast_cal=1。
- 通过AFL_HANG_TMOUT设置对应的hang_out时间。
- 保证dumb_mode == 2 与 no_forkserver的互斥。
- 设置LD_PRELOAD和DYLD_INSERT_LIBRARIES为AFL_PRELOAD。
- save_cmdline 保存argv到局部变量buf中，没看出来有什么用。
- check_if_tty 检测是否是终端环境，根据AFL_NO_UI设置not_on_tty = 1。然后通过IOCTL设置TIOCGWINSZ。
- get_core_count() 获取cpu数量。
- 然后根据亲缘性设置绑定CPU。
- check_crash_handling()：确保core dump的设置正确。
- check_cpu_governor()：
- setup_post()：设置后处理函数？
- setup_shm()：设置共享内存和virgin_bits。
- init_count_class16()：初始化count_class_lookup16数组，为分支路径的规整做准备。
- setup_dirs_fds()：创建一些相关文件夹，写入一些信息。
- read_testcases()：读取测试用例并入队，在启动时调用。
- load_auto()：加载automatic extra
- pivot_inputs()：在输出目录中为输入测试用例创建硬链接，选择好名字，并据此进行调整。
- 如果设置了extras_dir
  - 调用load_extras(extras_dir)，加载extras_dir下的文件放入extra数组并排序。
- 如果没设置```timeout_given``` 那么调用 ```find_timeout``` 设置超时时间。
- detect_file_args(argv + optind + 1)：检测argv中的 @@ 并替换。
- 如果没设置out_file，调用setup_stdio_file()，在```output/.cur_input```新建一个文件作为输出文件，打开后fd赋值给：```static s32 out_fd,                    /* Persistent fd for out_file       */```
- check_binary(argv[optind])，检查目标文件有效性：是否是可执行文件，是否是Mach-O还是ELF还是一个生成的shell文件。
- start_time = get_cur_time()获取当前时间
- 如果是qemu_mode
  - 调用```use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind)```为qemu重写参数。
  - 否则直接令：```use_argv = argv + optind```
  - 如果不是，use_argv = argv + optind
- perform_dry_run(use_argv)：对所有测试用例执行试运行，以确认该应用程序按照预期正常运行。仅对初始输入执行此操作，并且仅执行一次。
- cull_queue()：精简队列
- show_init_stats():向用户输出一些状态信息
- find_start_position()
  - 只有在resuming_fuzz时才起作用。
  - 如果设置了in_place_resume。
    - 打开out_dir/fuzzer_stats
  - 否则打开in_dir/../fuzzer_stats
  - 读取4095字节到tmp中。
  - 查找子串```"cur_path          : "```的位置为off。
  - 设置```ret = atoi(off + 20);```
    - 如果```ret >= queued_paths```，将ret归零后return ret。
    - 否则直接return ret
- write_stats_file(0, 0, 0)：更新统计信息文件以进行无人值守的监视。
- save_auto()
  - Save automatically generated extras.
  - 扫描a_extras[]数组，将对应的a_extras[i].data写入 ```"%s/queue/.state/auto_extras/auto_%06u", out_dir, i```中，其中i最大是min(a_extras_cnt，USE_AUTO_EXTRAS)
- 如果设置了stop_soon，跳转到stop_fuzzing
- 如果是tty启动（终端），那么先sleep 4 秒，start_time += 4000。
  - 再检测如果设置了stop_soon，跳转到stop_fuzzing

**至此，整个启动前的初始化完成，准备进入fuzz主循环**
***
- 进入循环一开始，首先再次简化队列。
  ```cull_queue()```
- ```queue_cur```指向当前队列中的元素。（entry）
- 如果```queue_cur```说明此时整个队列已经扫描了一遍了。
  - ```queue_cycle```计数加一，说明走了一个循环了。
  - ```current_entry```归零。
  - ```cur_skipped_paths```归零。
  - ```queue_cur```重新指向队头。
  - 如果```seek_to```不为零。
    - ```queue_cur```顺着队列持续后移。
    - 同时```seek_to--```；```current_entry++```
    - 直到```seek_to==0```
    个人感觉就是把```queue_cur```置位到```seek_to```的位置。
  - ```show_stats()```展示状态
  - 如果不是终端模式即：```not_on_tty==1```
    - 输出当前是第几个循环
    ```ACTF("Entering queue cycle %llu.", queue_cycle);```
  - 如果我们经历了一个完整的扫描周期后都没有新的路径发现，那么尝试调整策略。
  - 如果：```queued_paths == prev_queued```相等。
    - 当设置了```use_splicing```
      - ```cycles_wo_finds```计数加一。
    - 否则设置```use_splicing```为1。（代表我们要通过splicing进行队列重组。）
  - 否则设置```cycles_wo_finds```为0.
  - 令prev_queued等于queued_paths
  - 如果设置了```sync_id```并且```queue_cycle == 1```，并且环境变量中设置了```AFL_IMPORT_FIRST```
    - 调用```sync_fuzzers(use_argv)```
- 调用```fuzz_one(use_argv)```对于我们的样本进行变换后fuzz，返回skipped_fuzz
- 若skipped_fuzz为0，并且stop_soon为0，并且设置了sync_id
  - 若sync_interval_cnt没有到一个周期（% SYNC_INTERVAL）
    - 调用```sync_fuzzers(use_argv)```同步其他fuzzer
- 如果没有设置stop_soon，且 exit_1不为0，那么设置stop_soon=2后break出fuzz主循环。
- 否则准备fuzz队列中下一个样本。
- 主循环结束后，销毁内存空间，关闭描述符，输出/更新一些状态，至此整个afl的fuzz过程就结束了。
## fuzz主循环中的关键函数
### fuzz_one(char **argv)
**从队列中取出当前的一项，然后进行fuzz，返回0如果fuzz成功。返回1如果跳过或者bailed out**
- 如果设置了```pending_favored```
  - 查看（当前queue中的这一项是否已经fuzz过了或者不是favored）并且打一个100以内的随机数，如果小于```SKIP_TO_NEW_PROB```（百分之99）
    - 直接return 1.
- 如果非dumb_mode，且当前的不是favored，并且queued_paths > 10
  - 若queue_cycle > 1，并且当前的queue_cur还没有fuzz过。
    - 打一个100以内的随机数，如果小于```SKIP_NFAV_NEW_PROB```，直接return 1.（百分之75）
  - 否则打一个100以内的随机数，如果小于```SKIP_NFAV_OLD_PROB```，直接return 1.（百分之95）
- 如果不是tty模式。
  - 输出```current_entry, queued_paths, unique_crashes```提示信息，刷新stdout缓冲区
- 将当前的test case映射进入内存。
  ```orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)```
- 分配len大小的空间，初始化为0，返回给out_buf。
- 设置```subseq_tmouts```为0
- 设置```cur_depth```为```queue_cur->depth```

**CALIBRATION (only if failed earlier on)阶段**
- 如果当前的```queue_cur->cal_failed```不为0（存在校准错误）
  - 如果校准错误的次数小于三次。
    - 重制exec_cksum来告诉```calibrate_case```重新执行testcase来避免对于无效trace_bits的使用。
    - 设置```queue_cur->exec_cksum```为0.
    - 对于queue_cur重新执行```calibrate_case```。
    ```res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0)```
    - 如果返回值为FAULT_ERROR，那么直接abort
  - 如果设置了stop_soon，或者res不等于crash_mode。
    - cur_skipped_paths计数加一。
    - 跳转到```abandon_entry```

**TRIMMING修剪阶段**
- 如果不是dumb_mode且当前的没有经过trim（!queue_cur->trim_done）
  - 调用```trim_case```对当前项进行修建。返回res
    ```trim_case(argv, queue_cur, in_buf)```
  - 如果res为FAULT_ERROR，直接abort
  - 如果设置了stop_soon
    - cur_skipped_paths计数加一。
    - 跳转到abandon_entry
  - 设置当前queue_cur为已经trim过。
    ```queue_cur->trim_done = 1```
  - 如果len不等于queue_cur->len。
    - 令len = queue_cur->len。
- 将in_buf中的内容拷贝len到out_buf。

**PERFORMANCE SCORE阶段**
- 调用```calculate_score(queue_cur)```计算当前queue_cur的score
- 如果设置了skip_deterministic或者queue_cur->was_fuzzed（被fuzz过了）或者queue_cur->passed_det=1
  - 直接goto havoc_stage
- 如果当前的```queue_cur->exec_cksum % master_max```不等于master_id - 1，那么goto havoc_stage
  *Skip deterministic fuzzing if exec path checksum puts this out of scope for this master instance.*
- 设置doing_det = 1

**SIMPLE BITFLIP (+dictionary construction)阶段**
```c
stage_short = "flip1";
stage_name = "bitflip 1/1";
```
- 定义stage_max为len << 3
- stage_val_type为STAGE_VAL_NONE
- orig_hit_cnt为queued_paths + unique_crashes
- 而prev_cksum为queue_cur->exec_cksum
- 接下来进入一个for循环
 ```c

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

        stage_cur_byte = stage_cur >> 3;

        FLIP_BIT(out_buf, stage_cur);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

        FLIP_BIT(out_buf, stage_cur);
        
        .......
    }
 ```
 这个循环中调用了```FLIP_BIT(out_buf, stage_cur)```
 ```c
#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)
```
  - ```(_bf) & 7)```相当于模8，产生了（0、1、2、3、4、5、6、7）
  - 128是二进制的10000000.
  - 等式的右边相当于将128右移动0-7个单位产生了二进制从（10000000 - 1）
  - ```(_bf) >> 3```相当于_bf/8
  - stage_cur最大为stage_max相当于len << 3
  - 所以对于```FLIP_BIT(_ar, _b)```来说，```_bf```最大为```(len << 3)>>3```还是len
  - 也就是说，对于这个for循环来说，每运行8次循环```_arf[i]```（大小为一个字节）的下标i就会加一，i最大为len。
  - 同时在每8次为一组的循环中，128分别右移0、1、2、3、4、5、6、7位，将右移后产生的数字与```_arf[i]```进行异或翻转，而```_arf[i]```大小为一个字节，等价于对这个字节的每一位都做一次翻转异或
  ![](https://s3.ax1x.com/2021/02/05/yG38S0.png)
  - 当这一位被异或完毕后，调用```common_fuzz_stuff(argv, out_buf, len)```进行fuzz。
    - 如果返回1，```goto abandon_entry```
  - 最后再调用一次```FLIP_BIT(out_buf, stage_cur)```异或翻转回来。
  - 这一部分代码中给出了注释进行解释：
  比如说对于一串二进制：
  xxxxxxxxIHDRxxxxxxxx
  当我们改变IHDR中的任意一个都会导致路径的改变or破坏， "IHDR"就像在二进制串中的一整体的具有原子性的可检查的特殊值（原语？）。*"IHDR" is an atomically-checked magic value of special significance to the fuzzed format.*，afl希望能找到这些值。
  - 如果不是dumb_mode且stage_cur & 7不等于7
    - 计算当前trace_bits的hash32为cksum
    - 如果当前到达最后一轮循环并且cksum == prev_cksum
      - 如果a_len小于MAX_AUTO_EXTRA
        - 令```a_collect[a_len]```为out_buf[stage_cur >> 3]
        - a_len递增1
      - 如果a_len 在MIN_AUTO_EXTRA与MAX_AUTO_EXTRA之间
        - 调用```maybe_add_auto(a_collect, a_len)```
    - 如果cksum != prev_cksum
      - 如果a_len 在MIN_AUTO_EXTRA与MAX_AUTO_EXTRA之间
        - 调用```maybe_add_auto(a_collect, a_len)```将发现的新token加入a_extra[]
      - a_len归零
      - 令prev_cksum = cksum
    - 如果cksum != queue_cur->exec_cksum
      - 若a_len < MAX_AUTO_EXTRA
        - a_collect[a_len] = out_buf[stage_cur >> 3]
      - a_len递增1.
- 更新new_hit_cnt为queued_paths + unique_crashes
- 更新```stage_finds[STAGE_FLIP1]```
  ```stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt```
  加上所有的新的路径和新crashs
- 更新```stage_cycles[STAGE_FLIP1]```
  ```stage_cycles[STAGE_FLIP1] += stage_max```
  加上bitflip 1/1阶段for循环中执行的次数（common_fuzz_stuff）

接下来进入```bitflip 2/1```
- 保存当前new_hit_cnt到orig_hit_cnt。
- 经过一个for循环做bit flip和样例运行。
 ```c
     stage_name = "bitflip 2/1";
     stage_short = "flip2";
     stage_max = (len << 3) - 1;

     orig_hit_cnt = new_hit_cnt;
     for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

        stage_cur_byte = stage_cur >> 3;

        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);
    }
 ```
 这一次唯一的不同是是每次连续异或翻转两个bit。
- 翻转结束后更新new_hit_cnt
- 更新```stage_finds[STAGE_FLIP2]```与```stage_cycles[STAGE_FLIP2]```

- 接下来同样的进入```bitflip 4/1```，连续翻转4次
- 生成Effector map
  ```c
      /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

  #define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
  #define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
  #define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
  #define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)
  ```
  - 首先分配len大小的空间eff_map
  - 将eff_map[0]初始化为1；将eff_map[(len - 1)>>3]初始化为1（及第一项和最后一项）

- 进入```"bitflip 8/8"```阶段
  - 本阶段有一个很重要的思想：我们通过对于 out_buf所有bit进行异或翻转，如果产生了不一样的路径，就在eff_map中标记为1，否则为0。因为如果对所有bit都做翻转还无法带来相关的路径变化，afl认为在后续的一些开销更大的阶段，参考eff_map，可以对这些无效的byte进行跳过。减小开销。
  - 这个阶段中不是通过FILP宏来做翻转，而是直接与0xff做异或。
  ```c
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

        stage_cur_byte = stage_cur;

        out_buf[stage_cur] ^= 0xFF;   //直接通过对于out_buf的每一个字节中的每一个bit做异或翻转。

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;  //运行对应的test case（翻转后）

        if (!eff_map[EFF_APOS(stage_cur)]) {  //如果eff_map[stage_cur>>3]为0的话
            //EFF_APOS宏也起到了一个将stage_cur>>3的效果
            u32 cksum;

            /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

            if (!dumb_mode && len >= EFF_MIN_LEN)//如果不是dumb_mode且len大于最小的EFF_MIN_LEN
                cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);//计算hash32
            else                                //否则，如果是dumb mode或者len过小
                cksum = ~queue_cur->exec_cksum;

            if (cksum != queue_cur->exec_cksum) {
                eff_map[EFF_APOS(stage_cur)] = 1;//产生新的路径，发生了变化，此时直接将对应的eff_map中的项标记为1
                eff_cnt++;
            }

        }

        out_buf[stage_cur] ^= 0xFF;//从新异或回来

    }
  ```
  - 如果eff_map的密度超过了EFF_MAX_PERC，那么将整个eff_map都标记为1（即使不这样做，我们也不会省很多时间）
  - 更新new_hit_cnt、stage_finds[STAGE_FLIP8]、stage_cycles[STAGE_FLIP8]
  - 如果len<2，直接跳到```skip_bitflip```
- 进入```"bitflip 16/8"```
  - 唯一不同的是，在异或变异之前先检查了对应的eff_map的对应两个字节是否为0
    - 如果是0，```stage_max```计数减1.然后continue跳过。
    - 否则进行异或翻转后运行。
- 更新new_hit_cnt、stage_finds[STAGE_FLIP16]、stage_cycles[STAGE_FLIP16]
- 如果len<4，跳转到skip_bitflip
- 接下来是```"bitflip 32/8"```，与上述基本相同。
- ```skip_bitflip:```
  - 如果设置了```no_arith```
    - goto ```skip_arith```

**ARITHMETIC INC/DEC 阶段**
本阶段主要做加减变异
 ```c
#define ARITH_MAX           35
 ```

- ```"arith 8/8"```以byte为单元变异阶段
  - 首先扫描out_buf。
    ```u8 orig = out_buf[i]```（此时一个orig是一个字节，此阶段是**按字节**扫描）
  - 如果对应的eff_map中的项为0，则stage_max减去2倍的ARITH_MAX，然后continue跳过此次变异
  - 否则进入一个for循环进行变异->运行
    ```c
            u8 orig = out_buf[i];
            .......
            for (j = 1; j <= ARITH_MAX; j++) {  //依次扫描orig到orig+35

            u8 r = orig ^(orig + j);            //将orig与orig+j（j最大为35）进行异或翻转

            /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

            if (!could_be_bitflip(r)) { //判断是否为可以通过上一阶段bitfilp得到的（这一步是为了防止相同的冗余变异，节省时间）

                stage_cur_val = j;
                out_buf[i] = orig + j;  //将out_buf[i]本身加j变异

                if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;//进行fuzz
                stage_cur++;

            } else stage_max--;         //否则stage_max减1

            r = orig ^ (orig - j);      //将orig与orig-j（j最大为35）进行异或翻转

            if (!could_be_bitflip(r)) {//如果判断为可以bitfilp

                stage_cur_val = -j;
                out_buf[i] = orig - j;//将out_buf[i]本身减j变异

                if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;//进行fuzz
                stage_cur++;

            } else stage_max--;

            out_buf[i] = orig;      

        }
    ```

- ```"arith 16/8"```阶段
  - 此时以2个字节（word）为单位进行加减变异，并且对于大端序与小端序都进行变异。
- ```"arith 32/8"```阶段
  - 以4个字节（32bits）为单位进行加减变异，并且对于大端序与小端序都进行变异。

**INTERESTING VALUES阶段**
本阶段主要做替换变异
- 首先是```"interest 8/8"```阶段，以一个字节为单位进行**替换**变异
  - 本阶段首先通过```could_be_bitflip(orig ^ (u8) interesting_8[j])||could_be_arith(orig, (u8) interesting_8[j], 1))```
    保证替换不会由前面的异或和加减变异阶段得到（本质是在防止冗余变换，减小开销）
  - 然后通过``` out_buf[i] = interesting_8[j]```进行一个字节的替换。
  - 之后调用```common_fuzz_stuff(argv, out_buf, len)```进行fuzz
- ```"interest 16/8"```阶段，以两个字节为单位进行替换变异，并且去除异或、加减、与单字节变异阶段的冗余，同时考虑大小端序。
- ```"interest 32/8"```阶段（4字节为单位替换变异）与前面类似。

**DICTIONARY STUFF阶段**
本阶段主要基于用户提供的extra来进行一定的变异
- ```"user extras (over)"```替换阶段
  - 在满足一定大小的条件下（同时有一定随机性），将用户的extra token以memcpy的方式替换/覆写（over）进去，然后进行fuzz
  ```c
  memcpy(out_buf + i, extras[j].data, last_len);
  if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
  ```
  - 最后在进行恢复。
- ```"user extras (insert)"```插入阶段
  - 插入（insert）用户的extras[j]，然后产生一个新的ex_tmp，对于这个ex_tmp进行fuzz。
- ```"auto extras (over)"```替换阶段2
  - 本阶段类似于over，只不过用于替换的变成了```a_extras[j]```而非```extras[j]```

- 接下来到达标签：```skip_extras:```，如果我们在不跳至havoc_stage或abandon_entry的情况下来到这里，说明我们已经正确的完成了确定的fuzz（deterministic steps）步骤，我们可以对其进行标记如 .state/ 目录
  - 如果没有设置```queue_cur->passed_det```
    - 调用```mark_as_det_done(queue_cur)```进行标记。

**RANDOM HAVOC（随机毁灭）阶段**
本阶段做大范围的随机变异。
- 首先检测如果没有设置```splice_cycle```
  - 那么标记此阶段为```"havoc"```
- 否则标记此阶段为```"splice"```
- 设置stage_max
  - 在每一轮stage中首先产生随机数```use_stacking```
  - 根据产生的```use_stacking```做相应次数的变换。相当于每一轮stage中具体的变换由多次小变化叠加产生。
  - 每次变换具体的内容也由一个随机数决定。
    ```UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))```
    - 随机替换一个```interesting_8[]```中的byte进来
    - 随机替换```interesting_16[]```中的某个word进来（大小端序随机选择）
    - 随机替换```interesting_32[]```中的某个dword进来（大小端序随机选择）
    - 随机选取```out_buf[]```中某个byte进行减变异（减随机数）
    - 随机选取```out_buf[]```中某个byte进行加变异（加随机数）
    - 随机选取```out_buf[]```中某个word进行减变异（减随机数，大小端序随机选择）
    - 随机选取```out_buf[]```中某个word进行加变异（加随机数，大小端序随机选择）
    - 随机选取```out_buf[]```中某个dword进行减变异（减随机数，大小端序随机选择）
    - 随机选取```out_buf[]```中某个dword进行加变异（加随机数，大小端序随机选择）
    - 随机选取```out_buf[]```中某个byte进行异或翻转变异
    - 随机选取```out_buf[]```中某个byte进行删除
    - 随机选取```out_buf[]```中某个位置插入一段随机长度```clone_to = UR(temp_len)```的内容。这段内容有75%的概率是原来```out_buf[]```中的内容；有25%的概率是一段相同的随机选取的数字。（这串随机选取的数字有50%的几率随机生成，有50%的几率从out_buf中选一个字节）
    - 随机选取```out_buf[]```中某个位置覆写一段随机长度的内容。这段内容有75%的概率是原来```out_buf[]```中的内容；有25%的概率是一段相同的随机选取的数字。（这串随机选取的数字有50%的几率随机生成，有50%的几率从out_buf中选一个字节）
    - 随机选取一段内容覆写成extra token
      ```a_extras[use_extra].data```或者```extras[use_extra].data```
    - 随机选取一段内容插入extra token
      ```a_extras[use_extra].data```或者```extras[use_extra].data```
  - 至此，叠加变化结束，调用```common_fuzz_stuff(argv, out_buf, temp_len)```对进行这些随机大变换后的进行fuzz。
  - 如果fuzz后的```queued_paths```与```havoc_queued```不一样了，说明发现了新路径，更新stage_max、perf_score、havoc_queued。
  
**SPLICING阶段**
- 当没有```define IGNORE_FINDS```时。如果我们经过了一整轮什么都没有发现，那么afl会进入```retry_splicing:```这里进一步的对于输入样本进行变换，通过拼接另一个输入样本来完成此变换，最后又跳回```havoc_stage```上一阶段进行大范围的随机变换。
- 否则设置```ret_val = 0```
- 到达```abandon_entry:```
- 设置```splicing_with = -1```
- 对于队列当前项信息更新。
  - 如果未设置stop_soon且queue_cur->cal_failed为0，queue_cur->was_fuzzed未被标记已经fuzz过。
    - 标记queue_cur->was_fuzzed为已经fuzz过了
    - pending_not_fuzzed计数减1
    - 如果当前对象是favored，那么pending_favored计数也减1
- return ret_val
- 至此，fuzz_one结束。
### sync_fuzzers(char **argv)
本函数用于抓取其他fuzzer的case，读取其他fuzz文件夹下的文件调用，记录下来我们最后一个打开的文件的qd_ent->d_name，最后将其写到```out_dir/.synced/sd_ent->d_name```中
- 首先打开目录```sync_dir```
- 然后通过```readdir(sd)```返回一个指向struct dirent的指针sd_ent。
- 接下来通过一个while循环遍历```sync_dir```目录下的所有文件。（由其他的fuzzer创建的）
  - 首先跳过```.```还有我们自己本fuzzer创建的文件。
  - 接着打开```"sync_dir/sd_ent->d_name/queue"```目录。
  - 检索最后看到的测试用例的ID。
  - 打开```out_dir/.synced/sd_ent->d_name```，返回到id_fd。
  - 接着从打开的id_fd读取一个```sizeof(u32)```到```min_accept```。
  - 然后lseek从新调整文件内指针到开头。
  - 设置当前的``` next_min_accept```为我们刚刚读取的```min_accept```。
  - ```sync_cnt```计数加一，由"sync %u"格式化到```stage_tmp```中。
  - 设置```stage_cur = stage_max = 0```
  - 接下来利用一个while循环对于此fuzzer排队的每个文件，解析ID并查看我们之前是否曾看过它； 如果没有，执行此个测试用例。
  - 我们利用```readdir(qd)```进一步取出目录中的文件。
    ```while ((qd_ent = readdir(qd))) ```
    - 若文件以'.'开头，或者```syncing_case < min_accept```或者；或者我们使用
    ```sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case)```失败返回-1。直接跳过此次case的扫描。
    - 如果```syncing_case >= next_min_accept```。
      - 设置```next_min_accept```为```syncing_case + 1```
    - 打开```qd_path/qd_ent->d_name```返回为fd。
    - 忽略大小为0和超过大小的文件。
    - 将fd对应的文件映射到进程空间中，返回```u8 *mem```
    - 调用```write_to_testcase(mem, st.st_size)```将其写到outfile中。
    - 接着```run_target```运行对应文件，返回fault。
    - 如果设置了stop_soon，直接返回。
    - 将```syncing_party```置为```sd_ent->d_name```
    - 调用```save_if_interesting(argv, mem, st.st_size, fault)```将感兴趣的样本保存。
    - 设置```syncing_party = 0```
    - 调用 ```munmap(mem, st.st_size)``` 接触映射。
    - 然后 ```stage_cur++ % stats_update_freq``` 如果是0即循环到一个周期，那么输出对应的fuzz信息。
  - 将```&next_min_accept```对应文件中的内容写到id_fd对应的文件中。 
  - 关闭对应的文件/目录描述等。

### save_if_interesting(char **argv, void *mem, u32 len, u8 fault)
本函数用于检测我们在```run_target```中运行的文件返回的结果是否是“有趣的”，进而确定是否要在未来的分析时保存或者插入队列中。若需要返回1，否则返回0.
- 如果fault等于crash_mode。
  - 查看此时是否出现了newbits。
  - 如果没有的话若设置了crash_mode，则total_crashes计数加一。return 0；
    - 否则直接return 0；
  - 若出现了newbits则调用 ```fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,describe_op(hnb));```拼接出路径fn
  - 通过调用```add_to_queue(fn, len, 0)```将其插入队列。
  - 如果```hnb==2```成立。（有新路径发现）
    - 设置```queue_top->has_new_cov```为1。同时```queued_with_cov```计数加一。
  - 利用hash32从新计算trace_bits的哈希值，将其设置为```queue_top->exec_cksum```
  - 调用```calibrate_case```进行用例校准，评估当前队列。
  - 打开fn，将mem的内容写入文件fn。
  - 设置keeping = 1.
- 接下来通过switch来判断fault类型。
  - ```FAULT_TMOUT```
    - 首先```total_tmouts```计数加一。
    - 如果```nique_hangs >= KEEP_UNIQUE_HANG```那么直接返回keeping
    - 如果不是```dumb_mode```
      - 调用```simplify_trace```对trace_bits进行调整。
      - 若没有新的超时路径，直接returnkeeping。
      ```if (!has_new_bits(virgin_tmout)) ```
    - unique_tmouts计数加一。
    - 如果```exec_tmout小于hang_tmout```
      - 将mem的内容写到outfile。
      - 然后再次调用```run_target```运行一次，返回new_fault。
      - 如果未设置```stop_soon```，并且new_fault为``` FAULT_CRASH```，那么跳转到```keep_as_crash```
      - 如果设置了```stop_soon```，或者```new_fault != FAULT_TMOUT```，直接return keeping。
    - 拼接出路径：
      ```fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,unique_hangs, describe_op(0));```
    - ```unique_hangs```计数加一。
    - 通过```get_cur_time()```获取last_hang_time
    - break；
  - ```FAULT_CRASH```
    - ```keep_as_crash:```
    - total_crashes计数加一。
    - 如果```unique_crashes >= KEEP_UNIQUE_CRASH```
      - 直接返回keeping；
    - 若dumb_mode=0
      - 调用simplify_trace规整trace_bits
      - 若没有新的crash路径，直接return keeping。
    - 如果unique_crashes=0
      - 调用```write_crash_readme()```
    - 拼接出路径：
      ```fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,unique_crashes, kill_signal, describe_op(0));```
    - ```unique_crashes```计数加一。
    - 获取当前时间为last_crash_time。
    - 令last_crash_execs为total_execs。
    - break
  - ```FAULT_ERROR```
    - 输出提示信息后直接abort。
  - ```default:```
    - 返回keeping。
- 接下来将mem中的内容写出到文件fn中。
- return keeping。

### simplify_trace(u64 *mem)
```c
/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */

static const u8 simplify_lookup[256] = {

        [0]         = 1,
        [1 ... 255] = 128

};
```
- 8个bytes为一组扫描整个mem（trace_bits）
- 如果当前这一组*mem不空。
  - 令```u8 *mem8 = (u8 *) mem;```
  - 那么取```simplify_lookup[mem8[i]]```放入```mem8[i]```
    代表当命中了（mem8[i]=1）时，对应的是mem8[i]被设置为128。（0b10000000）
    没命中被设置为mem8[i]被设置为1。
- 当(*mem)为0时。
  - 设置这一组为```0x0101010101010101```，代表都没有命中，每个字节被置1.
- mem++，后移到下一组。
### trim_case(char **argv, struct queue_entry *q, u8 *in_buf) 
```c
    static u8 tmp[64];
    static u8 clean_trace[MAP_SIZE];

    u8 needs_write = 0, fault = 0;
    u32 trim_exec = 0;
    u32 remove_len;
    u32 len_p2;
```
对于我们的test case进行修剪。
- 如果过当前队列entry的len<5，那么直接return 0；
- 令stage_name指向tmp数组首位。bytes_trim_in计数加上当前的q->len。
- 接着找出使得2^x > q->len的最小的x，作为len_p2。
  ```len_p2 = next_p2(q->len)```
- 设置remove_len为```MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES)```
  即len_p2/16，与4中最大的那个，作为步长。
- 通过一个while循环调整步长，直到变得太长或太短。```while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES))```（每轮remove_len/2）
  - 首先令```remove_pos = remove_len```
  - 通过```sprintf```格式化```remove_len```到tmp中。
  - 令当前的stage_cur为0， stage_max为```q->len / remove_len```
  - 进入一个while循环```while (remove_pos < q->len)```
    - 令```trim_avail = MIN(remove_len, q->len - remove_pos)```
    - 调用```write_with_gap```
    - 接着```run_target```运行此样例，返回fault。
    - ```trim_execs```计数加一。
    - 如果设置了stop_soon或者fault == FAULT_ERROR，直接跳转到```abort_trimming```
    - 计算当前trace_bits的hash32为cksum。
    - 如果当前的q->exec_cksum与计算出来的cksum相等。
      - 令```move_tail```为q->len - remove_pos - trim_avail。
      - q->len减去trim_avail
      - 重新计算当前的```len_p2 = next_p2(q->len)```
      - 从```in_buf + remove_pos + trim_avail```复制```move_tail```个字节到```in_buf + remove_pos```
      - 如果```needs_write```为0.
        - 设置```needs_write = 1```
        - 拷贝trace_bits到clean_trace
    - 如果不等，remove_pos前移remove_len个字节。
    - 如果trim的次数到达一个周期，那么输出信息。
    - ```stage_cur```计数加一。
  - ```remove_len```减半
- 如果设置了needs_write
  - 打开q->fname对应的文件。
  - 将in_buf中的内容写出到q->fname文件
  - 拷贝clean_trace到trace_bits
  - 调用```update_bitmap_score(q)```更新此时的bitmap信息。
- ```abort_trimming:```
  - bytes_trim_out加上q->len
  - return fault。



### write_with_gap(void *mem, u32 len, u32 skip_at, u32 skip_len)
```c
static void write_with_gap(void *mem, u32 len, u32 skip_at, u32 skip_len) {

    s32 fd = out_fd;
    u32 tail_len = len - skip_at - skip_len;

    if (out_file) {

        unlink(out_file); /* Ignore errors. */

        fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

        if (fd < 0) PFATAL("Unable to create '%s'", out_file);

    } else lseek(fd, 0, SEEK_SET);

    if (skip_at) ck_write(fd, mem, skip_at, out_file);

    if (tail_len) ck_write(fd, mem + skip_at + skip_len, tail_len, out_file);

    if (!out_file) {

        if (ftruncate(fd, len - skip_len)) PFATAL("ftruncate() failed");
        lseek(fd, 0, SEEK_SET);

    } else close(fd);

}
```

### calculate_score(struct queue_entry *q)
*Calculate case desirability score to adjust the length of havoc fuzzing.*
- 首先计算平均时间
  ```avg_exec_us = total_cal_us / total_cal_cycles```
- 计算平均bitmap大小
  ```avg_bitmap_size = total_bitmap_size / total_bitmap_entries```
- 定义初始的```perf_score = 100```
- 接下来通过给q->exec_us乘一个系数，判断他和avg_exec_us的大小来调整perf_score。
  ```c
   if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
    else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
    else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
    else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
    else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
    else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
    else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;
  ```
- 然后通过给q->bitmap_size 乘一个系数，判断与avg_bitmap_size的大小关系来调整perf_score。
  ```c
  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
    else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
    else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
    else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
    else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
    else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;
  ```
- 如果q->handicap大于等于4
  - perf_score乘4.
  - q->handicap减4.
- 否则，若q->handicap不为0
  - perf_score乘2.
  - q->handicap减1.
- 通过深度来调整
  ```c
      switch (q->depth) {

        case 0 ... 3:
            break;
        case 4 ... 7:
            perf_score *= 2;
            break;
        case 8 ... 13:
            perf_score *= 3;
            break;
        case 14 ... 25:
            perf_score *= 4;
            break;
        default:
            perf_score *= 5;

    }
  ```
- 最后保证我们调整后的不会超出最大界限。
- return perf_score

### common_fuzz_stuff(char **argv, u8 *out_buf, u32 len)
写出修改后的测试用例，运行程序，处理result与错误等。
- 如果设置了post_handler
  - 调用```post_handler(out_buf, &len)```，返回out_buf
  - 若out_buf为0或len为0，return 0；
- 调用``` write_to_testcase```写出out_buf
- ```run_target```运行要fuzz的程序，返回fault。
- 如果设置了stop_soon，直接返回1
- 如果```fault等于FAULT_TMOUT```
  - ```subseq_tmouts```计数加一
  - 如果大于TMOUT_LIMIT
    - cur_skipped_paths计数加一后return 1；
- 否则令```subseq_tmouts = 0```
- 如果设置```skip_requested```
  - 归零```skip_requested```
  - ```subseq_tmouts```计数加一
  - return 1；
- 接下来处理```FAULT_ERROR```
  - ```save_if_interesting```检测我们在```run_target```中运行的文件返回的结果是否是“有趣的”。
  - 返回值加上```queued_discovered```成为新的```queued_discovered```
- 根据运行的轮数来输出fuzz统计信息。
- return 0；
## 开始fuzz之前的一些关键函数
### setup_signal_handlers()
在函数开头时有这样一个修饰符 ```EXP_ST``` 主要被用于当afl被build成一个链接库时导出一些变量。
```c
/* A toggle to export some variables when building as a library. Not very
   useful for the general public. */

#ifdef AFL_LIB
#  define EXP_ST
#else
#  define EXP_ST static
#endif /* ^AFL_LIB */
```
- 首先我们定义一个 ```struct sigaction sa``` 用于储存信号相关的信息。接着我们设置 ```sa.sa_handler = handle_stop_sig``` ，然后使用 ```sigaction()``` 函数指定，当 ```SIGHUP,SIGINT,SIGTERM``` 信号来临时，信号处理函数是：```sa.sa_handler = handle_stop_sig```。其实就是指定了当停止是调用的 handler。
  - 主要处理包括 cirl-C之类的操作。
  - 设置stop_soon = 1
  - 杀死 child_pid 和 forksrv_pid 对应的进程。
- SIGALRM：指定timeout的handler为 ```handle_timeout``` 函数。
  - 当处于主进程时杀死子进程
  - child_pid == -1 且 forksrv_pid > 0时杀死forkserver进程。（-1是定义的初始值，不是返回值）
  - 均设置child_timed_out = 1。
- SIGWINCH：Window resize为```handle_resize``` 
  - 设置clear_screen = 1
- SIGUSR1（自定义）：skip entry为```handle_skipreq```。
  - 设置skip_requested = 1
- SIGTSTP、SIGPIPE：这是我们不太关心的两个信号，为：```SIG_IGN```
  - ```SIG_IGN```是一个由宏定义的函数指针。

### check_asan_opts()
本函数主要用来检测对于asan的一些设置。
- ASAN_OPTIONS如果设置，那么检测是否同时设置了：abort_on_error=1 和 symbolize=0，如果没有，abort。
- MSAN_OPTIONS如果设置，那么检测是否同时设置了：对应的exit的status、symbolize=0，如果没有，abort。

### setup_shm()
设置共享内存和virgin_bits。
首先需要注意两个数组：
```c
virgin_tmout[MAP_SIZE],    /* Bits we haven't seen in tmouts   */
virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */
```
- 如果in_bitmap未设置，那么将virgin_bits后65536个bytes初始化为255
- 初始化virgin_tmout、virgin_crash数组均为255（index：0-65535）
- 调用 ```shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600)``` 设置一段共享内存。容量65536。
https://blog.csdn.net/ec06cumt/article/details/51444961
  -  ```int shmget(key_t key, size_t size, int shmflg)```
  - 第一参数为 IPC_PRIVATE，*使用IPC_PRIVATE创建的IPC对象, key值属性为0，和IPC对象的编号就没有了对应关系。这样毫无关系的进程，就不能通过key值来得到IPC对象的编号（因为这种方式创建的IPC对象的key值都是0）。因此，这种方式产生的IPC对象，和无名管道类似，不能用于毫无关系的进程间通信。但也不是一点用处都没有，仍然可以用于有亲缘关系的进程间通信。*
  - 第二参数 MAP_SIZE 为65536，是这一段内存的大小。
  - 第三参数 IPC_CREAT | IPC_EXCL | 0600，代表这段内存的权限。
    - 0600权限代表，只有创建者可以进行读写
    - IPC_CREAT   如果共享内存不存在，则创建一个共享内存，否则打开操作。
    - IPC_EXCL     只有在共享内存不存在的时候，新的共享内存才建立，否则就产生错误。
- 当申请共享内存成功后，通过设置析构函数atexit()，调用 shmctl 删除这一段共享内存。
- 如果没有设置dumb_mode（哑模式），那么设置SHM_ENV_VAR为shm_str（此时是65539）
- 接下来调用 shmat 启动对该段共享内存的访问。
  -  ```void *shmat(int shm_id, const void *shm_addr, int shmflg)```
  - 第一参数指定这一段共享内存的id
  - 第二参数为NULL一般，shm_addr指定共享内存连接到当前进程中的地址位置，通常为空，表示让系统来选择共享内存的地址。
  - 第三参数shm_flg是一组标志位，通常为0。
  - 最后返回指向共享内存第一个字节的指针，放入 trace_bits 。
- 最后判断 trace_bits 有效性。
### init_count_class16()
```c
static const u8 count_class_lookup8[256] = {

        [0]           = 0,  //0
        [1]           = 1,  //1
        [2]           = 2,  //2
        [3]           = 4,  //3
        [4 ... 7]     = 8,  //4
        [8 ... 15]    = 16, //5
        [16 ... 31]   = 32, //6
        [32 ... 127]  = 64, //7
        [128 ... 255] = 128 //8

};

static u16 count_class_lookup16[65536];


EXP_ST void init_count_class16(void) {

    u32 b1, b2;

    for (b1 = 0; b1 < 256; b1++)
        for (b2 = 0; b2 < 256; b2++)
            count_class_lookup16[(b1 << 8) + b2] =
                    (count_class_lookup8[b1] << 8) |
                    count_class_lookup8[b2];
}
```
本函数用来初始化 ```u16 count_class_lookup16[65536]``` 这个数组。
- 将整个 count_class_lookup16 分成256段，每一段256份儿。初始化的时候利用了 count_class_lookup8。
  - count_class_lookup8中对于执行次数进行了规整，比如执行了4-7次的其计数为8，比如32次到127次都会认为是64次。
  - 变量 ```trace_bits``` 来记录分支执行次数，而count_class_lookup8实际就是对于```trace_bits```的规整。
  - 而初始化 count_class_lookup16 实际是因为 AFL 中对于一条分支径的表示是由一个二元组来表示的。
    - 例如：```A->B->C->D->A-B```， 可以用[A,B] [B,C] [C,D] [D,A]四个二元组表示，只需要记录跳转的源地址和目标地址。并且[A,B]执行了两次，其余执行了一次，这里用hash映射在一张map中。
    - 而基于这种二元组的表示的效率考虑，又使用了```u16 count_class_lookup16[65536]``` 这个数组，并在此初始化。

在网上找到这样一段解释我觉得很好：
*这样处理之后，对分支执行次数就会有一个简单的归类。例如，如果对某个测试用例处理时，分支A执行了32次；对另外一个测试用例，分支A执行了33次，那么AFL就会认为这两次的**代码覆盖**是相同的。当然，这样的简单分类肯定不能区分所有的情况，不过在某种程度上，处理了一些因为循环次数的微小区别，而误判为不同执行结果的情况。*
### setup_dirs_fds()
https://www.cnblogs.com/xiaofeiIDO/p/6695459.html
设置输出的文件夹与fd。
- 如果设置了sync_id且通过mkdir(sync_dir, 0700)创建了对应的文件夹失败，并且errno != EEXIST时，abort
- 如果没设置sync_id，尝试创建了sync_dir，创建失败，且errno != EEXIST时abort。
  - 如果创建sync_dir失败，且errno = EEXIST。调用maybe_delete_out_dir()收尾。
- 如果创建成功。
  - 设置了in_place_resume，则abort
  - 否则调用open以读权限打开，返回fd，赋值给out_dir_fd。
- 接下来将out_dir与/queue拼接为tmp。（output/queue）
- 创建tmp文件夹。
- 创建output/queue/.state/ （Top-level directory for queue metadata used for session resume and related tasks）
- 创建output/queue/.state/deterministic_done/ （Directory for flagging queue entries that went through deterministic fuzzing in the past.）
- 创建output/queue/.state/auto_extras/ （Directory with the auto-selected dictionary entries）
- 创建output/queue/.state/redundant_edges/（The set of paths currently deemed redundant）
- 创建output/queue/.state/variable_behavior/（The set of paths showing variable behavior）
- 接下来做目录的同步，用于追踪共同工作的fuzzer
  - 如果设置了sync_id。那么创建output/.synced/
- **创建output/crashes，记录crash样本。**（All recorded crashes）
- 创建output/hangs（ All recorded hangs.）
- 打开/dev/null与/dev/urandom，fd为dev_null_fd和dev_urandom_fd。
- 创建output/plot_data，通过```open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600)``` 打开返回fd。
- 通过fdopen将fd转为文件指针plot_file，通过fprintf将一些信息写入文件。忽略错误。
```c
    fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                       "pending_total, pending_favs, map_size, unique_crashes, "
                       "unique_hangs, max_depth, execs_per_sec\n");
```

**注意，以上的操作除了特殊说明，如果创建，打开失败，均abort**
### read_testcases()
本函数从输入（input）读取测试用例并入队，在启动时调用。
在函数开头首先定义了
```c
    struct dirent **nl; 
    s32 nl_cnt;
```
而struct dirent如下：
```c
//Data structure for a directory entry
struct dirent   
{   
　　long d_ino; /* inode number 索引节点号 */  
　　   
    off_t d_off; /* offset to this dirent 在目录文件中的偏移 */  
　　   
    unsigned short d_reclen; /* length of this d_name 文件名长 */  
　　   
    unsigned char d_type; /* the type of d_name 文件类型 */  
　　   
    char d_name [NAME_MAX+1]; /* file name (null-terminated) 文件名，最长255字符 */  
}  
```
- 首先测试iutput/queue是否可访问。如果可访问，那么将 in_dir赋值为 iutput/queue。
- 接下来通过调用```scandir(in_dir, &nl, NULL, alphasort)```扫描对应的in_dir目录。
  - 函数原型：```int scandir(const char *dir, struct dirent **namelist, nt (*select) (const struct dirent *), nt(*compar) (const struct dirent **, const struct dirent**));```
  - 第一参数dir代表要扫描的路径。
  - 第三参数select适用于过滤的函数，对于第一参数指定的进行过滤
  - 第四参数compar将过滤后的结果进行排序。
  - 最终储存在第二参数namelist列表中。每一项都是一个dirent 。
  - 那么本函数在这里的作用就是扫描目录in_dir中的每一项，将结果排序后放入 ```nl``` 这一列表中。
  - 返回值为函数成功执行时返回找到匹配模式文件的个数，存储在 ```nl_cnt``` 中。
    - 此时如果```nl_cnt<0``` 说明匹配失败，errno若是ENOENT、ENOTDIR，则输出路径无效提示信息后abort。否则直接abort
- 当匹配成功后，若设置了shuffle_queue，那么调用 ```shuffle_ptrs``` 对此时的input-qeue进行改组（Shuffle）
- 接下来进入一个for循环：```for (i = 0; i < nl_cnt; i++)``` 扫描数组nl中的每一项。
  - 首先将扫描到的文件名（nl[i]->d_name）与in_dir拼接形成路径```fn``` 。（in_dir, nl[i]->d_name）
  - 接下来将（in_dir, "/.state/deterministic_done/",nl[i]->d_name）拼接形成```dfn```。
  - 设置passed_det = 0
  - 随后通过lstat(fn, &st) || access(fn, R_OK)检测目录是否可访问。不可访问则abort。将从lstat(fn, &st)获取的文件信息保存在```struct stat st;```中。https://baike.baidu.com/item/lstat
  - 下一步检查我们扫描到的文件是否是有效的常规文件？
    - 通过S_ISREG查看st.st_mode确定文件的性质；st.st_size 确定大小；strstr查找是否是README.txt文件。
      - 这一步主要是排除一些无关文件的干扰，比如README.txt、. 和 ..
  - 若是有效的常规文件，那么检测大小是否超界限。
  - 接下来通过```if (!access(dfn, F_OK))```检测```dfn```判断此文件是否已经fuzz过了，防止多余的时间消耗。（因为若fuzz过了，会被放到in_dir/.state/deterministic_done/下）
    - 如果没有fuzz过，设置passed_det = 1。
    - 如果fuzz过了，保持passed_det = 0。
  - 至此，一切检查完成，我们将调用 ```add_to_queue(fn, st.st_size, passed_det)``` 将这个文件入队。同时也带上了他的大小和passed_det信息。
- for循环结束后，到达函数最后收尾的位置。首先检查是否设置queued_paths，没设置则代表没有测试用例。abort掉。
- 通过了queued_paths后，设置last_path_time = 0、以及queued_at_start = queued_paths。
至此，整个```read_testcases()```结束。


### shuffle_ptrs()
进行队列改组。
调用：```shuffle_ptrs((void **) nl, nl_cnt)```
```c
/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(void **ptrs, u32 cnt) {

    u32 i;

    for (i = 0; i < cnt - 2; i++) {

        u32 j = i + UR(cnt - i);
        void *s = ptrs[i];
        ptrs[i] = ptrs[j];
        ptrs[j] = s;

    }

}
```
其中UR是产生一个0 -（limit-1）的随机数。
在i到cnt-1内随机产生一个索引下标j。将数组元素```nl[i]``` 与 ```nl[j]``` 位置互换。
个人理解是对于input-qeue做了一个随机化or扰动。

### load_auto()
- 首先通过  ```alloc_printf``` 拼接出形如：```("%s/.state/auto_extras/auto_%06u", in_dir, i)``` 的路径，赋值给 ```fn``` 。如：input/.state/auto_extras/auto_000000
- 接下来进入一个50次的for循环
  - 接着以0600权限打开 fn对应的文件，返回fd。如果open失败则abort掉。
  - 从fd读取MAX_AUTO_EXTRA + 1大小的bytes，放入tmp数组中。MAX_AUTO_EXTRA + 1 = 33。注意这里多读取了一个字节来判断是否读取的token过长。read的返回值为len。
    - 如果读取失败则abort
  - 如果len在：[ MIN_AUTO_EXTRA,MAX_AUTO_EXTRA ] 之间的话，调用maybe_add_auto(tmp, len)，将我们此时的语料加入a_extras[]数组中。
  - 关闭fd。
- 如果for循环正常进行了，输出信息：```OKF("Loaded %u auto-discovered dictionary tokens.", i)```
- 否则输出相反的信息。

### maybe_add_auto(u8 *mem, u32 len)
maybe_add_auto(tmp, len)，此时tmp(mem)对应的是读取的auto extra文件，len对应长度。
```c
/* Interesting values, as per config.h */

static s8 interesting_8[] = {INTERESTING_8};
static s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
static s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};


static struct extra_data *extras;     /* Extra tokens to fuzz with        */
static u32 extras_cnt;                /* Total number of tokens read      */

static struct extra_data *a_extras;   /* Automatically selected extras    */
static u32 a_extras_cnt;              /* Total number of tokens available */
```
- 如果MAX_AUTO_EXTRAS和USE_AUTO_EXTRAS没有设置的话直接return。
  - 前者代表最大的auto_extras token(**这里的token可以翻译成语料？**)数量，值为USE_AUTO_EXTRAS * 10；后者代表用户指定的auto_extras token数量，默认50.
- 接下来从mem[1]开始扫描，跳过与mem[0]相同的byte。最后索引i停止在第一个与mem[0]不相同的位置。
- 如果i==len，代表所有的mem中的byte都相同，那么return。
- 如果len==2：与interesting_8[]中每一项比较，如果相等就return
- 如果len==4：与interesting_16[]中每一项比较，如果相等就return
- 接下来与 ```extras[]``` 数组中已经存在的extras相比，如果相等就return。（样例敏感）
- 设置auto_changed=1
- 扫描a_extras[]数组，如果遇到和mem相等的，那么 ```a_extras[i].hit_cnt++``` 命中计数+1，跳转到```sort_a_extras:```
  - 首先，按使用次数，降序对所有a_extras[i]进行排序。
  - 然后，按大size对a_extras中前USE_AUTO_EXTRAS个进行排序。
- 如果当前的a_extras_cnt < MAX_AUTO_EXTRAS，则说明a_extras还没填满。
  - 此时我们首先用realloc调整a_extras_cnt的空间为a_extras_cnt + 1。
  - 将a_extras[a_extras_cnt].data赋值为mem，.len=len，然后a_extras_cnt++，相当于加了新的一项。
  - 如果已经填满了，那么取一个随机数i，将a_extras[i]换成mem。

### pivot_inputs()
首先定义：
```c
    struct queue_entry *q = queue;  //   指向input case queue 队头
    u32 id = 0;

#ifndef SIMPLE_FILES
#  define CASE_PREFIX "id:"
#else
#  define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */
```
- 接下来进入一个遍历input队列的大While循环：```while (q)```
  - 首先通过 ```*rsl = strrchr(q->fname, '/')``` 扫描queue中第一个元素的fname，并从取出最后一个'/'以及其后的内容。
  - 接下来判断是否取成功。
    - 如果成功，则 ```rsl++``` 跳过 '/'
    - 如果失败，说明没有 '/'，直接令 ```rsl = q->fname```
  - 如果rsl以CASE_PREFIX开头，尝试将CASE_PREFIX后的数字以 ```"%06u"``` 格式化后存入orig_id。
    - 若此时的orig_id与id相等，设置resuming_fuzz = 1。使用alloc_printf("%s/queue/%s", out_dir, rsl)，拼接产生nfn。接下来使用 ```strchr(rsl + 3, ':')``` 跳过 CASE_PREFIX 查找下一个 ":" 的位置，存储在src_str中。
    - 如果 src_str 存在，用sscanf将其后的数字以 ```"%06u"``` 格式化后存入src_id。
      - 接下来让指针s从队头开始扫描，每扫描过一个元素，src_id--；s后移。若扫描结束后s还没有移动到队尾（此时src_id==0），那么令队列深度为s的位置+1。```q->depth = s->depth + 1```
      - 然后判断队列深度是否超过最大深度，如果超过最大深度，则指定为最大深度。```if (max_depth < q->depth) max_depth = q->depth```
  - 如果不以CASE_PREFIX开头。
    - 当没有定义SIMPLE_FILES时。（非单文件）
      - 检测rsl是否有```,orig:``` 为前缀的子串，如果是的话跳过前缀；如果不是直接令```use_name = rsl```
      - 然后通过 ```nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name)``` 拼接产生nfn。如："output/queue/id:000000,orig:a.out"
    - 当定义了SIMPLE_FILES时（单文件）
      - 直接拼接 ```nfn = alloc_printf("%s/queue/id_%06u", out_dir, id)```，并且不考虑id了。
  - 至此nfn获取完毕，这个nfn个人理解实际就是当前队列中测试用例的一个编号。
  - 调用 ```link_or_copy(q->fname, nfn)``` 创建硬链接（q->fname到nfn）并将```input/a.out```文件中的内容写入```output/queue/id:000000,orig:a.out```（以我这里为例）
  - 重新对队列中这一元素的fname赋值：  ```q->fname = nfn```
  - 如果设置了 ```q->passed_det=1``` ，那么调用```mark_as_det_done(q)```标记queue这一项已经fuzz过了，并保持q->passed_det=1
  - 接下来q指针后移。id++。
- 遍历结束后检测是否设置in_place_resume，若设置了调用 ```nuke_resume_dir()``` 删除 ```output/_resume/*```临时目录。这个目录主要用于本地临时恢复。

### link_or_copy(u8 *old_path, u8 *new_path)
调用如下：
```c
link_or_copy(q->fname, nfn)
//q->fname: "input/a.out"
//nfn:      "output/queue/id:000000,orig:a.out"
```
- 首先调用 ```link(old_path, new_path)``` 将new_path简历为一个old_path的硬链接。
  ```i = link(old_path, new_path)```
- 尝试以只读打开old_path：```sfd = open(old_path, O_RDONLY)```
- 尝试以只读+0600权限打开new_path，同时使用```O_CREAT | O_EXCL```测试文件是否存在。打开成功返回dfd
  [Linux中打开文件时的O_EXCL有什么用](https://blog.csdn.net/nyist327/article/details/39612057)
- 接着分配64k的空间为缓冲区，通过缓冲区中转，将old_path中的内容写入new_path。
  ```c
  while ((i = read(sfd, tmp, 64 * 1024)) > 0)
        ck_write(dfd, tmp, i, new_path);
  ```

### mark_as_det_done(struct queue_entry *q)
```c
/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

static void mark_as_det_done(struct queue_entry *q) {

    u8 *fn = strrchr(q->fname, '/');
    s32 fd;

    fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600); //打开fn对应的文件，若没有则创建。
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

    ck_free(fn);

    q->passed_det = 1;                              //设置queue中这一项的passed_det=1代表已经fuzz过了

}
```
### load_extras(u8 *dir)
```load_extras(extras_dir)```
首先定义：
```c
   DIR *d;
    struct dirent *de;
    u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
    u8 *x;
 ```
- 首先扫描dir中是否有```@``` ，有的话替换成空字节。提取下一字节转成int赋值到```dict_level```
- 尝试```d = opendir(dir)```打开对应dir。
  - 打开失败且 ```errno == ENOTDIR``` (	不是一个目录文件)。调用 ```load_extras_file(dir, &min_len, &max_len, dict_level);```然后跳到 ```check_and_sort```。对这个file进行检查和排序（by size）
  - 打开失败且```errno ！= ENOTDIR``` 直接abort。
- 接下来一个大While循环扫描并读取目录下的文件到 ```extras[]``` 中。
- 最后在 ```check_and_sort:``` 中对 ```extras[]```（extra token） 进行检测与排序

### find_timeout(void)
本函数的作用是当恢复本地会话时没有使用-t进行设置时防止不停的调整超时时间。
```c
    static u8 tmp[4096]; /* Ought to be enough for anybody. */

    u8 *fn, *off;
    s32 fd, i;
    u32 ret;
```
- 如果没有设置resuming_fuzz，直接return。
- 如果设置了in_place_resume，```fn = alloc_printf("%s/fuzzer_stats", out_dir)``` 拼接路径
  - 否则```fn = alloc_printf("%s/../fuzzer_stats", in_dir)``` 拼接路径。
- 打开fn，返回fd。
- 从fd读取0xfff字节到缓冲区tmp
- 匹配tmp中是否有子串 ```exec_timeout      :```
  - 如果没有则return
  - 如果有 ```ret = atoi(off + 20)``` ，如果ret>4那么设置 ```exec_tmout = ret``` 并且 ```timeout_given = 3```。否则return，不进行设置。

### detect_file_args(char **argv)
本函数负责扫描每一个argv[i]是否有```@@``` 子串，如果有就进行替换。
```c
u32 i = 0;
u8 *cwd = getcwd(NULL, 0);
```
- 首先获取当前路径cwd，然后进入一个大 ```while (argv[i]) ``` 扫描argv，查找是否有"@@"子串
  - 如果找到了 "@@" 子串。位置存在```aa_loc```中。
    - 若没设置out_file：拼接产生out_file：```out_file = alloc_printf("%s/.cur_input", out_dir)```
    - 若果 ```out_file[0] == '/'``` 那么直接令：```aa_subst = out_file```。否则拼接产生out_file ```aa_subst = alloc_printf("%s/%s", cwd, out_file)```
    - 接下来将当前位置（*aa_loc = 0）的 '@' 换成空字节。然后跳过```aa_loc```两个字节，拼接产生n_arg。
      ```n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2) ```
    - 然后将argv[i]这里的参数换成n_arg。
    - 最后重新将当前位置换成 '@'，（*aa_loc = '@'）

### perform_dry_run(use_argv)
对所有测试用例执行试运行，以确认该应用程序按照预期正常运行。仅对初始输入执行此操作，并且仅执行一次。
```c
    struct queue_entry *q = queue;
    u32 cal_failures = 0;
    u8 *skip_crashes = getenv("AFL_SKIP_CRASHES");
```
- 进入一个大循环 ```while (q)``` 扫描输入队列的每一项。
  - 取文件名放入fn。如："id:000000,orig:a.out"
  - 打开文件返回fd。接着以q->len为大小分配空间，返回use_mem
  - 将此文件的内容读入use_mem中。
  - ```  close(fd)```
  - 调用```calibrate_case(argv, q, use_mem, 0, 1)``` 进行测试用例的校准。返回值为res
  - 释放use_mem
  - 如果设置了stop_soon那就立刻停止
  - 返回值为 ```crash_mode``` 或者 ```FAULT_NOBIT```时
  - 打印提示信息后进入一个大switch。```switch (res)```
      - case FAULT_NONE:
        - 如果q此时是queue头，那么调用```check_map_coverage()```检测map覆盖率。
        - 接下来如果设置了crash_mode，那么输出提示信息后exit。
      - case FAULT_TMOUT:
        - 如果设置了timeout_given
          - timeout_given>1：设置queue当前项 ```q->cal_failed = CAL_CHANCES``` ，然后 ```cal_failures++```
          - 否则输出信息后abort（处理初始测试用例超时）。
        - 如果未设置则直接abort。
      - case FAULT_CRASH:
        - 如果设置了crash_mode，那么break。
        - 如果设置了skip_crashes，那么 ```q->cal_failed = CAL_CHANCES``` 然后 ```cal_failures++``` 之后直接break。
        - 如果设置了mem_limit，输出提示信息（内存不够）后abort
        - 否则直接abort
      - case FAULT_ERROR:
      - case FAULT_NOINST:
      - case FAULT_NOBITS:
        - ``` useless_at_start++```
        - 如果 ```!in_bitmap && !shuffle_queue``` 都未设置，提示用户用例可能无效后break
  - 如果设置了 ```q->var_behavior``` 输出提示信息：*Instrumentation output varies across runs.*
  - q顺着队列后移一个元素。
- 如果设置了cal_failures
  - cal_failures == queued_paths：所有用例均超时。
  - 否则告诉用户我们跳过了 ```cal_failures``` 由于超时
  - 计算cal_failures * 5 是否大于 queued_paths
    - 如果大于，则说明测试用例的问题比例太高，可能需要重新检查设置。
- 结束。

### calibrate_case(char **argv, struct queue_entry *q, u8 *use_mem,u32 handicap, u8 from_queue)
本函数对我们所有的输入文件做了评估并将testcase多次运行，并且当发现有新的bits/路径产生时评估此文件是否是variable（通过多次运行看是否产生路径变化？）
测试用例校准 ```calibrate_case(argv, q, use_mem, 0, 1)```  use_mem为测试用例的内容（可执行文件）
```c
    static u8 first_trace[MAP_SIZE];

    u8 fault = 0, new_bits = 0, var_detected = 0, hnb = 0,
            first_run = (q->exec_cksum == 0);

    u64 start_us, stop_us;

    s32 old_sc = stage_cur, old_sm = stage_max;
    u32 use_tmout = exec_tmout;
    u8 *old_sn = stage_name;
```
- 如果没有设置from_queue，或者设置了resuming_fuzz（恢复会话或尝试校准已添加的发现时），那么设置：
  ```use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,exec_tmout * CAL_TMOUT_PERC / 100);```其实就是对于此时timeout进行适当的宽松。
- q->cal_failed++
- 设置此时的状态信息 ```stage_name = "calibration";stage_max = fast_cal ? 3 : CAL_CYCLES;```
- 判断此时的```forkserver```是否已经启动。
  - 若未启动则调用```init_forkserver(argv)```
- 如果设置了q->exec_cksum。
  - 首先拷贝 ```memcpy(first_trace, trace_bits, MAP_SIZE);```
  - 接着调用```hnb = has_new_bits(virgin_bits)```，查看是否有新的tuple产生还是仅有hit-count改变。
  - 如果返回的hnb > new_bits（一开始是0），那么更新new_bits。```new_bits = hnb;```
- 获取当前时间：```start_us = get_cur_time_us()```
- 接着进入一个大for循环中：```for (stage_cur = 0; stage_cur < stage_max; stage_cur++) ```
  - 如果不是```first_run``` 并且 ```stage_cur % stats_update_freq == 0```也就是经过了一个周期，那么调用```show_stats()```输出fuzz信息。
  - 调用```write_to_testcase(use_mem, q->len)```将读取的内容写入我们的outfile中。
  - 接下来调用```run_target(argv, use_tmout) ```运行文件，返回结果存储在fault中。
  - 如果设置了```stop_soon```或者```fault != crash_mode```。
    ```goto abort_calibration:```
  - 如果非dumb_mode，并且stage_cur==0（第一次运行）；并且调用```count_bytes(trace_bits)```查找trace_bit中是否有被设置为1的bit，若没有，则设置 ```fault = FAULT_NOINST``` 最后跳转到```abort_calibration```
  - 接着根据当前的trace_bits计算cksum。（checksum？）
  - 如果当前的```q->exec_cksum != cksum```。
    - 重新调用```has_new_bits(virgin_bits)```，返回hnb若大于new_bits，更新new_bits = hnb。
    - 如果q->exec_cksum不为零（不是第一次执行这个queue entry）
      - i为索引，扫描var_bytes、first_trace、trace_bits。
      - 当满足```var_bytes[i]==0```，```first_trace[i] != trace_bits[i]```时，代表发现了可变的entry，设置对应的```var_bytes[i] = 1``` ，令```stage_max = CAL_CYCLES_LONG```。
      - 最后设置```var_detected = 1```。
    - 如果q->exec_cksum为零（第一次执行这一队列项）
      - 更新``` q->exec_cksum = cksum```（cksum为之前通过trace_bits计算的）
      - 将trace_bits用memcpy拷贝到first_trace。
- 获取当前时间，计算总时间和轮数。
- 计算当前这一queue entry的```q->exec_us```。
- ```q->bitmap_size = count_bytes(trace_bits)```计算执行完毕后trace_bits中的路径信息。
- ```q->handicap = handicap; q->cal_failed = 0;```
- 累加q->bitmap_size;到total_bitmap_size，即累加了当前发生变化的bits的个数。
- ```total_bitmap_entries++;```
- 调用```update_bitmap_score(q);```更新一些比如偏好因子的信息，包括进行对应的trace_bits压缩，以判断此判断此路径是否是更有利的。
- 如果当前的case没有产生一个新的结果，那么通知用户这是一个不重要的问题。
- 满足```!dumb_mode && first_run && !fault && !new_bits```（第一次运行，fault未设置，newbits未设置）设置fault = FAULT_NOBITS;
- 接下来是 ```abort_calibration:```
  - 如果new_bits == 2（产生了新路径）且q->has_new_cov未设置。
    - 设置q->has_new_cov = 1;
    - queued_with_cov++;计数++
  - 如果设置了```var_detected```
    - 调用```count_bytes(var_bytes);```获取变化的bytes的数量存在var_byte_count。
    - 如果```q->var_behavior```未设置。
      - 调用```mark_as_variable(q)```，然后```queued_variable++```计数增加。
        实际此时是将此entry标记为可变。在mark_as_variable(q)中创建了符号链接```/queue/.state/variable_behavior/q->fname```
  - 接下来恢复之前的stage相关数据
  - 如果不是第一轮，那么输出相关信息。
  - return fault
  


### init_forkserver(char **argv)
[Linux 的进程间通信：管道](https://zhuanlan.zhihu.com/p/58489873)
本函数用来初始化/启动forkserver。首先有如下定义：
```c
    static struct itimerval it;
    int st_pipe[2], ctl_pipe[2];
    int status;
    s32 rlen;
```
- 首先创建两个管道：```pipe(st_pipe) || pipe(ctl_pipe)```，其中st_pipe：状态管道。ctl_pipe：控制管道
- 然后产生一个forkserver：```forksrv_pid = fork()```
- 在子进程中（forkserver）
  -  首先进行 ```setsid()```创建新的会话，使子进程完全独立，脱离控制。
  - 接下来重新配置fd。关闭子进程中的stdout和stderr，然后将其重定向到/dev/null中。（相当于关闭了子进程的全部输出）
  - 如果设置了out_file，那么用dup2再关掉子进程的stdin，重定向到/dev/null
  - 否则关闭stdin，重定向到out_fd。最后关闭out_fd
  - 将FORKSRV_FD重定向到ctl_pipe[0]。将FORKSRV_FD + 1重定向到st_pipe[1]。
    - 此时，**子进程只能从控制管道中读命令；向状态管道中写。**
  - 接下来关闭子进程中一些描述符。
    ```c
        close(ctl_pipe[0]);
        close(ctl_pipe[1]);
        close(st_pipe[0]);
        close(st_pipe[1]);

        close(out_dir_fd);
        close(dev_null_fd);
        close(dev_urandom_fd);
        close(fileno(plot_file));
    ```
  - 如果没有设置LD_BIND_LAZY，那么设置 ```setenv("LD_BIND_NOW", "1", 0)``` 防止linker在fork之后做额外的工作。
  - 设置asan与msan选项。
  - **最后启动```execv(target_path, argv);```**
  - 如果execv启动失败，那么会运行到：```*(u32 *) trace_bits = EXEC_FAIL_SIG``` 通过在bitmap中设置签名来通知父进程执行execv失败。
     [setsid的作用](https://blog.csdn.net/sweetfather/article/details/79457261)
     [Linux--setsid() 与进程组、会话、守护进程](https://www.cnblogs.com/gx-303841541/p/3360071.html)
     [进程间通信管道进阶篇：linux下dup/dup2函数的用法](https://www.cnblogs.com/GODYCA/archive/2013/01/05/2846197.html)
     ![](https://s3.ax1x.com/2021/01/29/yiipon.png)
- 在父进程中关闭```ctl_pipe[0]``` 与 ```st_pipe[1]``` 即：控制管道读与状态管道写。（父进程不需要）
- 然后对于父进程需要的进行如下赋值：```fsrv_ctl_fd = ctl_pipe[1];fsrv_st_fd = st_pipe[0];```
- 接下来等待forkserver启动。（等待很短的一段时间） 
- 然后从st从读取forkserver的状态信息。
  - 如果我们成功读到了4btytes的状态信息，那么说明一切就绪。直接return
  - 如果设置了child_timed_out，则通知用户调整-t参数。
  - 否则```waitpid(forksrv_pid, &status, 0)``` 等待forksrv返回status
    - 调用```WIFSIGNALED(status)``` 判断forksrv是否返回的异常退出的信号status。
      ![](https://s3.ax1x.com/2021/01/29/yiPTII.png)
    - 如果是。（异常退出）
      - 是否设置 ```mem_limit && mem_limit < 500 && uses_asan``` （mem_limit过小）。告知用户是由于未收到任何input就crash，可能是由于asan和mem_limit的原因。查看notes_for_asan.txt 。
      - 如果没有设置mem_limit。告知用户可能的原因。
      - 否则通知用户其他可能的原因。（比如触发了oom之类的）
      - 最后直接通过```WTERMSIG(status)``` 获取信号告知用户single值。
    - 如果否。（非异常退出）
      - 检查是否设置了：```trace_bits == EXEC_FAIL_SIG``` 如果设置了说明execv没正常执行。
      - 检查是否设置：```mem_limit && mem_limit < 500 && uses_asan``` 。可能是由于配置的内存限制导致的。
      - 如果没有设置 ```mem_limit```。可能是fuzzer的bug。 ：-）
      - 否则告知用户其他可能的原因，比如oom之类的。
- 结束。

### has_new_bits(u8 *virgin_map)

*Check **if the current execution path brings anything new to the table.**
   Update virgin bits to reflect the finds. **Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.**
   Updates the map, so subsequent calls will always return 0.*
首先有如下定义：
```c
#ifdef WORD_SIZE_64

    u64 *current = (u64 *) trace_bits;
    u64 *virgin = (u64 *) virgin_map;

    u32 i = (MAP_SIZE >> 3);

    这里 MAP_SIZE>>3 代表 MAP_SIZE/8 也就是按照8个字节一组，一共分了i组 （64位实现）

#else

  u32* current = (u32*)trace_bits;

  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

  这里 MAP_SIZE>>3 代表 MAP_SIZE/4 也就是按照4个字节一组，一共分了i组 （32位实现）

#endif /* ^WORD_SIZE_64 */
```

- current指向trace_bits首地址。virgin指向virgin_map首地址。
- 进入一个大``` while (i--)```循环分组扫描。
  - 如果```*current```不为0(命中了相应路径)，且```*current & *virgin```不为0。（代表我们命中的某个bit之前是没有碰到过的新的）
    - 如果ret<2。
      ```u8 *cur = (u8 *) current;u8 *vir = (u8 *) virgin;```（指向第一个字节，注意这里是u8）
    - 接着进行如下判断：
      ```c
      if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
                    (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
                    (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
                    (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
      ```    
      即查看每组中的每一个字节是否满足```cur[i] && vir[i] == 0xff```。（即检查是否覆盖到了新的路径）
      若有一对儿成立，则```ret = 2```(new tuple出现了新路径)；否则```ret=1```(only hit-count changed，仅仅是命中次数更新)
    - 进行```*virgin &= ~*current```
  - 这一组处理完了，进行```current++;virgin++;```准备处理下一组
- 最后如果```ret && virgin_map == virgin_bits```，那么令```bitmap_changed = 1```
- 返回ret。

### write_to_testcase(void *mem, u32 len)
Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated.
- 令```fd = out_fd```
- 首先检测是否设置out_file。
  - 若设置了。打开outfile然后把mem的内容写到outfile。
  - 若没设置，调整大小。```ftruncate(fd, len)```  .
  https://baike.baidu.com/item/ftruncate

### run_target(char **argv, u32 timeout)
Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[].
调用如下
```fault = run_target(argv, use_tmout);```
- 首先memset清零trace_bits。
- 接下来如果设置了```dumb_mode == 1```或者满足```no_forkserver```会执行一段与```init_forkserver```中非常相似的代码。（没有forkserver时，在子进程中执行targetfile）
  - fork出一个子进程，在子进程中执行target_path，如果失败，则```*(u32 *) trace_bits = EXEC_FAIL_SIG```
- 否则代表此时已经有一个fork server up and running了。（此时代表有forkserver）
  - 此时我们向控制管道写4个字节的```prev_timed_out```，再从状态管道读取4个字节的```child_pid```。
    - 如果读取失败则说明forkserver异常
- 接下来设置timer。```setitimer```
- 如果满足```dumb_mode == 1 || no_forkserver```（无forkserver，以子进程的方式execve）
  - waitpid等待子进程（child_pid）的status
- 否则直接从forkserver的状态管道中读status。
- 计算执行时间```exec_ms ```
- 重制timer，```total_execs++;```执行次数的计数+1。
- ```prev_timed_out = child_timed_out;```
- 判断子进程是否是异常退出，如果是，判断异常退出的原因后return。
- 判断退出状态是否是```uses_asan && WEXITSTATUS(status) == MSAN_ERROR``` ，如果是，设置```kill_signal = 0;```后return FAULT_CRASH
- 接下来判断是否是无forkserver情况下execve执行失败。
- 如果最慢执行时间小与当前执行时间，并且```timeout < exec_tmout```，则更新```slowest_exec_ms = exec_ms;```
- return ```FAULT_NONE```
结束
### classify_counts(u64 *mem)
```classify_counts((u64 *) trace_bits)```
```c
static inline void classify_counts(u64 *mem) {

    u32 i = MAP_SIZE >> 3;  //八个一组，一共i组

    while (i--) {           //每一组扫描

        /* Optimize for sparse bitmaps. */

        if (unlikely(*mem)) {//如果对应的mem中的值不为0

            u16 *mem16 = (u16 *) mem;

            mem16[0] = count_class_lookup16[mem16[0]];
            mem16[1] = count_class_lookup16[mem16[1]];
            mem16[2] = count_class_lookup16[mem16[2]];
            mem16[3] = count_class_lookup16[mem16[3]];
        }
        mem++;
    }
}
 ```

### count_bytes(u8 *mem)
调用：```count_bytes(trace_bits)```
实现如下：

 ```c
#define FF(_b)  (0xff << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

static u32 count_bytes(u8 *mem) {

    u32 *ptr = (u32 *) mem;   //ptr指向trace bits的首位
    u32 i = (MAP_SIZE >> 2);  //四个字节一组
    u32 ret = 0;              //ret计数初始化为0

    while (i--) {             //一组一组扫描

        u32 v = *(ptr++);     //v每次取4个字节

        if (!v) continue;    //如果4个字节全部是0的话直接跳过这四个字节取下一组。
        if (v & FF(0)) ret++; //0xff
        if (v & FF(1)) ret++; //0xff00
        if (v & FF(2)) ret++; //0xff0000
        if (v & FF(3)) ret++; //0xff000000
    }
    return ret;
}
```
其实就是四个一组，扫描哪个字节不为0。若扫描到不为0的就ret++；最后返回ret。
### update_bitmap_score(struct queue_entry *q)
当我们碰到一个新路径时，判断此路径是否是更有利的。即是否是能遍历到bitmap中的bit的最小的路径集合。
```c
    u32 i;
    u64 fav_factor = q->exec_us * q->len;
```
- 首先在开始时定义了一个偏好因子```fav_factor = q->exec_us * q->len;```
- 接着进入一个for循环：```for (i = 0; i < MAP_SIZE; i++)```
  - 扫描trace_bits中每一位trace_bits[i]
    - 如果trace_bits[i]=1（代表这是已经被覆盖到的路径）
      - 若设置了top_rated[i]
        - 判断当前的fav_factor是否大于```top_rated[i]```列表中维护的因子的值。
          - 如果大于则说明top_rate[i]中存的是最优的fav_factor。则直接continue掉此次循环。
          - 否则```top_rated[i]->tc_ref```计数减1。并free掉对应的top_rated[i]->trace_mini，然后置空。
      - **接下来相当于重新更新对应的```top_rated[i]```中维护的相关数据。**
      - 令top_rated[i] = q
      - q->tc_ref++计数增加
      - 如果q->trace_mini为0
        - 那么令```q->trace_mini = ck_alloc(MAP_SIZE >> 3)```（分配8192字节）
        - 调用```minimize_bits(q->trace_mini, trace_bits);```对原trace_bits进行压缩，放到只有原先1/8大小的q->trace_mini中。
      - 最后令```score_changed = 1```
- 结束

### minimize_bits(u8 *dst, u8 *src)
https://blog.csdn.net/La745739773/article/details/89604412
对src进行压缩，压缩到原来的1/8，
```c
/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8 *dst, u8 *src) {

    u32 i = 0;

    while (i < MAP_SIZE) {

        if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
        i++;

    }

}
```
- *(src++)每次取trace_bits[]数组中一个元素的值。
- i>>3得到了要压缩到的dst的index，即这个数据会被压缩到dst[index]的bits中。
- i&7相当于i%8(即不考虑高位，只保留低三bits)，相当于计算我们要放到dst[]的一个byte中的哪个bit。
- 最后将1<<(i%8)把1放到对应的bits上。
- 压缩结束
### check_map_coverage()
```c
/* Examine map coverage. Called once, for first test case. */

static void check_map_coverage(void) {

    u32 i;

    if (count_bytes(trace_bits) < 100) return;

    for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
        if (trace_bits[i]) return;

    WARNF("Recompile binary with newer version of afl to improve coverage!");

}
```
- 利用```count_bytes(trace_bits)```统计发现的路径数量（不为0的字节），小于100则return。
- 扫描trace_bits后半部分，如果有不为零的就返回。
- 否则告诉用户改进覆盖率。
### cull_queue()
用于精简队列。
```c
    struct queue_entry *q;
    static u8 temp_v[MAP_SIZE >> 3];  //temp_v[8192]
    u32 i;
```
- 如果设置了dumb_mode或者未设置score_changed，直接return。
- 设置 ```score_changed = 0```，初始化temp_v数组，```queued_favored = 0;pending_favored = 0;```
- 从queue队头开始扫描，设置队列中每一项的 ```q->favored = 0```
- 接下来进入一个```for (i = 0; i < MAP_SIZE; i++)```
  - 如果对于当前queue entry```top_rated[i]```被设置了，并且对应的```temp_v[i >> 3]```的第```(1 << (i & 7))```bit被置位。（即对应的path是否置位）
    - 在temp_v中清除掉对应的path（将此bit位置0）
    https://blog.csdn.net/Chen_zju/article/details/80791268
  - 令```top_rated[i]->favored = 1;```然后```queued_favored```计数加一。
  - 如果当前的```top_rated[i]->was_fuzzed```为0 （没有被fuzz过） ，那么```pending_favored```计数加一。
- 接着扫描queue队列。
- 对每一项调用：```mark_as_redundant(q, !q->favored)```
- 若state设置了。
  - 尝试创建+打开：```out_dir/queue/.state/redundant_edges/q->fname```
- 否则删除对应的```out_dir/queue/.state/redundant_edges/q->fname```


### mark_as_redundant(struct queue_entry *q, u8 state)
- 如果当前```state == q->fs_redundant```，那么直接返回。
- 否则将```q->fs_redundan 标记为 state```

### write_stats_file(double bitmap_cvg, double stability, double eps)
- 创建or打开对应的：```out_dir/fuzzer_stats```
- 然后将一些状态信息写入。
```c
"start_time        : %llu\n"
               "last_update       : %llu\n"
               "fuzzer_pid        : %u\n"
               "cycles_done       : %llu\n"
               "execs_done        : %llu\n"
               "execs_per_sec     : %0.02f\n"
               "paths_total       : %u\n"
               "paths_favored     : %u\n"
               "paths_found       : %u\n"
               "paths_imported    : %u\n"
               "max_depth         : %u\n"
               "cur_path          : %u\n" /* Must match find_start_position() */
               "pending_favs      : %u\n"
               "pending_total     : %u\n"
               "variable_paths    : %u\n"
               "stability         : %0.02f%%\n"
               "bitmap_cvg        : %0.02f%%\n"
               "unique_crashes    : %llu\n"
               "unique_hangs      : %llu\n"
               "last_path         : %llu\n"
               "last_crash        : %llu\n"
               "last_hang         : %llu\n"
               "execs_since_crash : %llu\n"
               "exec_timeout      : %u\n" /* Must match find_timeout() */
               "afl_banner        : %s\n"
               "afl_version       : " VERSION "\n"
               "target_mode       : %s%s%s%s%s%s%s\n"
               "command_line      : %s\n"
               "slowest_exec_ms   : %llu\n",
```
# 附录
## 一些参数/名词
### GCC之fsanitize
https://wizardforcel.gitbooks.io/100-gcc-tips/content/address-sanitizer.html
gcc从4.8版本起，集成了Address Sanitizer工具，可以用来检查内存访问的错误（编译时指定“-fsanitize=address”）
### GCC之FORTIFY_SOURCE
https://gcc.gnu.org/legacy-ml/gcc-patches/2004-09/msg02055.html
### ASAN
AddressSanitizer (ASan) is a fast memory error detector based on compiler instrumentation (LLVM).
基于llvm的一个内存错误快速检测器。

## 一些函数/宏
### UR(u32 limit)
```c
/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit) {

    if (unlikely(!rand_cnt--)) {

        u32 seed[2];

        ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

        srandom(seed[0]);
        rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

    }

    return random() % limit;

}
```
### alloc_printf
```c
/* User-facing macro to sprintf() to a dynamically allocated buffer. */

#define alloc_printf(_str...) ({ \
    u8* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })
``` 
alloc_printf通过snprintf的一个小陷阱来做动态分配，说起来去年校赛好像学长还出了个snprintf的题（笑）。大概就是说，第一个snprintnf那里size=0，那么返回值此时是 “如果在理想情况下，字符串需要的长度”。相当于获取了一下length，接下来再通过获取的lenngth分配空间，然后二次调用snprintf把字符串放过去。

### strrchr
```char *strchr(const char *str, int c)``` 
该函数返回在字符串 str 中第一次出现字符 c 的位置，如果未找到该字符则返回 NULL。

### sigaction()
```int sigaction( int sig,const struct sigaction * act,struct sigaction * oact );```
Examine or specify the action associated with a signal。检查并指定对应信号的行为。

### access
https://blog.csdn.net/tigerjibo/article/details/11712039
成功执行时，返回0。失败返回-1，errno被设为以下的某个值 
```
EINVAL： 模式值无效 
EACCES： 文件或路径名中包含的目录不可访问 
ELOOP ： 解释路径名过程中存在太多的符号连接 
ENAMETOOLONG：路径名太长 
ENOENT：路径名中的目录不存在或是无效的符号连接 
ENOTDIR： 路径名中当作目录的组件并非目录 
EROFS： 文件系统只读 
EFAULT： 路径名指向可访问的空间外 
EIO：输入输出错误 
ENOMEM： 不能获取足够的内核内存 
ETXTBSY：对程序写入出错
```

### ck_read/ck_write
```c
/* Error-checking versions of read() and write() that call RPFATAL() as
   appropriate. */

#define ck_write(fd, buf, len, fn) do { \
    u32 _len = (len); \
    s32 _res = write(fd, buf, _len); \
    if (_res != _len) RPFATAL(_res, "Short write to %s", fn); \
  } while (0)

#define ck_read(fd, buf, len, fn) do { \
    u32 _len = (len); \
    s32 _res = read(fd, buf, _len); \
    if (_res != _len) RPFATAL(_res, "Short read from %s", fn); \
  } while (0)
```

### DMS
```c
/* Describe integer as memory size. */

static u8 *DMS(u64 val) {

    static u8 tmp[12][16];
    static u8 cur;

    cur = (cur + 1) % 12;

    /* 0-9999 */
    CHK_FORMAT(1, 10000, "%llu B", u64);

    /* 10.0k - 99.9k */
    CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

    /* 100k - 999k */
    CHK_FORMAT(1024, 1000, "%llu kB", u64);

    /* 1.00M - 9.99M */
    CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

    /* 10.0M - 99.9M */
    CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

    /* 100M - 999M */
    CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

    /* 1.00G - 9.99G */
    CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

    /* 10.0G - 99.9G */
    CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

    /* 100G - 999G */
    CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

    /* 1.00T - 9.99G */
    CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

    /* 10.0T - 99.9T */
    CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

    /* 100T+ */
    strcpy(tmp[cur], "infty");
    return tmp[cur];

}
```
## 一些结构体
### struct sigaction
```c
struct sigaction {
	void         (*sa_handler)(int);      /* address of signal handler */
	sigset_t     sa_mask;                 /* additional signals to block */
	int          sa_flags;                /* signal options */
	
	/* alternate signal handler */
	void         (*sa_sigaction)(int, siginfo_t *, void*);
};
 ```
The sigaction structure specifies how to handle a signal.
### struct queue_entry（entry in fuzz queue ）
```c
struct queue_entry {

    u8 *fname;                          /* File name for the test case      */
    u32 len;                            /* Input length                     */

    u8 cal_failed,                     /* Calibration failed?              */
    trim_done,                      /* Trimmed?                         */
    was_fuzzed,                     /* Had any fuzzing done yet?        */
    passed_det,                     /* Deterministic stages passed?     */
    has_new_cov,                    /* Triggers new coverage?           */
    var_behavior,                   /* Variable behavior?               */
    favored,                        /* Currently favored?               */
    fs_redundant;                   /* Marked as redundant in the fs?   */

    u32 bitmap_size,                    /* Number of bits set in bitmap     */
    exec_cksum;                     /* Checksum of the execution trace  */

    u64 exec_us,                        /* Execution time (us)              */
    handicap,                       /* Number of queue cycles behind    */
    depth;                          /* Path depth                       */

    u8 *trace_mini;                     /* Trace bytes, if kept             */
    u32 tc_ref;                         /* Trace bytes ref count            */

    struct queue_entry *next,           /* Next element, if any             */
    *next_100;       /* 100 elements ahead               */

};
 ```
### static struct extra_data
首先展示两个关键的static struct extra_data *
```c
static struct extra_data *extras;     /* Extra tokens to fuzz with        */
static u32 extras_cnt;                /* Total number of tokens read      */

static struct extra_data *a_extras;   /* Automatically selected extras    */
static u32 a_extras_cnt;              /* Total number of tokens available */
```
extra_data原型如下：
```c
struct extra_data {
    u8 *data;                           /* Dictionary token data            */
    u32 len;                            /* Dictionary token length          */
    u32 hit_cnt;                        /* Use count in the corpus          */
};
```
保存了一条token（语料）的值，大小，以及语料库中的使用次数。

# REF
[《100个gcc小技巧》](https://wizardforcel.gitbooks.io/100-gcc-tips/content/)
https://www.anquanke.com/post/id/201760#h2-4
http://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/s/sigaction_struct.html
https://chromium.googlesource.com/chromium/src/+/master/docs/asan.md
[AFL(American Fuzzy Lop)实现细节与文件变异](https://paper.seebug.org/496/#_2)
[Linux错误代码含义](https://blog.csdn.net/a8039974/article/details/25830705)
[AFL Reading Notes 2: Virgin Bits, Calibration and Queue Culling](https://mem2019.github.io/jekyll/update/2019/08/26/AFL-Fuzzer-Notes-2.html)