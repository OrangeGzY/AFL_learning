本篇文章是AFL源码阅读系列的最后一篇，在本篇之后就不会再专门大范围的聊AFL源码了，如果后续在实践过程中学习到了一些新的AFL使用/魔改技巧会出番外篇再分享～（茶）

本篇文章主要讲3个文件：
![](https://s3.ax1x.com/2021/02/09/yaccUU.png)
最好是看完上一篇再来看本篇。
# afl-clang-fast.c源码阅读
本文件作为clang的wrapper
## main
- 首先查找运行时libraries的位置。
- 然后编辑参数
- 使用```execvp(cc_params[0], (char**)cc_params)```执行clang
## find_obj(argv[0]) 
找运行时lib。
- 首先获取环境变量```"AFL_PATH"```为afl_path。
  - 如果存在，生成路径tmp：```tmp = alloc_printf("%s/afl-llvm-rt.o", afl_path)```
  - 判断是否有读取权限。
    - 若有，令```obj_path```为afl_path
    - return。
- 获取argv[0]的最后一个 ```/```的位置为slash。dir为argv[0]
  - 尝试读取目录：```alloc_printf("%s/afl-llvm-rt.o", dir)```
    - 若成功，则令```obj_path = dir```
- 否则尝试查找```AFL_PATH```宏指定的目录下是否有```afl-llvm-rt.o```
  - 如果找到了赋值:```obj_path = AFL_PATH```，return。

如果经历以上过程均没有找到，那么abort掉。
## edit_params(argc, argv)
本函数编辑参数数组。
- 首先判断如果我们用的是```afl-clang-fast++```
  - 设置cc_params[0]为环境变量```"AFL_CXX"```，如果环境变量为空，设置为```"clang++"```
- 否则设置cc_params[0]为环境变量```"AFL_CC"```，如果环境变量为空，设置为```"clang"```

***
接下来AFL提到了如下两种方式来进行插桩：
1.传统模式:使用```afl-llvm-pass.so```注入来插桩。
2.'trace-pc-guard' mode:使用原生的 ```LLVM instrumentation callbacks```


第二种方式相关链接如下：
https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards
***
- 如果我们使用方式2(```#ifdef USE_TRACE_PC```)
  - 若```#define __ANDROID__```依次向参数数组中添加：
    - ```"-fsanitize-coverage=trace-pc-guard```
    - ```"-mllvm"```(__ANDROID__)
    - ```"-sanitizer-coverage-block-threshold=0"```(__ANDROID__)
  - 否则添加：
    - ```"-fsanitize-coverage=trace-pc-guard```
    - ```"-Xclang"```
    - ```-load"```
    - ```"-Xclang"```
- 再补一个```"-Qunused-arguments"```
- 接下来扫描参数数组，设置对应的标志位
  ```c
      if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "armv7a-linux-androideabi")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-x")) x_set = 1;

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-Wl,-z,defs") ||
        !strcmp(cur, "-Wl,--no-undefined")) continue;
  ```

- 如果环境变量设置了```"AFL_HARDEN"```
  - 添加```"-fstack-protector-all"```
  - 如没有设置```"FORTIFY_SOURCE"```
    - 添加：```"-D_FORTIFY_SOURCE=2"```
  - 如果没有设置```"-fsanitize=memory"```
    - 首先尝试获取```"AFL_USE_ASAN"```
      - 若获取成功，满足互斥关系后添加：```"-U_FORTIFY_SOURCE"```、```"-fsanitize=address"```。
      - 否则尝试获取```"AFL_USE_MSAN"```满足互斥关系后添加：```"-U_FORTIFY_SOURCE"```、```"-fsanitize=memory"```

- 如果是使用的方式2进行插桩。判断是否设置```"AFL_INST_RATIO"```，若设置了则abort

- 接下来设置一些优化选项与对内置函数的检查。然后定义了两个宏，如下：

```c
-D__AFL_LOOP(_A)=
({ static volatile char *_B __attribute__((used));
_B = (char*)##SIG_AFL_PERSISTENT##; \
__attribute__((visibility("default")))int _L(unsigned int) __asm__("___afl_persistent_loop");
_L(_A); })
```

```c
-D__AFL_INIT()=
do { 
  static volatile char *_A __attribute__((used)); \
  _A = (char*)##SIG_AFL_DEFER_FORKSRV## ; \
__attribute__((visibility("default")))void _I(void) __asm__("___afl_manual_init"); \
_I(); } while (0)
```

- 如果x_set被设置了
  - 添加参数：```-x none```
- 如果非ANDROID
  - 根据不同的bit_mode来设置对应的```afl-llvm-rt```，并检查是否可读
    - 32位：```obj_path/afl-llvm-rt-32.o```
    - 64位：```obj_path/afl-llvm-rt-64.o```
    - 如果没有特别设置：```obj_path/afl-llvm-rt.o```

# afl-llvm-pass.so.cc源码阅读

快速了解llvm可以看一下：
https://zhuanlan.zhihu.com/p/122522485
https://llvm.org/docs/WritingAnLLVMPass.html#introduction-what-is-a-pass
在AFL中只有一个Pass：
```cpp
namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

  };

}
```
- 在AFLCoverage::runOnModule中进行如下操作。获取线程上下文。https://stackoverflow.com/questions/13184835/what-is-llvm-context
```cpp
 LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
```
- 如果```stderr```为终端。且未设置```"AFL_QUIET"```模式。输出对应的信息。
否则设置be_quiet = 1。
```cpp
  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;
```


- 设置插桩密度。
```cpp
/* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }
```
- 获取指向共享内存块shm的指针。
```cpp
GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
```
- 获取前一个桩的位置（随机数编号）
```cpp
GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
```

- 接下来进入插桩过程，扫描basic block：
```cpp
BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));
```
- 随机插桩（如果大于插桩密度）
```cpp
if (AFL_R(100) >= inst_ratio) continue;
```
- 生成当前block的随机编号
```cpp
      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc)
```
- 加载上一个block的编号。
```cpp
LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());
```
- 首先获取共享内存块的地址，然后找到对应当前桩的计数位置
```cpp
    /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc))
```
- 该地址上对应的桩计数器加一
```cpp
 LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
```
- 设置对应的```AFLPrevLoc```为```cur_loc >> 1```，关于为什么要右移1，主要是为了做路径区分，可以看上一篇。
```cpp
/* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
```
- 最后插桩计数加一：```inst_blocks++```
- 开始扫描下一个block
- 最后根据设置是否为quiet模式等。
  - 如果inst_blocks为0，说明没有插桩。
  - 否则输出各种信息。
  ```cpp
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);
  ```

整体的过程还是非常清晰的。
# afl-llvm-rt.o.c源码阅读
afl的llvmmode中有三个功能在这里实现。
## deferred instrumentation
AFL尝试通过仅执行目标二进制文件一次来优化性能，
在main（）之前停止它，然后克隆此“主”进程以获取
稳定提供fuzz目标。

尽管这种方法消除了许多OS，链接器和libc级别
执行程序的成本，它并不总是对二进制文件有帮助
执行其他耗时的初始化步骤-例如，解析大型配置
文件进入模糊数据。

在这种情况下，最好稍后再初始化forkserver
大多数初始化工作已经完成，但是在二进制尝试之前
读取模糊的输入并进行解析；在某些情况下，这可以提供10倍以上的收益
性能提升。

只需将：
```cpp
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
```
这一段插入对应位置即可。
具体可见上文的```-D__AFL_INIT()```宏
真正起作用的是如下：
```cpp
void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}
```
- 没有初始化，那么首先调用```__afl_map_shm()```设置共享内存。
- 然后调用```__afl_start_forkserver()```起forkserver。
- 最后设置为已经初始化。

```c
/* SHM setup. */

static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);//通过环境变量读取id

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {                   //如果读取成功

    u32 shm_id = atoi(id_str);    

    __afl_area_ptr = shmat(shm_id, NULL, 0);//获取shm的地址为__afl_area_ptr

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;                  //设置__afl_area_ptr[0]为1

  }

}
```
接下来是__afl_start_forkserver()
```cpp
static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return; //向状态管道写入4字节告知已启动

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */
    /* 当子进程超时，父进程会kill掉子进程 */
    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    /* 如果在persistent mode下，且子进程已经被killed */
    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {       //如果子进程真的彻底结束了

      /* Once woken up, create a clone of our process. */
      //重新fork一次
      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */
      //如果是fork出的子进程
      if (!child_pid) {

        close(FORKSRV_FD);        //关闭对应描述符。然后返回执行真正的程序
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      /* 如果子进程并非彻底结束而是暂停 */
      /* 重新启动这个暂停的子进程 */
      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    //在父进程（fork-server）中，向afl-fuzzer写4字节（子进程pid）到管道，告知fuzzer
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);
    //读取子进程退出状态
    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */
    //子进程收到停止信号，此时子进程可能是停止或结束。
    if (WIFSTOPPED(status)) child_stopped = 1;  //child_stopped=1则不确定究竟是否彻底结束

  
    //向状态管道写入4字节
    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}
```

## persistent mode
一些库提供的API是无状态的，或者可以在其中重置状态的API
处理不同的输入文件之间。进行此类重置后，
一个长期存在的过程可以重复使用，以尝试多个测试用例，
消除了重复执行fork（）调用的需求以及相关的OS开销。

基本结构如下：
```cpp
  while (__AFL_LOOP(1000)) {

    /* Read input data. */
    /* Call library code to be fuzzed. */
    /* Reset state. */

  }
```
关于循环的最大数量，循环内指定的数值控制AFL从头重新启动过程之前的最大迭代次数。这样可以最大程度地减少内存泄漏和类似故障的影响；1000是一个很好的起点，而更高的值会增加出现hiccups的可能性，而不会给带来任何实际的性能优势。

```__AFL_LOOP()```和```__AFL_INIT()```相似。也是由宏来定义。可见上文的：```-D__AFL_LOOP(_A)```
真正起作用的是```__afl_persistent_loop```
```cpp
/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {
  static u8  first_pass = 1;
  static u32 cycle_cnt;
  if (first_pass) {
    if (is_persistent) {
      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }
    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;
  }
  if (is_persistent) {
    if (--cycle_cnt) {
      raise(SIGSTOP);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
      return 1;
    } else {
      __afl_area_ptr = __afl_area_initial;
    }
  }
  return 0;
}
 ```
- 如果是第一次执行那么```first_pass = 1```
  - 如果处于persistent mode下。
    - 清空```__afl_area_ptr```。
    - 然后令```__afl_area_ptr[0] = 1```
    - 令```__afl_prev_loc = 0```
  - 设置循环次数```cycle_cnt```为```max_cnt```
  - 设置```first_pass = 0```初次循环已经结束。return 1.
- 如果在persistent mode下，且--cycle_cnt大于1。
  - 发出信号```SIGSTOP```暂停当前进程。
  - 设置```__afl_area_ptr[0] = 1```与```__afl_prev_loc = 0```
  - return 1
- 如果在persistent mode下，且--cycle_cnt为0
  - 让```__afl_area_ptr```指向```__afl_area_initial``` 
- 最后return 0

整体过程大致如下：
当第一次运行到__AFL_LOOP 时，进行初始化然后return 1，此时满足```while (__AFL_LOOP(1000))```，于是执行一次fuzz。

当我们再次进入fuzz loop时，计数减1，触发：```raise(SIGSTOP)```暂停进程，而forkserver收到了此时的暂停信号，设置```child_stopped = 1```，通知afl-fuzzer。

当afl-fuzzer再进行一次fuzz时，恢复之前的子进程继续执行，并设置child_stopped为0。

此时相当于重新执行了一遍程序，重新对__afl_prev_loc设置，随后直接返回1，此时又进入```while (__AFL_LOOP(1000))```执行一次，接下来下一次触发```raise(SIGSTOP)```暂停进程。

- 以上的步骤重复执行，直到第1000次，cnt被减到0，不会再暂停子进程，而是令```__afl_area_ptr```指向无关的```__afl_area_initial``` ，随后子进程结束。指向一个无关值主要是因为程序仍然会进行插桩，导致向```__afl_area_ptr```中写值。我们选择向一个无关的位置写值而不影响到共享内存等。


## trace-pc-guard mode
https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards
如果想使用这个功能需要设置：
```
AFL_TRACE_PC=1
```
传入：```With -fsanitize-coverage=trace-pc-guard``` 
*the compiler will insert the following code on every edge*
然后重新编译。

```cpp
/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}
```
此函数```__sanitizer_cov_trace_pc_guard```将在每个basic block edge（边界）被调用，其实就是通过（*guard）索引到共享内存对应的计数位置，然后计数加一。

而guard的初始化如下：
```cpp
/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}
```
首先获取了插桩密度。

然后从第一个guard遍历。llvm设置guard的收尾为start与stop。并设置guard指向的值。

注意有一定的概率不进行插桩（随机插桩）。

特别的，若此时的basic block因为概率选择的原因没有进行插桩，那么设置这里的guard指向的值为0，这里的0是作为一个特殊值，代表不进行插桩。


```cpp
*(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }
```