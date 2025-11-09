---
layout: post
title:  "[MSG CTF 2025] Format Sniper Revenge write-up"
date:   2025-11-09 21:00:20 +0900
categories: [ctf]
toc: true
---

# introduction
---
`MSG CTF 2025`에서 약 1년 전에 만들어둔 문제를 드디어 출제하게 되었습니다  
이 문제는 당시 [Xion](https://x.com/0x10n)님이 VRP 포상금을 전액 기부하셨다는 기사를 보고 영감을 받아 일종의 팬심(?)으로 과거 dreamhack 워게임 사이트에 출제하셨던 [Format sniper](https://dreamhack.io/wargame/challenges/281)문제의 Revenge문제를 만들어보았습니다  

# binary analysis
---
## Launcher
```c++
// Launcher binary
int __fastcall main()
{
  const char *envp[2]; // [rsp+20h] [rbp-30h] BYREF
  const char *argv[3]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);

  argv[0] = "./ld-linux-x86-64.so.2";
  argv[1] = "./format-sniper_revenge";
  argv[2] = 0LL;

  envp[0] = "LD_PRELOAD=./libc.so.6";
  envp[1] = 0LL;
  execve("./ld-linux-x86-64.so.2", argv, envp);
  return 0;
}
```
해당 문제는 `Launcher`를 통해 문제 바이너리(`format-sniper_revenge`)를 실행시킵니다
## format-sniper_revenge
```c++
// format-sniper_revenge binary

/* 
.init_array:0000000000003D68 _init_array     segment qword public 'DATA' use64
.init_array:0000000000003D68                 assume cs:_init_array
.init_array:0000000000003D68                 ;org 3D68h
.init_array:0000000000003D68 __frame_dummy_init_array_entry dq offset frame_dummy
.init_array:0000000000003D68                                         ; DATA XREF: LOAD:0000000000000168↑o
.init_array:0000000000003D68                                         ; LOAD:00000000000002F0↑o
.init_array:0000000000003D70                 dq offset sandbox       ; ** sandbox funciton **
.init_array:0000000000003D70 _init_array     ends
*/

int sandbox()
{
  int result; // eax

  result = flag;
  if ( !flag )
  {
    initialize();
    result = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
    flag = 1;
  }
  return result;
}

int initialize()
{
  int fd; // [rsp+Ch] [rbp-4h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  unsetenv("LD_PRELOAD");
  puts("inspired by xion's format-sniper");
  fd = open("/dev/null", 1);
  dup2(fd, 1);
  dup2(fd, 2);
  return close(fd);
}

int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  fgets(format, 1024, stdin);
  printf(format);
  exit(0);
}
```
`format-sniper_revenge` 바이너리에서는 `format sniper`문제와 유사하지만 `seccomp strict mode`를 추가하였고 기존에 `ROP`가 가능했던 부분도 제거하여 존재하는 풀이를 통해 `exploit` 불가능하도록 하였습니다

그래서 `Revenge`문제에서 `Exploit`을 할때 고려해야하는 점들은 아래와 같습니다
- full mitigation
- can't print out data through fsb (stdout, stderr redirected to `/dev/null`)
- seccomp strict mode (only open, read, write syscall is allowed)
- Eliminate the ROP possibility that existed in the original challenge


# exploitation
---
## Setting infinite fsb state
```plaintext
.text:0000000000001351 ; int __fastcall main(int argc, const char **argv, const char **envp)
.text:0000000000001351 public main
.text:0000000000001351 main proc near
.text:0000000000001351 ; __unwind {
.text:0000000000001351 endbr64
.text:0000000000001355 push    rbp
.text:0000000000001356 mov     rbp, rsp
.text:0000000000001359 mov     rax, cs:stdin@GLIBC_2_2_5
.text:0000000000001360 mov     rdx, rax        ; stream
.text:0000000000001363 mov     esi, 400h       ; n
.text:0000000000001368 lea     rax, format
.text:000000000000136F mov     rdi, rax        ; s
.text:0000000000001372 call    _fgets
.text:0000000000001377 lea     rax, format
.text:000000000000137E mov     rdi, rax        ; format
.text:0000000000001381 mov     eax, 0
.text:0000000000001386 call    _printf
.text:000000000000138B mov     edi, 0          ; status
.text:0000000000001390 call    _exit
.text:0000000000001390 ; } // starts at 1351
.text:0000000000001390 main endp
```
우선 1번의 `fsb`를 통해 `exploit`을 수행하는 것은 매우 어렵기 때문에 연속적으로 `fsb`를 트리거를 할 수 있는 상태를 만들어줘야합니다  

<center><img src='/assets/CTF-FormatSniper_Revenge/ret_to_main.png' width="800" height="500"></center>
`printf`를 호출한 뒤 바로 `exit` 함수가 호출되기 때문에 `main`함수의 return주소를 건드리는 것은 무의미하며 `exit`함수 호출 전인 `printf`의 ret를 `main`함수 등으로 조작할 경우 연속적으로 `fsb`를 트리거할 수 있습니다

### corrupting stack data
`printf`함수의 ret주소를 변조하면 연속적으로 `fsb`를 트리거할 수 있다는 것을 알았지만 `.bss`에서 `user input`을 받고 릭 또한 못한 상태기 떄문에 스택에 포인터를 쓰고 `aaw`를 하지는 못합니다  
하지만 **`%n`형식자를 통해 스택에 존재하는 포인터**에는 여전히 접근이 가능합니다  

<center><img src='/assets/CTF-FormatSniper_Revenge/printf_stack.png' width="800" height="500"></center>

`stack`에는 위 사진과 같이 스택 내에 스택을 가리키는 스택 포인터가 존재합니다
해당 스택 포인터를 부분적으로 덮어 스택 포인터를 `printf ret`로 옮기게 되면 `return address`를 변조할 수 있습니다
> DSFSB(Double Stage Format String Bug)이라는 명칭으로 이 방법에 대해 상세히 다루는 글들이 많아 여기서는 생략하겠습니다

### ASLR bypass via "*"
`%n`형식자를 통해 스택에 존재하는 포인터에 값을 쓸 수는 있지만 `double stack pointer`를 `printf ret` 위치로 포인터를 옮기기 위해서는 스택 주소를 알아야합니다  
```c++
#include <stdio.h>

int main() {

  printf("%d%d%d%d%d%d%d%d%d%d%*d\n", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);

}
```
`printf`에는 `width`또는 `precision`값을 인자로 받아올 수 있으며 이때 `*`가 사용됩니다

<center>
  <img src="/assets/CTF-FormatSniper_Revenge/printf_test.png"
       style="width:50px; !important; height:30px !important;">
</center>

위 사진은 위 코드의 실행 결과로 `*`가 11번째 인자를 가져와 총 11칸 공간을 확보하는 것을 확인할 수 있습니다
이를 통해 스택 포인터 하나를 `printf`의 `return address`로 바꿔 연속적으로 `fsb`를 트리거할 수 있습니다

### corrputing the stack with double stack pointer
<center><img src='/assets/CTF-FormatSniper_Revenge/create_second_pointer.png' width="800" height="500"></center>

이 문제의 경우 스택을 확인해보면 위 사진처럼 1개의 `double stack pointer`만이 존재합니다
하지만 `return address`를 조작하며 스택에 있는 데이터들을 조작하기 위해서는 추가적인 포인터가 필요합니다

<center><img src='/assets/CTF-FormatSniper_Revenge/init_stack.png' width="400" height="500"></center>

그림을 통해 어떤식으로 `double stack pointer`를 통해 스택 내 다른 스택 포인터를 `printf ret`를 가리키는 포인터로 조작하고 `printf ret`를 `main`으로 변조하였는지 설명하겠습니다

<center><img src='/assets/CTF-FormatSniper_Revenge/stack_change1.png' width="400" height="500"></center>

먼저 `%*c`를 통해 `+0x30` 오프셋의 스택 포인터 하위 4byte를 참조하여 `+0x48`포인터를 부분적 변조하여 `+0x108`를 가리키도록합니다

<center><img src='/assets/CTF-FormatSniper_Revenge/stack_change2.png' width="400" height="500"></center>

`printf`에서 참조하고자하는 인덱스는 2가지 방법으로 접근이 가능합니다
1. `%c`의 반복으로 접근
2. `$`를 사용하여 접근

먼저 `%c`를 통해 해당 `+0x118`오프셋에 접근하여 `+0x108`오프셋에 있는 스택 포인터를 `printf ret`로 조작합니다

<center><img src='/assets/CTF-FormatSniper_Revenge/stack_change3.png' width="400" height="500"></center>

마지막으로 조작한 `+0x108`오프셋에 있는 `printf ret`포인터를 `$`를 통해 접근하여 `printf ret`를 조작해줍니다
이렇게되면 `printf ret`를 가리키는 포인터가 하나 존재하고 추가로 기존 `double stack pointer A`를 재사용하여 스택을 조작할 수 있습니다


위 과정들을 통해 연속적으로 `FSB`를 트리거해 스택을 조작할 수 있는 상태가 되었습니다  
`seccomop`이 `strict mode`로 설정되어있고 `stdout`을 `/dev/null`로 `redirect` 되어있다는 점을 고려해 `exploit`시나리오는 아래와 같습니다

1. 안정성이 보장된 위치에 `rop chain`을 구성한다
2. `rop chain`에서는 `open`, `read`를 통해 플래그를 읽고 `time-base side channel attack`으로 플래그를 릭한다


## stage1 ROP
먼저 **안정성이 보장된 위치**에 `ROP`를 구성하기 위한 상태를 만들어줘야합니다
`*`를 사용해 `rop`를 구성할때 하위 4byte만들 컨트롤할 수 있어 연속적인 포인터가 있는 위치여야합니다
생각해볼 수 있는 곳은 `libc`의 `got` 또는 `main arena`일껍니다
우선 2가지 방법을 모두 플래그를 릭하는데 노이즈가 발생하여 완벽하게 릭을 하는데 어려움이 존재합니다

그래서 `main`함수의 스택 프레임에 `rop`를 구성**하기로 하였습니다

<center><img src='/assets/CTF-FormatSniper_Revenge/stage1_rop_stack.png' width="600" height="500"></center>

`printf ret`를 `main`함수 대신 `start`함수로 조작해 분기하면서 스택을 증가 시켜 추가적인 값들을 확보할 수 있습니다
위 사진은 `start`함수로 2번 분기한 스택 상태이며 값들을 잘 조작하면 원하는 함수를 호출한 뒤 `main`으로 되돌아가는 `rop`를 구성할 수 있습니다

<center><img src='/assets/CTF-FormatSniper_Revenge/stage1_rop_field.png' width="800" height="500"></center>

최종적으로 구성하고 싶은 `ROP chain`은 `open`, `read`, 플래그 검사 후 다시 `main`으로 복귀하는 `rop`이기 때문에 스택에 많은 `libc`포인터가 필요합니다

<center><img src='/assets/CTF-FormatSniper_Revenge/stage1_rop_result.png' width="550" height="600"></center>

그래서 `stage1 rop`에서는 `memcpy`를 호출해 스택에 `libc`의 `got`를 복사해 최종 `rop`를 작성하기 위한 스택 상태를 만들어줍니다
위 사진이 `stage1 rop`에서 `memcpy`를 통해 `libc`의 `got` 주소들을 스택으로 복사한 뒤의 스택 상태입니다

## stage2 ROP
`stage1 rop`를 통해 스택에 `libc`주소를 spray되었기 때문에 `double stack pointer`를 통해 편하게 `rop`를 구성해주면 됩니다

> `ROP chain`을 구성하고 재검사하는 과정에서 `ROP chain`을 재사용하여 플래그를 릭하는 시간을 줄일 수 있는 방법이 존재하는데 이는 추후에 내용을 추가하겠습니다

### exploit code repo
- [https://github.com/p05wn/CTF/tree/main/MSG2025/pwn-Format_Sniper_Revenge](https://github.com/p05wn/CTF/tree/main/MSG2025/pwn-Format_Sniper_Revenge)
