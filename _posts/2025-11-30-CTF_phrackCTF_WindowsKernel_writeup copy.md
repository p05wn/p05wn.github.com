---
layout: post
title:  "[phrack CTF 2025] Windows Kernel Challenge write-up"
date:   2025-11-30 23:32:07 +0900
categories: [ctf, Windows]
tags: [CTF, pwnable, Windows, Exploitation]
fullview: false
comments: true
toc: true
#description: "pwn challenge i made last year and released on MSG CTF 2025"

---

저번 추석연휴 동안 `Phrack 40th Anniversary CTF Challenge`에 출제된 `Windows Kernel`문제를 풀어봤습니다.    
공개된 `write-up`이 없기도하고 공식적인(?)방식 외의 풀이도 가능하여 이 두방식에 대한 `write-up`을 작성해볼까합니다.  
풀이에서 언급하는 모든 함수, 변수, 구조체명은 임의로 설정하였습니다.

제가 풀이한 방식에는 플래그를 릭하는 방법과 `LPE` 방법이 존재합니다.  
`write-up`작성은 플래그를 릭 풀이 -> LPE 풀이 순으로 진행됩니다
> challenge github repo: [https://github.com/xforcered/PhrackCTF](https://github.com/xforcered/PhrackCTF)


## Given File
- AVeryNormalDriver.sys

## Test Environment
- Windows 11 24H2 26100.4652 (leak flag solution)
- Windows 11 24H2 26100.6725 (token stealing solution)



# Binary Analysis
---
제공되는 문제 드라이버는 `DeviceIoControl` 그리고 `MDL`을 통해 `Usermode process`와 통신합니다

## DriverEntry
```c
__int64 __fastcall DriverEntry(PDRIVER_OBJECT DriverObject)
{

  ...

  KeInitializeSpinLock(&SpinLock);
  DriverObject->DriverUnload = MU_UNLOAD;
  DriverObject->MajorFunction[IRP_MJ_CREATE] = MJ_FUNC;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = MJ_FUNC;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MJ_DEVICECONTROL;
  DriverObject->MajorFunction[IRP_MJ_CLEANUP] = MJ_CLEANUP;
  RtlInitUnicodeString(&DestinationString, L"\\Device\\VeryNormalDriver");
  v2 = IoCreateDevice(DriverObject, 0x10u, &DestinationString, 0x22u, 0, 1u, &DeviceObject);// DeviceExtensionSize: 0x10
  if ( v2 >= 0 )
  {
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\VeryNormalDriver");
    v2 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
    if ( v2 >= 0 )
    {
      GlobalBufferPointer = ExAllocatePool2(0x40LL, 0x1000LL, 'VndP');// POOL_FLAG_NON_PAGED
      if ( GlobalBufferPointer )
      {
        DeviceExtension = DeviceObject->DeviceExtension;
        DeviceObject->Flags |= 4u;
        DeviceExtension->prev = DeviceExtension;
        DeviceExtension->next = DeviceExtension;
      }
      else
      {
        return 0xC000009A;
      }
    }
    else
    {
      IoDeleteDevice(DeviceObject);
    }
  }
  return v2;
}
```
`DriverEntry`에서는 따로 특이한 동작은 없지만 `MDL`과의 읽고쓰기 그리고 `flag` 값이 저장될 `GlobalBuffer`를 할당 받습니다.  
추가로 `DeviceExtension`은 `double-linked list`로 `user context`를 저장합니다.  
해당 드라이버에 존재하는 `DeviceIoControl code`는 아래와 같습니다.  

## DeviceIoControl code
```plaintext
0x80002000 : Create context
0x80002004 : Free MDL
0x80002008 : Allocate MDL
0x8000200C : Write to Global Buffer
0x80002010 : Read From Global Buffer
0x80002014 : read flag
```

## Create context (IOCTL: 0x80002000)
```c++
__int64 __fastcall AllocateProcessContext(_DEVICE_OBJECT *DeviceObject, _IRP *Irp)
{
  
  ...

  v4 = KeAcquireSpinLockRaiseToDpc(&SpinLock);
  SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
  status = 0;
  DeviceExtension = DeviceObject->DeviceExtension;
  if ( !SystemBuffer )
    goto Error;
  InputBufferLength = Irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.InputBufferLength;
  if ( InputBufferLength < 0x10 )
  {
    status = 0xC0000023;
    goto Return;
  }
  len = SystemBuffer->BufferLen;
  if ( len <= InputBufferLength - 0x10 && len + 0x38 >= len )
  {
    _mm_lfence();
    NwCtx = ExAllocatePool2(0x40LL, len + 0x38, 'VndP');
    if ( NwCtx )
    {
      CurrentProcessId = PsGetCurrentProcessId();
      NwCtx->DataLen = len;
      NwCtx->CurrentProcessId = CurrentProcessId;
      memmove(NwCtx->data, &SystemBuffer->data, len);
      ctx = GetProcessContext(DeviceObject);

      if ( ctx )
      {
        // if there's existing context then only copys the data
        _mm_lfence();
        DataLen = ctx->DataLen;
        if ( len <= DataLen )
          DataLen = len;
        memmove(ctx->data, NwCtx->data, DataLen);
        ExFreePoolWithTag(NwCtx, 0);
      }
      else
      {
        // New context link routine
        NwCtx->EnableFlag = 1;
        LastCtx = DeviceExtension->CtxList.Blink;
        if ( LastCtx->CtxList.Flink != DeviceExtension )
          __fastfail(3u);

        NwCtx->CtxList.Flink = &DeviceExtension->CtxList;
        NwCtx->CtxList.Blink = &LastCtx->CtxList;
        LastCtx->CtxList.Flink = &NwCtx->CtxList;
        DeviceExtension->CtxList.Blink = &NwCtx->CtxList;
      }
    }
    else
    {
      status = 0xC000009A;
    }
  }
  else
  {
Error:
    status = 0xC000000D;
  }
Return:
  KeReleaseSpinLock(&SpinLock, v4);
  return status;
}
```
`ioctl 0x80002000`code에 대한 처리는 `AllocateProcessContext`함수에서 수행합니다.  
```c++
00000000 struct __unaligned __declspec(align(8)) context // sizeof=0x38;variable_size
00000000 {
00000000     _LIST_ENTRY CtxList;
00000010     _QWORD CurrentProcessId;
00000018     _BYTE EnableFlag;
00000019     _BYTE ReadFlag;
0000001A     _BYTE gap1A[6];
00000020     struct _MDL *Mdl;
00000028     _QWORD MappedAddr;
00000030     _DWORD DataLen;
00000034     char data[];
00000034     // padding byte
00000035     // padding byte
00000036     // padding byte
00000037     // padding byte
00000038 };
```
해당 함수에서는 `process` 당 하나의 `ctx`를 생성하고 이미 존재할 경우 `data`만을 새로 갱신합니다.  
생성된 `ctx`는 `DeviceExtension`에 있는 `CtxList`를 통해 `double linked-list`로 관리됩니다.

```c++
context *__fastcall GetProcessContext(_DEVICE_OBJECT *DeviceObject)
{
  HANDLE CurrentProcessId; // rax MAPDST
  DeviceExtension *DeviceExtension; // rdx
  context *result; // rax
  context *ctx; // rcx

  CurrentProcessId = PsGetCurrentProcessId();
  DeviceExtension = DeviceObject->DeviceExtension;
  result = 0LL;
  ctx = DeviceExtension->CtxList.Flink;
  if ( DeviceExtension->CtxList.Flink )
  {
    // loop all the ctx list
    while ( ctx != DeviceExtension )
    {
      if ( ctx->CurrentProcessId == CurrentProcessId )
      {
        result = ctx;
        break;
      }
      ctx = ctx->CtxList.Flink;
      if ( !ctx )
        return result;
    }
  }
  if ( result )
    return (-(result->EnableFlag != 0) & result);
  return result;
}
```
다른 `DeviceIoControl`을 처리하는 루틴에서는 가장 먼저 `GetProcessContext`함수를 호출해 `CurrentProcessId`에 해당하는 `ctx`를 찾습니다.  


## Handling MDL
MDL은 `ioctl code` `0x80002008`과 `0x80002004`을 통해 할당/해제를 수행합니다.  
```c++
// ioctl 0x80002008
__int64 __fastcall AllocateMdl(_DEVICE_OBJECT *DeviceObject, _IRP *Irp)
{
  unsigned int status; // edi
  KIRQL v5; // r14
  context *ctx; // rbx
  struct _MDL *NewMdl; // rsi
  struct _MDL *mdl; // rcx
  PVOID v9; // rax

  status = 0xC0000001;
  v5 = KeAcquireSpinLockRaiseToDpc(&SpinLock);
  if ( Irp->AssociatedIrp.SystemBuffer )
  {
    ctx = GetProcessContext(DeviceObject);
    if ( ctx )
    {
      if ( Irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.InputBufferLength >= 0x10 )
      {
        NewMdl = IoAllocateMdl(*Irp->AssociatedIrp.SystemBuffer, 0x1000u, 0, 0, 0LL);
        if ( NewMdl )
        {
          mdl = ctx->Mdl;
          if ( mdl )
          {
            MmUnlockPages(mdl);
            IoFreeMdl(ctx->Mdl);
          }
          MmProbeAndLockPages(NewMdl, 1, IoModifyAccess);
          ctx->Mdl = NewMdl;
          v9 = MmMapLockedPagesSpecifyCache(NewMdl, 0, MmNonCached, 0LL, 0, 0x10u);
          ctx->MappedAddr = v9;
          if ( v9 )
            status = 0;
  
  ...

}
```
```c++
// ioctl 0x80002004
__int64 __fastcall FreeMdl(_DEVICE_OBJECT *DeviceObject)
{
  unsigned int status; // edi
  KIRQL code; // si
  context *ctx; // rax MAPDST
  struct _MDL *Mdl; // rcx

  status = 0xC0000001;
  code = KeAcquireSpinLockRaiseToDpc(&SpinLock);
  ctx = GetProcessContext(DeviceObject);
  if ( ctx )
  {
    Mdl = ctx->Mdl;
    if ( Mdl )
    {
      MmUnlockPages(Mdl);
      IoFreeMdl(ctx->Mdl);
    }
    ctx->EnableFlag = 0;
    status = 0;
  }
  KeReleaseSpinLock(&SpinLock, code);
  return status;
}
```
## read/write GlobalBuffer
```c++
// ioctl : 0x8000200C
__int64 __fastcall WriteToGlobalBuffer(_DEVICE_OBJECT *DeviceObject)
{
  KIRQL v2; // di
  context *ctx; // rax
  unsigned int status; // ebx
  const void *MappedAddr; // rdx

  v2 = KeAcquireSpinLockRaiseToDpc(&SpinLock);
  ctx = GetProcessContext(DeviceObject);
  status = 0;
  if ( ctx )
  {
    MappedAddr = ctx->MappedAddr;
    if ( MappedAddr )
      memmove(GlobalBufferPointer, MappedAddr, 0x1000uLL);
    else
      status = 0xC0000184;
  }
  else
  {
    status = 0xC0000272;
  }
  KeReleaseSpinLock(&SpinLock, v2);
  return status;
}
```
```c++
// 0x80002010
__int64 __fastcall ReadFromGlobalBuffer(_DEVICE_OBJECT *a1)
{
  KIRQL v2; // di
  context *ProcessContext; // rax
  unsigned int status; // ebx
  void *MappedAddr; // rcx

  v2 = KeAcquireSpinLockRaiseToDpc(&SpinLock);
  ProcessContext = GetProcessContext(a1);
  status = 0;
  if ( ProcessContext )
  {
    MappedAddr = ProcessContext->MappedAddr;
    if ( MappedAddr )
      memmove(MappedAddr, GlobalBufferPointer, 0x1000uLL);
    else
      status = 0xC0000184;
  }
  else
  {
    status = 0xC0000272;
  }
  KeReleaseSpinLock(&SpinLock, v2);
  return status;
}
```
`MDL`을 설정한 뒤 해당 버퍼를 통해 `GlobalBUffer`에 값을 읽고 쓰기가 가능합니다
- 0x80002010 : `GlobalBuffer` 데이터 읽기
- 0x8000200C : `GlobalBuffer`에 데이터 쓰기

# Vulnerability
---
```c++
__int64 __fastcall MJ_CLEANUP(_DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
  ...

  CurrentProcessId = PsGetCurrentProcessId();
  v5 = KeAcquireSpinLockRaiseToDpc(&SpinLock);
  DeviceExtension = DeviceObject->DeviceExtension;

  for ( ctx = DeviceExtension->next; ctx && ctx != DeviceExtension; ctx = ctx->next )
  {
    if ( ctx->CurrentProcessId == CurrentProcessId )
    {

      if ( !ctx->EnableFlag )
        goto unlink;

      MemoryDescriptorList = ctx->Mdl;
      if ( MemoryDescriptorList )
      {
        MmUnlockPages(MemoryDescriptorList);
        IoFreeMdl(ctx->Mdl);
      }

      // unlink from list
      if ( !ctx->DataLen || ctx->data[0] != 'p' )
      {
unlink:
        next = ctx->next;
        if ( ctx->next->prev != ctx || (prev = ctx->prev, prev->next != ctx) )
          __fastfail(3u);
        prev->next = next;
        next->prev = prev;
      }

      ExFreePoolWithTag(ctx, 0);
      break;
    }
  }
  KeReleaseSpinLock(&SpinLock, v5);
  Irp->IoStatus.Status = 0;
  IofCompleteRequest(Irp, 0);
  return 0LL;
}
```
취약점은 `MJ_CLEANUP`루틴에서 발생합니다.  
생성된 `context`을 해제하는 루틴에서 아래 조건들이 맞을 경우 
- `ctx->EnableFlag` 설정
- `ctx->DataLen` != 0
-  `ctx->data[0]` == `'p'`  

`ctx`를 `ctx list`에서 `unlink`하는 과정이 생략된채로 `ctx`를 해제하고 이를 통해 `ctx list`에 `dangling pointer`가 남습니다.  
`non-paged pool spray`를 통해 `target ctx`를 변조할 때 `CurrentProcessId`필드를 현재 프로세스로 맞춰줄 경우  
새로운 핸들을 열어 변조된 `target ctx`에 접근할 수 있습니다.


# Exploitation (Flag Leak Solution)
---
```c++
__int64 __fastcall ReadFlag(_DEVICE_OBJECT *DeviceObject)
{

  ...

  if ( ctx )
  {
    if ( ctx->ReadFlag )
    {
      RtlInitUnicodeString(&DestinationString, L"\\??\\C:\\Secrets\\flag.txt");
      ObjectAttributes.RootDirectory = 0LL;
      ObjectAttributes.ObjectName = &DestinationString;
      ObjectAttributes.Length = 0x30;
      ObjectAttributes.Attributes = 0x240;
      *&ObjectAttributes.SecurityDescriptor = 0LL;
      status = ZwCreateFile(
                 &FileHandle,
                 0x80000000,
                 &ObjectAttributes,
                 &IoStatusBlock,
                 0LL,
                 0x80u,
                 1u,
                 1u,
                 0x60u,
                 0LL,
                 0);
      if ( status >= 0 )
      {
        status = ZwReadFile(FileHandle, 0LL, 0LL, 0LL, &IoStatusBlock, Buffer, 36u, 0LL, 0LL);
        if ( status >= 0 )
        {
          if ( IoStatusBlock.Information == 0x24 )
          {
            pSrc = GlobalBufferPointer;
            status = 0;
            *GlobalBufferPointer = *Buffer;
            *(pSrc + 1) = *&Buffer[16];
            *(pSrc + 8) = *&Buffer[32];
            pSrc[36] = Buffer[36];
          }
          else
          {
            status = 0xC00000E9;
          }
        }
      }
    }
    else
    {
      status = 0xC0000022;
    }
  }
  else
  {
    status = 0xC0000272;
  }
  if ( FileHandle )
    ZwClose(FileHandle);
  return status;
}
```
`flag`를 릭하는 풀이는 간단합니다.  
`readflag`함수에서 `ctx->ReadFlag`(offset: 0x19)값을 설정되어있을 경우 `flag`를 읽어낼 수 있어 `Global Buffer`로 읽어드릴 수 있습니다.  
하지만 해당 필드는 정상적인 방법으로는 설정하는 방법이 존재하지 않고 `CLEANUP`루틴에서 `dangling pointer`를 만들고 `spray`를 통해 변조하는 방식으로 해당 필드를 활성화 할 수 있습니다.  

## Screenshot
<center><img src='/assets/CTF_phrackCTF_WindowsKernel_writeup/flag_leak_screenshot.png' width=auto height=auto></center>

# Exploitation (Token Stealing Solution)
---

## leak nt base
### gaining AAR
```c++
__int64 __fastcall AllocateProcessContext(_DEVICE_OBJECT *DeviceObject, _IRP *Irp)
{
  ...

  len = SystemBuffer->BufferLen;
  if ( len <= InputBufferLength - 0x10 && len + 0x38 >= len )
  {
    _mm_lfence();
    NwCtx = ExAllocatePool2(0x40LL, len + 0x38, 'VndP');
    if ( NwCtx )
    {
      CurrentProcessId = PsGetCurrentProcessId();
      NwCtx->DataLen = len;
      NwCtx->CurrentProcessId = CurrentProcessId;
      memmove(NwCtx->data, &SystemBuffer->data, len);
      ctx = GetProcessContext(DeviceObject);

      if ( ctx )
      {
        // if there's existing context then only copys the data
        _mm_lfence();
        DataLen = ctx->DataLen;
        if ( len <= DataLen ) // ***
          DataLen = len;
        memmove(ctx->data, NwCtx->data, DataLen);
        ExFreePoolWithTag(NwCtx, 0);
      }
    ...
```
`CLEANUP`루틴에서 `dangling pointer`를 만들고 `ReadFlag`에 값을 설정할 수도 있지만 이를 `ctx->DataLen`필드를 조작하여 기존 값보다 크게 줄 경우 `pool overflow`를 발생시킬 수 있습니다.
이걸 가지고 유명한 [non-paged pool exploitation](https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation)글을 참고하여 `Named-pipe`를 가지고 `AAR`을 달성하였습니다.  

### leak nt base in 24h2 LFH
`Windows11 24H2`에서 `Windows LFH`에 사용되는 구조체들이 조금씩 변했다는 것을 확인했습니다.  
분석과정에서 미세하게 바뀐 `LFH`구조에서 `_HEAP_LFH_CONTEXT`까지 접근하여 `ntbase`를 릭하는게 가능하다는 것이 확인되었고 해당 방법을 통해 `ntbase`를 릭하였습니다.  

<center><img src='/assets/CTF_phrackCTF_WindowsKernel_writeup/LFH_before.png' width=auto height=auto></center>

`windows 24hh2`이전의 간단한 `LFH`의 구조를 보면 위와 같습니다.  
할당받고 사용되는 `pool chunk`가 `block`이며 이를 관리하는 `_HEAP_LFH_SUBSEGMENT`구조체 다음 연속적으로 존재합니다.  
목표는 릭 할 `callback`함수가 존재하는 `_HEAP_LFH_CONTEXT`까지 도달하는 것이며 이전에는 단순히 `_HEAP_LFH_SUBSEGMENT`의 `Owner`포인터를 통해 바로 접근이 가능했습니다.  

```c++
// windows11 23H2                                                            0x38 bytes (sizeof)
struct _HEAP_LFH_SUBSEGMENT
{
    struct _LIST_ENTRY ListEntry;                                           //0x0
    union
    {
        struct _HEAP_LFH_SUBSEGMENT_OWNER* Owner;                           //0x10
        union _HEAP_LFH_SUBSEGMENT_DELAY_FREE DelayFree;                    //0x10
    };
    ULONGLONG CommitLock;                                                   //0x18
    union
    {
        struct
        {
            USHORT FreeCount;                                               //0x20
            USHORT BlockCount;                                              //0x22
        };
        volatile SHORT InterlockedShort;                                    //0x20
        volatile LONG InterlockedLong;                                      //0x20
    };

  ...

}; 

// windows11 24H2                                                           0x48 bytes (sizeof)
struct _HEAP_LFH_SUBSEGMENT
{
    struct _LIST_ENTRY ListEntry;                                           //0x0
    union _HEAP_LFH_SUBSEGMENT_STATE State;                                 //0x10
    union
    {
        struct _SINGLE_LIST_ENTRY OwnerFreeListEntry;                       //0x18
        struct
        {
            UCHAR CommitStateOffset;                                        //0x18
            UCHAR Spare0:4;                                                 //0x19
        };
    };
    USHORT FreeCount;                                                       //0x20

  ...
}; 
```
하지만 `Windows11 24H2`부터 `Owner`포인터 필드가 사라지면서 해당 필드를 통해 바로 `_HEAP_LFH_AFFINITY_SLOT`에 접근할 수는 없지만 `Subsegment`들은 `_LIST_ENTRY`로 연결되어 있고 해당 리스트 또한 `_HEAP_LFH_AFFINITY_SLOT`과 연결되어있어 이를 통해 `_HEAP_LFH_CONTEXT`까지 접근이 가능합니다.  
```c++
//0x6c0 bytes (sizeof)
struct _HEAP_LFH_CONTEXT
{
    VOID* BackendCtx;                                                       //0x0
    struct _HEAP_SUBALLOCATOR_CALLBACKS Callbacks;                          //0x8
    UCHAR* AffinityModArray;                                                //0x38
    UCHAR MaxAffinity;                                                      //0x40
    UCHAR LockType;                                                         //0x41
    SHORT MemStatsOffset;                                                   //0x42
    struct _HEAP_LFH_CONFIG Config;                                         //0x44
    ULONG TlsSlotIndex;                                                     //0x4c
    ULONGLONG EncodeKey;                                                    //0x50
    ULONGLONG ExtensionLock;                                                //0x80
    struct _SINGLE_LIST_ENTRY MetadataList[4];                              //0x88
    struct _HEAP_LFH_HEAT_MAP HeatMap;                                      //0xc0
    struct _HEAP_LFH_BUCKET* Buckets[128];                                  //0x1c0
    struct _HEAP_LFH_SLOT_MAP SlotMaps[1];                                  //0x5c0
}; 
```
`_HEAP_LFH_CONTEXT`에는 `_HEAP_SUBALLOCATOR_CALLBACKS`이 존재하며 해당 주소는 `ntoskrnl`에 존재합니다.  

```c++
      Callbacks[0] = RtlpHpSegLfhAllocate;
      Callbacks[1] = RtlpHpSegLfhVsFree;
      Callbacks[2] = RtlpHpSegLfhVsCommit;
      Callbacks[3] = RtlpHpSegLfhVsDecommit;
      Callbacks[4] = RtlpHpSegLfhExtendContext;
      Callbacks[5] = RtlpHpSegTlsCleanup;

      RtlpHpLfhContextInitialize(
        &SegmentHeap->LfhContext,               // SegmentHeap_LfhContext
        SegmentHeap->SegContexts,               // SegContext
        MaximumProcessorCount,
        a4->h[0] & 1,
        Callbacks,
        SegmentHeap + 0x80);                    // MemStats
```
```c++
unsigned __int64 __fastcall RtlpHpLfhContextInitialize(
        _HEAP_LFH_CONTEXT *aLfhContext,
        _HEAP_SEG_CONTEXT *apSegContext,
        unsigned int aMaximumProcessorCount,
        unsigned __int8 aLockType,
        void *Callbacks,
        __int16 MemStats)
{

  ...

  memset_0(aLfhContext, 0, sizeof(_HEAP_LFH_CONTEXT));
  aLfhContext->BackendCtx = apSegContext;
  aLfhContext->LockType = aLockType;

  v10 = *(Callbacks + 1);
  *&aLfhContext->Callbacks.Allocate = *Callbacks;
  v11 = *(Callbacks + 2);
  aLfhContext->MemStatsOffset = MemStats - aLfhContext;
  *&aLfhContext->Callbacks.Commit = v10;
  v12 = 0LL;
  *&aLfhContext->Callbacks.ExtendContext = v11;

  do
    *(&aLfhContext->Callbacks.Allocate + v12++) ^= aLfhContext ^ RtlpHpHeapGlobals.HeapKey;
  while ( v12 < 4 );

  ExtendContext = aLfhContext->Callbacks.ExtendContext;
  if ( ExtendContext )
    aLfhContext->Callbacks.ExtendContext = aLfhContext ^ RtlpHpHeapGlobals.HeapKey ^ ExtendContext;
  TlsCleanup = aLfhContext->Callbacks.TlsCleanup;
  if ( TlsCleanup )
    aLfhContext->Callbacks.TlsCleanup = aLfhContext ^ RtlpHpHeapGlobals.HeapKey ^ TlsCleanup;
```
`_HEAP_LFH_CONTEXT` 초기화 과정에서 해당 `callback`들은  `LfhContext`, `RtlpHpHeapGlobals.HeapKey`와 인코딩 (`xor`)되어 저장되어 `callback`을 릭하기 뮈해서는 `LfhContext`의 주소와 `RtlpHpHeapGlobals.HeapKey`를 알고 있어야합니다.  

```c++
unsigned __int64 __fastcall RtlpHpLfhContextInitialize(
        _HEAP_LFH_CONTEXT *aLfhContext,
        _HEAP_SEG_CONTEXT *apSegContext,
        unsigned int aMaximumProcessorCount,
        unsigned __int8 aLockType,
        void *Callbacks,
        __int16 MemStats)
{
  MaxAffinity = 64;
  if ( aMaximumProcessorCount <= 64 )
    MaxAffinity = aMaximumProcessorCount;
  aLfhContext->MaxAffinity = MaxAffinity;
  if ( MaxAffinity > 1u )
    aLfhContext->AffinityModArray = AffinityArray + (((62 - (64 - MaxAffinity)) * (64 - MaxAffinity + 61)) >> 1);

  ...
}
```
`LfhContext`는 알아낼 수 있었지만 `RtlpHpHeapGlobals.HeapKey`를 알아내는대에는 어려움이 존재하여 `LfhContext`의 다른 포인터들을 확인해보다가 `AffinityModArray`가 `nt`에 위치해있지만 인코딩이 되어있지 않는다는 것을 확인하여 해당 필드를 릭하여 `nt base`를 얻어냈습니다.  

## token stealing
### gaining AAW
<center><img src='/assets/CTF_phrackCTF_WindowsKernel_writeup/fake_ctx.png' width=auto height=auto></center>
`AAW`는 `face ctx`를 만들고 `MappedAddr`필드를 변경하며 4096(0x1000)byte `AAW/R`이 가능하여 이걸 통해 

## Clean Up
`SYSTEM`토큰을 얻을 뒤 `userland`로 돌아와서 프로세스를 종료 시키지 않거나 `system`함수로 새로운 프로세스를 실행시키는 등의 작업으로 `pool overflow`과정에서 망가진 `heap` 상태로 `BSOD`가 발생하는 것을 방지할 수 있습니다.  
하지만 깔끔하게 익스 프로세스를 종료 시키고 싶은 마음이 있어 망가진 `heap`을 완벽히 복구하고 돌아가는 방법을 선택하였습니다.  
```c++
00000000 struct _NP_DATA_QUEUE_ENTRY // sizeof=0x30;variable_size
00000000 {
00000000     LIST_ENTRY QueueEntry;
00000010     _IRP *Irp;
00000018     PSECURITY_CLIENT_CONTEXT ClientSecurityContext;
00000020     ULONG DataEntryType;
00000024     _DWORD QuotaInEntry;
00000028     _DWORD DataSize;
0000002C     // padding byte
0000002D     // padding byte
0000002E     // padding byte
0000002F     // padding byte
00000030     char data[];
00000030 };
```
`pool overflow`가 발생시키는 과정에서 `pool header`와 `DATA_QUEUE_ENTRY`의 `DataSize`전까지의 필드들이 망가져있습니다.  
다른 필드들은 쉽게 복구가 가능하지만 `QueueEntry`의 경우 `_CCB`구조체까지 접근을 해야하기 때문에 망가진 `Named pipe`의 `_FILE_OBJECT`을 찾아야합니다.  
핸들 값을 알고있고 `AAR`로 `_EPROCESS`까지 알아낸 상태이기 때문에 `_EPROCESS`의 `ObjectTable`필드를 통해 타겟 `Named pipe`핸들에 해단 `_FILE_OBJECT`를 구해 `QueueEntry`값을 복구 할 수 있습니다.  

## Screenshot
---
<center><img src='/assets/CTF_phrackCTF_WindowsKernel_writeup/LPE_screenshot.png' width=auto height=auto></center>

# Exploit code repo
- [https://github.com/p05wn/Windows-CTF/tree/main/Phrack72_Binary_Exploitation_CTF_2025](https://github.com/p05wn/Windows-CTF/tree/main/Phrack72_Binary_Exploitation_CTF_2025)
