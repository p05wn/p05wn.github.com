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
...드라이버는 ...를 수행하는 드라이버로 `DeviceIoControl` 그리고 `MDL`을 통해 `Usermode process`와 통신합니다

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

# Exploitation (Flag Leak Solution)
---
```c++
__int64 __fastcall ReadFlag(_DEVICE_OBJECT *DeviceObject)
{

  ...

  memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
  memset(Buffer, 0, sizeof(Buffer));
  v2 = KeAcquireSpinLockRaiseToDpc(&SpinLock);
  ctx = GetProcessContext(DeviceObject);
  KeReleaseSpinLock(&SpinLock, v2);
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
`readflag`함수에서 `flag`를 읽어내기 위해서 `ctx->ReadFlag`(offset: 0x19)값을 설정되어야합니다.
`Cleanup`루틴을 통해 `dangling pointer`를 통해 

# Exploitation (Token Stealing Solution)
---


# Screenshot
---
<center><img src='/assets/CTF_phrackCTF_WindowsKernel_writeup/phrack_screenshot.png' width=auto height=auto></center>


### Exploit code link
- [https://github.com/p05wn/Windows-CTF/tree/main/Phrack72_Binary_Exploitation_CTF_2025](https://github.com/p05wn/Windows-CTF/tree/main/Phrack72_Binary_Exploitation_CTF_2025)
