// RtlCreateUserThread.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

#define NT_SUCCESS(x) ((x) >= 0)

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(NTAPI * pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL);

BOOL GrantPriviledge(WCHAR* PriviledgeName);
BOOL GetProcessIdByProcessImageName(IN WCHAR* wzProcessImageName, OUT UINT32* TargetProcessId);
BOOL InjectDll(UINT32 ProcessId);

CHAR	DllFullPath[MAX_PATH] = { 0 };

int main()
{
	printf("This Injection used RtlCreateUserThread\r\n");
	// 首先提权一波
	if (GrantPriviledge(SE_DEBUG_NAME) == FALSE)
	{
		printf("GrantPriviledge Error\r\n");
	}

	// 接着通过进程名得到进程id
	UINT32	ProcessId = 0;

	GetCurrentDirectoryA(MAX_PATH, DllFullPath);

#ifdef _WIN64
	GetProcessIdByProcessImageName(L"Taskmgr.exe", &ProcessId);
	strcat_s(DllFullPath, "\\x64Dll.dll");
#else
	GetProcessIdByProcessImageName(L"notepad++.exe", &ProcessId);
	strcat_s(DllFullPath, "\\x86Dll.dll");
#endif

	if (ProcessId == 0)
	{
		printf("Can't Find Target Process\r\n");
		return 0;
	}

	printf("DllFullPath is :%s\r\n", DllFullPath);
	printf("Target ProcessId is :%d\r\n", ProcessId);

	BOOL bOk = InjectDll(ProcessId);
	if (bOk == FALSE)
	{
		printf("Inject Error\r\n");
		return 0;
	}

	printf("Inject Success\r\nInput Any Key To Exit\r\n");
	getchar();
	getchar();

	return 0;
}

/************************************************************************
*  Name : InjectDll
*  Param: ProcessId		进程Id
*  Ret  : BOOLEAN
*  使用CreateRemoteThread创建远程线程实现注入
************************************************************************/

BOOL InjectDll(UINT32 ProcessId)
{
	HANDLE ProcessHandle = NULL;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	// 在对方进程空间申请内存,存储Dll完整路径
	UINT32	DllFullPathLength = (strlen(DllFullPath) + 1);
	PVOID DllFullPathBufferData = VirtualAllocEx(ProcessHandle, NULL, DllFullPathLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (DllFullPathBufferData == NULL)
	{
		CloseHandle(ProcessHandle);
		return FALSE;
	}

	// 将DllFullPath写进刚刚申请的内存中
	SIZE_T	ReturnLength;
	BOOL bOk = WriteProcessMemory(ProcessHandle, DllFullPathBufferData, DllFullPath, strlen(DllFullPath) + 1, &ReturnLength);

	LPTHREAD_START_ROUTINE	LoadLibraryAddress = NULL;
	HMODULE					Kernel32Module = GetModuleHandle(L"Kernel32");

	LoadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32Module, "LoadLibraryA");

	pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCreateUserThread");


	HANDLE ThreadHandle = NULL;
	NTSTATUS Status = RtlCreateUserThread(ProcessHandle, NULL, FALSE, 0, 0, 0, LoadLibraryAddress, DllFullPathBufferData, &ThreadHandle, NULL);
	if (!NT_SUCCESS(Status) || ThreadHandle == NULL)
	{
		CloseHandle(ProcessHandle);
		return FALSE;
	}

	if (WaitForSingleObject(ThreadHandle, INFINITE) == WAIT_FAILED)
	{
		return FALSE;
	}

	CloseHandle(ProcessHandle);
	CloseHandle(ThreadHandle);

	return TRUE;
}

/************************************************************************
*  Name : GetProcessIdByProcessImageName
*  Param: wzProcessImageName		进程映像名称	（IN）
*  Param: TargetProcessId			进程Id			（OUT）
*  Ret  : BOOLEAN
*  使用ToolHelp系列函数通过进程映像名称获得进程Id
************************************************************************/

BOOL GetProcessIdByProcessImageName(IN WCHAR* wzProcessImageName, OUT UINT32* TargetProcessId)
{
	HANDLE			ProcessSnapshotHandle = NULL;
	PROCESSENTRY32	ProcessEntry32 = { 0 };

	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);		// 初始化PROCESSENTRY32结构

	ProcessSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);	// 给系统所有的进程快照

	if (ProcessSnapshotHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	Process32First(ProcessSnapshotHandle, &ProcessEntry32);		// 找到第一个
	do
	{
		if (lstrcmpi(ProcessEntry32.szExeFile, wzProcessImageName) == 0)		// 不区分大小写
		{
			*TargetProcessId = ProcessEntry32.th32ProcessID;
			break;
		}
	} while (Process32Next(ProcessSnapshotHandle, &ProcessEntry32));

	CloseHandle(ProcessSnapshotHandle);
	ProcessSnapshotHandle = NULL;
	return TRUE;
}

/************************************************************************
*  Name : GrantPriviledge
*  Param: PriviledgeName		想要提升的权限
*  Ret  : BOOLEAN
*  提升自己想要的权限
************************************************************************/

BOOL GrantPriviledge(WCHAR* PriviledgeName)
{
	TOKEN_PRIVILEGES TokenPrivileges, OldPrivileges;
	DWORD			 dwReturnLength = sizeof(OldPrivileges);
	HANDLE			 TokenHandle = NULL;
	LUID			 uID;

	// 打开权限令牌
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &TokenHandle))
	{
		if (GetLastError() != ERROR_NO_TOKEN)
		{
			return FALSE;
		}
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
		{
			return FALSE;
		}
	}

	if (!LookupPrivilegeValue(NULL, PriviledgeName, &uID))		// 通过权限名称查找uID
	{
		CloseHandle(TokenHandle);
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;		// 要提升的权限个数
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;    // 动态数组，数组大小根据Count的数目
	TokenPrivileges.Privileges[0].Luid = uID;

	// 在这里我们进行调整权限
	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), &OldPrivileges, &dwReturnLength))
	{
		CloseHandle(TokenHandle);
		return FALSE;
	}

	// 成功了
	CloseHandle(TokenHandle);
	return TRUE;
}