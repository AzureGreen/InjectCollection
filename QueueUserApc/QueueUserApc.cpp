// QueueUserApc.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <vector>
#include <TlHelp32.h>


using namespace std;

BOOL GrantPriviledge(IN PWCHAR PriviledgeName);

BOOL GetProcessIdByProcessImageName(IN PWCHAR wzProcessImageName, OUT PUINT32 ProcessId);

BOOL GetThreadIdByProcessId(IN UINT32 ProcessId, OUT vector<UINT32>& ThreadIdVector);

BOOL InjectDllByApc(IN UINT32 ProcessId, IN UINT32 ThreadId);

#ifndef _WIN64
BOOL InjectShellCodeByApc(IN UINT32 ProcessId, IN UINT32 ThreadId);
#endif // !_WIN64





CHAR	DllFullPath[MAX_PATH] = { 0 };

PVOID	DllFullPathBufferData = NULL;

PVOID	ShellCodeBufferData = NULL;

#ifdef _WIN64


#else
// 测试 32 位 只能被注入一次
UINT8	ShellCode[0x100] = {
	0x60,					// [+0] pusha
	0x9c,					// [+1] pushf
	0x68, 0, 0, 0, 0,		// [+2] push 0 
	0x68, 0, 0, 0, 0,		// [+7] push 0 
	0x68, 0, 0, 0, 0,		// [+12]psuh 0 
	0x68, 0, 0, 0, 0,		// [+17]push 0
	0xff, 0x15, 0, 0, 0, 0,	// [+22]call 
	0x9d,					// [+28]popf
	0x61,					// [+29]popa
	0, 0, 0, 0				// [+30]
};

#endif



int main()
{
	UINT32			ProcessId = 0;
	vector<UINT32>	ThreadIdVector;
	UINT32			ThreadCount = 0;


	// 1.提权
	if (GrantPriviledge(SE_DEBUG_NAME) == FALSE)
	{
		printf("GrantPriviledge Error\r\n");
	}

	// 2.Dll路径
	GetCurrentDirectoryA(MAX_PATH, DllFullPath);

#ifdef _WIN64
	strcat_s(DllFullPath, "\\x64NormalDll.dll");
#else
	strcat_s(DllFullPath, "\\x86NormalDll.dll");
#endif

	// 3.获进程Id

#ifdef _WIN64
	GetProcessIdByProcessImageName(L"explorer.exe", &ProcessId);
#else
	GetProcessIdByProcessImageName(L"notepad++.exe", &ProcessId);
#endif
	
	// 4.获线程IdVector
	GetThreadIdByProcessId(ProcessId, ThreadIdVector);

	UINT32 ThreadId = ThreadIdVector[0];


	// 5.注入
	ThreadCount = ThreadIdVector.size();
	for (INT i = ThreadCount - 1; i >= 0; i--)
	{
		UINT32 ThreadId = ThreadIdVector[i];
		InjectDllByApc(ProcessId, ThreadId);
	}

	getchar();

	return 0;
}

#ifndef _WIN64 
BOOL InjectShellCodeByApc(IN UINT32 ProcessId, IN UINT32 ThreadId)
{
	BOOL		bOk = 0;
	HANDLE		ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
	HANDLE		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	UINT32		ShellCodeLength = sizeof(ShellCode);
	SIZE_T		ReturnLength = 0;

	// 申请一次内存
	if (ShellCodeBufferData == NULL)
	{
		//申请内存
		ShellCodeBufferData = VirtualAllocEx(ProcessHandle, NULL, ShellCodeLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (ShellCodeBufferData == NULL)
		{
			CloseHandle(ProcessHandle);
			CloseHandle(ThreadHandle);
			return FALSE;
		}
	}

	UINT_PTR	MessageBoxAAddress = (UINT_PTR)GetProcAddress(GetModuleHandle(L"User32.dll"), "MessageBoxA");

	*(PUINT32)(ShellCode + 30) = MessageBoxAAddress;
	*(PUINT32)(ShellCode + 24) = (UINT32)ShellCodeBufferData + 30;


	bOk = WriteProcessMemory(ProcessHandle, ShellCodeBufferData, ShellCode, ShellCodeLength, &ReturnLength);
	if (bOk == FALSE)
	{
		CloseHandle(ProcessHandle);
		CloseHandle(ThreadHandle);
		return FALSE;
	}


	QueueUserAPC((PAPCFUNC)ShellCodeBufferData, ThreadHandle, 0);

	return FALSE;
}

#endif

/************************************************************************
*  Name : InjectDllByApc
*  Param: ProcessId				进程Id		（IN）
*  Ret  : BOOL
*  申请内存 + 写入内存 + 获得线程Id + QueueUserApc注入Dll
************************************************************************/

BOOL InjectDllByApc(IN UINT32 ProcessId, IN UINT32 ThreadId)
{
	BOOL		bOk = 0;
	HANDLE		ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
	HANDLE		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	UINT_PTR	LoadLibraryAddress = 0;
	SIZE_T		ReturnLength = 0;
	UINT32		DllFullPathLength = (strlen(DllFullPath) + 1);

	// 申请一次内存
	if (DllFullPathBufferData == NULL)
	{
		//申请内存
		DllFullPathBufferData = VirtualAllocEx(ProcessHandle, NULL, DllFullPathLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (DllFullPathBufferData == NULL)
		{
			CloseHandle(ProcessHandle);
			CloseHandle(ThreadHandle);
			return FALSE;
		}
	}

	// 避免之前写操作失败，每次重复写入

	bOk = WriteProcessMemory(ProcessHandle, DllFullPathBufferData, DllFullPath, strlen(DllFullPath) + 1,
		&ReturnLength);
	if (bOk == FALSE)
	{
		CloseHandle(ProcessHandle);
		CloseHandle(ThreadHandle);
		return FALSE;
	}

	LoadLibraryAddress = (UINT_PTR)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "LoadLibraryA");
	if (LoadLibraryAddress == NULL)
	{
		CloseHandle(ProcessHandle);
		CloseHandle(ThreadHandle);
		return FALSE;
	}

	__try
	{

		QueueUserAPC((PAPCFUNC)LoadLibraryAddress, ThreadHandle, (UINT_PTR)DllFullPathBufferData);

	}
	__except (EXCEPTION_CONTINUE_EXECUTION)
	{
	}


	CloseHandle(ProcessHandle);
	CloseHandle(ThreadHandle);

	return TRUE;
}


/************************************************************************
*  Name : GetProcessIdByProcessImageName
*  Param: ProcessId				进程Id		（IN）
*  Param: ThreadIdVector		线程Id模板	（OUT）
*  Ret  : BOOL
*  枚举制定进程Id的所有线程，压入模板中，返回线程模板集合（TlHelp32）
************************************************************************/

BOOL GetThreadIdByProcessId(IN UINT32 ProcessId, OUT vector<UINT32>& ThreadIdVector)
{
	HANDLE			ThreadSnapshotHandle = NULL;
	THREADENTRY32	ThreadEntry32 = { 0 };

	ThreadEntry32.dwSize = sizeof(THREADENTRY32);

	ThreadSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (ThreadSnapshotHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	Thread32First(ThreadSnapshotHandle, &ThreadEntry32);
	do
	{
		if (ThreadEntry32.th32OwnerProcessID == ProcessId)
		{
			ThreadIdVector.emplace_back(ThreadEntry32.th32ThreadID);		// 把该进程的所有线程id压入模板
		}
	} while (Thread32Next(ThreadSnapshotHandle, &ThreadEntry32));

	CloseHandle(ThreadSnapshotHandle);
	ThreadSnapshotHandle = NULL;
	return TRUE;
}

/************************************************************************
*  Name : GetProcessIdByProcessImageName
*  Param: wzProcessImageName		进程映像名称（IN）
*  Param: ProcessId					进程Id		（OUT）
*  Ret  : BOOL
*  通过进程映像名称获得进程Id（TlHelp32）
************************************************************************/

BOOL GetProcessIdByProcessImageName(IN PWCHAR wzProcessImageName, OUT PUINT32 ProcessId)
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
			*ProcessId = ProcessEntry32.th32ProcessID;
			break;
		}
	} while (Process32Next(ProcessSnapshotHandle, &ProcessEntry32));

	CloseHandle(ProcessSnapshotHandle);
	ProcessSnapshotHandle = NULL;

	if (*ProcessId == 0)
	{
		return FALSE;
	}

	return TRUE;
}

/************************************************************************
*  Name : GrantPriviledge
*  Param: PriviledgeName		需要提升的权限
*  Ret  : BOOL
*  提升到想要的权限（权限令牌）
************************************************************************/

BOOL GrantPriviledge(IN PWCHAR PriviledgeName)
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
		TokenHandle = NULL;
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;		// 要提升的权限个数
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;    // 动态数组，数组大小根据Count的数目
	TokenPrivileges.Privileges[0].Luid = uID;

	// 在这里我们进行调整权限
	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), &OldPrivileges, &dwReturnLength))
	{
		CloseHandle(TokenHandle);
		TokenHandle = NULL;
		return FALSE;
	}

	// 成功了
	CloseHandle(TokenHandle);
	TokenHandle = NULL;

	return TRUE;
}