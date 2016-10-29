// SetWindowsHookEx.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <vector>
#include <TlHelp32.h>

using namespace std;


BOOL GrantPriviledge(IN PWCHAR PriviledgeName);
BOOL GetProcessIdByProcessImageName(IN WCHAR* wzProcessImageName, OUT UINT32* TargetProcessId);
BOOL GetThreadIdByProcessId(UINT32 ProcessId, vector<UINT32>& ThreadIdVector);
BOOL Inject(IN UINT32 ThreadId, OUT HHOOK& HookHandle);



CHAR	DllFullPath[MAX_PATH] = { 0 };



int main()
{
	// 首先提权一波
	if (GrantPriviledge(SE_DEBUG_NAME) == FALSE)
	{
		printf("GrantPriviledge Error\r\n");
	}

	// 接着通过进程名得到进程id
	UINT32	ProcessId = 0;

	GetCurrentDirectoryA(MAX_PATH, DllFullPath);

#ifdef _WIN64
	//	GetProcessIdByProcessImageName(L"Taskmgr.exe", &ProcessId);
	//	GetProcessIdByProcessImageName(L"calculator.exe", &ProcessId);
	GetProcessIdByProcessImageName(L"explorer.exe", &ProcessId);
	strcat_s(DllFullPath, "\\x64WindowHookDll.dll");
#else
	GetProcessIdByProcessImageName(L"notepad++.exe", &ProcessId);
	strcat_s(DllFullPath, "\\x86WindowHookDll.dll");
#endif



	// 然后通过进程id枚举到所有线程id
	vector<UINT32> ThreadIdVector;
	GetThreadIdByProcessId(ProcessId, ThreadIdVector);

	HHOOK HookHandle = NULL;

	for (UINT32 ThreadId : ThreadIdVector)
	{
		Inject(ThreadId, HookHandle);
		break;
	}

	printf("Input Any Key To UnHook\r\n");
	getchar();
	getchar();

	UnhookWindowsHookEx(HookHandle);

	return 0;
}

/************************************************************************
*  Name : Inject
*  Param: ThreadId			线程Id			（IN）
*  Param: HookHandle		消息钩子句柄	（OUT）
*  Ret  : BOOL
*  给目标线程的指定消息上下钩，走进Dll导出函数
************************************************************************/

BOOL Inject(IN UINT32 ThreadId, OUT HHOOK& HookHandle)
{
	HMODULE	DllModule = LoadLibraryA(DllFullPath);
	FARPROC FunctionAddress = GetProcAddress(DllModule, "Sub_1");

	HookHandle = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)FunctionAddress, DllModule, ThreadId);
	if (HookHandle == NULL)
	{
		return FALSE;
	}
	return TRUE;
}

/************************************************************************
*  Name : GetProcessIdByProcessImageName
*  Param: ProcessId				进程Id		（IN）
*  Param: ThreadIdVector		线程Id模板	（OUT）
*  Ret  : BOOL
*  枚举制定进程Id的所有线程，压入模板中，返回线程模板集合（TlHelp32）
************************************************************************/

BOOL GetThreadIdByProcessId(UINT32 ProcessId, vector<UINT32>& ThreadIdVector)
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

	if (*TargetProcessId == 0)
	{
		return FALSE;
	}

	return TRUE;
}

/************************************************************************
*  Name : GrantPriviledge
*  Param: PriviledgeName		想要提升的权限
*  Ret  : BOOLEAN
*  提升自己想要的权限
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