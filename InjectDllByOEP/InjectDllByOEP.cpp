// InjectDllByOEP.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

using namespace std;


BOOL GrantPriviledge(WCHAR* PriviledgeName);

UINT32 GetLoadDllByOEPOffsetInFile(PVOID DllBuffer);

UINT32 RVAToOffset(UINT32 RVA, PIMAGE_NT_HEADERS NtHeader);

BOOL GetProcessIdByProcessImageName(IN WCHAR* wzProcessImageName, OUT UINT32* TargetProcessId);

HANDLE WINAPI LoadRemoteDll(HANDLE ProcessHandle, PVOID ModuleFileBaseAddress, UINT32 ModuleFileSize, LPVOID lParam);

CHAR DllFullPath[MAX_PATH] = { 0 };

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
	GetProcessIdByProcessImageName(L"explorer.exe", &ProcessId);
	strcat_s(DllFullPath, "\\x64LoadRemoteDll.dll");
#else
	GetProcessIdByProcessImageName(L"notepad++.exe", &ProcessId);
	strcat_s(DllFullPath, "\\x86LoadRemoteDll.dll");
#endif

	// 获得dll句柄
	HANDLE FileHandle = CreateFileA(DllFullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		printf("Open File Error\r\n");
		return 0;
	}

	// 获得dll文件长度
	UINT32	FileSize = GetFileSize(FileHandle, NULL);
	if (FileSize == INVALID_FILE_SIZE || FileSize == 0)
	{
		printf("Get File Size Error\r\n");
		CloseHandle(FileHandle);
		return 0;
	}

	// 申请内存，保存
	PVOID	FileData = HeapAlloc(GetProcessHeap(), 0, FileSize);
	if (FileData == NULL)
	{
		printf("HeapAlloc Error\r\n");
		CloseHandle(FileHandle);
		return 0;
	}

	DWORD ReturnLength = 0;
	BOOL bOk = ReadFile(FileHandle, FileData, FileSize, &ReturnLength, NULL);
	CloseHandle(FileHandle);
	if (bOk == FALSE)
	{
		printf("ReadFile Error\r\n");
		HeapFree(GetProcessHeap(), 0, FileData);
		return 0;
	}

	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (ProcessHandle == NULL)
	{
		printf("OpenProcess Error\r\n");
		HeapFree(GetProcessHeap(), 0, FileData);
		return 0;
	}

	// 执行Dll中的导出函数LoadDllByOEP，让目标进程实现LoadLibrary功能
	HANDLE ThreadHandle = LoadRemoteDll(ProcessHandle, FileData, FileSize, NULL);
	if (ThreadHandle == NULL)
	{
		goto _Clear;
	}

	WaitForSingleObject(ThreadHandle, INFINITE);

_Clear:

	if (FileData)
	{
		HeapFree(GetProcessHeap(), 0, FileData);
	}

	if (ProcessHandle)
	{
		CloseHandle(ProcessHandle);
	}

	return 0;
}


/************************************************************************
*  Name : LoadRemoteDll
*  Param: ProcessHandle			进程句柄	（IN）
*  Param: ModuleBaseAddress		模块基地址
*  Param: ModuleLength			模块在文件中的大小
*  Param: lParam				模块句柄
*  Ret  : HANDLE
*  将Dll以文件格式写入目标进程内存，并执行Dll的导出函数LoadDllByOEP
************************************************************************/

HANDLE WINAPI LoadRemoteDll(HANDLE ProcessHandle, PVOID ModuleFileBaseAddress, UINT32 ModuleFileSize, LPVOID lParam)
{

	HANDLE	ThreadHandle = NULL;

	__try
	{
		if (ProcessHandle == NULL || ModuleFileBaseAddress == NULL || ModuleFileSize == 0)
		{
			return NULL;
		}

		// 导出函数相对于 ModuelBaseAddress 的 Offset
		UINT32	FunctionOffset = GetLoadDllByOEPOffsetInFile(ModuleFileBaseAddress);
		if (FunctionOffset == 0)
		{
			return NULL;
		}

		// 在目标进程申请内存
		PVOID	RemoteBufferData = VirtualAllocEx(ProcessHandle, NULL, ModuleFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (RemoteBufferData == NULL)
		{
			return NULL;
		}
		
		// 把Dll文件写入目标进程内存空间
		BOOL	bOk = WriteProcessMemory(ProcessHandle, RemoteBufferData, ModuleFileBaseAddress, ModuleFileSize, NULL);
		if (bOk == FALSE)
		{
			return NULL;
		}

		// 以文件格式去执行 Dll 中的 LoadDllByOEP
		LPTHREAD_START_ROUTINE	RemoteThreadCallBack = (LPTHREAD_START_ROUTINE)((PUINT8)RemoteBufferData + FunctionOffset);

		ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 1024 * 1024, RemoteThreadCallBack, lParam, 0, NULL);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ThreadHandle = NULL;
	}

	return ThreadHandle;
}


/************************************************************************
*  Name : LoadRemoteDll
*  Param: ProcessHandle			进程句柄
*  Ret  : HANDLE
*  获得LoadDllByOEP在Dll文件中的偏移量
************************************************************************/

UINT32 GetLoadDllByOEPOffsetInFile(PVOID DllBuffer)
{
	UINT_PTR			BaseAddress = (UINT_PTR)DllBuffer;
	PIMAGE_DOS_HEADER	DosHeader = NULL;
	PIMAGE_NT_HEADERS	NtHeader = NULL;

	DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)BaseAddress + DosHeader->e_lfanew);

	/*
	#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
	#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
	#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107
	*/

	if (NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)	// pe32
	{
	}
	else if (NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)	// pe64
	{
	}
	else
	{
		return 0;
	}

	UINT32					ExportDirectoryRVA = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)BaseAddress + RVAToOffset(ExportDirectoryRVA, NtHeader));

	UINT32					AddressOfNamesRVA = ExportDirectory->AddressOfNames;
	PUINT32					AddressOfNames = (PUINT32)((PUINT8)BaseAddress + RVAToOffset(AddressOfNamesRVA, NtHeader));

	UINT32					AddressOfFunctionsRVA = ExportDirectory->AddressOfFunctions;
	PUINT32					AddressOfFunctions = (PUINT32)((PUINT8)BaseAddress + RVAToOffset(AddressOfFunctionsRVA, NtHeader));

	UINT32					AddressOfNameOrdinalsRVA = ExportDirectory->AddressOfNameOrdinals;
	PUINT16					AddressOfNameOrdinals = (PUINT16)((PUINT8)BaseAddress + RVAToOffset(AddressOfNameOrdinalsRVA, NtHeader));

	for (UINT32 i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		CHAR*	ExportFunctionName = (CHAR*)((PUINT8)BaseAddress + RVAToOffset(*AddressOfNames, NtHeader));

		if (strstr(ExportFunctionName, "LoadDllByOEP") != NULL)
		{
			UINT16	ExportFunctionOrdinals = AddressOfNameOrdinals[i];

			return RVAToOffset(AddressOfFunctions[ExportFunctionOrdinals], NtHeader);
		}
	}
	return 0;
}

/************************************************************************
*  Name : RVAToOffset
*  Param: RVA				内存中偏移
*  Param: NtHeader			Nt头
*  Ret  : UINT32
*  内存中偏移转换成文件中偏移
************************************************************************/

UINT32 RVAToOffset(UINT32 RVA, PIMAGE_NT_HEADERS NtHeader)
{
	UINT32					i = 0;
	PIMAGE_SECTION_HEADER	SectionHeader = NULL;

	SectionHeader = IMAGE_FIRST_SECTION(NtHeader);

	if (RVA < SectionHeader[0].PointerToRawData)
	{
		return RVA;
	}

	for (i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	{
		if (RVA >= SectionHeader[i].VirtualAddress && RVA < (SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData))
		{
			return (RVA - SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData);
		}
	}

	return 0;
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