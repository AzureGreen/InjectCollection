// SetThreadContext.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>

#include "Define.h"

using namespace std;

typedef
NTSTATUS(NTAPI * pfnRtlAdjustPrivilege)(
	UINT32 Privilege,
	BOOLEAN Enable,
	BOOLEAN Client,
	PBOOLEAN WasEnabled);

typedef
NTSTATUS(NTAPI * pfnZwQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN UINT32 SystemInformationLength,
	OUT PUINT32 ReturnLength OPTIONAL);

typedef
NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in UINT32 ProcessInformationLength,
	__out_opt PUINT32 ReturnLength
	);

BOOL GrantPriviledge(IN UINT32 Priviledge);

BOOL GetThreadIdByProcessId(IN UINT32 ProcessId, OUT PUINT32 ThreadId);

BOOL GetLoadLibraryAddressInTargetProcessImportTable(IN UINT32 ProcessId, OUT PUINT_PTR FunctionAddress);

BOOL GetPebByProcessId(IN UINT32 ProcessId, OUT PPEB Peb);

BOOL Inject(IN UINT32 ProcessId, IN UINT32 ThreadId);



/*

ShellCode:
010D9000 60                   pushad
010D9001 9C                   pushfd
010D9002 68 AA BB CC DD       push        0DDCCBBAAh		// 这里修改为dll路径
010D9007 FF 15 DD CC BB AA    call        dword ptr ds:[0AABBCCDDh]		// 这里修改为 Kernel32.dll导出表的 LoadLibrary 地址
010D900D 9D                   popfd
010D900E 61                   popad
010D900F FF 25 AA BB CC DD    jmp         dword ptr ds:[0DDCCBBAAh]		// 跳转回原来的eip

*/

#ifdef _WIN64
// 测试 64 位 dll被注，Bug已修复

/*
0:019> u 0x000002b5d5f80000
000002b5`d5f80000 4883ec28        sub     rsp,28h
000002b5`d5f80004 488d0d20000000  lea     rcx,[000002b5`d5f8002b]
000002b5`d5f8000b ff1512000000    call    qword ptr [000002b5`d5f80023]
000002b5`d5f80011 4883c428        add     rsp,28h
000002b5`d5f80015 ff2500000000    jmp     qword ptr [000002b5`d5f8001b]
*/

UINT8	ShellCode[0x100] = {
	0x48,0x83,0xEC,0x28,	// sub rsp ,28h

	0x48,0x8D,0x0d,			// [+4] lea rcx,
	0x00,0x00,0x00,0x00,	// [+7] DllNameOffset = [+43] - [+4] - 7

	// call 跳偏移，到地址，解*号
	0xff,0x15,				// [+11]
	0x00,0x00,0x00,0x00,	// [+13] 

	0x48,0x83,0xc4,0x28,	// [+17] add rsp,28h

	// jmp 跳偏移，到地址，解*号
	0xff,0x25,				// [+21]
	0x00,0x00,0x00,0x00,	// [+23] LoadLibraryAddressOffset

	// 存放原先的 rip
	0x00,0x00,0x00,0x00,	// [+27]
	0x00,0x00,0x00,0x00,	// [+31]

	// 跳板 loadlibrary地址
	0x00,0x00,0x00,0x00,	// [+35] 
	0x00,0x00,0x00,0x00,	// [+39]

// 存放dll完整路径
//	0x00,0x00,0x00,0x00,	// [+43]
//	0x00,0x00,0x00,0x00		// [+47]
//	......
};
#else
// 测试 32 位 配合新写的Dll可重复注入

/*
0:005> u 0x00ca0000
00000000`00ca0000 60              pusha
00000000`00ca0001 9c              pushfq
00000000`00ca0002 681d00ca00      push    0CA001Dh
00000000`00ca0007 ff151900ca00    call    qword ptr [00000000`01940026]
00000000`00ca000d 9d              popfq
00000000`00ca000e 61              popa
00000000`00ca000f ff251500ca00    jmp     qword ptr [00000000`0194002a]

*/

UINT8	ShellCode[0x100] = {
	0x60,					// [+0] pusha
	0x9c,					// [+1] pushf
	0x68,					// [+2] push
	0x00,0x00,0x00,0x00,	// [+3] ShellCode + 
	0xff,0x15,				// [+7] call	
	0x00,0x00,0x00,0x00,	// [+9] LoadLibrary Addr  Addr
	0x9d,					// [+13] popf
	0x61,					// [+14] popa
	0xff,0x25,				// [+15] jmp
	0x00,0x00,0x00,0x00,	// [+17] jmp  eip

	// eip 地址
	0x00,0x00,0x00,0x00,	// [+21]
	// LoadLibrary 地址
	0x00,0x00,0x00,0x00,	// [+25] 
	// DllFullPath 
	0x00,0x00,0x00,0x00		// [+29] 
};

#endif

WCHAR		DllFullPath[MAX_PATH] = { 0 };

UINT_PTR	LoadLibraryWAddress = 0;

int main()
{
	BOOL	bOk = FALSE;

	// 1.提权

	bOk = GrantPriviledge(SE_DEBUG_PRIVILEGE);
	if (bOk == FALSE)
	{
		printf("[-]Grant Priviledge Error\r\n");
		return FALSE;
	}

	// 2.动态库路径

	GetCurrentDirectoryW(MAX_PATH, DllFullPath);
#ifdef _WIN64
	wcscat_s(DllFullPath, L"\\x64NormalDll.dll");
#else
	wcscat_s(DllFullPath, L"\\x86NormalDll.dll");
#endif


	// 3.进程Id
	UINT32	ProcessId = 0;
	printf("Input Process Id\r\n");
	scanf_s("%d", &ProcessId);

	// 4.获得目标进程LoadLibrary导入表中地址
	bOk = GetLoadLibraryAddressInTargetProcessImportTable(ProcessId, &LoadLibraryWAddress);
	if (bOk == FALSE)
	{
		return 0;
	}

	// 5.获得线程Id
	UINT32	ThreadId = 0;
	bOk = GetThreadIdByProcessId(ProcessId, &ThreadId);

	// 6.注入
	Inject(ProcessId, ThreadId);


	return 0;
}

/************************************************************************
*  Name : Inject
*  Param: ProcessId			进程Id	（IN）
*  Param: ThreadId			线程Id	（OUT）
*  Ret  : BOOL
*  通过SuspendThread/GetThreadContext/修改ip/SetThreadContext/ResumeThreadContext完成注入工作
************************************************************************/

BOOL Inject(IN UINT32 ProcessId, IN UINT32 ThreadId)
{
	BOOL		bOk = FALSE;
	CONTEXT		ThreadContext = { 0 };
	PVOID		BufferData = NULL;

	HANDLE		ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
	HANDLE		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);


	// 首先挂起线程
	SuspendThread(ThreadHandle);


	ThreadContext.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(ThreadHandle, &ThreadContext) == FALSE)
	{
		CloseHandle(ThreadHandle);
		CloseHandle(ProcessHandle);
		return FALSE;
	}

	BufferData = VirtualAllocEx(ProcessHandle, NULL, sizeof(ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (BufferData != NULL)
	{

		if (LoadLibraryWAddress != NULL)
		{
#ifdef _WIN64

			// ShellCode + 43处 存放完整路径
			PUINT8	v1 = ShellCode + 43;
			memcpy(v1, DllFullPath, (wcslen(DllFullPath) + 1) * sizeof(WCHAR));
			UINT32	DllNameOffset = (UINT32)(((PUINT8)BufferData + 43) - ((PUINT8)BufferData + 4) - 7);
			*(PUINT32)(ShellCode + 7) = DllNameOffset;

			// ShellCode + 35处 放置 LoadLibrary 函数地址
			*(PUINT64)(ShellCode + 35) = (UINT64)LoadLibraryWAddress;
			UINT32	LoadLibraryAddressOffset = (UINT32)(((PUINT8)BufferData + 35) - ((PUINT8)BufferData + 11) - 6);
			*(PUINT32)(ShellCode + 13) = LoadLibraryAddressOffset;

			// 放置 rip 地址
			*(PUINT64)(ShellCode + 27) = ThreadContext.Rip;

			if (!WriteProcessMemory(ProcessHandle, BufferData, ShellCode, sizeof(ShellCode), NULL))
			{
				return FALSE;
			}
			ThreadContext.Rip = (UINT64)BufferData;

#else
			PUINT8	v1 = ShellCode + 29;

			memcpy((char*)v1, DllFullPath, (wcslen(DllFullPath) + 1) * sizeof(WCHAR));	//这里是要注入的DLL名字
			*(PUINT32)(ShellCode + 3) = (UINT32)BufferData + 29;

			*(PUINT32)(ShellCode + 25) = LoadLibraryWAddress;   //loadlibrary地址放入shellcode中
			*(PUINT32)(ShellCode + 9) = (UINT32)BufferData + 25;//修改call 之后的地址 为目标空间存放 loaddlladdr的地址
																//////////////////////////////////
			*(PUINT32)(ShellCode + 21) = ThreadContext.Eip;
			*(PUINT32)(ShellCode + 17) = (UINT32)BufferData + 21;//修改jmp 之后为原来eip的地址
			if (!WriteProcessMemory(ProcessHandle, BufferData, ShellCode, sizeof(ShellCode), NULL))
			{
				printf("write Process Error\n");
				return FALSE;
			}
			ThreadContext.Eip = (UINT32)BufferData;

#endif			
			if (!SetThreadContext(ThreadHandle, &ThreadContext))
			{
				printf("set thread context error\n");
				return FALSE;
			}
			ResumeThread(ThreadHandle);


			printf("ShellCode 注入完成\r\n");
		}
	}

	CloseHandle(ThreadHandle);
	CloseHandle(ProcessHandle);
	return TRUE;
}

/************************************************************************
*  Name : GetLoadLibraryAddressInTargetProcessImportTable
*  Param: ProcessId					进程Id							（IN）
*  Param: ImportFunctionAddress		LoadLibraryW目标进程导入表中地址（OUT）
*  Ret  : BOOL
*  ReadProcessMemory读取目标进程模块，遍历导入表，获得导入函数LoadLibraryW地址
************************************************************************/

BOOL GetLoadLibraryAddressInTargetProcessImportTable(IN UINT32 ProcessId, OUT PUINT_PTR ImportFunctionAddress)
{
	BOOL					bOk = FALSE;
	INT						i = 0, j = 0;
	HANDLE					ProcessHandle = NULL;
	PEB						Peb = { 0 };
	UINT_PTR				ModuleBase = 0;
	IMAGE_DOS_HEADER		DosHeader = { 0 };
	IMAGE_NT_HEADERS		NtHeader = { 0 };
	IMAGE_IMPORT_DESCRIPTOR	ImportDescriptor = { 0 };
	CHAR					szImportModuleName[MAX_PATH] = { 0 };			// 导入模块名称
	IMAGE_THUNK_DATA		OriginalFirstThunk = { 0 };
	PIMAGE_IMPORT_BY_NAME	ImageImportByName = NULL;
	CHAR					szImportFunctionName[MAX_PATH] = { 0 };			// 名称导入函数名称
	UINT32					ImportDescriptorRVA = 0;


	// 通过进程Id获得目标进程Peb
	bOk = GetPebByProcessId(ProcessId, &Peb);
	if (bOk == FALSE)
	{
		return FALSE;
	}

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (ProcessHandle == NULL)
	{
		return FALSE;
	}

	ModuleBase = (UINT_PTR)Peb.ImageBaseAddress;

	ReadProcessMemory(ProcessHandle, (PVOID)ModuleBase, &DosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
	ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + DosHeader.e_lfanew), &NtHeader, sizeof(IMAGE_NT_HEADERS), NULL);

	ImportDescriptorRVA = NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// 遍历每一个

	for (i = 0, ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptorRVA), &ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL);
		ImportDescriptor.FirstThunk != 0;
		++i, ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptorRVA + i * sizeof(IMAGE_IMPORT_DESCRIPTOR)), &ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL))
	{
		// 读取导入表

		if (ImportDescriptor.OriginalFirstThunk == 0 && ImportDescriptor.FirstThunk == 0)
		{
			break;
		}

		// 读取导入模块名
		ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptor.Name), szImportModuleName, MAX_PATH, NULL);

		if (_stricmp(szImportModuleName, "Kernel32.dll") == 0)
		{
			// 目标模块找到了，开始遍历IAT INT
			for (j = 0, ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptor.OriginalFirstThunk), &OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA), NULL);
				/*OriginalFirstThunk.u1.AddressOfData != 0*/;
				++j, ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptor.OriginalFirstThunk + j * sizeof(IMAGE_THUNK_DATA)), &OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA), NULL))
			{
				// 序号导入的不处理
				if (IMAGE_SNAP_BY_ORDINAL(OriginalFirstThunk.u1.Ordinal))
				{
					continue;
				}

				// 名称导入的函数名称
				ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PUINT8)ModuleBase + OriginalFirstThunk.u1.AddressOfData);
				ReadProcessMemory(ProcessHandle, ImageImportByName->Name, szImportFunctionName, MAX_PATH, NULL);

				// 获导入函数地址
				ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptor.FirstThunk + j * sizeof(IMAGE_THUNK_DATA)), ImportFunctionAddress, sizeof(UINT_PTR), NULL);

				if (_stricmp(szImportFunctionName, "LoadLibraryW") == 0)		// 调试发现，只找到了W函数
				{
					// Hit!
					//	MessageBoxA(0, 0, 0, 0);
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}


/************************************************************************
*  Name : GetPebByProcessId
*  Param: ProcessId			进程Id		（IN）
*  Param: Peb				PEB结构体	（OUT）
*  Ret  : BOOL
*  NtQueryInformationProcess+ProcessBasicInformation获得Peb基地址
************************************************************************/

BOOL GetPebByProcessId(IN UINT32 ProcessId, OUT PPEB Peb)
{
	BOOL						bOk = FALSE;
	NTSTATUS					Status = 0;
	HANDLE						ProcessHandle = NULL;
	UINT32						ReturnLength = 0;
	SIZE_T						NumberOfBytesRead = 0;
	PROCESS_BASIC_INFORMATION	pbi = { 0 };

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (ProcessHandle == NULL)
	{
		return FALSE;
	}

	pfnNtQueryInformationProcess	NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL)
	{
		CloseHandle(ProcessHandle);
		ProcessHandle = NULL;
		return FALSE;
	}

	// 通过 NtQueryInformationProcess 获得 ProcessBasicInformation

	Status = NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &ReturnLength);
	if (!NT_SUCCESS(Status))
	{
		CloseHandle(ProcessHandle);
		ProcessHandle = NULL;
		return FALSE;
	}

	// 通过ReadProcessMemory 从进程里面 PebBaseAddress 内存数据读取出来

	bOk = ReadProcessMemory(ProcessHandle, pbi.PebBaseAddress, Peb, sizeof(PEB), &NumberOfBytesRead);
	if (bOk == FALSE)
	{
		CloseHandle(ProcessHandle);
		ProcessHandle = NULL;
		return FALSE;
	}

	CloseHandle(ProcessHandle);
	return TRUE;
}

/************************************************************************
*  Name : GetThreadIdByProcessId
*  Param: ProcessId			进程Id		（IN）
*  Param: ThreadId			线程Id		（OUT）
*  Ret  : BOOL
*  ZwQuerySystemInformation+SystemProcessInformation获得进程相关信息从而得到一个线程Id
************************************************************************/

BOOL GetThreadIdByProcessId(IN UINT32 ProcessId, OUT PUINT32 ThreadId)
{
	BOOL						bOk = FALSE;
	NTSTATUS					Status = 0;
	PVOID						BufferData = NULL;
	PSYSTEM_PROCESS_INFO		spi = NULL;
	pfnZwQuerySystemInformation ZwQuerySystemInformation = NULL;

	ZwQuerySystemInformation = (pfnZwQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	if (ZwQuerySystemInformation == NULL)
	{
		return FALSE;
	}

	BufferData = malloc(1024 * 1024);
	if (!BufferData)
	{
		return FALSE;
	}

	// 在QuerySystemInformation系列函数中，查询SystemProcessInformation时，必须提前申请好内存，不能先查询得到长度再重新调用
	Status = ZwQuerySystemInformation(SystemProcessInformation, BufferData, 1024 * 1024, NULL);
	if (!NT_SUCCESS(Status))
	{
		free(BufferData);
		return FALSE;
	}

	spi = (PSYSTEM_PROCESS_INFO)BufferData;

	// 遍历进程，找到我们的目标进程
	while (TRUE)
	{
		bOk = FALSE;
		if (spi->UniqueProcessId == (HANDLE)ProcessId)
		{
			bOk = TRUE;
			break;
		}
		else if (spi->NextEntryOffset)
		{
			spi = (PSYSTEM_PROCESS_INFO)((PUINT8)spi + spi->NextEntryOffset);
		}
		else
		{
			break;
		}
	}

	if (bOk)
	{
		for (INT i = 0; i < spi->NumberOfThreads; i++)
		{
			// 返出找到的线程Id
			*ThreadId = (UINT32)spi->Threads[i].ClientId.UniqueThread;
			break;
		}
	}

	if (BufferData != NULL)
	{
		free(BufferData);
	}

	return bOk;
}


/************************************************************************
*  Name : GrantPriviledge
*  Param: Priviledge			提升的权限
*  Ret  : BOOL
*  利用ntdll导出函数RtlAdjustPrivilege提权
************************************************************************/

BOOL GrantPriviledge(IN UINT32 Priviledge)
{
	pfnRtlAdjustPrivilege	RtlAdjustPrivilege = NULL;
	BOOLEAN					WasEnable = FALSE;

	RtlAdjustPrivilege = (pfnRtlAdjustPrivilege)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlAdjustPrivilege");
	if (RtlAdjustPrivilege == NULL)
	{
		return FALSE;
	}

	RtlAdjustPrivilege(Priviledge, TRUE, FALSE, &WasEnable);

	return TRUE;
}