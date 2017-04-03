// AddPeSection.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <strsafe.h>
using namespace std;

#define AlignSize(Size, Align) (Size + Align - 1) / Align * Align    // 对齐

UINT32 RVAToOffset(IN UINT32 RVA, IN PIMAGE_NT_HEADERS NtHeader);

VOID ModifyImportDescriptor(IN PVOID BaseAddress, IN const CHAR *szDllName, IN OPTIONAL const CHAR *szFunctionName = "");

BOOL AddNewSection(IN PVOID BaseAddress, IN const CHAR *szSectionName, IN UINT32 NewSectionSize);

BOOL CanAddNewSection(IN PVOID BaseAddress);

BOOL MappingPEFileInMemory(IN CHAR *szFileFullPath, OUT PVOID *MappingBaseAddress);

VOID UnMappingPEFileInMemory(IN PVOID MappingBaseAddress);

HANDLE g_FileHandle = INVALID_HANDLE_VALUE;
HANDLE g_MappingHandle = NULL;

// 该方法是从文件操作层面上的注入，对源文件有破坏性
int main()
{
	// 准备合适的dll路径与文件路径
	CHAR szFilePath[MAX_PATH] = { 0 };
	CHAR szDllPath[MAX_PATH] = { 0 };
	CHAR *szImportFuntionName = "InjectFunction";
	GetCurrentDirectoryA(MAX_PATH, szFilePath);
	StringCchCopyA(szDllPath, MAX_PATH, szFilePath);
	StringCchCatA(szFilePath, MAX_PATH, "\\Test.exe");  // 因为直接对文件操作，所以这里用自己写的测试程序
#ifdef _WIN64
	StringCchCatA(szDllPath, MAX_PATH, "\\x64SectionDll.dll");
#else
	StringCchCatA(szDllPath, MAX_PATH, "\\x86SectionDll.dll");
#endif // _WIN64

	PVOID MappingBase = NULL;

	// 将目标文件映射到内存
	BOOL bOk = MappingPEFileInMemory(szFilePath, &MappingBase);
	if (bOk)
	{
		bOk = CanAddNewSection(MappingBase);
		if (bOk)
		{
			bOk = AddNewSection(MappingBase, ".Inject", 256);
			if (bOk)
			{
				ModifyImportDescriptor(MappingBase, szDllPath, szImportFuntionName);
			}
		}
		else
		{
			printf("Can Not Add New Section\r\n");
		}
		UnMappingPEFileInMemory(MappingBase);
	}
	else
	{
		printf("MappingFile Failed\r\n");
	}
	system("pause");
	return 0;
}

/************************************************************************
*  Name : RVAToOffset
*  Param: RVA				内存中偏移
*  Param: NtHeader			Nt头
*  Ret  : UINT32
*  内存中偏移转换成文件中偏移
************************************************************************/

UINT32 RVAToOffset(IN UINT32 RVA, IN PIMAGE_NT_HEADERS NtHeader)
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
*  Name : ModifyImportDescriptor
*  Param: BaseAddress				映像基地址
*  Param: szDllName				    动态库路径
*  Param: szFunctionName			导出函数名称(OPTIONAL) 这里只作为示例导出一个函数，可以根据实际情况设计
*  Ret  : VOID
*  将导入表更新到新节中，顺便加上我们的dll
************************************************************************/

VOID ModifyImportDescriptor(IN PVOID BaseAddress, IN const CHAR *szDllName, IN OPTIONAL const CHAR *szFunctionName/* = ""*/)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)BaseAddress + DosHeader->e_lfanew);

	UINT32 ImportDirectoryRVA = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)BaseAddress + RVAToOffset(ImportDirectoryRVA, NtHeader));

	BOOL   bBoundImport = FALSE;
	if (ImportDescriptor->OriginalFirstThunk == 0 && ImportDescriptor->FirstThunk != 0)
	{
		// OriginalFirstThunk为0，FirstThunk不为0，表明使用了绑定导入，所以关闭绑定导入
		bBoundImport = TRUE;
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	}

	// 找到自己添加的新节
	PIMAGE_SECTION_HEADER NewSectionHeader = IMAGE_FIRST_SECTION(NtHeader) + NtHeader->FileHeader.NumberOfSections - 1;
	PUINT8 NewSection = (PUINT8)BaseAddress + NewSectionHeader->PointerToRawData;       // 定位到自己申请内存的新节上
	PIMAGE_IMPORT_DESCRIPTOR NewImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)NewSection;

	// 拷贝导入表
	INT i = 0;
	for (i = 0; ImportDescriptor->FirstThunk != 0 || ImportDescriptor->Characteristics != 0; i++)
	{
		RtlCopyMemory(NewSection + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		ImportDescriptor++;
		NewImportDescriptor++;
	}

	// 把最后一个复制一遍
	RtlCopyMemory(NewImportDescriptor, (PUINT8)(NewImportDescriptor - 1), sizeof(IMAGE_IMPORT_DESCRIPTOR));

	UINT32 Delta = NewSectionHeader->VirtualAddress - NewSectionHeader->PointerToRawData;    // 计算RVA与FOA的差值

																							 // 填充 ImportDescriptor->OriginalFirstThunk / FirstThunk
	PIMAGE_THUNK_DATA NewThunk = PIMAGE_THUNK_DATA(NewImportDescriptor + 2);   // 空一个，定位到后面的内存地址
	if (bBoundImport)
	{
		((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->OriginalFirstThunk = 0;
	}
	else
	{
		((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->OriginalFirstThunk = Delta + (UINT_PTR)NewThunk - (UINT_PTR)BaseAddress;
	}
	((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->FirstThunk = Delta + (UINT_PTR)NewThunk - (UINT_PTR)BaseAddress;   // RVA

																														// 填充 ImportDescriptor->Name
	PCHAR DllName = (PCHAR)(NewThunk + 2);    // 同样空一个，定位到后面的内存地址
	RtlCopyMemory(DllName, szDllName, strlen(szDllName) + 1);
	DllName[strlen(szDllName)] = '\0';

	((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->Name = Delta + (UINT_PTR)DllName - (UINT_PTR)BaseAddress;   // RVA

																												 // 填充 Thunk->u1.AddressOfData
	PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)(DllName + strlen(szDllName) + 1);
	ImportByName->Hint = 1;   // 序号
	RtlCopyMemory(ImportByName->Name, szFunctionName, strlen(szFunctionName) + 1);  // 函数名称
	ImportByName->Name[strlen(szFunctionName) + 1] = '\0';

	NewThunk->u1.AddressOfData = Delta + (UINT_PTR)ImportByName - (UINT_PTR)BaseAddress;

	// 修改ImportTable的位置，定位到NewSection上
	NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = NewSectionHeader->VirtualAddress;
	NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
}

/************************************************************************
*  Name : AddNewSection
*  Param: BaseAddress			 映像基地址
*  Param: szSectionName			 新节区的名字
*  Param: NewSectionSize		 新节区的大小
*  Ret  : BOOL
*  在文件末尾添加一个新节
************************************************************************/

BOOL AddNewSection(IN PVOID BaseAddress, IN const CHAR *szSectionName, IN UINT32 NewSectionSize)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)BaseAddress + DosHeader->e_lfanew);

	// 得到新节的起始地址， 最后的起始地址
	PIMAGE_SECTION_HEADER NewSectionHeader = IMAGE_FIRST_SECTION(NtHeader) + NtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER LastSectionHeader = NewSectionHeader - 1;

	UINT32 VirtualSize = AlignSize(NewSectionSize, NtHeader->OptionalHeader.SectionAlignment);
	UINT32 VirtualAddress = AlignSize(LastSectionHeader->VirtualAddress + LastSectionHeader->Misc.VirtualSize, NtHeader->OptionalHeader.SectionAlignment);
	UINT32 SizeOfRawData = AlignSize(NewSectionSize, NtHeader->OptionalHeader.FileAlignment);
	UINT32 PointerToRawData = AlignSize(LastSectionHeader->PointerToRawData + LastSectionHeader->SizeOfRawData, NtHeader->OptionalHeader.FileAlignment);

	// 填充新节信息
	RtlCopyMemory(NewSectionHeader->Name, szSectionName, strlen(szSectionName));
	NewSectionHeader->Misc.VirtualSize = VirtualSize;
	NewSectionHeader->VirtualAddress = VirtualAddress;
	NewSectionHeader->SizeOfRawData = SizeOfRawData;
	NewSectionHeader->PointerToRawData = PointerToRawData;
	NewSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;

	// 修改NtHeader相关信息
	NtHeader->FileHeader.NumberOfSections++;
	NtHeader->OptionalHeader.SizeOfImage += VirtualSize;
	// 关闭绑定导入
	NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;

	PUINT8 NewSection = (PUINT8)malloc(SizeOfRawData);
	BOOL bOk = FALSE;
	if (NewSection)
	{
		RtlZeroMemory(NewSection, SizeOfRawData);

		SetFilePointer(g_FileHandle, 0, 0, FILE_END);  // 将文件指针移到最后

		DWORD dwReturnLength = 0;
		bOk = WriteFile(g_FileHandle, NewSection, SizeOfRawData, &dwReturnLength, NULL);  // 在文件末尾追加一段空间

		free(NewSection);
	}
	return bOk;
}

/************************************************************************
*  Name : CanAddNewSection
*  Param: BaseAddress			 映像基地址
*  Ret  : BOOL
*  判断文件合法性，并通过判断是否能够插入一个新节
************************************************************************/

BOOL CanAddNewSection(IN PVOID BaseAddress)
{
	// 判断是否是合法PE文件
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)BaseAddress + DosHeader->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	// 是否可以再加入一个节区
	if ((NtHeader->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER) >         // 现有Section个数+1
		NtHeader->OptionalHeader.SizeOfHeaders - ((UINT_PTR)IMAGE_FIRST_SECTION(NtHeader) - (UINT_PTR)BaseAddress))  // 所有头大小 - 第一个Section首地址 - PE基地址 = 剩下可以个节的空间大小
	{
		return FALSE;
	}
	return TRUE;
}

/************************************************************************
*  Name : MappingPEFileInMemory
*  Param: szFileFullPath			系统导入模块名称
*  Param: MappingBaseAddress		模块映射基地址 （OUT）
*  Param: MappingViewSize			映射节大小 （OUT）
*  Ret  : BOOL
*  将目标文件映射到内存
************************************************************************/

BOOL MappingPEFileInMemory(IN CHAR *szFileFullPath, OUT PVOID *MappingBaseAddress)
{
	g_FileHandle = CreateFileA(szFileFullPath, GENERIC_READ | GENERIC_WRITE
		, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (g_FileHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	UINT32 FileSize = GetFileSize(g_FileHandle, NULL);

	g_MappingHandle = CreateFileMappingA(g_FileHandle, NULL, PAGE_READWRITE, 0, FileSize, NULL);
	if (g_MappingHandle == NULL)
	{
		return FALSE;
	}

	*MappingBaseAddress = MapViewOfFile(g_MappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, FileSize);

	return TRUE;
}

/************************************************************************
*  Name : UnMappingPEFileInMemory
*  Param: MappingBaseAddress		映射模块基地址
*  Ret  : BOOL
*  解除映射，销毁资源
************************************************************************/

VOID UnMappingPEFileInMemory(IN PVOID MappingBaseAddress)
{
	if (g_MappingHandle)
	{
		CloseHandle(g_MappingHandle);
		g_FileHandle = NULL;
	}
	if (g_FileHandle)
	{
		CloseHandle(g_FileHandle);
		g_MappingHandle = NULL;
	}
	if (MappingBaseAddress != NULL)
	{
		UnmapViewOfFile(MappingBaseAddress);
		MappingBaseAddress = NULL;
	}
}