#include <Windows.h>
#include <intrin.h>


#ifdef LOADREMOTEDLL_EXPORTS
#define LOADREMOTEDLL_API __declspec(dllexport)
#else
#define LOADREMOTEDLL_API __declspec(dllimport)
#endif


#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x534C0AB8

#define IMAGE_REL_BASED_ARM_MOV32A		5
#define IMAGE_REL_BASED_ARM_MOV32T		7

#define HASH_KEY						13

#pragma intrinsic( _rotr )

__forceinline UINT32 ror(UINT32 d)
{
	return _rotr(d, HASH_KEY);
}

__forceinline UINT32 hash(char * c)
{
	register UINT32 h = 0;
	do
	{
		h = ror(h);
		h += *c;
	} while (*++c);

	return h;
}

//////////////////////////////////////////////////////////////////////////

typedef struct _UNICODE_STRING
{
	USHORT					Length;
	USHORT					MaximumLength;
	PWSTR					Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _PEB_LDR_DATA_WIN7_X64
{
	UINT32	Length;
	UINT8   Initialized;
	UINT8   _PADDING0_[0x3];
	PVOID   SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID	EntryInProgress;
	UINT8   ShutdownInProgress;
	UINT8   _PADDING1_[0x7];
	PVOID   ShutdownThreadId;
}PEB_LDR_DATA_WIN7_X64, *PPEB_LDR_DATA_WIN7_X64;


typedef struct _PEB_LDR_DATA_WINXP_X86
{
	UINT32	Length;
	UINT8   Initialized;
	UINT8   _PADDING0_[0x3];
	PVOID   SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID	EntryInProgress;
}PEB_LDR_DATA_WINXP_X86, *PPEB_LDR_DATA_WINXP_X86;



#ifdef _WIN64
#define PPEB_LDR_DATA   PPEB_LDR_DATA_WIN7_X64
#define PEB_LDR_DATA	PEB_LDR_DATA_WIN7_X64
#else   
#define PPEB_LDR_DATA   PPEB_LDR_DATA_WINXP_X86
#define PEB_LDR_DATA	PEB_LDR_DATA_WINXP_X86
#endif

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS_WINXP_X86 {
	UINT32 MaximumLength;
	UINT32 Length;
	UINT32 Flags;
	UINT32 DebugFlags;
	HANDLE ConsoleHandle;
	UINT32 ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;
	CURDIR CurrentDirectory;        // ProcessParameters
	UNICODE_STRING DllPath;         // ProcessParameters
	UNICODE_STRING ImagePathName;   // ProcessParameters
	UNICODE_STRING CommandLine;     // ProcessParameters
	PVOID   Environment;
	UINT32	StartingX;
	UINT32	StartingY;
	UINT32	CountX;
	UINT32	CountY;
	UINT32	CountCharsX;
	UINT32	CountCharsY;
	UINT32	FillAttribute;
	UINT32	WindowFlags;
	UINT32	ShowWindowFlags;
	UNICODE_STRING	WindowTitle;
	UNICODE_STRING	DesktopInfo;
	UNICODE_STRING	ShellInfo;
	UNICODE_STRING	RuntimeData;
	UINT32	CurrentDirectores[8];
}RTL_USER_PROCESS_PARAMETERS_WINXP_X86, *PRTL_USER_PROCESS_PARAMETERS_WINXP_X86;


typedef struct _RTL_USER_PROCESS_PARAMETERS_WIN7_X64 {
	UINT32 MaximumLength;
	UINT32 Length;
	UINT32 Flags;
	UINT32 DebugFlags;
	HANDLE ConsoleHandle;
	UINT32  ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;
	CURDIR CurrentDirectory;        // ProcessParameters
	UNICODE_STRING DllPath;         // ProcessParameters
	UNICODE_STRING ImagePathName;   // ProcessParameters
	UNICODE_STRING CommandLine;     // ProcessParameters
	PVOID   Environment;
	UINT32	StartingX;
	UINT32	StartingY;
	UINT32	CountX;
	UINT32	CountY;
	UINT32	CountCharsX;
	UINT32	CountCharsY;
	UINT32	FillAttribute;
	UINT32	WindowFlags;
	UINT32	ShowWindowFlags;
	UNICODE_STRING	WindowTitle;
	UNICODE_STRING	DesktopInfo;
	UNICODE_STRING	ShellInfo;
	UNICODE_STRING	RuntimeData;
	UINT32	CurrentDirectores[8];
	UINT64  EnvironmentSize;
	UINT64  EnvironmentVersion;
}RTL_USER_PROCESS_PARAMETERS_WIN7_X64, *PRTL_USER_PROCESS_PARAMETERS_WIN7_X64;


#ifdef _WIN64
#define PRTL_USER_PROCESS_PARAMETERS	PRTL_USER_PROCESS_PARAMETERS_WIN7_X64
#define RTL_USER_PROCESS_PARAMETERS		RTL_USER_PROCESS_PARAMETERS_WIN7_X64
#else   
#define PRTL_USER_PROCESS_PARAMETERS	PRTL_USER_PROCESS_PARAMETERS_WINXP_X86
#define RTL_USER_PROCESS_PARAMETERS		RTL_USER_PROCESS_PARAMETERS_WINXP_X86
#endif


#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60
#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef UINT32 GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

// PEB结构
typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		UINT32 CrossProcessFlags;
		struct
		{
			UINT32 ProcessInJob : 1;
			UINT32 ProcessInitializing : 1;
			UINT32 ProcessUsingVEH : 1;
			UINT32 ProcessUsingVCH : 1;
			UINT32 ProcessUsingFTH : 1;
			UINT32 ReservedBits0 : 27;
		};
		UINT32 EnvironmentUpdateCount;
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	UINT32 SystemReserved[1];
	UINT32 AtlThunkSListPtr32;
	PVOID ApiSetMap;
	UINT32 TlsExpansionCounter;
	PVOID TlsBitmap;
	UINT32 TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	UINT32 NumberOfProcessors;
	UINT32 NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;
	UINT32 NumberOfHeaps;
	UINT32 MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	UINT32 GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	UINT32 OSMajorVersion;
	UINT32 OSMinorVersion;
	UINT16 OSBuildNumber;
	UINT16 OSCSDVersion;
	UINT32 OSPlatformId;
	UINT32 ImageSubsystem;
	UINT32 ImageSubsystemMajorVersion;
	UINT32 ImageSubsystemMinorVersion;
	UINT_PTR ImageProcessAffinityMask;
	GDI_HANDLE_BUFFER GdiHandleBuffer;
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	UINT32 TlsExpansionBitmapBits[32];
	UINT32 SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	PVOID ActivationContextData;
	PVOID ProcessAssemblyStorageMap;
	PVOID SystemDefaultActivationContextData;
	PVOID SystemAssemblyStorageMap;
	SIZE_T MinimumStackCommit;
	PVOID* FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	UINT32 FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(UINT32) * 8)];
	UINT32 FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pContextData;
	PVOID pImageHeaderHash;
	union
	{
		UINT32 TracingFlags;
		struct
		{
			UINT32 HeapTracingEnabled : 1;
			UINT32 CritSecTracingEnabled : 1;
			UINT32 LibLoaderTracingEnabled : 1;
			UINT32 SpareTracingBits : 29;
		};
	};
	UINT64 CsrServerReadOnlySharedMemoryBase;
} PEB, *PPEB;


// Ldr 三根链表结构
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	UINT16 LoadCount;
	UINT16 TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			UINT32 CheckSum;
		};
	};
	union {
		struct {
			UINT32 TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	struct _ACTIVATION_CONTEXT * EntryPointActivationContext;

	PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef const struct _LDR_DATA_TABLE_ENTRY *PCLDR_DATA_TABLE_ENTRY;


LOADREMOTEDLL_API UINT_PTR WINAPI LoadDllByOEP(PVOID lParam);