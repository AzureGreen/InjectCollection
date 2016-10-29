// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

DWORD CALLBACK CallBackRoutine(LPARAM lParam);


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{

		HANDLE ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CallBackRoutine, hModule, 0, NULL);

		CloseHandle(ThreadHandle);
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

DWORD CALLBACK CallBackRoutine(LPARAM lParam)
{
	HMODULE		ModuleBase = (HMODULE)lParam;
	MessageBoxA(0, 0, 0, 0);

	FreeLibraryAndExitThread(ModuleBase, 0);

	return 0;
}