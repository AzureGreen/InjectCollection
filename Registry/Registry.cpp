// Registry.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>

using namespace std;

int main()
{
	LSTATUS Status = 0;
#ifdef _WIN64
	WCHAR*	wzSubKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
#else
	WCHAR*	wzSubKey = L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
#endif // _WIN64
	HKEY	hKey = NULL;

	// 打开注册表
	Status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,		// 要打开的主键
		wzSubKey,			// 要打开的子键名字地址
		0,					// 保留，传0
		KEY_ALL_ACCESS,		// 打开的方式
		&hKey);				// 返回的子键句柄
	if (Status != ERROR_SUCCESS)
	{
		return 0;
	}

	WCHAR*	wzValueName = L"AppInit_DLLs";
	DWORD	dwValueType = 0;
	UINT8	ValueData[MAX_PATH] = { 0 };
	DWORD	dwReturnLength = 0;

	// 查询注册表
	Status = RegQueryValueExW(hKey,		// 子键句柄
		wzValueName,		// 待查询键值的名称
		NULL,				// 保留
		&dwValueType,		// 数据类型
		ValueData,			// 键值
		&dwReturnLength);

	// 准备我们要写入的Dll路径
	WCHAR	wzDllFullPath[MAX_PATH] = { 0 };
	GetCurrentDirectoryW(MAX_PATH, wzDllFullPath);

#ifdef _WIN64
	wcscat_s(wzDllFullPath, L"\\x64NormalDll.dll");
#else
	wcscat_s(wzDllFullPath, L"\\x86NormalDll.dll");
#endif

	// 设置键值
	Status = RegSetValueExW(hKey,
		wzValueName,
		NULL,
		dwValueType,
		(CONST BYTE*)wzDllFullPath,
		(lstrlen(wzDllFullPath) + 1) * sizeof(WCHAR));
	if (Status != ERROR_SUCCESS)
	{
		return 0;
	}

	wzValueName = L"LoadAppInit_DLLs";
	DWORD	dwLoadAppInit = 1;

	// 查询注册表
	Status = RegQueryValueExW(hKey, wzValueName, NULL, &dwValueType, ValueData, &dwReturnLength);

	// 设置键值
	Status = RegSetValueExW(hKey, wzValueName, NULL, dwValueType, (CONST BYTE*)&dwLoadAppInit, sizeof(DWORD));
	if (Status != ERROR_SUCCESS)
	{
		return 0;
	}

	printf("Input Any Key To Resume\r\n");

	getchar();
	getchar();

	// 恢复键值
	dwLoadAppInit = 0;
	Status = RegQueryValueExW(hKey, wzValueName, NULL, &dwValueType, ValueData, &dwReturnLength);
	Status = RegSetValueExW(hKey, wzValueName, NULL, dwValueType, (CONST BYTE*)&dwLoadAppInit, sizeof(DWORD));

	wzValueName = L"AppInit_DLLs";
	ZeroMemory(wzDllFullPath, (lstrlen(wzDllFullPath) + 1) * sizeof(WCHAR));
	Status = RegQueryValueExW(hKey, wzValueName, NULL, &dwValueType, ValueData, &dwReturnLength);
	Status = RegSetValueExW(hKey, wzValueName, NULL, dwValueType, (CONST BYTE*)wzDllFullPath, 0);

	RegCloseKey(hKey);

	return 0;
}
