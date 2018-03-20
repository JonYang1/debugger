// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"
#include "detours/detours.h"
#include <TlHelp32.h>
#include <tchar.h>

#ifdef _WIN64
#pragma comment(lib,"detours\\lib.X64\\\detours.lib")
#else
#pragma comment(lib,"detours\\lib.X86\\\detours.lib")
#endif // _WIN64

typedef HANDLE (WINAPI *FnOpenProcess)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
);

FnOpenProcess g_pfnOpenProcess;
TCHAR g_processName[MAX_PATH] = { _T("DbgDemo.exe") };
HANDLE WINAPI MyOpenProcess(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
)
{
	// Ҫ����ָ������.
	// ͨ��������������.
	//  |- ��Ҫ���������б�, �ҵ����̶�Ӧ��PID
 	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
 	PROCESSENTRY32 procInfo = { sizeof(PROCESSENTRY32)};
 	Process32First(hSnap, &procInfo);

	// ���̱����Ĵ��뻹��bug
 	do 
 	{
 		if (_wcsicmp(g_processName, procInfo.szExeFile) == 0)
 		{
 			if (dwProcessId == procInfo.th32ProcessID)
 			{
 				return NULL;
 			}
 		}
 	} while (Process32Next(hSnap,&procInfo));

	// ����ԭʼAPI,��ɴ򿪽��̵Ĺ���
	return g_pfnOpenProcess(dwDesiredAccess,
							bInheritHandle,
							dwProcessId);
}

//extern"C" void _setInt();

// ��OpenProcess����HOOK�ĺ���
extern"C" _declspec(dllexport) void hook()
{
	//_setInt();// �ֹ�����һ������ϵ�,ֻ���ڵ���
	g_pfnOpenProcess = &OpenProcess;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&g_pfnOpenProcess, MyOpenProcess);
	DetourTransactionCommit();
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hook();
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

