// ע���HOOK�������������ָ������.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <windows.h>
#include <locale.h>
#include<fstream>
#include<iostream>  
#include <string>
#include <Shlwapi.h>

int main()
{
	printf("�����������������PID");
	DWORD dwPid=0;
	scanf("%d", &dwPid);
	// ���������������.
	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,FALSE,dwPid);
	if (hProc == INVALID_HANDLE_VALUE)
	{
		printf("��ʧ��,������Ȩ�޲���\n");
		return 0;
	}

	char dllPath[MAX_PATH] = "D:\\Personal\\Desktop\\DbgDemo\\x64\\Release\\HookOpenProcess.dll";

	// 2. ��dll·��д�뵽����������Ľ����ڴ���.
	LPVOID pBuff = NULL;
	pBuff = VirtualAllocEx(hProc,/*���̾��*/
		NULL,/*ָ���ĵ�ַ.*/
		4096,/*����Ĵ�С*/
		MEM_RESERVE | MEM_COMMIT,/*�ڴ��״̬*/
		PAGE_READWRITE /*�ڴ��ҳ����*/);
	if (pBuff == NULL)
	{
		printf("�����ڴ�ʧ��\n");
		return 0;
	}

	// 3. ��dll·��д�뵽��������ڴ���
	SIZE_T dwWrite = 0;
	WriteProcessMemory(hProc,  /*���̾��*/
		pBuff,  /*Ҫд��ĵ�ַ*/
		dllPath, /*Ҫд�뻺����*/
		strlen(dllPath) + 1, /*���������ֽ���*/
		&dwWrite/*����ʵ��д����ֽ���*/);

	// 4. ����Զ���߳�
	//    Ŀ��: Ϊ����Զ�̽����е���LoadLibrary
	HANDLE hThread = INVALID_HANDLE_VALUE;
	hThread = CreateRemoteThread(hProc, /*���̾��*/
		NULL, /*��ȫ������*/
		0,/*�߳�ջ���ֽ���*/
		(LPTHREAD_START_ROUTINE)&LoadLibraryA,/*�̵߳Ļص�����*/
		pBuff,/*�̻߳ص������ĸ��Ӳ���*/
		0,
		0);
	// �ȴ��߳��˳�.
	// ��Ҫ�ȴ�LoadLibrary�����Ľ���.
	WaitForSingleObject(hThread, -1);

	// �ͷ�Զ�̽��̵Ŀռ�.
	VirtualFreeEx(hProc, pBuff, 0, MEM_RELEASE);

	return 0;
}
