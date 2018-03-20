#include "stdafx.h"
#include "DbgEngine.h"
#include "MyType.h"
#include <DbgHelp.h>
#include <TlHelp32.h>
/*******************************/
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "Bea/headers/BeaEngine.h"
#pragma comment(lib, "Bea/Win32/Lib/BeaEngine.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
/*******************************/
#include <strsafe.h>
#include <process.h>
#include "PE.h"

CDbgEngine::CDbgEngine() {
	
}


CDbgEngine::~CDbgEngine() {
}


//���߼�ѭ��
void CDbgEngine::DebugMain() {
	//1.1	���Է�ʽ�򿪳���
	WCHAR szPath[] = L"D:\\Personal\\Desktop\\ipcon.exe";
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	BOOL bStatus = CreateProcess(szPath, NULL, NULL, NULL, FALSE,
		DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,	//�����½����� | ӵ���¿���̨,���̳��丸������̨��Ĭ�ϣ�
		NULL, NULL, &si, &m_pi);
	if (!bStatus) {
		printf("�������Խ���ʧ��!\n");
		return;
	}
	//1.2	��ʼ�������¼��ṹ��
	DEBUG_EVENT DbgEvent = { 0 };
	DWORD dwState = DBG_EXCEPTION_NOT_HANDLED;
	
	//2.�ȴ�Ŀ��Exe���������¼�
	while (1) {
		WaitForDebugEvent(&DbgEvent, INFINITE);
		//2.1 ���ݵ����¼�����,�ֱ���
		m_pDbgEvt = &DbgEvent;
		dwState = DispatchDbgEvent(DbgEvent);
		//2.2 �������쳣,�������б�����Exe
		ContinueDebugEvent(DbgEvent.dwProcessId, DbgEvent.dwThreadId, dwState);
	}
}

//�жϵ�������
DWORD CDbgEngine::DispatchDbgEvent(DEBUG_EVENT& de) {
	
	DWORD dwRet = DBG_EXCEPTION_NOT_HANDLED;
	switch (de.dwDebugEventCode) {
	case CREATE_PROCESS_DEBUG_EVENT:	//���̵��� ֻ����һ��
		OEP = (DWORD)de.u.CreateProcessInfo.lpStartAddress;
		dwRet = OnCreateProcess(de);
		break;
	case EXCEPTION_DEBUG_EVENT:			//�쳣���ԣ�
		dwRet = OnException(de);	//��Ҫ�õ�
		break;
	case CREATE_THREAD_DEBUG_EVENT:		//�̵߳���
	case EXIT_THREAD_DEBUG_EVENT:		//�˳��߳�
		break;
	case EXIT_PROCESS_DEBUG_EVENT:		//�˳�����
		dwRet = DBG_CONTINUE;
		break;
	case LOAD_DLL_DEBUG_EVENT:			//����DLL					
		break;
	case UNLOAD_DLL_DEBUG_EVENT:		//ж��DLL				
		dwRet = DBG_CONTINUE;
		break;
	case OUTPUT_DEBUG_STRING_EVENT:		//��������ַ���
	case RIP_EVENT:						//RIP����
		return dwRet;	//����
	}
	return dwRet;
}

//�쳣����
DWORD CDbgEngine::OnException(DEBUG_EVENT& de) {
	DWORD dwRet = DBG_EXCEPTION_NOT_HANDLED;
	switch (de.u.Exception.ExceptionRecord.ExceptionCode) {
		//����ϵ�
	case EXCEPTION_BREAKPOINT:
		//��һ��
		if (this->rK == TRUE)
		{	// ��OEP����һ������ϵ�
			breakpoint((LPVOID)OEP);
			this->rK = FALSE;
			goto Title;
		}
		dwRet = OnExceptionCc(de);
		break;
		//�����쳣
	case EXCEPTION_SINGLE_STEP:
		dwRet = OnExceptionSingleStep(de);
		if (MwControl == FALSE)
		{
			return DBG_CONTINUE;
		}
		break;
		//�ڴ�����쳣
	case EXCEPTION_ACCESS_VIOLATION:
		dwRet = OnExceptionAccess(de);
		if (MwControl==FALSE)
		{
			return DBG_CONTINUE;
		}
		
		break;
	default:
		break;
	}
	WaitforUserCommand(de);
Title:	return dwRet;
}

//����ϵ�
DWORD CDbgEngine::OnExceptionCc(DEBUG_EVENT& de) 
{

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// all register
	GetThreadContext(hThread, &ct);
	//�����ϵ�
	if (duanTiaoJ == true)
	{
		if (ct.Eax == 1)
		{
			UserCommandStepInto();
		}
		else
		{
			printf("~~~~~~~~~~~~~~~~~����������~~~~~~~~~~~~~~~~~~~~\n");
		}
	}



	DWORD dsSize = 0;
	for (size_t i = 0; i <vectAddress.size(); i++)
	{
		//�ô����쳣�ĵ�ַ���ȶ�
		if (de.u.Exception.ExceptionRecord.ExceptionAddress== vectAddress[i])
		{
			WriteProcessMemory(hThread, vectAddress[i], &oldByteA[i], 1, &dsSize);
			ct.Eip--;
			SetThreadContext(hThread, &ct);
		}
	}	
	return DBG_CONTINUE;
}

//F2
BOOL CDbgEngine::breakpoint(LPVOID pAddress)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
	//�ж϶ϵ��Ƿ����
	for (int i = 0; i < vectAddress.size(); ++i)
	{
		if (vectAddress[i] == pAddress)
		{
			printf("�ϵ��Ѿ�����");
			return TRUE;
		}
	}
	BYTE oldByte = 0;
	DWORD dsSize = 0;
	//������
	if (!ReadProcessMemory(hProcess, pAddress, &oldByte, 1, &dsSize))
	{
		return FALSE;
	}
	//дdiz
	BYTE cc = '\xcc';
	if (!WriteProcessMemory(hProcess, pAddress, &cc, 1, &dsSize))
	{
		return FALSE;
	}
	checkpoint = TRUE;
	//��¼�ϵ�
	vectAddress.push_back(pAddress);
	//�ϵ�����
	oldByteA.push_back(oldByte);
	B_SoftwareB == true;
	count++;

	return TRUE;
}

//ɾ���ϵ�
void CDbgEngine::DelateVect(DEBUG_EVENT dbgEvent, CONTEXT ct)
{
	HANDLE hThreadId = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwThreadId);
	//�ж��ǲ����Լ��Ķϵ�
	for (int i = 0; i < vectAddress.size(); ++i)
	{
		//�ж��ǲ����Լ��µĶϵ��ǵĻ�ֱ�ӷ���
		//���Ƿ�����
			DWORD aa = ct.Eip;
			if (vectAddress[i] == dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress)
			{		
				DWORD dsSize = 0;
				//�ָ��ϵ�
				if (!WriteProcessMemory(hThreadId, vectAddress[i], &oldByteA[i], 1, &dsSize))
				{
					return;
				}
				ct.Eip--;
				//�Ƴ�2���ϵ���Ϣ
				removeBreakpoint(hThreadId, dbgEvent, ct, (LPVOID)oldByteA[i]);
				oldByteA.erase(oldByteA.begin() + i);
				vectAddress.erase(vectAddress.begin() + i);

				ct.ContextFlags = CONTEXT_ALL;// all register
				SetThreadContext(hThreadId,&ct);
				UserCommandStepInto();
				break;
			}
	}	
}

//�Ƴ��ϵ�
BOOL CDbgEngine::removeBreakpoint(HANDLE hwnd, DEBUG_EVENT DbgEvent, CONTEXT ct, LPVOID pAddress)
{
	//ѭ���ж��¶ϵ�ĵط�
	for (int i = 0; i < vectAddress.size(); ++i)
	{
		if (vectAddress[i] == (LPVOID)DbgEvent.u.Exception.ExceptionRecord.ExceptionAddress)
		{
			DWORD dwsizo = 0;
			checkpoint = FALSE;
			//ct.Eip-= 1;
			//*pAddress -= 1;
			//�Ƴ��ϵ��ʱ���ַ-1;
			return WriteProcessMemory(hwnd, pAddress, &oldByteA[i], 1, &dwsizo);
		}
	}
	return FALSE;


}

//Ӳ��ִ�жϵ�
BOOL CDbgEngine::setBreakpoint_hardExec()
{
	printf("������Ӳ���ϵ�ĵ�ַ\n");
	DWORD pAddressb;
	scanf("%x", &pAddressb);
	getchar();
	HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, 0, m_pi.dwThreadId);
	//�ظ�ֵ�ж�
	for (int i = 0; i < veYdbg.size(); ++i)
	{
		if (veYdbg[i] == pAddressb)
		{
			printf("ֵ�Ѿ�����");
			return TRUE;
		}
	}
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0 == 0)//����
	{

		ct.Dr0 = pAddressb;
		pDr7->L0 = 1;//Ӳ���ϵ�ؼ�λ��
		pDr7->RW0 = 0;
		pDr7->LEN0 = 0;

	}
	else if (pDr7->L1 == 0)
	{
		ct.Dr1 = pAddressb;
		pDr7->RW1 = 0;
		pDr7->LEN1 = 0;
	}
	else if (pDr7->L2 == 0)
	{
		ct.Dr2 = pAddressb;
		pDr7->RW2 = 0;
		pDr7->LEN2 = 0;
	}
	else if (pDr7->L3 == 0)
	{
		ct.Dr3 = pAddressb;
		pDr7->RW3 = 0;
		pDr7->LEN3 = 0;
	}
	else
	{
		return FALSE;
	}
	//ѹ��Ӳ���ϵ�ĵ�ַ
	veYdbg.push_back(pAddressb);
	printf("Ӳ���ϵ�%x\n", pAddressb);
	SetThreadContext(hThread, &ct);
	return TRUE;
}
//Ӳ��д��ϵ�
BOOL CDbgEngine::setBreakpoint_hardExecRead(int typeb, ULONG_PTR uAddress,DWORD Len)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, m_pi.dwThreadId);

	//�ظ�ֵ�ж�
	for (int i = 0; i < veRead.size(); ++i)
	{
		if (veRead[i] == uAddress)
		{
			printf("ֵ�Ѿ�����");
			return TRUE;
		}
	}

	CONTEXT ct = { 0 };

	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread, &ct);
	//������볤��
	if (Len == 1)
	{
		uAddress = uAddress - uAddress % 2;
	}
	else if (Len == 3)
	{
		uAddress = uAddress - uAddress % 4;
	}
	else if (Len > 3)
	{
		return FALSE;
	}


	//�ж���Щ�Ĵ���û�б�ʹ��
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0 == 0)//����
	{
		ct.Dr0 = uAddress;
		pDr7->RW0 = typeb;//ֱ�ӰѸ�����дȨ��
		pDr7->LEN0 = Len;
		pDr7->L0 = 1;

	}
	else if (pDr7->L1 == 0)
	{
		ct.Dr1 = uAddress;
		pDr7->RW1 = typeb;
		pDr7->LEN1 = Len;
		pDr7->L1 = 1;
	}
	else if (pDr7->L2 == 0)
	{
		ct.Dr2 = uAddress;
		pDr7->RW2 = typeb;
		pDr7->LEN2 = Len;
		pDr7->L2 = 1;
	}
	else if (pDr7->L3 == 0)
	{
		ct.Dr3 = uAddress;
		pDr7->RW3 = typeb;
		pDr7->LEN3 = Len;
		pDr7->L3 = 1;
	}
	else
	{
		return FALSE;
	}
	//д��ϵ�
	veRead.push_back(uAddress);
	rm = true;

	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
	return TRUE;
}

//�ڴ��ҳ��������
BOOL CDbgEngine::paging()
{
	printf("�����ڴ�ϵ�ĵ�ַ ֻ������һ��\n");
	HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
	DWORD pAddressb;
	scanf("%x", &pAddressb);
	DWORD dwSize=1;//�ڴ��С
	//����Ϊ��Ч
	if (!VirtualProtectEx(hThread, (LPVOID)pAddressb, dwSize, PAGE_NOACCESS, &oldAccess))
	{
		return FALSE;
	}
	B_paging = true;//�����ڴ���ʶϵ�
	MemoryAccess = pAddressb;

	return TRUE;
}
//��ʾ�Ĵ�����Ϣ
void CDbgEngine::registerA(CONTEXT ct)
{
	printf("EAX=%08X\n""ECX=%08X\n""EDX=%08X\n""EBX=%08X\n"
			"ESI=%08X\n""EDI=%08X\n""ESP=%08X\n""EBP=%08X\n""EiP=%08X\n",
			ct.Eax, ct.Ecx, ct.Edx, ct.Ebx, ct.Esi, ct.Edi, ct.Esp, ct.Ebp, ct.Eip);
}
//��ʾ��ջ
void CDbgEngine::stackA(CONTEXT ct)
{
	HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);

	// ��ȡջ�ռ��С
	DWORD number = (ct.Ebp - ct.Esp) / 4 + 1;
	DWORD *pBuff = new DWORD[number];
	DWORD dwSize = 0;

	// ��ȡջ�ڴ�
	ReadProcessMemory(hThread, (LPCVOID)ct.Esp, pBuff, ct.Ebp - ct.Esp + 4, &dwSize);
	printf("��ǰ��ջ��\n");

	for (int i = 0; i < number; i++)
		printf("0x%08X: 0x%08X \n", ct.Esp + 4 * i, pBuff[i]);
	delete[] pBuff;
	
}
//��ʾ�ڴ�
void CDbgEngine::memory()
{
	printf("��������Ҫ�鿴���ڴ��ַ\n");
	DWORD aa = 0;
	scanf("%x", &aa);
	getchar();
	HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
	//���ڴ��ַ
	BYTE buffaa[MAX_PATH] = { 0 };
	DWORD dwReadaa = 0;
	ReadProcessMemory(hThread, (LPCVOID)aa, buffaa, MAX_PATH, &dwReadaa);
	for (int i = 0; i < dwReadaa; ++i)
	{
		if (i % 16 == 0)
		{
			printf("\n");
		}
		printf(" %x ", ((WORD*)buffaa)[i]);

	}
	printf("\n");
}
//��ʾ�ϵ�
void CDbgEngine::show()
{
	printf(" �ϵ����Ϣ--------------\n");
	for (int i=0;i<vectAddress.size();++i)
	{
		printf("%08X	%X\n", vectAddress[i], oldByteA[i]);
	}
	for (int i=0;i<veYdbg.size();++i)
	{
		printf("%08X\n", veYdbg[i]);
	}

}

//�����ϵ�
void CDbgEngine::CoBreak(DEBUG_EVENT& de,CONTEXT ct)
{
	printf("�����ϵ�ĵ�ַ\n");
	LPVOID pAddressb;
	scanf("%x", &pAddressb);
	duanTiaoJ = true;
	breakpoint((LPVOID)pAddressb);//�����ϵ�����һ��f2�ϵ�


}
//��ȡģ����Ϣ
bool CDbgEngine::GetModuleList(DWORD dwPId)
{	
		HANDLE   hModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
		// 1. ����һ��ģ����صĿ��վ��
		hModuleSnap = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE,  // ָ�����յ�����
			dwPId);            // ָ������
		if (hModuleSnap == INVALID_HANDLE_VALUE)
			return false;
		// 2. ͨ��ģ����վ����ȡ��һ��ģ����Ϣ
		if (!Module32First(hModuleSnap, &me32)) {
			CloseHandle(hModuleSnap);
			return false;
		}
		// 3. ѭ����ȡģ����Ϣ
		do {
			//me32.th32ProcessID;
			printf("ģ����%d  ", me32.hModule);
			printf("���ػ�ַ%d  ", me32.modBaseAddr);
			printf("ģ����%S  ", me32.szExePath);
			printf("\n");
		} while (Module32Next(hModuleSnap, &me32));
		// 4. �رվ�����˳�����
		CloseHandle(hModuleSnap);
		return true;
	
}

//�����쳣
DWORD CDbgEngine::OnExceptionSingleStep(DEBUG_EVENT& de)
{

	if (B_paging == true)
	{

		HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
		DWORD dwSize = 1;//�ڴ��С
						   //����Ϊ��Ч
		if (!VirtualProtectEx(hThread, (LPVOID)MemoryAccess, dwSize, PAGE_NOACCESS, &oldAccess))
		{
			return FALSE;
		}
		//WaitforUserCommand(de);
		UserCommandStepInto();//����
		MwControl =false;
		goto title;

	}



	//��ȡ�쳣�ĵ�ַ
	PVOID Address = de.u.Exception.ExceptionRecord.ExceptionAddress;
	HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, 0, m_pi.dwThreadId);
	// ��ȡ�̻߳���
	CONTEXT ConText = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(this->m_pi.hThread, &ConText);

	// ��ȡ�����쳣��Ӳ���ϵ� 1111B
	int Index = ConText.Dr6 & 0x0f;
	// ��ȡR7�Ĵ�����ֵ
	DBG_REG7 *r7 = (DBG_REG7*)&ConText.Dr7;

	// �жϴ�������һ��Ӳ���ϵ�,�Ѷϵ����û�ȥ
	switch (Index)
	{
	case 1: 
		r7->L0 = ConText.Dr0 = 0;
		break;
	case 2:
		r7->L1 = ConText.Dr1 = 0; 
		break;
	case 4: 
		r7->L2 = ConText.Dr2 = 0; 
		break;
	case 8: 
		r7->L3 = ConText.Dr3 = 0;
		break;
	}
	SetThreadContext(hThread, &ConText);
title:	return DBG_CONTINUE;
	
}

//�ڴ�����쳣��Ϣ
DWORD CDbgEngine::OnExceptionAccess(DEBUG_EVENT& de) 
{

	//�ڴ�д��ϵ�
	if (rm == true)
	{
		//Ӳ�������쳣
		PVOID Address = de.u.Exception.ExceptionRecord.ExceptionAddress;
		UserCommandStepInto();//�����ϵ�
	}
	

	//�ڴ���ʻָ�
	if (B_paging==true)
	{
		HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
		PVOID Addressaa = (LPVOID)de.u.Exception.ExceptionRecord.ExceptionInformation[1];
		//�ڴ��ַ  �ҵ�
		if (Addressaa == (LPVOID)MemoryAccess)
		{
			DWORD dwSize=1;//�ڴ��С
			//�����ҳ������
			if (!VirtualProtectEx(hThread, (LPVOID)MemoryAccess, dwSize, oldAccess, &oldAccess))
			{
				return FALSE;
			}
			UserCommandStepInto();//����
			B_paging = false;	
			MwControl = TRUE;

		}
		else
		{
			DWORD dwSize = 1;//�ڴ��С
							   //�����ҳ������
			DWORD newpro;

			if (!VirtualProtectEx(hThread, (LPVOID)MemoryAccess, dwSize, oldAccess, &newpro))
			{
				return FALSE;
			}
			UserCommandStepInto();//����
			MwControl = FALSE;

	
		}
		

	}

	if (B_SoftwareB==true)
	{
		B_SoftwareB = false;
		return DBG_CONTINUE;
	}
	
	return DBG_CONTINUE;
}



//�Ĵ�����Ϣ
VOID CDbgEngine::ShowRegisterInfo(CONTEXT& ct) {
	printf("~~~~~~~~~~~~~~~~~~�Ĵ�����Ϣ~~~~~~~~~~~~~~~~~~~~~\n"
		"EAX = 0x%x\tEBX = 0x%x\tECX = 0x%x\tEDX = 0x%x\t\n"
		"ESP = 0x%x\tEBP = 0x%x\tESI = 0x%x\tEIP = 0x%x\t\n"
		"Dr0 = 0x%x\tDr1 = 0x%x\tDr2 = 0x%x\tDr3 = 0x%x\t\n",
		ct.Eax, ct.Ebx, ct.Ecx, ct.Edx, ct.Esp, ct.Ebp, ct.Esi, ct.Eip,
		ct.Dr0, ct.Dr1, ct.Dr2, ct.Dr3
	);
}

//�û�����
DWORD CDbgEngine::WaitforUserCommand(DEBUG_EVENT& de)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId);

	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// all register
	GetThreadContext(hThread, &ct);
	
	CloseHandle(hThread);
	// 2.����������Ϣ
	DisasmAtAddr((DWORD)m_pDbgEvt->u.Exception.ExceptionRecord.ExceptionAddress, de, 5);
	// 3.�ȴ��û�����
	CHAR szCommand[MAX_INPUT] = {};
	int a = 0;
	de.dwThreadId;
	CPE PE;
	char path[MAX_PATH]= "D:\\Personal\\Desktop\\ipcon.exe";

	while (1) {
		printf(">>>");
		gets_s(szCommand, MAX_INPUT);
		switch (szCommand[0]) {
		case 'u':// ����� ���������û�����
			DisasmAtAddr((DWORD)m_pDbgEvt->u.Exception.ExceptionRecord.ExceptionAddress,de,10);
			break;
		case 't':// ����F7
			DelateVect(de, ct);//ɾ���ϵ�
			MwControl = TRUE;
			UserCommandStepInto();
			return DBG_CONTINUE;
		case 'p':// ����F8
			//UserCommandStepOver();
			break;
		case 'g':// go	
			return DBG_CONTINUE;
		case 'b':
			/*
			bp ����ϵ�
			bm �ڴ�ϵ�
			bh Ӳ���ϵ�
			bl ��ѯ�ϵ��б�
			*/
			aa = TRUE;
			UserCommandB(szCommand);
			break;
		case '1'://�Ĵ���
			registerA(ct);
			break;
		case '2'://��ջ
			stackA(ct);
			break;
		case '3'://�ڴ�	
			memory();
			break;
		case 'm':// �鿴ģ����Ϣ
			GetModuleList(de.dwProcessId);//PID
			break;
		case 'd':
			char* bb;
			scanf("%s",&bb);
			//FindApiAddressYJ(bb);
			break;
		case 'a'://�����ϵ�
			CoBreak(de,ct);//�����ϵ�
			break;
		case 'e':
			PE.PETou(path);
			break;
		default:
			printf("��������ȷ��ָ�\n");
			break;
		}
	}
	return DBG_CONTINUE;
}

//���õ���
void CDbgEngine::UserCommandStepInto() {
	
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ1
	GetThreadContext(hThread, &ct);
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	PDBG_REG6 pDr6 = (PDBG_REG6)&ct.Dr6;
	pElg->TF = 1;//�ؼ���2
	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
}

//�û���������
void CDbgEngine::UserCommandB(CHAR* pCommand) {
	// BP�ϵ����
	DWORD pAddressb;
	int type, len;
	switch (pCommand[1]) {
	case 'p':// bp �¶ϵ�
		UserCommandBP(pCommand); //F2
		break;
	case '1'://��ʾ�ϵ���Ϣ
		show();
		break;
	case 'h':// bh Ӳ���ϵ�
		setBreakpoint_hardExec();
		break;
	case 'w'://Ӳ����д�ϵ�
		printf("������Ȩ��,��ַ,����\n");
		scanf("%d", &type);
		scanf("%x", &pAddressb);
		getchar();
		setBreakpoint_hardExecRead(type, pAddressb,0);
		break;
	case 'm':// bm�ڴ���ʶϵ�
		//VirtualProtectEx �ڴ��ҳ����API
		paging();//�ڴ�ϵ�
		break;

	}
}

// ����BP�ϵ�
void CDbgEngine::UserCommandBP(CHAR* pCommand)
{
	//��ȡ�߳�
	printf("�������ַ\n");
	DWORD pAddressb;
	scanf("%x", &pAddressb);
	getchar();
	//�¶ϵ�
	breakpoint((LPVOID)pAddressb);

}

//U�����
void CDbgEngine::UserCommandDisasm(DEBUG_EVENT DbgEvent,CHAR* pCommand)
{
	char seps[] = " ";
	char *token = NULL;
	char *next_token = NULL;
	// token = 'u'
	token = strtok_s(pCommand, seps, &next_token);
	// ������ַ
	// token = address(123456)
	token = strtok_s(NULL, seps, &next_token);
	if (token == nullptr) {
		printf("��������ȷ��ָ�\n");
		return;
	}
	DWORD dwAddress = strtol(token, NULL, 16);
	
	if (!dwAddress) {
		printf("��������ȷ��ָ�\n");
		return;
	}
	// ���������
	DWORD dwCount = 10;
	// token = count(10)
	token = strtok_s(NULL, seps, &next_token);
	if (token != nullptr) {
		dwCount = strtol(token, NULL, 16);
		dwCount == 0 ? dwCount = 10 : dwCount;
	}
	DisasmAtAddr(dwAddress, DbgEvent ,dwCount);
}

DWORD CDbgEngine::OnCreateProcess(DEBUG_EVENT& de) 
{
	// ���������Ϣ�������߳���Ϣ
	m_pi.dwProcessId = de.dwProcessId;
	m_pi.dwThreadId = de.dwThreadId;
	// ���̾��������ʹ��
	m_pi.hProcess = de.u.CreateProcessInfo.hProcess;
	// ����߳̾������ʹ��
	m_pi.hThread = de.u.CreateProcessInfo.hThread;
	// ��������ģ����Ϣ
	// .......��
	return DBG_CONTINUE;
}



//����ಽ��
void CDbgEngine::DisasmAtAddr(DWORD addr, DEBUG_EVENT DbgEvent, DWORD dwCount/*= 10*/) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
	//1. �Ѷϵ��ֵд��ȥ����ֹӰ�췴���
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
	ShowRegisterInfo(ct);

	BOOL zhuan = FALSE;

	int a = 0;

	//1. �Ѷϵ��ֵд��ȥ����ֹӰ�췴���
	if (removeBreakpoint(hProcess, DbgEvent, ct, (LPVOID)addr) != FALSE)
	{
		for (int i = 0; i < vectAddress.size(); ++i)
		{
			if (vectAddress[i] == (LPVOID)addr)
			{
				zhuan = TRUE;
				//�Ƴ��ϵ�
				a = i;
				removeBreakpoint(hProcess, DbgEvent, ct, vectAddress[i]);
			}
		}
	}

	WCHAR szOpCode[50] = {};
	WCHAR szAsm[50] = {};
	WCHAR szComment[50] = {};
	//2.3 һ�η����1��,Ĭ�Ϸ����5���������Զ��巴���ָ����Ŀ��Ҳ��������������ָ��
	printf("%-10s %-20s%-32s%s\n", "addr", "opcode", "asm", "comment");
	UINT uLen;
	for (DWORD i = 0; i < dwCount; i++) {
		// �����
		uLen = DBG_Disasm(hProcess, (LPVOID)addr, szOpCode, szAsm, szComment);
		wprintf_s(L"0x%08x %-20s%-32s%s\n", addr, szOpCode, szAsm, szComment);
		addr += uLen;
	}
	//�ж��Ƿ�ִ�е�����,��ѵ�ַд��ȥ
	//3. �Ѳ���1��д��ȥ�Ķϵ�д����
	//�ǲ����Լ��µĶϵ�
	if (zhuan == TRUE)
	{
		for (int i = 0; i < vectAddress.size(); ++i)
		{
			if (vectAddress[i] == (LPVOID)addr)
			{
				zhuan = FALSE;
				//д��ϵ�	
				breakpoint(vectAddress[i]);
			}
		}
	}
	CloseHandle(hProcess);
}

//������---��
UINT CDbgEngine::DBG_Disasm(HANDLE hProcess, LPVOID lpAddress, PWCHAR pOPCode, PWCHAR pASM, PWCHAR pComment) {
	DWORD oldAccess = 0;
	VirtualProtectEx(hProcess, lpAddress, sizeof(DWORD), PAGE_READWRITE, &oldAccess);
	
	// 1. �����Գ�����ڴ渴�Ƶ�����
	DWORD  dwRetSize = 0;
	BYTE lpRemote_Buf[32] = {};
	ReadProcessMemory(hProcess, lpAddress, lpRemote_Buf, 32, &dwRetSize);
	// 2. ��ʼ�����������
	DISASM objDiasm;
	objDiasm.EIP = (UIntPtr)lpRemote_Buf; // ��ʼ��ַ
	objDiasm.VirtualAddr = (UINT64)lpAddress;     // �����ڴ��ַ��������������ڼ����ַ��
	objDiasm.Archi = 0;                     // AI-X86
	objDiasm.Options = 0x000;                 // MASM
											  // 3. ��������
	UINT unLen = Disasm(&objDiasm);
	if (-1 == unLen) return unLen;
	// 4. ��������ת��Ϊ�ַ���
	LPWSTR lpOPCode = pOPCode;
	PBYTE  lpBuffer = lpRemote_Buf;
	for (UINT i = 0; i < unLen; i++) {
		StringCbPrintf(lpOPCode++, 50, L"%X", *lpBuffer & 0xF0);
		StringCbPrintf(lpOPCode++, 50, L"%X", *lpBuffer & 0x0F);
		lpBuffer++;
	}
	// 6. ���淴������ָ��
	WCHAR szASM[50] = { 0 };
	MultiByteToWideChar(CP_ACP, 0, objDiasm.CompleteInstr, -1, szASM, _countof(szASM));
	StringCchCopy(pASM, 50, szASM);

	VirtualProtectEx(hProcess, lpAddress, sizeof(DWORD), oldAccess, &oldAccess);
	return unLen;
}

