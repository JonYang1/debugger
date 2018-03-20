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


//主逻辑循环
void CDbgEngine::DebugMain() {
	//1.1	调试方式打开程序
	WCHAR szPath[] = L"D:\\Personal\\Desktop\\ipcon.exe";
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	BOOL bStatus = CreateProcess(szPath, NULL, NULL, NULL, FALSE,
		DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,	//调试新建进程 | 拥有新控制台,不继承其父级控制台（默认）
		NULL, NULL, &si, &m_pi);
	if (!bStatus) {
		printf("创建调试进程失败!\n");
		return;
	}
	//1.2	初始化调试事件结构体
	DEBUG_EVENT DbgEvent = { 0 };
	DWORD dwState = DBG_EXCEPTION_NOT_HANDLED;
	
	//2.等待目标Exe产生调试事件
	while (1) {
		WaitForDebugEvent(&DbgEvent, INFINITE);
		//2.1 根据调试事件类型,分别处理
		m_pDbgEvt = &DbgEvent;
		dwState = DispatchDbgEvent(DbgEvent);
		//2.2 处理完异常,继续运行被调试Exe
		ContinueDebugEvent(DbgEvent.dwProcessId, DbgEvent.dwThreadId, dwState);
	}
}

//判断调试类型
DWORD CDbgEngine::DispatchDbgEvent(DEBUG_EVENT& de) {
	
	DWORD dwRet = DBG_EXCEPTION_NOT_HANDLED;
	switch (de.dwDebugEventCode) {
	case CREATE_PROCESS_DEBUG_EVENT:	//进程调试 只调用一次
		OEP = (DWORD)de.u.CreateProcessInfo.lpStartAddress;
		dwRet = OnCreateProcess(de);
		break;
	case EXCEPTION_DEBUG_EVENT:			//异常调试，
		dwRet = OnException(de);	//主要用到
		break;
	case CREATE_THREAD_DEBUG_EVENT:		//线程调试
	case EXIT_THREAD_DEBUG_EVENT:		//退出线程
		break;
	case EXIT_PROCESS_DEBUG_EVENT:		//退出进程
		dwRet = DBG_CONTINUE;
		break;
	case LOAD_DLL_DEBUG_EVENT:			//加载DLL					
		break;
	case UNLOAD_DLL_DEBUG_EVENT:		//卸载DLL				
		dwRet = DBG_CONTINUE;
		break;
	case OUTPUT_DEBUG_STRING_EVENT:		//输出调试字符串
	case RIP_EVENT:						//RIP调试
		return dwRet;	//废弃
	}
	return dwRet;
}

//异常分类
DWORD CDbgEngine::OnException(DEBUG_EVENT& de) {
	DWORD dwRet = DBG_EXCEPTION_NOT_HANDLED;
	switch (de.u.Exception.ExceptionRecord.ExceptionCode) {
		//软件断点
	case EXCEPTION_BREAKPOINT:
		//第一次
		if (this->rK == TRUE)
		{	// 在OEP设置一个软件断点
			breakpoint((LPVOID)OEP);
			this->rK = FALSE;
			goto Title;
		}
		dwRet = OnExceptionCc(de);
		break;
		//单步异常
	case EXCEPTION_SINGLE_STEP:
		dwRet = OnExceptionSingleStep(de);
		if (MwControl == FALSE)
		{
			return DBG_CONTINUE;
		}
		break;
		//内存访问异常
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

//软件断点
DWORD CDbgEngine::OnExceptionCc(DEBUG_EVENT& de) 
{

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// all register
	GetThreadContext(hThread, &ct);
	//条件断点
	if (duanTiaoJ == true)
	{
		if (ct.Eax == 1)
		{
			UserCommandStepInto();
		}
		else
		{
			printf("~~~~~~~~~~~~~~~~~条件不成立~~~~~~~~~~~~~~~~~~~~\n");
		}
	}



	DWORD dsSize = 0;
	for (size_t i = 0; i <vectAddress.size(); i++)
	{
		//用触发异常的地址来比对
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
	//判断断点是否存在
	for (int i = 0; i < vectAddress.size(); ++i)
	{
		if (vectAddress[i] == pAddress)
		{
			printf("断点已经存在");
			return TRUE;
		}
	}
	BYTE oldByte = 0;
	DWORD dsSize = 0;
	//读进程
	if (!ReadProcessMemory(hProcess, pAddress, &oldByte, 1, &dsSize))
	{
		return FALSE;
	}
	//写diz
	BYTE cc = '\xcc';
	if (!WriteProcessMemory(hProcess, pAddress, &cc, 1, &dsSize))
	{
		return FALSE;
	}
	checkpoint = TRUE;
	//记录断点
	vectAddress.push_back(pAddress);
	//断点数据
	oldByteA.push_back(oldByte);
	B_SoftwareB == true;
	count++;

	return TRUE;
}

//删除断点
void CDbgEngine::DelateVect(DEBUG_EVENT dbgEvent, CONTEXT ct)
{
	HANDLE hThreadId = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwThreadId);
	//判断是不是自己的断点
	for (int i = 0; i < vectAddress.size(); ++i)
	{
		//判断是不是自己下的断点是的话直接返回
		//不是放他走
			DWORD aa = ct.Eip;
			if (vectAddress[i] == dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress)
			{		
				DWORD dsSize = 0;
				//恢复断点
				if (!WriteProcessMemory(hThreadId, vectAddress[i], &oldByteA[i], 1, &dsSize))
				{
					return;
				}
				ct.Eip--;
				//移除2个断点信息
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

//移除断点
BOOL CDbgEngine::removeBreakpoint(HANDLE hwnd, DEBUG_EVENT DbgEvent, CONTEXT ct, LPVOID pAddress)
{
	//循环判断下断点的地方
	for (int i = 0; i < vectAddress.size(); ++i)
	{
		if (vectAddress[i] == (LPVOID)DbgEvent.u.Exception.ExceptionRecord.ExceptionAddress)
		{
			DWORD dwsizo = 0;
			checkpoint = FALSE;
			//ct.Eip-= 1;
			//*pAddress -= 1;
			//移除断点的时候地址-1;
			return WriteProcessMemory(hwnd, pAddress, &oldByteA[i], 1, &dwsizo);
		}
	}
	return FALSE;


}

//硬件执行断点
BOOL CDbgEngine::setBreakpoint_hardExec()
{
	printf("请输入硬件断点的地址\n");
	DWORD pAddressb;
	scanf("%x", &pAddressb);
	getchar();
	HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, 0, m_pi.dwThreadId);
	//重复值判断
	for (int i = 0; i < veYdbg.size(); ++i)
	{
		if (veYdbg[i] == pAddressb)
		{
			printf("值已经存在");
			return TRUE;
		}
	}
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0 == 0)//无用
	{

		ct.Dr0 = pAddressb;
		pDr7->L0 = 1;//硬件断点关键位置
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
	//压入硬件断点的地址
	veYdbg.push_back(pAddressb);
	printf("硬件断点%x\n", pAddressb);
	SetThreadContext(hThread, &ct);
	return TRUE;
}
//硬件写入断点
BOOL CDbgEngine::setBreakpoint_hardExecRead(int typeb, ULONG_PTR uAddress,DWORD Len)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, m_pi.dwThreadId);

	//重复值判断
	for (int i = 0; i < veRead.size(); ++i)
	{
		if (veRead[i] == uAddress)
		{
			printf("值已经存在");
			return TRUE;
		}
	}

	CONTEXT ct = { 0 };

	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread, &ct);
	//整理对齐长度
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


	//判断那些寄存器没有被使用
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0 == 0)//无用
	{
		ct.Dr0 = uAddress;
		pDr7->RW0 = typeb;//直接把给他读写权限
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
	//写入断点
	veRead.push_back(uAddress);
	rm = true;

	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
	return TRUE;
}

//内存分页属性设置
BOOL CDbgEngine::paging()
{
	printf("输入内存断点的地址 只能设置一次\n");
	HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
	DWORD pAddressb;
	scanf("%x", &pAddressb);
	DWORD dwSize=1;//内存大小
	//设置为无效
	if (!VirtualProtectEx(hThread, (LPVOID)pAddressb, dwSize, PAGE_NOACCESS, &oldAccess))
	{
		return FALSE;
	}
	B_paging = true;//控制内存访问断点
	MemoryAccess = pAddressb;

	return TRUE;
}
//显示寄存器信息
void CDbgEngine::registerA(CONTEXT ct)
{
	printf("EAX=%08X\n""ECX=%08X\n""EDX=%08X\n""EBX=%08X\n"
			"ESI=%08X\n""EDI=%08X\n""ESP=%08X\n""EBP=%08X\n""EiP=%08X\n",
			ct.Eax, ct.Ecx, ct.Edx, ct.Ebx, ct.Esi, ct.Edi, ct.Esp, ct.Ebp, ct.Eip);
}
//显示堆栈
void CDbgEngine::stackA(CONTEXT ct)
{
	HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);

	// 获取栈空间大小
	DWORD number = (ct.Ebp - ct.Esp) / 4 + 1;
	DWORD *pBuff = new DWORD[number];
	DWORD dwSize = 0;

	// 读取栈内存
	ReadProcessMemory(hThread, (LPCVOID)ct.Esp, pBuff, ct.Ebp - ct.Esp + 4, &dwSize);
	printf("当前堆栈：\n");

	for (int i = 0; i < number; i++)
		printf("0x%08X: 0x%08X \n", ct.Esp + 4 * i, pBuff[i]);
	delete[] pBuff;
	
}
//显示内存
void CDbgEngine::memory()
{
	printf("请输入需要查看的内存地址\n");
	DWORD aa = 0;
	scanf("%x", &aa);
	getchar();
	HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
	//读内存地址
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
//显示断点
void CDbgEngine::show()
{
	printf(" 断点的信息--------------\n");
	for (int i=0;i<vectAddress.size();++i)
	{
		printf("%08X	%X\n", vectAddress[i], oldByteA[i]);
	}
	for (int i=0;i<veYdbg.size();++i)
	{
		printf("%08X\n", veYdbg[i]);
	}

}

//条件断点
void CDbgEngine::CoBreak(DEBUG_EVENT& de,CONTEXT ct)
{
	printf("条件断点的地址\n");
	LPVOID pAddressb;
	scanf("%x", &pAddressb);
	duanTiaoJ = true;
	breakpoint((LPVOID)pAddressb);//条件断点上下一个f2断点


}
//获取模块信息
bool CDbgEngine::GetModuleList(DWORD dwPId)
{	
		HANDLE   hModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
		// 1. 创建一个模块相关的快照句柄
		hModuleSnap = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE,  // 指定快照的类型
			dwPId);            // 指定进程
		if (hModuleSnap == INVALID_HANDLE_VALUE)
			return false;
		// 2. 通过模块快照句柄获取第一个模块信息
		if (!Module32First(hModuleSnap, &me32)) {
			CloseHandle(hModuleSnap);
			return false;
		}
		// 3. 循环获取模块信息
		do {
			//me32.th32ProcessID;
			printf("模块句柄%d  ", me32.hModule);
			printf("加载基址%d  ", me32.modBaseAddr);
			printf("模块名%S  ", me32.szExePath);
			printf("\n");
		} while (Module32Next(hModuleSnap, &me32));
		// 4. 关闭句柄并退出函数
		CloseHandle(hModuleSnap);
		return true;
	
}

//单步异常
DWORD CDbgEngine::OnExceptionSingleStep(DEBUG_EVENT& de)
{

	if (B_paging == true)
	{

		HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
		DWORD dwSize = 1;//内存大小
						   //设置为无效
		if (!VirtualProtectEx(hThread, (LPVOID)MemoryAccess, dwSize, PAGE_NOACCESS, &oldAccess))
		{
			return FALSE;
		}
		//WaitforUserCommand(de);
		UserCommandStepInto();//单步
		MwControl =false;
		goto title;

	}



	//获取异常的地址
	PVOID Address = de.u.Exception.ExceptionRecord.ExceptionAddress;
	HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, 0, m_pi.dwThreadId);
	// 获取线程环境
	CONTEXT ConText = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(this->m_pi.hThread, &ConText);

	// 获取引发异常的硬件断点 1111B
	int Index = ConText.Dr6 & 0x0f;
	// 获取R7寄存器的值
	DBG_REG7 *r7 = (DBG_REG7*)&ConText.Dr7;

	// 判断触发了哪一个硬件断点,把断点设置回去
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

//内存访问异常信息
DWORD CDbgEngine::OnExceptionAccess(DEBUG_EVENT& de) 
{

	//内存写入断点
	if (rm == true)
	{
		//硬件访问异常
		PVOID Address = de.u.Exception.ExceptionRecord.ExceptionAddress;
		UserCommandStepInto();//单步断点
	}
	

	//内存访问恢复
	if (B_paging==true)
	{
		HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
		PVOID Addressaa = (LPVOID)de.u.Exception.ExceptionRecord.ExceptionInformation[1];
		//内存地址  找到
		if (Addressaa == (LPVOID)MemoryAccess)
		{
			DWORD dwSize=1;//内存大小
			//管理分页的属性
			if (!VirtualProtectEx(hThread, (LPVOID)MemoryAccess, dwSize, oldAccess, &oldAccess))
			{
				return FALSE;
			}
			UserCommandStepInto();//单步
			B_paging = false;	
			MwControl = TRUE;

		}
		else
		{
			DWORD dwSize = 1;//内存大小
							   //管理分页的属性
			DWORD newpro;

			if (!VirtualProtectEx(hThread, (LPVOID)MemoryAccess, dwSize, oldAccess, &newpro))
			{
				return FALSE;
			}
			UserCommandStepInto();//单步
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



//寄存器信息
VOID CDbgEngine::ShowRegisterInfo(CONTEXT& ct) {
	printf("~~~~~~~~~~~~~~~~~~寄存器信息~~~~~~~~~~~~~~~~~~~~~\n"
		"EAX = 0x%x\tEBX = 0x%x\tECX = 0x%x\tEDX = 0x%x\t\n"
		"ESP = 0x%x\tEBP = 0x%x\tESI = 0x%x\tEIP = 0x%x\t\n"
		"Dr0 = 0x%x\tDr1 = 0x%x\tDr2 = 0x%x\tDr3 = 0x%x\t\n",
		ct.Eax, ct.Ebx, ct.Ecx, ct.Edx, ct.Esp, ct.Ebp, ct.Esi, ct.Eip,
		ct.Dr0, ct.Dr1, ct.Dr2, ct.Dr3
	);
}

//用户交互
DWORD CDbgEngine::WaitforUserCommand(DEBUG_EVENT& de)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId);

	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// all register
	GetThreadContext(hThread, &ct);
	
	CloseHandle(hThread);
	// 2.输出反汇编信息
	DisasmAtAddr((DWORD)m_pDbgEvt->u.Exception.ExceptionRecord.ExceptionAddress, de, 5);
	// 3.等待用户命令
	CHAR szCommand[MAX_INPUT] = {};
	int a = 0;
	de.dwThreadId;
	CPE PE;
	char path[MAX_PATH]= "D:\\Personal\\Desktop\\ipcon.exe";

	while (1) {
		printf(">>>");
		gets_s(szCommand, MAX_INPUT);
		switch (szCommand[0]) {
		case 'u':// 反汇编 继续接受用户命令
			DisasmAtAddr((DWORD)m_pDbgEvt->u.Exception.ExceptionRecord.ExceptionAddress,de,10);
			break;
		case 't':// 单步F7
			DelateVect(de, ct);//删除断点
			MwControl = TRUE;
			UserCommandStepInto();
			return DBG_CONTINUE;
		case 'p':// 单步F8
			//UserCommandStepOver();
			break;
		case 'g':// go	
			return DBG_CONTINUE;
		case 'b':
			/*
			bp 软件断点
			bm 内存断点
			bh 硬件断点
			bl 查询断点列表
			*/
			aa = TRUE;
			UserCommandB(szCommand);
			break;
		case '1'://寄存器
			registerA(ct);
			break;
		case '2'://堆栈
			stackA(ct);
			break;
		case '3'://内存	
			memory();
			break;
		case 'm':// 查看模块信息
			GetModuleList(de.dwProcessId);//PID
			break;
		case 'd':
			char* bb;
			scanf("%s",&bb);
			//FindApiAddressYJ(bb);
			break;
		case 'a'://条件断点
			CoBreak(de,ct);//条件断点
			break;
		case 'e':
			PE.PETou(path);
			break;
		default:
			printf("请输入正确的指令：\n");
			break;
		}
	}
	return DBG_CONTINUE;
}

//设置单步
void CDbgEngine::UserCommandStepInto() {
	
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息1
	GetThreadContext(hThread, &ct);
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	PDBG_REG6 pDr6 = (PDBG_REG6)&ct.Dr6;
	pElg->TF = 1;//关键点2
	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
}

//用户交互续集
void CDbgEngine::UserCommandB(CHAR* pCommand) {
	// BP断点后面
	DWORD pAddressb;
	int type, len;
	switch (pCommand[1]) {
	case 'p':// bp 下断点
		UserCommandBP(pCommand); //F2
		break;
	case '1'://显示断点信息
		show();
		break;
	case 'h':// bh 硬件断点
		setBreakpoint_hardExec();
		break;
	case 'w'://硬件读写断点
		printf("请输入权限,地址,长度\n");
		scanf("%d", &type);
		scanf("%x", &pAddressb);
		getchar();
		setBreakpoint_hardExecRead(type, pAddressb,0);
		break;
	case 'm':// bm内存访问断点
		//VirtualProtectEx 内存分页属性API
		paging();//内存断点
		break;

	}
}

// 设置BP断点
void CDbgEngine::UserCommandBP(CHAR* pCommand)
{
	//获取线程
	printf("请输入地址\n");
	DWORD pAddressb;
	scanf("%x", &pAddressb);
	getchar();
	//下断点
	breakpoint((LPVOID)pAddressb);

}

//U反汇编
void CDbgEngine::UserCommandDisasm(DEBUG_EVENT DbgEvent,CHAR* pCommand)
{
	char seps[] = " ";
	char *token = NULL;
	char *next_token = NULL;
	// token = 'u'
	token = strtok_s(pCommand, seps, &next_token);
	// 反汇编地址
	// token = address(123456)
	token = strtok_s(NULL, seps, &next_token);
	if (token == nullptr) {
		printf("请输入正确的指令：\n");
		return;
	}
	DWORD dwAddress = strtol(token, NULL, 16);
	
	if (!dwAddress) {
		printf("请输入正确的指令：\n");
		return;
	}
	// 反汇编行数
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
	// 保存进程信息，和主线程信息
	m_pi.dwProcessId = de.dwProcessId;
	m_pi.dwThreadId = de.dwThreadId;
	// 进程句柄，放心使用
	m_pi.hProcess = de.u.CreateProcessInfo.hProcess;
	// 这个线程句柄谨慎使用
	m_pi.hThread = de.u.CreateProcessInfo.hThread;
	// 保存下主模块信息
	// .......略
	return DBG_CONTINUE;
}



//反汇编步进
void CDbgEngine::DisasmAtAddr(DWORD addr, DEBUG_EVENT DbgEvent, DWORD dwCount/*= 10*/) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, m_pi.dwProcessId);
	//1. 把断点的值写回去，防止影响反汇编
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
	ShowRegisterInfo(ct);

	BOOL zhuan = FALSE;

	int a = 0;

	//1. 把断点的值写回去，防止影响反汇编
	if (removeBreakpoint(hProcess, DbgEvent, ct, (LPVOID)addr) != FALSE)
	{
		for (int i = 0; i < vectAddress.size(); ++i)
		{
			if (vectAddress[i] == (LPVOID)addr)
			{
				zhuan = TRUE;
				//移除断点
				a = i;
				removeBreakpoint(hProcess, DbgEvent, ct, vectAddress[i]);
			}
		}
	}

	WCHAR szOpCode[50] = {};
	WCHAR szAsm[50] = {};
	WCHAR szComment[50] = {};
	//2.3 一次反汇编1条,默认反汇编5条，可以自定义反汇编指令数目，也可以由输入命令指定
	printf("%-10s %-20s%-32s%s\n", "addr", "opcode", "asm", "comment");
	UINT uLen;
	for (DWORD i = 0; i < dwCount; i++) {
		// 反汇编
		uLen = DBG_Disasm(hProcess, (LPVOID)addr, szOpCode, szAsm, szComment);
		wprintf_s(L"0x%08x %-20s%-32s%s\n", addr, szOpCode, szAsm, szComment);
		addr += uLen;
	}
	//判断是否执行到这里,这把地址写回去
	//3. 把步骤1中写回去的断点写回来
	//是不是自己下的断点
	if (zhuan == TRUE)
	{
		for (int i = 0; i < vectAddress.size(); ++i)
		{
			if (vectAddress[i] == (LPVOID)addr)
			{
				zhuan = FALSE;
				//写入断点	
				breakpoint(vectAddress[i]);
			}
		}
	}
	CloseHandle(hProcess);
}

//反汇编的---主
UINT CDbgEngine::DBG_Disasm(HANDLE hProcess, LPVOID lpAddress, PWCHAR pOPCode, PWCHAR pASM, PWCHAR pComment) {
	DWORD oldAccess = 0;
	VirtualProtectEx(hProcess, lpAddress, sizeof(DWORD), PAGE_READWRITE, &oldAccess);
	
	// 1. 将调试程序的内存复制到本地
	DWORD  dwRetSize = 0;
	BYTE lpRemote_Buf[32] = {};
	ReadProcessMemory(hProcess, lpAddress, lpRemote_Buf, 32, &dwRetSize);
	// 2. 初始化反汇编引擎
	DISASM objDiasm;
	objDiasm.EIP = (UIntPtr)lpRemote_Buf; // 起始地址
	objDiasm.VirtualAddr = (UINT64)lpAddress;     // 虚拟内存地址（反汇编引擎用于计算地址）
	objDiasm.Archi = 0;                     // AI-X86
	objDiasm.Options = 0x000;                 // MASM
											  // 3. 反汇编代码
	UINT unLen = Disasm(&objDiasm);
	if (-1 == unLen) return unLen;
	// 4. 将机器码转码为字符串
	LPWSTR lpOPCode = pOPCode;
	PBYTE  lpBuffer = lpRemote_Buf;
	for (UINT i = 0; i < unLen; i++) {
		StringCbPrintf(lpOPCode++, 50, L"%X", *lpBuffer & 0xF0);
		StringCbPrintf(lpOPCode++, 50, L"%X", *lpBuffer & 0x0F);
		lpBuffer++;
	}
	// 6. 保存反汇编出的指令
	WCHAR szASM[50] = { 0 };
	MultiByteToWideChar(CP_ACP, 0, objDiasm.CompleteInstr, -1, szASM, _countof(szASM));
	StringCchCopy(pASM, 50, szASM);

	VirtualProtectEx(hProcess, lpAddress, sizeof(DWORD), oldAccess, &oldAccess);
	return unLen;
}

