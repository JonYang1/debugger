#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
using namespace std;
typedef struct _EFLAGS
{
	unsigned CF : 1;  // 进位或错位
	unsigned Reserve1 : 1;
	unsigned PF : 1;  // 计算结果低位包含偶数个1时，此标志为1
	unsigned Reserve2 : 1;
	unsigned AF : 1;  // 辅助进位标志，当位3处有进位或借位时该标志为1
	unsigned Reserve3 : 1;
	unsigned ZF : 1;  // 计算结果为0时，此标志为1
	unsigned SF : 1;  // 符号标志，计算结果为负时该标志为1
	unsigned TF : 1;  // * 陷阱标志，此标志为1时，CPU每次仅会执行1条指令
	unsigned IF : 1;  // 中断标志，为0时禁止响应（屏蔽中断），为1时恢复
	unsigned DF : 1;  // 方向标志
	unsigned OF : 1;  // 溢出标志，计算结果超出机器表达范围时为1，否则为0
	unsigned IOPL : 2;  // 用于标明当前任务的I/O特权级
	unsigned NT : 1;  // 任务嵌套标志
	unsigned Reserve4 : 1;
	unsigned RF : 1;  // 调试异常相应控制标志位，为1禁止响应指令断点异常
	unsigned VM : 1;  // 为1时启用虚拟8086模式
	unsigned AC : 1;  // 内存对齐检查标志
	unsigned VIF : 1;  // 虚拟中断标志
	unsigned VIP : 1;  // 虚拟中断标志
	unsigned ID : 1;  // CPUID检查标志
	unsigned Reserve5 : 10;
}EFLAGS, *PEFLAGS;

#define MAX_SYM_NAME            2000
/* （1） 00 只执行
（2） 01 写入数据断点
（3） 10 I / O端口断点（只用于pentium + ，需设置CR4的DE位，DE是CR4的第3位 ）
（4） 11 读或写数据断点*/
enum en_type
{
	perform,
	write,
	IO,
	readPerform
};

class CDbgEngine {
public:
#define MAX_INPUT 1024   // 控制台命令最大长度
	CDbgEngine();
	~CDbgEngine();
	// 调试主循环
	void DebugMain();
	// 调试事件分发
	DWORD DispatchDbgEvent(DEBUG_EVENT& de);
	// 进程创建事件

	// 异常调试事件，项目时间都在这
	DWORD OnException(DEBUG_EVENT& de);
	// 异常调试事件
	// 软件断点异常
	DWORD OnExceptionCc(DEBUG_EVENT& de);
	BOOL breakpoint(LPVOID pAddress);//F2断点
	void DelateVect(DEBUG_EVENT dbgEvent, CONTEXT ct);//删除断点
	BOOL removeBreakpoint(HANDLE  hwnd, DEBUG_EVENT DbgEvent, CONTEXT ct, LPVOID pAddress);//移除断点
	BOOL setBreakpoint_hardExec();//硬件断点记录执行断点
	BOOL setBreakpoint_hardExecRead(int typeb,ULONG_PTR uAddress, DWORD Len);//硬件断点记录执行断点
	BOOL paging();//内存分页
	void registerA(CONTEXT ct);//显示寄存器信息
	void stackA(CONTEXT ct);//显示堆栈
	void memory();//显示内存
	void show();//显示断点


	void CoBreak(DEBUG_EVENT& de,CONTEXT ct);//条件断点
	bool GetModuleList(DWORD dwPId);//获取进程模块信息

	// 单步异常
	DWORD OnExceptionSingleStep(DEBUG_EVENT& de);
	// 内存访问异常
	DWORD OnExceptionAccess(DEBUG_EVENT& de);

	//初始化寄存器
	DWORD OnCreateProcess(DEBUG_EVENT& de);
	// 打印寄存器信息
	VOID ShowRegisterInfo(CONTEXT& ct);
	// 等待用户输入调试命令
	DWORD WaitforUserCommand(DEBUG_EVENT& de);
	// 用户命令
	// t命令
	void UserCommandStepInto();
	// b命令
	void UserCommandB(CHAR* pCommand);
	//bp断点
	void UserCommandBP(CHAR* pCommand);
	// u命令
	void UserCommandDisasm(DEBUG_EVENT DbgEvent, CHAR* pCommand);
private:
	// 反汇编函数
	void DisasmAtAddr(DWORD addr, DEBUG_EVENT DbgEvent, DWORD dwCount = 10);
	UINT DBG_Disasm(HANDLE hProcess, LPVOID lpAddress, PWCHAR pOPCode, PWCHAR pASM, PWCHAR pComment);
private:
	// 调试进程的信息，进程创建事件的时候赋值OnCreateProcess
	PROCESS_INFORMATION m_pi;
	// 新一次的调试循环开始的时候重新赋值
	LPDEBUG_EVENT m_pDbgEvt;



private:
	BOOL checkpoint = FALSE;//控制是否是自己下的断点
	vector<BYTE> oldByteA;//保存的f2断点1个字节
	vector<LPVOID> vectAddress;//保存下段的地址
	vector<ULONG_PTR> veYdbg;//硬件断点
	vector<ULONG_PTR> veRead;//硬件读断点
	vector<LPVOID> vePaging;//内存访问断点

	DWORD MemoryAccess;//内存访问断点
	//HANDLE hProcess;//打开线程
	BOOL aa=FALSE;
	DWORD oldAccess;//接管内存异常权限
	bool  B_SoftwareB=FALSE;//软件断点
	bool  B_paging = false;//内存访问断点
	char path[MAX_PATH];
	DWORD OEP;

	bool rm = false;//内存写入断点
	int count=0;//用于控制软件断点的个数
	bool rK= TRUE;
	bool duanTiaoJ=false;//条件断点


	BOOL MwControl = FALSE;

};

