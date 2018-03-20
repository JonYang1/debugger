#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
using namespace std;
typedef struct _EFLAGS
{
	unsigned CF : 1;  // ��λ���λ
	unsigned Reserve1 : 1;
	unsigned PF : 1;  // ��������λ����ż����1ʱ���˱�־Ϊ1
	unsigned Reserve2 : 1;
	unsigned AF : 1;  // ������λ��־����λ3���н�λ���λʱ�ñ�־Ϊ1
	unsigned Reserve3 : 1;
	unsigned ZF : 1;  // ������Ϊ0ʱ���˱�־Ϊ1
	unsigned SF : 1;  // ���ű�־��������Ϊ��ʱ�ñ�־Ϊ1
	unsigned TF : 1;  // * �����־���˱�־Ϊ1ʱ��CPUÿ�ν���ִ��1��ָ��
	unsigned IF : 1;  // �жϱ�־��Ϊ0ʱ��ֹ��Ӧ�������жϣ���Ϊ1ʱ�ָ�
	unsigned DF : 1;  // �����־
	unsigned OF : 1;  // �����־������������������ﷶΧʱΪ1������Ϊ0
	unsigned IOPL : 2;  // ���ڱ�����ǰ�����I/O��Ȩ��
	unsigned NT : 1;  // ����Ƕ�ױ�־
	unsigned Reserve4 : 1;
	unsigned RF : 1;  // �����쳣��Ӧ���Ʊ�־λ��Ϊ1��ֹ��Ӧָ��ϵ��쳣
	unsigned VM : 1;  // Ϊ1ʱ��������8086ģʽ
	unsigned AC : 1;  // �ڴ�������־
	unsigned VIF : 1;  // �����жϱ�־
	unsigned VIP : 1;  // �����жϱ�־
	unsigned ID : 1;  // CPUID����־
	unsigned Reserve5 : 10;
}EFLAGS, *PEFLAGS;

#define MAX_SYM_NAME            2000
/* ��1�� 00 ִֻ��
��2�� 01 д�����ݶϵ�
��3�� 10 I / O�˿ڶϵ㣨ֻ����pentium + ��������CR4��DEλ��DE��CR4�ĵ�3λ ��
��4�� 11 ����д���ݶϵ�*/
enum en_type
{
	perform,
	write,
	IO,
	readPerform
};

class CDbgEngine {
public:
#define MAX_INPUT 1024   // ����̨������󳤶�
	CDbgEngine();
	~CDbgEngine();
	// ������ѭ��
	void DebugMain();
	// �����¼��ַ�
	DWORD DispatchDbgEvent(DEBUG_EVENT& de);
	// ���̴����¼�

	// �쳣�����¼�����Ŀʱ�䶼����
	DWORD OnException(DEBUG_EVENT& de);
	// �쳣�����¼�
	// ����ϵ��쳣
	DWORD OnExceptionCc(DEBUG_EVENT& de);
	BOOL breakpoint(LPVOID pAddress);//F2�ϵ�
	void DelateVect(DEBUG_EVENT dbgEvent, CONTEXT ct);//ɾ���ϵ�
	BOOL removeBreakpoint(HANDLE  hwnd, DEBUG_EVENT DbgEvent, CONTEXT ct, LPVOID pAddress);//�Ƴ��ϵ�
	BOOL setBreakpoint_hardExec();//Ӳ���ϵ��¼ִ�жϵ�
	BOOL setBreakpoint_hardExecRead(int typeb,ULONG_PTR uAddress, DWORD Len);//Ӳ���ϵ��¼ִ�жϵ�
	BOOL paging();//�ڴ��ҳ
	void registerA(CONTEXT ct);//��ʾ�Ĵ�����Ϣ
	void stackA(CONTEXT ct);//��ʾ��ջ
	void memory();//��ʾ�ڴ�
	void show();//��ʾ�ϵ�


	void CoBreak(DEBUG_EVENT& de,CONTEXT ct);//�����ϵ�
	bool GetModuleList(DWORD dwPId);//��ȡ����ģ����Ϣ

	// �����쳣
	DWORD OnExceptionSingleStep(DEBUG_EVENT& de);
	// �ڴ�����쳣
	DWORD OnExceptionAccess(DEBUG_EVENT& de);

	//��ʼ���Ĵ���
	DWORD OnCreateProcess(DEBUG_EVENT& de);
	// ��ӡ�Ĵ�����Ϣ
	VOID ShowRegisterInfo(CONTEXT& ct);
	// �ȴ��û������������
	DWORD WaitforUserCommand(DEBUG_EVENT& de);
	// �û�����
	// t����
	void UserCommandStepInto();
	// b����
	void UserCommandB(CHAR* pCommand);
	//bp�ϵ�
	void UserCommandBP(CHAR* pCommand);
	// u����
	void UserCommandDisasm(DEBUG_EVENT DbgEvent, CHAR* pCommand);
private:
	// ����ຯ��
	void DisasmAtAddr(DWORD addr, DEBUG_EVENT DbgEvent, DWORD dwCount = 10);
	UINT DBG_Disasm(HANDLE hProcess, LPVOID lpAddress, PWCHAR pOPCode, PWCHAR pASM, PWCHAR pComment);
private:
	// ���Խ��̵���Ϣ�����̴����¼���ʱ��ֵOnCreateProcess
	PROCESS_INFORMATION m_pi;
	// ��һ�εĵ���ѭ����ʼ��ʱ�����¸�ֵ
	LPDEBUG_EVENT m_pDbgEvt;



private:
	BOOL checkpoint = FALSE;//�����Ƿ����Լ��µĶϵ�
	vector<BYTE> oldByteA;//�����f2�ϵ�1���ֽ�
	vector<LPVOID> vectAddress;//�����¶εĵ�ַ
	vector<ULONG_PTR> veYdbg;//Ӳ���ϵ�
	vector<ULONG_PTR> veRead;//Ӳ�����ϵ�
	vector<LPVOID> vePaging;//�ڴ���ʶϵ�

	DWORD MemoryAccess;//�ڴ���ʶϵ�
	//HANDLE hProcess;//���߳�
	BOOL aa=FALSE;
	DWORD oldAccess;//�ӹ��ڴ��쳣Ȩ��
	bool  B_SoftwareB=FALSE;//����ϵ�
	bool  B_paging = false;//�ڴ���ʶϵ�
	char path[MAX_PATH];
	DWORD OEP;

	bool rm = false;//�ڴ�д��ϵ�
	int count=0;//���ڿ�������ϵ�ĸ���
	bool rK= TRUE;
	bool duanTiaoJ=false;//�����ϵ�


	BOOL MwControl = FALSE;

};

