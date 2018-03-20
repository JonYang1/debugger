#include "stdafx.h"
#include "PE.h"


CPE::CPE()
{
}


CPE::~CPE()
{
}
//����ƫ�ƺ���
DWORD CPE::RVAToOffset(IMAGE_DOS_HEADER* pDos, DWORD dwRva)
{
	IMAGE_SECTION_HEADER* pScnHdr;

	IMAGE_NT_HEADERS* pNtHdr =
		(IMAGE_NT_HEADERS*)(pDos->e_lfanew + (DWORD)pDos);

	pScnHdr = IMAGE_FIRST_SECTION(pNtHdr);
	DWORD dwNumberOfScn = pNtHdr->FileHeader.NumberOfSections;

	// 1. �������������ҵ���������
	for (int i = 0; i < dwNumberOfScn; ++i)
	{
		DWORD dwEndOfSection = pScnHdr[i].VirtualAddress + pScnHdr[i].SizeOfRawData;
		// �ж����RVA�Ƿ���һ�����εķ�Χ��
		if (dwRva >= pScnHdr[i].VirtualAddress
			&& dwRva < dwEndOfSection)
		{
			// 2. �����RVA�������ڵ�ƫ��:rva ��ȥ�׵�ַ
			DWORD dwOffset = dwRva - pScnHdr[i].VirtualAddress;
			// 3. ��������ƫ�Ƽ������ε��ļ���ʼƫ��
			return dwOffset + pScnHdr[i].PointerToRawData;
		}
	}
	return -1;
}

//PE
void CPE::PETou(LPCSTR filePath)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFileA(filePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("�ļ�������\n");
		return ;
	}

	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);

	// 2. �����ڴ�ռ�
	BYTE* pBuf = new BYTE[dwFileSize];

	// 3. ���ļ����ݶ�ȡ���ڴ���
	DWORD dwRead = 0;
	ReadFile(hFile,
		pBuf,
		dwFileSize,
		&dwRead,
		NULL);
	// 1. �ҵ�Dosͷ
	IMAGE_DOS_HEADER* pDosHdr;// DOSͷ
	pDosHdr = (IMAGE_DOS_HEADER*)pBuf;

	// 2. �ҵ�Ntͷ
	IMAGE_NT_HEADERS* pNtHdr = NULL;
	pNtHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pDosHdr);

	// 3. �ҵ���չͷ
	IMAGE_OPTIONAL_HEADER* pOptHdr = NULL;
	pOptHdr = &pNtHdr->OptionalHeader;

	// 4. �ҵ�����Ŀ¼��
	IMAGE_DATA_DIRECTORY* pDataDir = NULL;
	pDataDir = pOptHdr->DataDirectory;
	// 5. �õ�������RVA
	DWORD dwImpRva = pDataDir[1].VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* pImpArray;

	pImpArray = (IMAGE_IMPORT_DESCRIPTOR*)
		(RVAToOffset(pDosHdr, dwImpRva) + (DWORD)pDosHdr);
	// �����ı�־����һ��ȫ0��Ԫ����Ϊ��β
	while (pImpArray->Name != 0)
	{
		// �����Dll������(Rva)
		DWORD dwNameOfs = RVAToOffset(pDosHdr, pImpArray->Name);
		char* pDllName = (char*)(dwNameOfs + (DWORD)pDosHdr);
		printf("�����ĵ�ַ:[%s]\n", pDllName);
		pImpArray->OriginalFirstThunk;
		pImpArray->FirstThunk;
		DWORD INTOfs = RVAToOffset(pDosHdr, pImpArray->FirstThunk);
		DWORD IATOfs = RVAToOffset(pDosHdr, pImpArray->FirstThunk);
		IMAGE_THUNK_DATA* pInt = NULL;
		IMAGE_THUNK_DATA* pIat = NULL;
		pInt = (IMAGE_THUNK_DATA*)(INTOfs + (DWORD)pDosHdr);
		pIat = (IMAGE_THUNK_DATA*)(IATOfs + (DWORD)pDosHdr);
		while (pInt->u1.Function != 0)
		{
			if (IMAGE_SNAP_BY_ORDINAL32(pInt->u1.Function))
			{
			
			//	printf("%d", pInt->u1.Ordinal & 0xFFFF);
			}
			else
			{
				IMAGE_IMPORT_BY_NAME* pImpName;
				DWORD dwImpNameOfs = RVAToOffset(pDosHdr, pInt->u1.Function);
				pImpName = (IMAGE_IMPORT_BY_NAME*)
					(dwImpNameOfs + (DWORD)pDosHdr);
				

			//	printf("%",pImpName->Hint);
			}
			++pInt;
		}
		++pImpArray;
		
	}


	// 5. �ҵ�������
	DWORD dwExpRva = pDataDir[0].VirtualAddress;

	// 5.1 �õ�RVA���ļ�ƫ��
	DWORD dwExpOfs = RVAToOffset(pDosHdr, dwExpRva);
	IMAGE_EXPORT_DIRECTORY* pExpTab = NULL;
	pExpTab = (IMAGE_EXPORT_DIRECTORY*)(dwExpOfs + (DWORD)pDosHdr);
	// 1. ����DLL����
	DWORD dwNameOfs = RVAToOffset(pDosHdr, pExpTab->Name);
	char* pDllName =(char*)(dwNameOfs + (DWORD)pDosHdr);
	printf("������ĵ�ַ : %s\n", pDllName);

	// �������ű�
	DWORD dwExpAddrTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfFunctions);
	DWORD dwExpNameTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfNames);
	DWORD dwExpOrdTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfNameOrdinals);

	// �����еĵ�ַ��,���ƶ���һ��DWORD��������
	DWORD* pExpAddr =
		(DWORD*)(dwExpAddrTabOfs + (DWORD)pDosHdr);

	DWORD* pExpName =
		(DWORD*)(dwExpNameTabOfs + (DWORD)pDosHdr);

	// ��ű���WORD���͵�����
	DWORD* pExpOrd =
		(DWORD*)(dwExpOrdTabOfs + (DWORD)pDosHdr);

	// �������еĺ�����ַ
	for (int i = 0; i< pExpTab->NumberOfFunctions; ++i)
	{
		printf("������ַ(RVA):[%08X]\n", pExpAddr[i]);
		// ���ҵ�ǰ�������ĵ�ַ��û������
		int j = 0;
		for (; j<pExpTab->NumberOfNames; ++j)
		{
			if (i == pExpOrd[j])
				break;
		}
		if (j < pExpTab->NumberOfNames)
		{			
			DWORD dwNameRva = pExpName[j];
			DWORD dwNameOfs = RVAToOffset(pDosHdr, dwNameRva);
			char* pFunctionName = nullptr;
			pFunctionName = (char*)(dwNameOfs + (DWORD)pDosHdr);
			printf("\t������:[%s]\n", pFunctionName);
		}
		else
		{		
			if (pExpAddr[i] != 0)
			{
				printf("\t�������[%04X]\n", pExpTab->Base + i);
			}
		}
	}
}
