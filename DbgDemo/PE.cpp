#include "stdafx.h"
#include "PE.h"


CPE::CPE()
{
}


CPE::~CPE()
{
}
//计算偏移函数
DWORD CPE::RVAToOffset(IMAGE_DOS_HEADER* pDos, DWORD dwRva)
{
	IMAGE_SECTION_HEADER* pScnHdr;

	IMAGE_NT_HEADERS* pNtHdr =
		(IMAGE_NT_HEADERS*)(pDos->e_lfanew + (DWORD)pDos);

	pScnHdr = IMAGE_FIRST_SECTION(pNtHdr);
	DWORD dwNumberOfScn = pNtHdr->FileHeader.NumberOfSections;

	// 1. 遍历所有区段找到所在区段
	for (int i = 0; i < dwNumberOfScn; ++i)
	{
		DWORD dwEndOfSection = pScnHdr[i].VirtualAddress + pScnHdr[i].SizeOfRawData;
		// 判断这个RVA是否在一个区段的范围内
		if (dwRva >= pScnHdr[i].VirtualAddress
			&& dwRva < dwEndOfSection)
		{
			// 2. 计算该RVA在区段内的偏移:rva 减去首地址
			DWORD dwOffset = dwRva - pScnHdr[i].VirtualAddress;
			// 3. 将区段内偏移加上区段的文件开始偏移
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
		printf("文件不存在\n");
		return ;
	}

	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);

	// 2. 申请内存空间
	BYTE* pBuf = new BYTE[dwFileSize];

	// 3. 将文件内容读取到内存中
	DWORD dwRead = 0;
	ReadFile(hFile,
		pBuf,
		dwFileSize,
		&dwRead,
		NULL);
	// 1. 找到Dos头
	IMAGE_DOS_HEADER* pDosHdr;// DOS头
	pDosHdr = (IMAGE_DOS_HEADER*)pBuf;

	// 2. 找到Nt头
	IMAGE_NT_HEADERS* pNtHdr = NULL;
	pNtHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pDosHdr);

	// 3. 找到扩展头
	IMAGE_OPTIONAL_HEADER* pOptHdr = NULL;
	pOptHdr = &pNtHdr->OptionalHeader;

	// 4. 找到数据目录表
	IMAGE_DATA_DIRECTORY* pDataDir = NULL;
	pDataDir = pOptHdr->DataDirectory;
	// 5. 得到导入表的RVA
	DWORD dwImpRva = pDataDir[1].VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* pImpArray;

	pImpArray = (IMAGE_IMPORT_DESCRIPTOR*)
		(RVAToOffset(pDosHdr, dwImpRva) + (DWORD)pDosHdr);
	// 结束的标志是以一个全0的元素作为结尾
	while (pImpArray->Name != 0)
	{
		// 导入的Dll的名字(Rva)
		DWORD dwNameOfs = RVAToOffset(pDosHdr, pImpArray->Name);
		char* pDllName = (char*)(dwNameOfs + (DWORD)pDosHdr);
		printf("导入表的地址:[%s]\n", pDllName);
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


	// 5. 找到导出表
	DWORD dwExpRva = pDataDir[0].VirtualAddress;

	// 5.1 得到RVA的文件偏移
	DWORD dwExpOfs = RVAToOffset(pDosHdr, dwExpRva);
	IMAGE_EXPORT_DIRECTORY* pExpTab = NULL;
	pExpTab = (IMAGE_EXPORT_DIRECTORY*)(dwExpOfs + (DWORD)pDosHdr);
	// 1. 解析DLL的名
	DWORD dwNameOfs = RVAToOffset(pDosHdr, pExpTab->Name);
	char* pDllName =(char*)(dwNameOfs + (DWORD)pDosHdr);
	printf("导出表的地址 : %s\n", pDllName);

	// 解析三张表
	DWORD dwExpAddrTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfFunctions);
	DWORD dwExpNameTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfNames);
	DWORD dwExpOrdTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfNameOrdinals);

	// 三张中的地址表,名称都是一个DWORD类型数组
	DWORD* pExpAddr =
		(DWORD*)(dwExpAddrTabOfs + (DWORD)pDosHdr);

	DWORD* pExpName =
		(DWORD*)(dwExpNameTabOfs + (DWORD)pDosHdr);

	// 序号表是WORD类型的数组
	DWORD* pExpOrd =
		(DWORD*)(dwExpOrdTabOfs + (DWORD)pDosHdr);

	// 遍历所有的函数地址
	for (int i = 0; i< pExpTab->NumberOfFunctions; ++i)
	{
		printf("函数地址(RVA):[%08X]\n", pExpAddr[i]);
		// 查找当前遍历到的地址有没有名称
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
			printf("\t函数名:[%s]\n", pFunctionName);
		}
		else
		{		
			if (pExpAddr[i] != 0)
			{
				printf("\t导出序号[%04X]\n", pExpTab->Base + i);
			}
		}
	}
}
