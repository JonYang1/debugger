#pragma once
#include <windows.h>
class CPE
{
public:
	CPE();
	~CPE();
public:
	DWORD RVAToOffset(IMAGE_DOS_HEADER* pDos, DWORD dwRva);//����ƫ�ƺ���

	void PETou(LPCSTR filePath);

};

