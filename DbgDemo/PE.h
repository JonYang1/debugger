#pragma once
#include <windows.h>
class CPE
{
public:
	CPE();
	~CPE();
public:
	DWORD RVAToOffset(IMAGE_DOS_HEADER* pDos, DWORD dwRva);//¼ÆËãÆ«ÒÆº¯Êý

	void PETou(LPCSTR filePath);

};

