#pragma once
#ifndef ADDSECTION_H_
#define ADDSECTION_H_
#include "stdafx.h"

/*
	类名称：AddSection
	用途：添加一个区段
	时间：2018/11/30
*/

class AddSection
{
public:
	AddSection();

	~AddSection();

public:
	void puModifySectioNumber(){ this->ModifySectionNumber(); }

	void puModifyProgramEntryPoint(){ this->ModifyProgramEntryPoint(); }

	void puModifySizeofImage(){ this->ModifySizeofImage(); }

	BOOL puModifySectionInfo(BYTE* Name, const DWORD & size){ return this->ModifySectionInfo(Name, size); }

	BOOL puAddNewSectionByData(const DWORD & size){ return this->AddNewSectionByteData(size); }

	void* puGetNewBaseAddress(){ return this->newlpBase; }

	DWORD puGetNewBaseSize(){ return this->FileSize + 0x1000; }


private:
	// 1. 修改区段数量
	BOOL ModifySectionNumber();
	// 2. 修改区段信息(RVA\大小\属性)
	BOOL ModifySectionInfo(const BYTE* Name, const DWORD & size);
	// 3. 修改程序入口点
	BOOL ModifyProgramEntryPoint();
	// 4. 修改SizeImage
	BOOL ModifySizeofImage();
	// 5. 增加新的字节(一定最后在调用)
	BOOL AddNewSectionByteData(const DWORD & size);

private:
	// 保存FileImage
	void* pFileBaseData = nullptr;
	// 保存Nt头
	void* pNtHeadre = nullptr;
	// 保存区段头
	void* pSectionHeadre = nullptr;
	// 保存区段一共多少个字节 (区段个数*每个区段大小--不是区段数据而是区段结构体（保存区段信息的大小）)
	DWORD SectionSizeof = 0;
	// 保存文件大小
	DWORD FileSize = 0;
	// 新内存空间
	static char* newlpBase;
	// 保存文件句柄
	HANDLE FileHandle = nullptr;
	// 新区段
	PIMAGE_SECTION_HEADER NewpSection = { 0 };
	// 保存原始OEP
	DWORD OldOep = 0;
};


#endif