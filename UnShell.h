#pragma once
#ifndef UNSHELL_H_
#define UNSHELL_H_
#include "stdafx.h"

/*
	类名称：UnShell
	用途：脱壳
	时间：2018/12/7
*/

class UnShell
{
public:
	UnShell();
	~UnShell();

public:
	void puRepCompressionData(){ this->RepCompressionData(); }
	void puDeleteSectionInfo(){ this->DeleteSectionInfo(); }
	BOOL puSaveUnShell(){ return this->SaveUnShell(); }

private:
	// 恢复压缩的数据
	BOOL RepCompressionData();
	// 删除区段数据
	BOOL DeleteSectionInfo();
	// 保存及收尾工作
	BOOL SaveUnShell();

private:
	// 保存文件基址
	void* m_Base = nullptr;
	// 保存文件NT
	void* m_NtAddress = nullptr;
	// 保存文件句柄
	HANDLE hFile = nullptr;
	// 保存stub数据
	void* m_studBase = nullptr;
	// 保存PE数据
	PIMAGE_DOS_HEADER pDosHander;
	PIMAGE_NT_HEADERS pHeadres;
	PIMAGE_SECTION_HEADER pSection;
	// 保存完整的解压数据
	char* UnShellNewFile = nullptr;
	// 正常区段数据大小
	DWORD TotaldwSize = 0;
	// 保存解压后的数据
	char* Sectionbuf = nullptr;
	// 文件指针
	FILE *fpFile = nullptr;
};

#endif