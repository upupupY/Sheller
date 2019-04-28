#pragma once
#ifndef STUDDATA_H_
#define STUDDATA_H_
#include "stdafx.h"


/*
	类名称：studData
	用途：stud数据相关操作
	时间：2018/12/1
	修改日期：2018/12/2
*/


class studData
{
public:
	studData();
	~studData();

public:
	void puLoadLibraryStud(){ this->LoadLibraryStud(); }

	void puRepairReloCationStud(){ this->RepairReloCationStud(); }

	BOOL puCopyStud(){ return this->CopyStud(); }

private:
	// 加载stud
 	BOOL LoadLibraryStud();
	// 修复重定位
	BOOL RepairReloCationStud();
	// 拷贝stud数据到新增区段
	BOOL CopyStud();

private:
	// 保存导出函数的地址
	void* dexportAddress = 0; // main
	void* WinMain = 0;		  // WinMain
	// 保存加载基址stud
	void* m_studBase = nullptr;
	// 保存当前文件lpBase加载基址
	void* m_lpBase = nullptr;
	// 保存新区段的起始地址
	DWORD m_dwNewSectionAddress = 0;
	// stud原区段的起始位置
	DWORD m_dwStudSectionAddress = 0;
	// 保存OEP原始
	DWORD m_Oep = 0;
	// 保存ImageBase
	DWORD m_ImageBase = 0;
};

#endif