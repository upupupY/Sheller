#include "AddSection.h"
#include "puPEinfoData.h"


char* AddSection::newlpBase = nullptr;

AddSection::AddSection()
{
	PuPEInfo obj_PuPE;

	pFileBaseData = obj_PuPE.puGetImageBase();

	pNtHeadre = obj_PuPE.puGetNtHeadre();

	pSectionHeadre = obj_PuPE.puGetSection();

	FileSize = obj_PuPE.puFileSize();

	FileHandle = obj_PuPE.puFileHandle();

	OldOep = obj_PuPE.puOldOep();
}

AddSection::~AddSection()
{

}

// 修改区段数量
BOOL AddSection::ModifySectionNumber()
{
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)this->pNtHeadre;

	DWORD temp = pNtHeaders->FileHeader.NumberOfSections;

	SectionSizeof = temp * 0x28;

	pNtHeaders->FileHeader.NumberOfSections += 0x1;

	return TRUE;
}

// 修改区段信息(RVA\大小\属性)
BOOL AddSection::ModifySectionInfo(const BYTE* Name, const DWORD & size)
{
	DWORD pSectionAddress = (DWORD)pSectionHeadre;
	// 获取最后一个区段结构的地址(末尾，下一个开始出)
	pSectionAddress = pSectionAddress + SectionSizeof - 0x28;
	// 保存上一个的区段信息
	PIMAGE_SECTION_HEADER PtrpSection = (PIMAGE_SECTION_HEADER)pSectionAddress;
	// 新区段地址
	pSectionAddress += 0x28;
	NewpSection = (PIMAGE_SECTION_HEADER)pSectionAddress;
	// 修改新区段名称
	memcpy(NewpSection->Name, Name, sizeof(Name));
	DWORD dwtemps = PtrpSection->VirtualAddress + PtrpSection->SizeOfRawData;
	// 内存对齐修复（0x1000）
	__asm{
		pushad;
		mov		esi, dwtemps;
		mov		eax, dwtemps;
		mov		edx, 0x1;
		mov		cx, 0x1000;
		div		cx;
		test	dx, dx;
		jz		MemSucess
		shr		dx, 12;
		inc		dx;
		shl		dx, 12;
		add		esi, edx;
		shr		esi, 12;
		shl		esi, 12;
		mov		dwtemps, esi;
	MemSucess:
		popad
	}
	NewpSection->VirtualAddress = dwtemps;
	// 文件对齐修复
	/*
		缺少一步判断：虽然这种情况极少数
			判断是否文件末尾，如果不是末尾地址，使用文件末尾地址+1（否则有可能会覆盖一些数据）
	*/
	DWORD Temp = PtrpSection->SizeOfRawData + PtrpSection->PointerToRawData;
	// 对齐测试数据 DWORD Temp = 0x00AA4567;
	__asm{
		pushad;
		mov		esi, Temp;
		mov		edx, 0x1;
		mov		eax, Temp;
		mov		ecx, 0x200;
		div		cx;
		test	dx, dx;
		jz		FileSucess
		xor		eax, eax
		mov		ax, 0x200;
		sub		ax, dx;
		add		esi, eax;
		mov		Temp, esi;
	FileSucess:
		popad
	}
	// 新区段保存对齐后的数据保存
	NewpSection->PointerToRawData = Temp;
	// 新区段大小(0x1000)大小
	NewpSection->SizeOfRawData = size;
	NewpSection->Misc.VirtualSize = NewpSection->SizeOfRawData;
	// 区段属性可读可写可执行
	NewpSection->Characteristics = 0xE00000E0;
	return TRUE;
}

// 修改入口点
BOOL AddSection::ModifyProgramEntryPoint()
{
	// 入口点等于VirtualAddress
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)pNtHeadre;

	pNt->OptionalHeader.AddressOfEntryPoint = NewpSection->VirtualAddress;

	return TRUE;
}

// 修改镜像基址大小及去掉随机地址
BOOL AddSection::ModifySizeofImage()
{
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)pNtHeadre;

	pNt->OptionalHeader.SizeOfImage = NewpSection->VirtualAddress + NewpSection->SizeOfRawData;
	
	pNt->OptionalHeader.DllCharacteristics = 0x8000;
	
	return TRUE;
}

// 增加新的字节(一定最后在调用)
BOOL AddSection::AddNewSectionByteData(const DWORD & size)
{
	// 申请新的堆空间
	newlpBase = (char *)malloc(FileSize + size);
	// 初始化空间
	memset(newlpBase, 0, (FileSize + size));
	// 拷贝修改后的数据到新内存空间
	memcpy(newlpBase, pFileBaseData, FileSize);
	// 释放原来的空间
	free(pFileBaseData);

	DWORD dWriteSize = 0; OVERLAPPED OverLapped = { 0 };

	int nRetCode = WriteFile(FileHandle, newlpBase, (FileSize + size), &dWriteSize, &OverLapped);

	free(newlpBase);

	if (dWriteSize == 0){ AfxMessageBox(L"CreateSection WriteFIle faliuer"); return FALSE; }

	return TRUE;
}

