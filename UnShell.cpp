#include "UnShell.h"
#include "./Stud/Stud.h"
#include <malloc.h>
#include "lz4.h"
#include "puPEinfoData.h"

extern _Stud* g_stu;

UnShell::UnShell()
{
	PuPEInfo obj_puPe;

	HANDLE tempHandle = obj_puPe.puFileHandle();

	CloseHandle(tempHandle);

	hFile = CreateFile(L"C:\\Users\\Administrator\\Desktop\\CompressionMask.exe", GENERIC_READ | GENERIC_WRITE, FALSE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD dwSize = GetFileSize(hFile, NULL);

	m_Base = (void *)malloc(dwSize);

	memset(m_Base, 0, dwSize);

	DWORD dwRead = 0;

	OVERLAPPED OverLapped = { 0 };

	int nRetCode = ReadFile(hFile, m_Base, dwSize, &dwRead, &OverLapped);

	pDosHander = (PIMAGE_DOS_HEADER)m_Base;

	pHeadres = (PIMAGE_NT_HEADERS)(pDosHander->e_lfanew + (LONG)m_Base);

	pSection = IMAGE_FIRST_SECTION(pHeadres);

	m_NtAddress = (void*)pHeadres;

	if ((fpFile = fopen("FileData.txt", "r+")) == NULL)
	{
		AfxMessageBox(L"文件打开失败");
	}
}

UnShell::~UnShell()
{
	fclose(fpFile);
}

// 恢复压缩的数据
BOOL UnShell::RepCompressionData()
{
	// 把压缩的数据都申请空间保存--->文件200对齐拼接
	// 加载stub中的数据里面保存了区段数据大小
	m_studBase = LoadLibraryEx(L"E:\\VS项目\\加壳器\\Release\\Stud.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);

	g_stu = (_Stud*)GetProcAddress((HMODULE)m_studBase, "g_stud");

	DWORD SectionCount = pHeadres->FileHeader.NumberOfSections;

	/*===================文件中读取必要的数据================================*/
	for (DWORD i = 0; i < SectionCount - 3; ++i)
	{
		fread(&g_stu->s_blen[i], sizeof(DWORD), 1, fpFile);
	}


	for (DWORD i = 0; i < 16; ++i)
	{
		fread(&g_stu->s_DataDirectory[i][0], sizeof(DWORD), 1, fpFile);
		fread(&g_stu->s_DataDirectory[i][1], sizeof(DWORD), 1, fpFile);
		// fscanf(fpFile, "%04x %04x", &g_stu->s_DataDirectory[i][0], &g_stu->s_DataDirectory[i][1]);
	}

	for (DWORD i = 0; i < SectionCount - 2; ++i)
	{
		fread(&g_stu->s_SectionOffsetAndSize[i][0], sizeof(DWORD), 1, fpFile);
		fread(&g_stu->s_SectionOffsetAndSize[i][1], sizeof(DWORD), 1, fpFile);
		// fscanf(fpFile, "%04x %04x", &g_stu->s_SectionOffsetAndSize[i][0], &g_stu->s_SectionOffsetAndSize[i][1]);
	}

	fread(&g_stu->s_dwOepBase, sizeof(DWORD), 1, fpFile);

	/*========================================================================*/

	TotaldwSize = 0;

	for (DWORD i = 0; i < SectionCount - 2; ++i)
	{
		// 获取文件偏移及文件大小0是偏移 1是大小
		TotaldwSize += g_stu->s_SectionOffsetAndSize[i][0];
	}

	// 申请
	Sectionbuf = (char*)malloc(TotaldwSize);

	// 文件中加密数据其实位置	
	DWORD DataStart = 0x400;
	// 保存游标
	DWORD Flag = 0;

	PuPEInfo obj_pePE;

	BYTE Name[] = ".com";

	// 区段压缩的数据起始位置
	PIMAGE_SECTION_HEADER address = (PIMAGE_SECTION_HEADER)obj_pePE.puGetSectionAddress((char*)m_Base, Name);

	int nFlag = 0;

	DWORD Address = address->PointerToRawData;

	for (DWORD i = 0; i < SectionCount - 2; ++i)
	{
		if (g_stu->s_blen[nFlag] == 0)
		{
			nFlag += 1;
			continue;
		}
		// 缓冲区  RVA+加载基址  缓冲区大小  压缩过去的大小
		int nRet = LZ4_decompress_safe((char*)(Address + (DWORD)m_Base), &Sectionbuf[Flag], g_stu->s_blen[nFlag], g_stu->s_SectionOffsetAndSize[i][0]);
		Address += g_stu->s_blen[i];
		Flag += g_stu->s_SectionOffsetAndSize[i][0];
		nFlag++;
	}

	return TRUE;
}

// 删除区段数据
BOOL UnShell::DeleteSectionInfo()
{
	DWORD dwSectionCount = pHeadres->FileHeader.NumberOfSections;

	PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)pHeadres->OptionalHeader.DataDirectory;

	// 修复数据目录表
	for (DWORD i = 0; i < 16; ++i)
	{
		// 先读取数据
		if (0 != g_stu->s_DataDirectory[i][0])
			pDataDirectory->VirtualAddress = g_stu->s_DataDirectory[i][0];
		if (0 != g_stu->s_DataDirectory[i][1])
			pDataDirectory->Size = g_stu->s_DataDirectory[i][1];
		++pDataDirectory;
	}

	// 修复所有区段的数据
	for (DWORD i = 0; i < dwSectionCount - 2; ++i)
	{
		if (0 != g_stu->s_SectionOffsetAndSize[i][0])
			pSection->SizeOfRawData = g_stu->s_SectionOffsetAndSize[i][0];
		if (0 != g_stu->s_SectionOffsetAndSize[i][1])
			pSection->PointerToRawData = g_stu->s_SectionOffsetAndSize[i][1];
		++pSection;
	}

	// 区段个数 - 2;
	pHeadres->FileHeader.NumberOfSections -= 2;

	// 清空新增区段的PE结构（数据）
	PIMAGE_SECTION_HEADER pSection_s = IMAGE_FIRST_SECTION(pHeadres);

	DWORD NewdwSectionOfSize = (dwSectionCount - 2) * 0x28;

	char* temp = (char*)malloc(80);

	memset(temp, 0, 80);

	// 清空加载的区段数据 修改不了里面数据
	DWORD old = 0;
	BYTE Name[] = ".mas";
	BYTE Name1[] = ".com";
	PuPEInfo pePu;

	DWORD masAdd = (DWORD)pePu.puGetSectionAddress((char*)m_Base, Name);
	VirtualProtect((char*)masAdd, 40, PAGE_READWRITE, &old);
	memcpy((char*)masAdd, temp, 40);
	VirtualProtect((char*)masAdd, 40, old, &old);

	DWORD comAdd = (DWORD)pePu.puGetSectionAddress((char*)m_Base, Name1);
	VirtualProtect((char*)comAdd, 40, PAGE_READWRITE, &old);
	memcpy((char*)comAdd, temp, 40);
	VirtualProtect((char*)comAdd, 40, old, &old);

	free(temp);

	temp = nullptr;

	--pSection;

	// 修复SizeofImage = 最后一个区段.VirtualAddress + 最后一个区段.SizeOfRawData按内存对齐粒度对齐的大小
	pHeadres->OptionalHeader.SizeOfImage = pSection->VirtualAddress + pSection->SizeOfRawData;

	// 恢复OEP
	pHeadres->OptionalHeader.AddressOfEntryPoint = g_stu->s_dwOepBase;
	
	return TRUE;
}

// 保存\收尾工作
BOOL UnShell::SaveUnShell()
{
	DWORD Size = 0x400 + TotaldwSize;
	// PE头 + 解压后的数据
	UnShellNewFile = (char*)malloc(Size);

	memcpy(UnShellNewFile, m_Base, 0x400);

	memcpy(&UnShellNewFile[0x400], Sectionbuf, TotaldwSize);

	// 写入exe程序完成压缩
	DWORD dwWrite = 0; OVERLAPPED OverLapped;

	// 创建文件
	HANDLE Handle = CreateFile(L"C:\\Users\\Administrator\\Desktop\\UnShellNewPro.exe", GENERIC_READ | GENERIC_WRITE, FALSE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	// 写入文件
	int nRet = WriteFile(Handle, UnShellNewFile, Size, &dwWrite, NULL);

	// 关闭句柄
	CloseHandle(Handle);

	if (!nRet)
		return FALSE;
	return TRUE;
}