#pragma once
#ifndef STUD_H_
#define STUD_H_
#include <Windows.h>


//  /NODEFAULTLIB:LIBCMT.lib 
typedef struct _Stud
{
	// 获取模块基址保存
	DWORD s_dwOepBase;
	DWORD s_Krenel32;
	DWORD s_User32;
	DWORD s_Gdi32;
	DWORD s_MSVCRT;
	// 保存数据目录表个数
	DWORD s_DirectoryCount;
	// 保存区段个数
	DWORD s_SectionCount;
	// 保存数据目录表 数据目录16个 保存RVA以及Size[2][4]
	DWORD s_DataDirectory[16][2];
	// 保存区段文件偏移以及数据大小 区段最大设置20个（实际10几个区段足够）
	DWORD s_SectionOffsetAndSize[20][2];
	// 计算缓冲区大小，并为其分配内存 
	DWORD s_blen[20];
	// 标记第一个代码段是否为0
	BOOL s_OneSectionSizeofData;
	// 压缩数据的区段RVA(实现加载内存后找到压缩的数据)
	DWORD s_CompressionSectionRva;
	// 保存导出表的RVA
	DWORD s_SaveExportTabRVA;
}Stud;

/*
	Hash加密参照表(有可能用到的)：
			0xEC1C6278;			kernel32.dll
			0xC0D83287;			LoadlibraryExa
			0x4FD18963;			ExitPorcess
			0x5644673D			User32.dll
			0x1E380A6A			MessageBoxA
			0x9EBC86B			RtlExitUserProcess
			0xF4E2F2C8			GetModuleHandleW
			0xBB7420F9			CreateSolidBrush
			0xBC05E48			RegisterClassW
			0x1FDAF571			CreateWindowExW
			0xDD8B5FB8			ShowWindow
			0x9BB5D8DC			UpdateWindow
			0x61060461			GetMessageW
			0xE09980A2			TranslateMessage
			0x7A1506D8			DispatchMessageW
			0x457BF55A			GetWindowTextW
			0x7EAD1F86			lstrcmpW
			0x1E380A6A			MessageBoxA
			0xCAA94781			PostQuitMessage
			0x22E85CBA			DefWindowProcW
			0xC6B20165			LoadCursorW
			0x7636E8F4			LoadIconW
			0x1FDAF55B			CreateWindowA
			0x68D82F59			RegisterClassExW
			0x5D0CB479			GetDlgItem
			0x818F6ED7			Mymemcpy
			0x328CEB95			msvcrt.dll
*/
// 获取模块基址，比如kernel32.dll
DWORD puGetModule(const DWORD Hash);
// 获取函数VA基址（重写GetProcAddress）
DWORD puGetProcAddress(const DWORD dllvalues, const DWORD Hash);

#endif