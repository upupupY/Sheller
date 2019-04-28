#include "stud.h"
#include <CommCtrl.h>
#include "../lz4.h"

#pragma comment(linker, "/merge:.data=.text")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")



// ==================定义一个全局变量导出======================
extern "C"{
	__declspec(dllexport) Stud g_stud = { 0 };
}

// 保存GetModulHnadle（NULL）
HINSTANCE g_hInstance;

// =====================伪函数定义============================
typedef void* (WINAPI*FnGetProcAddress)(HMODULE, const char*);
FnGetProcAddress MyGetProcAddress;

typedef HMODULE (WINAPI* FnLoadLibraryExA)(_In_ LPCSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags);
FnLoadLibraryExA MyLoadLibraryExA;

typedef HMODULE (WINAPI* FnGetModuleHandleW)(_In_opt_ LPCWSTR lpModuleName);
FnGetModuleHandleW MyGetModuleHandleW;

typedef HBRUSH  (WINAPI* FnCreateSolidBrush)(_In_ COLORREF color);
FnCreateSolidBrush MyCreateSolidBrush;

typedef ATOM (WINAPI* FnRegisterClassW)(_In_ CONST WNDCLASSW *lpWndClass);
FnRegisterClassW MyRegisterClassW;

typedef	WINUSERAPI HWND(WINAPI* FnCreateWindowExW)(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCWSTR lpClassName,
	_In_opt_ LPCWSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam);
FnCreateWindowExW MyCreateWindowExW;

typedef BOOL (WINAPI* FnShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow);
FnShowWindow MyShowWindow;

typedef BOOL (WINAPI* FnUpdateWindow)(_In_ HWND hWnd);
FnUpdateWindow MyUpdateWindow;

typedef BOOL (WINAPI* FnGetMessageW)(_Out_ LPMSG lpMsg, _In_opt_ HWND hWnd, _In_ UINT wMsgFilterMin, _In_ UINT wMsgFilterMax);
FnGetMessageW MyGetMessageW;

typedef BOOL (WINAPI* FnTranslateMessage)(_In_ CONST MSG *lpMsg);
FnTranslateMessage	MyTranslateMessage;

typedef LRESULT (WINAPI* FnDispatchMessageW)(_In_ CONST MSG *lpMsg);
FnDispatchMessageW MyDispatchMessageW;

typedef int (WINAPI* FnGetWindowTextW)(_In_ HWND hWnd, _Out_writes_(nMaxCount) LPWSTR lpString, _In_ int nMaxCount);
FnGetWindowTextW MyGetWindowTextW;

typedef int (WINAPI* FnlstrcmpW)(_In_ LPCWSTR lpString1, _In_ LPCWSTR lpString2);
FnlstrcmpW MylstrcmpW;

typedef int (WINAPI* FnMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
FnMessageBoxA MyMessageBoxA;

typedef VOID(WINAPI* FnPostQuitMessage)(_In_ int nExitCode);
FnPostQuitMessage MyPostQuitMessage;

typedef LRESULT(WINAPI* FnDefWindowProcW)(_In_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);
FnDefWindowProcW MyDefWindowProcW;

typedef HCURSOR(WINAPI* FnLoadCursorW)(_In_opt_ HINSTANCE hInstance, _In_ LPCWSTR lpCursorName);
FnLoadCursorW MyLoadCursorW;

typedef HICON (WINAPI* FnLoadIconW)(_In_opt_ HINSTANCE hInstance, _In_ LPCWSTR lpIconName);
FnLoadIconW MyLoadIconW;

typedef	ATOM (WINAPI* FnRegisterClassExW)(_In_ CONST WNDCLASSEXW *);
FnRegisterClassExW MyRegisterClassExW;

typedef VOID(WINAPI* FnExitProcess)(_In_ UINT uExitCode);
FnExitProcess MyExitProcess;

typedef HWND (WINAPI* FnGetDlgItem)(_In_opt_ HWND hDlg, _In_ int nIDDlgItem);
FnGetDlgItem MyGetDlgItem;

typedef void * (__cdecl* Fnmemcpy)(_Out_writes_bytes_all_(_Size) void * _Dst, _In_reads_bytes_(_Size) const void * _Src, _In_ size_t _Size);
Fnmemcpy Mymemcpy;

typedef BOOL(WINAPI* FnVirtualProtect)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
FnVirtualProtect MyVirtualProtect;

typedef HWND(WINAPI* FnFindWindowExW)(_In_opt_ HWND hWndParent, _In_opt_ HWND hWndChildAfter, _In_opt_ LPCWSTR lpszClass, _In_opt_ LPCWSTR lpszWindow);
FnFindWindowExW MyFindWindowExW;




// ===================获取模块基址============================
DWORD puGetModule(const DWORD Hash)
{
	DWORD	nDllBase = 0;
	__asm{
		jmp			start
	/*函数1：遍历PEB_LDR_DATA链表HASH加密*/
	GetModulVA:
		push		ebp;
		mov			ebp, esp;
		sub			esp, 0x20;
		push		edx;
		push		ebx;
		push		edi;
		push		esi;
		mov			ecx, 8;
		mov			eax, 0CCCCCCCCh;
		lea			edi, dword ptr[ebp - 0x20];
		rep stos	dword ptr es : [edi];
		mov			esi, dword ptr fs : [0x30];
		mov			esi, dword ptr[esi + 0x0C];
		mov			esi, dword ptr[esi + 0x1C];
	tag_Modul:
		mov			dword ptr[ebp - 0x8], esi;	// 保存LDR_DATA_LIST_ENTRY
		mov			ebx, dword ptr[esi + 0x20];	// DLL的名称指针(应该指向一个字符串)
		mov			eax, dword ptr[ebp + 0x8];
		push		eax;
		push		ebx;						// +0xC
		call		HashModulVA;
		test		eax, eax;
		jnz			_ModulSucess;
		mov			esi, dword ptr[ebp - 0x8];
		mov			esi, [esi];					// 遍历下一个
		LOOP		tag_Modul
		_ModulSucess :
		mov			esi, dword ptr[ebp - 0x8];
		mov			eax, dword ptr[esi + 0x8];
		pop			esi;
		pop			edi;
		pop			ebx;
		pop			edx;
		mov			esp, ebp;
		pop			ebp;
		ret

		/*函数2：HASH解密算法（宽字符解密）*/
	HashModulVA :
		push		ebp;
		mov			ebp, esp;
		sub			esp, 0x04;
		mov			dword ptr[ebp - 0x04], 0x00
		push		ebx;
		push		ecx;
		push		edx;
		push		esi;
		// 获取字符串开始计算
		mov			esi, [ebp + 0x8];
		test		esi, esi;
		jz			tag_failuers;
		xor			ecx, ecx;
		xor			eax, eax;
	tag_loops:
		mov			al, [esi + ecx];		// 获取字节加密
		test		al, al;					// 0则退出
		jz			tag_ends;
		mov			ebx, [ebp - 0x04];
		shl			ebx, 0x19;
		mov			edx, [ebp - 0x04];
		shr         edx, 0x07;
		or			ebx, edx;
		add			ebx, eax;
		mov[ebp - 0x4], ebx;
		inc			ecx;
		inc			ecx;
		jmp			tag_loops;
	tag_ends:
		mov			ebx, [ebp + 0x0C];		// 获取HASH
		mov			edx, [ebp - 0x04];
		xor			eax, eax;
		cmp			ebx, edx;
		jne			tag_failuers;
		mov			eax, 1;
		jmp			tag_funends;
	tag_failuers:
		mov			eax, 0;
	tag_funends:
		pop			esi;
		pop			edx;
		pop			ecx;
		pop			ebx;
		mov			esp, ebp;
		pop			ebp;
		ret			0x08

	start:
	/*主模块*/
		pushad;
		push		Hash;
		call		GetModulVA;
		add			esp, 0x4
		mov			nDllBase, eax;
		popad;
	}
	return nDllBase;
}

// ===================获取函数地址============================
DWORD puGetProcAddress(const DWORD dllvalues, const DWORD Hash)
{
	DWORD FunctionAddress = 0;
	__asm{
		jmp			start
		// 自定义函数计算Hash且对比返回正确的函数
	GetHashFunVA:
		push		ebp;
		mov			ebp, esp;
		sub			esp, 0x30;
		push		edx;
		push		ebx;
		push		esi;
		push		edi;
		lea			edi, dword ptr[ebp - 0x30];
		mov			ecx, 12;
		mov			eax, 0CCCCCCCCh;
		rep	stos	dword ptr es : [edi];
		// 以上开辟栈帧操作（Debug版本模式）
		mov			eax, [ebp + 0x8];				// ☆ kernel32.dll(MZ)
		mov			dword ptr[ebp - 0x8], eax;
		mov			ebx, [ebp + 0x0c];				// ☆ GetProcAddress Hash值
		mov			dword ptr[ebp - 0x0c], ebx;
		// 获取PE头与RVA及ENT
		mov			edi, [eax + 0x3C];				// e_lfanew
		lea			edi, [edi + eax];				// e_lfanew + MZ = PE
		mov			dword ptr[ebp - 0x10], edi;		// ☆ 保存PE（VA）
		// 获取ENT
		mov			edi, dword ptr[edi + 0x78];		// 获取导出表RVA
		lea			edi, dword ptr[edi + eax];		// 导出表VA
		mov[ebp - 0x14], edi;						// ☆ 保存导出表VA
		// 获取函数名称数量
		mov			ebx, [edi + 0x18];
		mov			dword ptr[ebp - 0x18], ebx;		// ☆ 保存函数名称数量
		// 获取ENT
		mov			ebx, [edi + 0x20];				// 获取ENT(RVA)
		lea			ebx, [eax + ebx];				// 获取ENT(VA)
		mov			dword ptr[ebp - 0x20], ebx;		// ☆ 保存ENT(VA)
		// 遍历ENT 解密哈希值对比字符串
		mov			edi, dword ptr[ebp - 0x18];
		mov			ecx, edi;
		xor			esi, esi;
		mov			edi, dword ptr[ebp - 0x8];
		jmp			_WHILE
		// 外层大循环
	_WHILE :
		mov			edx, dword ptr[ebp + 0x0c];		// HASH
		push		edx;
		mov			edx, dword ptr[ebx + esi * 4];	// 获取第一个函数名称的RVA
		lea			edx, [edi + edx];				// 获取一个函数名称的VA地址
		push		edx;							// ENT表中第一个字符串地址
		call		_STRCMP;
		cmp			eax, 0;
		jnz			_SUCESS;
		inc			esi;
		LOOP		_WHILE;
		jmp			_ProgramEnd
		// 对比成功之后获取循环次数（下标）cx保存下标数
	_SUCESS :
		// 获取EOT导出序号表内容
		mov			ecx, esi;
		mov			ebx, dword ptr[ebp - 0x14];
		mov			esi, dword ptr[ebx + 0x24];
		mov			ebx, dword ptr[ebp - 0x8];
		lea			esi, [esi + ebx];				// 获取EOT的VA
		xor			edx, edx;
		mov			dx, [esi + ecx * 2];			// 注意双字 获取序号
		// 获取EAT地址表RVA
		mov			esi, dword ptr[ebp - 0x14];		// Export VA
		mov			esi, [esi + 0x1C];
		mov			ebx, dword ptr[ebp - 0x8];
		lea			esi, [esi + ebx];				// 获取EAT的VA			
		mov			eax, [esi + edx * 4];			// 返回值eax（GetProcess地址）
		lea			eax, [eax + ebx];
		jmp			_ProgramEnd;

	_ProgramEnd:
		pop			edi;
		pop			esi;
		pop			ebx;
		pop			edx;
		mov			esp, ebp;
		pop			ebp;
		ret			0x8;

		// 循环对比HASH值
	_STRCMP:
		push		ebp;
		mov			ebp, esp;
		sub			esp, 0x04;
		mov			dword ptr[ebp - 0x04], 0x00;
		push		ebx;
		push		ecx;
		push		edx;
		push		esi;
		// 获取字符串开始计算
		mov			esi, [ebp + 0x8];
		xor			ecx, ecx;
		xor			eax, eax;

	tag_loop:
		mov			al, [esi + ecx];		// 获取字节加密
		test		al, al;					// 0则退出
		jz			tag_end;
		mov			ebx, [ebp - 0x04];
		shl			ebx, 0x19;
		mov			edx, [ebp - 0x04];
		shr         edx, 0x07;
		or			ebx, edx;
		add			ebx, eax;
		mov[ebp - 0x4], ebx;
		inc			ecx;
		jmp			tag_loop

		tag_end :
		mov			ebx, [ebp + 0x0C];		// 获取HASH
		mov			edx, [ebp - 0x04];
		xor			eax, eax;
		cmp			ebx, edx;
		jne			tag_failuer;
		mov			eax, 1;
		jmp			tag_funend;

	tag_failuer:
		mov			eax, 0;

	tag_funend:
		pop			esi;
		pop			edx;
		pop			ecx;
		pop			ebx;
		mov			esp, ebp;
		pop			ebp;
		ret			0x08

	start:
		pushad;
		push		Hash;						// Hash加密的函数名称
		push		dllvalues;					// 模块基址.dll
		call		GetHashFunVA;				// GetProcess
		mov			FunctionAddress, eax;		// ☆ 保存地址
		popad;
	}
	return FunctionAddress;
}

// =====================控件实现==============================
void SetString(HWND hWnd)
{
	// 获取PostQuitMessage
	MyPostQuitMessage = (FnPostQuitMessage)puGetProcAddress(g_stud.s_User32, 0xCAA94781);
	// 获取DefWindowProcW
	MyDefWindowProcW = (FnDefWindowProcW)puGetProcAddress(g_stud.s_User32, 0x22E85CBA);
	 // 设置边框
	MyCreateWindowExW(0L, WC_BUTTON, TEXT("   咳咳、自我介绍一下，本人叫壳"), WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 20, 98, 300, 200, hWnd, NULL, 0, NULL);
	 // 创建用户与密码静态文本
	MyCreateWindowExW(0L, WC_STATIC, TEXT("Account:"), WS_CHILD | WS_VISIBLE, 30, 145, 80, 20, hWnd, NULL, 0, NULL);
	MyCreateWindowExW(0L, WC_STATIC, TEXT("Passwd :"), WS_CHILD | WS_VISIBLE, 30, 175, 80, 20, hWnd, NULL, 0, NULL);
	 // 创建文本框
	MyCreateWindowExW(WS_EX_CLIENTEDGE, WC_EDIT, TEXT(""), WS_CHILD | WS_VISIBLE, 120, 145, 160, 20, hWnd, (HMENU)0x1001, 0, NULL);
	MyCreateWindowExW(WS_EX_CLIENTEDGE, WC_EDIT, TEXT(""), WS_CHILD | WS_VISIBLE, 120, 175, 160, 20, hWnd, (HMENU)0x1002, 0, NULL);
	 // 登录按钮
	MyCreateWindowExW(0L, WC_BUTTON, TEXT("登	录："), WS_CHILD | WS_VISIBLE, 120, 220, 70, 25, hWnd, (HMENU)0x1003, 0, NULL);
}

// =====================创建回调==============================
LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE:
	{
		// 创建控件
		SetString(hWnd);
	}
	break;
	case WM_COMMAND:
	{
		if (0x1003 == LOWORD(wParam)) {
			WCHAR User[20] = { 0 };
			WCHAR Pass[20] = { 0 };
			MyGetWindowTextW(MyGetDlgItem(hWnd, 0x1001), User, 20);
			MyGetWindowTextW(MyGetDlgItem(hWnd, 0x1002), Pass, 20);
			if ((0 == MylstrcmpW(User, L"admin") && (0 == MylstrcmpW(Pass, L"admin"))))
				MyMessageBoxA(NULL, "Seucess", "成功", NULL);
			else
				MyMessageBoxA(NULL, "Failure", "失败", NULL);
		}
	}
	break;
	case WM_CLOSE:
	{
		MyPostQuitMessage(0);
	}
	break;
	}
	// 不处理的消息全部交给默认回调函数
	return MyDefWindowProcW(hWnd, uMsg, wParam, lParam);
}

// =====================创建窗口==============================
int CreateWind()
{
	WNDCLASS WndClass = { 0 };

	// 1. 预定义窗口类的信息
	WndClass.cbClsExtra = 0;
	WndClass.cbWndExtra = 0;
	WndClass.hbrBackground = MyCreateSolidBrush(RGB(255, 255, 255));
	WndClass.hCursor = MyLoadCursorW(NULL, IDC_ARROW);
	WndClass.hIcon = MyLoadIconW(NULL, IDI_APPLICATION);
	WndClass.hInstance = g_hInstance;
	WndClass.lpfnWndProc = WndProc;
	WndClass.lpszClassName = TEXT("PasswdWind");
	WndClass.lpszMenuName = NULL;
	WndClass.style = CS_VREDRAW | CS_HREDRAW;

	// 2. 注册窗口类
	if (!MyRegisterClassW(&WndClass))
	{
		MyMessageBoxA(NULL, "注册窗口类失败", "警告", MB_OK | MB_ICONERROR);
		MyExitProcess(0);
	}

	// 3. 创建主窗口
	HWND hWnd = MyCreateWindowExW(WS_EX_CLIENTEDGE,TEXT("PasswdWind"), TEXT("登录输入"), WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, 357, 500, NULL, NULL, 0, NULL);

	// 4. 显示并刷新主窗口
	MyShowWindow(hWnd, SW_SHOWNORMAL);
	MyUpdateWindow(hWnd);

	// 5. 开始进入消息循环
	MSG msg = { 0 };
	while (MyGetMessageW(&msg, NULL, 0, 0))
	{
		// 5.1 消息转换
		MyTranslateMessage(&msg);
		// 5.2 消息分发
		MyDispatchMessageW(&msg);
	}
	return 0;
}

// ======================解压缩===============================
void UnCompression()
{
	// ☆ 调用的函数，需要获取伪函数
	// 1. 还原数据目录表以及区段信息
	DWORD m_lpbase = 0x400000;
	
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)m_lpbase)->e_lfanew + (DWORD)m_lpbase);

	PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)pNt->OptionalHeader.DataDirectory;
	
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	
	DWORD Att_old = 0;

	for (DWORD i = 0; i < 16; ++i)
	{
		MyVirtualProtect(pDataDirectory, 0x8, PAGE_READWRITE, &Att_old);
		if (0 != g_stud.s_DataDirectory[i][0])
			pDataDirectory->VirtualAddress = g_stud.s_DataDirectory[i][0];
		if (0 != g_stud.s_DataDirectory[i][1])
			pDataDirectory->Size = g_stud.s_DataDirectory[i][1];
		MyVirtualProtect(pDataDirectory, 0x8, Att_old, &Att_old);
		++pDataDirectory;
	}

	for (DWORD i = 0; i < g_stud.s_SectionCount - 2; ++i)
	{
		MyVirtualProtect(pSection, 0x8, PAGE_READWRITE, &Att_old);
		if (0 != g_stud.s_SectionOffsetAndSize[i][0])
			pSection->SizeOfRawData = g_stud.s_SectionOffsetAndSize[i][0];
		if (0 != g_stud.s_SectionOffsetAndSize[i][1])
			pSection->PointerToRawData=g_stud.s_SectionOffsetAndSize[i][1];
		MyVirtualProtect(pSection, 0x8, PAGE_READWRITE, &Att_old);
		++pSection;
	}
	
	PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pNt);

	//  2. 解压全部区段数据到虚拟内存 virtualAddress = VA
	DWORD Att_olds = 0;
	DWORD SectionAddress = g_stud.s_CompressionSectionRva;
	for (DWORD i = 0; i < g_stud.s_SectionCount - 2; ++i)
	{
		byte* Address = (byte *)(pSections->VirtualAddress + m_lpbase);

		MyVirtualProtect(Address, g_stud.s_SectionOffsetAndSize[i][0], PAGE_READWRITE, &Att_old);
		MyVirtualProtect((void*)SectionAddress, g_stud.s_blen[i], PAGE_READWRITE, &Att_olds);

		// 缓冲区  RVA+加载基址  缓冲区大小  压缩过去的大小
		int nRet = LZ4_decompress_safe((char*)(SectionAddress + m_lpbase), (char*)(pSections->VirtualAddress + m_lpbase), g_stud.s_blen[i], pSections->SizeOfRawData);
		
		MyVirtualProtect(Address, g_stud.s_SectionOffsetAndSize[i][0], Att_old, &Att_old);
		MyVirtualProtect((void*)SectionAddress, g_stud.s_blen[i], Att_olds, &Att_olds);

		++pSections;
		SectionAddress += g_stud.s_blen[i];
	}
}

// ======================反调试===============================
void FDebug()
{
	MyFindWindowExW = (FnFindWindowExW)puGetProcAddress(g_stud.s_User32, 0x4818F71E);
	char result = 0;
	__asm{
		push eax;
		xor eax, eax;
		mov eax, fs:[0x30];
		mov al, byte ptr[eax + 0x2];
		mov result, al;
		pop eax;
	}
	if (0x1 == result)
		MyExitProcess(0);
	else
	{
		HWND x32 = MyFindWindowExW(NULL, NULL, L"Qt5QWindowIcon", L"x32dbg");
		if (x32 != NULL)
			MyExitProcess(0);
	}
}

// =====================修复IAT===============================
void RepairTheIAT()
{
	// Mymemcpy = (Fnmemcpy)puGetProcAddress(g_stud.s_MSVCRT, 0x818F6ED7);
	// 获取加载基址
	DWORD dwMoudle = (DWORD)MyGetModuleHandleW(NULL);
	// 获取导入表的VA
	DWORD ImportTabVA = g_stud.s_DataDirectory[1][0] + dwMoudle;
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)ImportTabVA;

	while (pImport->Name)
	{
		// 获取基址名称
		char* Name = (char*)(pImport->Name + dwMoudle);
		// 获取模块基址
		HMODULE hModuledll = MyLoadLibraryExA(Name, NULL, NULL);
		// 加载模块
		PIMAGE_THUNK_DATA pThunkINT = (PIMAGE_THUNK_DATA)(pImport->OriginalFirstThunk + dwMoudle);
		PIMAGE_THUNK_DATA pThunkIAT = (PIMAGE_THUNK_DATA)(pImport->FirstThunk + dwMoudle);
		// INT在文件中内容指向的RVA是一样的， IAT在加载到内存后就被填充成真正的VA
		DWORD Att_old = 0;
		while (pThunkINT->u1.AddressOfData)
		{
			MyVirtualProtect((void*)pThunkIAT, 0x4, PAGE_READWRITE, &Att_old);
			if (!IMAGE_SNAP_BY_ORDINAL32(pThunkIAT->u1.Ordinal))
			{
				// 获取BY_NAME结构体
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pThunkINT->u1.AddressOfData + dwMoudle);
				// 获取pName的函数名称, 字符串动态加密
				//unsigned long nDigest = 0;
				//char *p = nullptr;
				//p = pName->Name;
				//while (*p)
				//{
				//	nDigest = ((nDigest << 25) | (nDigest >> 7));
				//	nDigest = nDigest + *p;
				//	p++;
				//}
				// HASH获取函数VA
				// DWORD FunAddress = puGetProcAddress((DWORD)hModuledll, nDigest);
				DWORD FunAddress = (DWORD)MyGetProcAddress(hModuledll, pName->Name);
				// 保存到IAT中
				pThunkIAT->u1.Function = FunAddress;
			}
			else
			{
				DWORD dwFunOrdinal = (pThunkIAT->u1.Ordinal) & 0x7FFFFFFF;
				DWORD Fundll = (DWORD)MyGetProcAddress(hModuledll, (char*)dwFunOrdinal);
				pThunkIAT->u1.Function = Fundll;
			}
			// 填充到IAT中
			MyVirtualProtect((void*)pThunkIAT, 0x4, Att_old, &Att_old);
			++pThunkINT;
			++pThunkIAT;
		}
		++pImport;
	}
}

// ===================花指令、混淆=============================
void TakeInstruc()
{
	DWORD p;
	__asm{
		call	l1;
	l1:
		pop		eax;
		mov		p, eax;			//确定当前程序段的位置
		call	f1;
		_EMIT	0xEA;			//花指令，此处永远不会执行到
		jmp		l2;				//call结束以后执行到这里
	f1:							//这里用F8OD会终止调试，F7跟进的话就正常,why?
		pop ebx;
		inc ebx;
		push ebx;
		mov eax, 0x11111111;
		ret;
	l2:
		call f2;				//用ret指令实现跳转
		mov ebx, 0x33333333;	//这里永远不会执行到
		jmp e;					//这里永远不会执行到
	f2:
		mov ebx, 0x11111111;
		pop ebx;				//弹出压栈的地址
		mov ebx, offset e;		//要跳转到的地址
		push ebx;				//压入要跳转到的地址
		ret;					//跳转
	e:
		mov ebx, 0x22222222;
	}
}

// =====================主函数=================================
extern "C" __declspec(dllexport) // __declspec(naked)
void main()
{
	g_stud.s_Krenel32 = puGetModule(0xEC1C6278);
	// 获取LoadlibraryExA
	MyLoadLibraryExA = (FnLoadLibraryExA)puGetProcAddress(g_stud.s_Krenel32, 0xC0D83287);
	// 加载User32.dll
	g_stud.s_User32 = (DWORD)MyLoadLibraryExA("User32.dll", NULL, NULL);
	// 获取ExitProcW
	MyExitProcess = (FnExitProcess)puGetProcAddress(g_stud.s_Krenel32, 0x4FD18963);
	// 反调试
	FDebug();
	// 加载GDI32.lib
	g_stud.s_Gdi32 = (DWORD)MyLoadLibraryExA("gdi32.dll", NULL, NULL);
	// 加载
	g_stud.s_MSVCRT = (DWORD)MyLoadLibraryExA("msvcrt.dll", NULL, NULL);
	// 获取GetModuleW
	MyGetModuleHandleW = (FnGetModuleHandleW)puGetProcAddress(g_stud.s_Krenel32, 0xF4E2F2C8);
	g_hInstance = (HINSTANCE)MyGetModuleHandleW(NULL);
	// 获取CreateSolidBrush
	MyCreateSolidBrush = (FnCreateSolidBrush)puGetProcAddress(g_stud.s_Gdi32, 0xBB7420F9);
	// 获取UpdateData
	MyUpdateWindow = (FnUpdateWindow)puGetProcAddress(g_stud.s_User32, 0x9BB5D8DC);
	// 获取GetMessageW
	MyGetMessageW = (FnGetMessageW)puGetProcAddress(g_stud.s_User32, 0x61060461);
	// 获取TranslateMessage
	MyTranslateMessage = (FnTranslateMessage)puGetProcAddress(g_stud.s_User32, 0xE09980A2);
	// 获取DispatchMessageW
	MyDispatchMessageW = (FnDispatchMessageW)puGetProcAddress(g_stud.s_User32, 0x7A1506D8);
	// 获取ShowWindow
	MyShowWindow = (FnShowWindow)puGetProcAddress(g_stud.s_User32, 0xDD8B5FB8);
	// 获取LoadCursorW
	MyLoadCursorW = (FnLoadCursorW)puGetProcAddress(g_stud.s_User32, 0xC6B20165);
	// 获取LoadIconW
	MyLoadIconW = (FnLoadIconW)puGetProcAddress(g_stud.s_User32, 0x7636E8F4);
	// 获取RegisterClassExW
	MyRegisterClassW = (FnRegisterClassW)puGetProcAddress(g_stud.s_User32, 0xBC05E48);
	// 获取MessageBox
	MyMessageBoxA = (FnMessageBoxA)puGetProcAddress(g_stud.s_User32, 0x1E380A6A);
	// 获取CreateWindowExW
	MyCreateWindowExW = (FnCreateWindowExW)puGetProcAddress(g_stud.s_User32, 0x1FDAF571);
	// 获取GetWindowTextW
	MyGetWindowTextW = (FnGetWindowTextW)puGetProcAddress(g_stud.s_User32, 0x457BF55A);
	// 获取lstrcmpW
	MylstrcmpW = (FnlstrcmpW)puGetProcAddress(g_stud.s_Krenel32, 0x7EAD1F86);
	// 获取DefWindowProcW
	MyDefWindowProcW = (FnDefWindowProcW)puGetProcAddress(g_stud.s_User32, 0x22E85CBA);
	// 获取GetDlgItem
	MyGetDlgItem = (FnGetDlgItem)puGetProcAddress(g_stud.s_User32, 0x5D0CB479);
	// 获取memcpy
	// Mymemcpy = (Fnmemcpy)puGetProcAddress(g_stud.s_MSVCRT, 0x818F6ED7);
	MyVirtualProtect = (FnVirtualProtect)puGetProcAddress(g_stud.s_Krenel32, 0xEF64A41E);
	// 获取MyGetProcessAddress
	MyGetProcAddress = (FnGetProcAddress)puGetProcAddress(g_stud.s_Krenel32, 0xBBAFDF85);
	// 解压全部区段数据
	UnCompression();
	// 修复IAT
	RepairTheIAT();
	// 密码弹框
	CreateWind();
	// 重定位修复 只修复了stub的重定位
	// 花指令、混淆器
	TakeInstruc();
	// 真正的OEP跳转
	__asm {
		pushad;
		mov		eax, g_stud.s_dwOepBase;
		add		eax, 0x400000;
		jmp		eax;
		popad;
	}
}


// ==================修复重定位(目标程序)========================
// ====================TLS处理==================================