#include "HashOfFunction.h"

HashofFunction::HashofFunction()
{

}

HashofFunction::~HashofFunction()
{

}

// 获取模块基址
DWORD HashofFunction::GetModule(const DWORD Hash)
{
	DWORD	nDllBase = 0;
	__asm{
	/*主模块*/
		pushad
		push		Hash;
		call		GetModulVA
		mov			nDllBase, eax;
		popad

	/*函数1：遍历PEB_LDR_DATA链表HASH加密*/
	GetModulVA :
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
		rep stos	dword ptr es : [edi]
		mov			esi, dword ptr fs : [0x30];
		mov			esi, dword ptr[esi + 0x0C];
		mov			esi, dword ptr[esi + 0x1C];
	tag_Modul:
		mov			dword ptr[ebp - 0x8], esi;	// 保存LDR_DATA_LIST_ENTRY
		mov			ebx, dword ptr[esi + 0x20];	// DLL的名称指针(应该指向一个字符串)
		mov			eax, dword ptr[ebp + 0x8];
		push		eax;
		push		ebx;						// +0xC
		call		HashModulVA
		test		eax, eax;
		jnz			_ModulSucess
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
		jz			tag_failuers
		xor			ecx, ecx;
		xor			eax, eax;
	tag_loops:
		mov			al, [esi + ecx];		// 获取字节加密
		test		al, al					// 0则退出
		jz			tag_ends
		mov			ebx, [ebp - 0x04];
		shl			ebx, 0x19;
		mov			edx, [ebp - 0x04];
		shr         edx, 0x07;
		or			ebx, edx;
		add			ebx, eax;
		mov[ebp - 0x4], ebx;
		inc			ecx;
		inc			ecx;
		jmp			tag_loops
	tag_ends :
		mov			ebx, [ebp + 0x0C];		// 获取HASH
		mov			edx, [ebp - 0x04];
		xor			eax, eax;
		cmp			ebx, edx;
		jne			tag_failuers
		mov			eax, 1
		jmp			tag_funends
		tag_failuers :
		mov			eax, 0
	tag_funends :
		pop			esi;
		pop			edx;
		pop			ecx;
		pop			ebx;
		mov			esp, ebp;
		pop			ebp;
		ret			0x08
	}
	return nDllBase;
}

// 获取函数地址
DWORD HashofFunction::GetProcAddress(const DWORD dllvalues, const DWORD Hash)
{
	DWORD FunctionAddress = 0;
	__asm{
		pushad;
		push		Hash;						// Hash加密的函数名称
		push		dllvalues;					// 模块基址.dll
		call		GetHashFunVA;				// GetProcess
		mov			FunctionAddress, eax;		// ☆ 保存地址
		popad;
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
		call		_STRCMP
		cmp			eax, 0;
		jnz			_SUCESS
		inc			esi;
		LOOP		_WHILE
		jmp			_ProgramEnd
		// 对比成功之后获取循环次数（下标）cx保存下标数
	_SUCESS :
		// 获取EOT导出序号表内容
		mov			ecx, esi
		mov			ebx, dword ptr[ebp - 0x14];
		mov			esi, dword ptr[ebx + 0x24];
		mov			ebx, dword ptr[ebp - 0x8];
		lea			esi, [esi + ebx];				// 获取EOT的VA
		xor			edx, edx
		mov			dx, [esi + ecx * 2];			// 注意双字 获取序号
		// 获取EAT地址表RVA
		mov			esi, dword ptr[ebp - 0x14];		// Export VA
		mov			esi, [esi + 0x1C];
		mov			ebx, dword ptr[ebp - 0x8];
		lea			esi, [esi + ebx]				// 获取EAT的VA			
		mov			eax, [esi + edx * 4]			// 返回值eax（GetProcess地址）
		lea			eax, [eax + ebx]
		jmp			_ProgramEnd

	_ProgramEnd :
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
		jmp			tag_funend

	tag_failuer :
		mov			eax, 0

	tag_funend :
		pop			esi;
		pop			edx;
		pop			ecx;
		pop			ebx;
		mov			esp, ebp;
		pop			ebp;
		ret			0x08
	}
	return FunctionAddress;
}