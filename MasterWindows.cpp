// MasterWindows.cpp : 实现文件
//

#include "stdafx.h"
#include "MasterWindows.h"
#include "afxdialogex.h"
#include "puPEinfoData.h"
#include "SectionInfo.h"
#include "AddSection.h"
#include "studData.h"
#include "CompressionData.h"
#include "UnShell.h"

// MasterWindows 对话框

IMPLEMENT_DYNAMIC(MasterWindows, CDialogEx)

MasterWindows::MasterWindows(CWnd* pParent /*=NULL*/)
	: CDialogEx(MasterWindows::IDD, pParent)
	, m_MasterStaticTextStr(_T(""))
{

}

MasterWindows::~MasterWindows()
{
}

void MasterWindows::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_STATIC1, m_MasterStaticText);
	DDX_Text(pDX, IDC_STATIC1, m_MasterStaticTextStr);
}

BEGIN_MESSAGE_MAP(MasterWindows, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &MasterWindows::OnBnClickedButton1)
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_BUTTON4, &MasterWindows::OnBnClickedButton4)
	// ON_BN_CLICKED(IDC_BUTTON3, &MasterWindows::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON9, &MasterWindows::OnBnClickedButton9)
	ON_BN_CLICKED(IDC_BUTTON3, &MasterWindows::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON2, &MasterWindows::OnBnClickedButton2)
END_MESSAGE_MAP()

// MasterWindows 消息处理程序

BOOL MasterWindows::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	/*重新设置图标*/
	SetIcon(LoadIcon(AfxGetApp()->m_hInstance, MAKEINTRESOURCE(IDI_ICON1)), TRUE);

	return TRUE; 
}

// 一键盘加壳
void MasterWindows::OnBnClickedButton1()
{
	// ☆ 先增加新区~段后压缩
	PuPEInfo obj_Peinfo;

	// 1. 新增区段
	if (NewSection())
		AfxMessageBox(L"添加新区段成功");
	else
		AfxMessageBox(L"添加新区段失败");

	CloseHandle(obj_Peinfo.puFileHandle()); UpdateData(TRUE);

	obj_Peinfo.puOpenFileLoad(m_MasterStaticTextStr);


	// 2. 压缩全部区段 压缩的时候不清空数据目录表以及区段大小（不压缩新增区段）
	CompressionData obj_ComperData;

	CloseHandle(obj_Peinfo.puFileHandle()); UpdateData(TRUE);

	obj_Peinfo.puOpenFileLoad(m_MasterStaticTextStr);

	if (!obj_ComperData.puCompressSection())
		AfxMessageBox(L"CompressSection failuer!");
	else
		AfxMessageBox(L"CompressSection Seucess!");

	CloseHandle(obj_Peinfo.puFileHandle()); 

	m_MasterStaticTextStr = "C:\\Users\\Administrator\\Desktop\\CompressionMask.exe";

	obj_Peinfo.puOpenFileLoad(m_MasterStaticTextStr);

	// 3. Stud数据操作...
	studData obj_stuData;

	obj_stuData.puLoadLibraryStud();

	obj_stuData.puRepairReloCationStud();

	if (obj_stuData.puCopyStud())
	{
		CloseHandle(obj_Peinfo.puFileHandle());
		UpdateData(TRUE);
		obj_Peinfo.puOpenFileLoad(m_MasterStaticTextStr);
	}
	else
		AfxMessageBox(L"StudWrite failure!");

	 // 4、收尾工作
	 CloseHandle(obj_Peinfo.puFileHandle());
}

// 响应文件拖拽
void MasterWindows::OnDropFiles(HDROP hDropInfo)
{
	// 1. 获取拖拽数目
	int DropCount = DragQueryFile(hDropInfo, -1, NULL, 0);
	// 2. 保存获取的路径
	char wcStr[MAX_PATH] = {};
	for (int i = 0; i < DropCount; ++i)
	{
		wcStr[0] = 0;
		DragQueryFileA(hDropInfo, i, wcStr, MAX_PATH);
		m_MasterStaticTextStr = wcStr;
	}
	// 3. 更新显示
	UpdateData(FALSE);
	// 4. 显示PE信息（包含区段查看）
	ShowPEInfoData(m_MasterStaticTextStr);
	// 5. 释放内存
	DragFinish(hDropInfo);
	CDialogEx::OnDropFiles(hDropInfo);
}

// 显示PE数据
void MasterWindows::ShowPEInfoData(const CString & FileName)
{
	PuPEInfo obj_puPe; CString Tempstr;	DWORD TempdwCode = 0;

	if (!obj_puPe.puOpenFileLoad(FileName))
		return;

	PIMAGE_NT_HEADERS pNtHeadre = (PIMAGE_NT_HEADERS)obj_puPe.puGetNtHeadre();

	PIMAGE_FILE_HEADER pFileHeadre = (PIMAGE_FILE_HEADER)&pNtHeadre->FileHeader;

	PIMAGE_OPTIONAL_HEADER pOption = (PIMAGE_OPTIONAL_HEADER)&pNtHeadre->OptionalHeader;

	// 区段数量
	TempdwCode = pFileHeadre->NumberOfSections;
	Tempstr.Format(L"%d", TempdwCode);
	SetDlgItemText(IDC_EDIT9, Tempstr);
	
	// OEP
	TempdwCode = pOption->AddressOfEntryPoint;
	Tempstr.Format(L"%08X", TempdwCode);
	SetDlgItemText(IDC_EDIT1, Tempstr);

	// 默认加载基址
	TempdwCode = pOption->ImageBase;
	Tempstr.Format(L"%08X", TempdwCode);
	SetDlgItemText(IDC_EDIT3, Tempstr);

	// 标志字
	TempdwCode = pOption->Magic;
	Tempstr.Format(L"%04X", TempdwCode);
	SetDlgItemText(IDC_EDIT2, Tempstr);

	// 数据目录个数
	TempdwCode = pOption->NumberOfRvaAndSizes;
	Tempstr.Format(L"%08X", TempdwCode);
	SetDlgItemText(IDC_EDIT7, Tempstr);

	// 起始代码相对虚拟地址
	TempdwCode = pOption->BaseOfCode;
	Tempstr.Format(L"%08X", TempdwCode);
	SetDlgItemText(IDC_EDIT4, Tempstr);

	// 起始数据相对地址
	TempdwCode = pOption->BaseOfData;
	Tempstr.Format(L"%08X", TempdwCode);
	SetDlgItemText(IDC_EDIT5, Tempstr);

	// 块对齐力度
	TempdwCode = pOption->SectionAlignment;
	Tempstr.Format(L"%08X", TempdwCode);
	SetDlgItemText(IDC_EDIT6, Tempstr);

	// 文件对齐力度
	TempdwCode = pOption->FileAlignment;
	Tempstr.Format(L"%08X", TempdwCode);
	SetDlgItemText(IDC_EDIT8, Tempstr);

}

// 加载区段信息
void MasterWindows::OnBnClickedButton4()
{
	SectionInfo obj_section;
	obj_section.DoModal();
	return;
}

// 新区段添加（壳）
void MasterWindows::OnBnClickedButton9()
{
	if (NewSection())
		AfxMessageBox(L"添加新区段成功");
	else
		AfxMessageBox(L"添加新区段失败");
}

// 区段添加内部调用函数
BOOL MasterWindows::NewSection()
{
	// 壳区段
	AddSection obj_addsection; BOOL nRet = TRUE;

	BYTE Name[] = ".mas";

	const DWORD SectionSize = 0x14D00;

	obj_addsection.puModifySectioNumber();

	nRet = obj_addsection.puModifySectionInfo(Name, SectionSize);

	obj_addsection.puModifyProgramEntryPoint();

	obj_addsection.puModifySizeofImage();

	nRet = obj_addsection.puAddNewSectionByData(SectionSize);

	return nRet;
}

// 全部区段压缩
void MasterWindows::OnBnClickedButton3()
{
	CompressionData obj_ComperData;
	
	if (!obj_ComperData.puCompressSection())
		AfxMessageBox(L"CompressSection failuer!");
	else
		AfxMessageBox(L"CompressSection Seucess!");
}

// 一键脱壳
void MasterWindows::OnBnClickedButton2()
{
	UnShell obj_Unshell;

	obj_Unshell.puRepCompressionData();

	obj_Unshell.puDeleteSectionInfo();

	if (obj_Unshell.puSaveUnShell())
		AfxMessageBox(L"一键脱壳成功");

}
