#pragma once
#include "stdafx.h"
#include "resource.h"
#include "afxwin.h"


// MasterWindows 对话框

class MasterWindows : public CDialogEx
{
	DECLARE_DYNAMIC(MasterWindows)

public:
	MasterWindows(CWnd* pParent = NULL);				// 标准构造函数
	virtual ~MasterWindows();

// 对话框数据
	enum { IDD = IDD_DIALOG1 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	CStatic m_MasterStaticText;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	CString m_MasterStaticTextStr;

public:
	afx_msg void OnBnClickedButton4();
//	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton9();

	/*自定义数据*/
private:
	// 显示PE数据
	void ShowPEInfoData(const CString & FileName);
	// 区段添加内部调用函数
	BOOL NewSection();
public:
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton2();
};
