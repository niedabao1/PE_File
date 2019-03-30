#pragma once
#include<stdio.h>
#include<windows.h>

class Section_table {
public:
	char Name[8];
	DWORD VtAddress;
	DWORD RawSize;
	DWORD RawPointer;
	DWORD VtSize;
};

class iamgeImport_descriptor {//IID��
public:
	char Dll_Name[30];
	unsigned Num = 0;
	DWORD APIaddress;
};

class importTable {
public:
	char Name[14];
	DWORD Image;
};




int PE_Check_Size(FILE* Fp)//������ָ����ļ��Ĵ�С,�����ļ�ָ��,�����ֽ���;
{
	int num = 0;
	fseek(Fp, 0, SEEK_END);
	num = ftell(Fp);
	fseek(Fp, 0, SEEK_SET);//SETֵ��ʼλ��.
	return num;
}

BOOL IsPEFile(LPVOID ImageBase) //����Ƿ�Ϊpe�ļ�.
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;

	if (!ImageBase)
		return FALSE;
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	pNtH = (PIMAGE_NT_HEADERS32)((DWORD)pDH + pDH->e_lfanew);
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	return true;
}

Section_table** Section_find(IMAGE_NT_HEADERS* NT_head)//ʹ�������ѿռ䲢����Ϣ�洢��class��.
{
	IMAGE_SECTION_HEADER *SEC_head = (IMAGE_SECTION_HEADER*)((DWORD)(NT_head)+0x18 + NT_head->FileHeader.SizeOfOptionalHeader);
	int Section_num = NT_head->FileHeader.NumberOfSections;
	Section_table **S_table = (Section_table**)malloc(sizeof(Section_table*)*Section_num);
	for (int i = 0; i < Section_num; i++)
	{
		S_table[i] = (Section_table*)malloc(sizeof(Section_table));
	}
	//test
	//*******


	//*******
	for (int i = 0; i < Section_num; i++)
	{

		(S_table[i])->RawPointer = SEC_head->PointerToRawData;//������λ��
		(S_table[i])->RawSize = SEC_head->SizeOfRawData;//�����д�С
		(S_table[i])->VtAddress = SEC_head->VirtualAddress;//�����ַ��ʼλ��
		for (int m = 0; m < 8; m++)//������
		{
			(S_table[i])->Name[m] = (char)(SEC_head->Name[m]);

		}
		SEC_head = (IMAGE_SECTION_HEADER*)((DWORD)SEC_head + 0x28);
	}
	return S_table;
}

int Dll_Num()
{
	return 0;
}



iamgeImport_descriptor** Import_Table(IMAGE_NT_HEADERS* NT_head)
{
	IMAGE_IMPORT_DESCRIPTOR* IID_table = (IMAGE_IMPORT_DESCRIPTOR*)(NT_head->OptionalHeader.DataDirectory[1].VirtualAddress);//��������λ��
	iamgeImport_descriptor** Dllname_table;

	Dllname_table = (iamgeImport_descriptor**)malloc(sizeof(iamgeImport_descriptor*) * (NT_head->OptionalHeader.DataDirectory[1].Size) / 20);


	//��������������IID����Ŀ
	IMAGE_IMPORT_DESCRIPTOR* IID_table_num = (IMAGE_IMPORT_DESCRIPTOR*)(NT_head->OptionalHeader.DataDirectory[1].VirtualAddress);
	for (int i = 0; i < (NT_head->OptionalHeader.DataDirectory[1].Size) / 20; i++)
	{
		Dllname_table[i] = (iamgeImport_descriptor*)malloc(sizeof(iamgeImport_descriptor));//�����iamgeImport_descriptor�ѿռ�

		int n = 0;
		while ((byte)(IID_table_num->Name + n) != NULL)
		{
			Dllname_table[i]->Dll_Name[n] = (byte)(IID_table_num->Name + n);
		}

		n = 0;//��ռ�����
		IMAGE_THUNK_DATA * ITD_table = (IMAGE_THUNK_DATA *)IID_table_num->OriginalFirstThunk;//����ÿ��DLL�������õ�API����
		while (ITD_table->u1.ForwarderString != NULL)
		{
			Dllname_table[i]->Num++;
		}
		IID_table_num += 0x14;//��һ��IID
		
	}


	for (int i = 0;; i++)
	{
		IID_table->Name;
	}




	Dllname_table;	//�����ڴ�




	IID_table->Name;



	//����:DLL

	//����:API

	//��ʼ��iid��itd����

	//��ֵ,IMAGE_THUNK_DATA�Ǹ�union,�����λΪ1ʱ,ֱ�������ָ����,Ϊ0ʱ,ָ��IMAGE_IMPORT_BY_NAME

}