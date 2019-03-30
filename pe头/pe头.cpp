// pe头.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include "PE_function.h"
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <string>

using namespace std;
#pragma warning (disable:4996)


typedef struct _MAP_FILE_STRUCT
{
	HANDLE hFile;
	HANDLE hMapping;
	LPVOID ImageBase;
} MAP_FILE_STRUCT;




int main(int argc, char** argv)
{
	//if (argc < 2)
	//{
//		std::cout << "you should add Parameters";
//		exit(1);
//	}
	//std::string Doc_ads;
	//Doc_ads = argv[1];

	FILE *PE_File = fopen("g:\\main.exe", "rb");
	unsigned int length;//PE文件长度
	unsigned char *File_Br;//

	length = PE_Check_Size(PE_File);//长度

	File_Br = (unsigned char*)malloc(length);
	fread(File_Br, 1, length, PE_File);
	if (!IsPEFile(File_Br))//检测是否是PE文件
	{
		fprintf(stderr, "not pe file\n");
		exit(1);
	}
	IMAGE_DOS_HEADER *Dos_Head = (IMAGE_DOS_HEADER*)File_Br;
	//cout << hex << Dos_Head->e_lfanew;
	IMAGE_NT_HEADERS* NT_Head = (IMAGE_NT_HEADERS*)((DWORD)Dos_Head + Dos_Head->e_lfanew);

	Section_table** S_table = Section_find(NT_Head);

	//IMAGE_SECTION_HEADER *SEC_head = (IMAGE_SECTION_HEADER*)((DWORD)(NT_Head) + 0x18 + NT_Head->FileHeader.SizeOfOptionalHeader);

	std::cout << "Machine: " << hex << NT_Head->FileHeader.Machine << std::endl;

	std::cout << "Section number: " << hex << NT_Head->FileHeader.NumberOfSections << std::endl;

	if (NT_Head->FileHeader.SizeOfOptionalHeader == 224)//系统编号
		cout << "system: X32" << endl;
	else
		cout << "system: X64" << endl;

	//std::cout << "opMagic: "<< hex << OP_head->Magic << std::endl;


	//std::cout << "Section name :";//第一个块的名称,用于调试
	//for (int i = 0; i < 8; i++)
	//	std::cout << (char)(SEC_head->Name[i]);
	//cout << endl;

	//数据目录表
	//**************
	cout << "Export table size: " << (NT_Head->OptionalHeader.DataDirectory[1].Size) << endl;//这个size是数据块的总体大小
	

	//**************
	
	//区块属性部分
	int Se_num = NT_Head->FileHeader.NumberOfSections;

	cout << '\n';
	cout << "     " << "SectionNumber:" << Se_num  << endl;
	for (int m = 0; m < Se_num; m++)
	{
		for (int i = 0; i < 8; i++)
		{
			cout << S_table[m]->Name[i];
		}
		cout << ':' << endl;
		cout << "VTadress:" << S_table[m]->VtAddress << endl;
		cout << "RAWaddress:" << S_table[m]->RawPointer << endl;
		cout << "RAWsize:" << S_table[m]->RawSize << endl;
		cout << endl;
	}
		
			
	
}