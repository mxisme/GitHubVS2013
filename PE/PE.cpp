// PE.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <locale.h>
#define PE_OUTPUT_STRUCT(a,b)      dprintf("\t+0x%02x  %-15s  0x%x\n" , ulOffset,#b, a.b);ulOffset += sizeof(a.b);
#define PE_OUTPUT_STRUCT_2(a,b,c)  {dprintf("\t\t+0x%02x  %-30s  0x%08x  "##c"\n" , ulTemp,#b, a.b );ulTemp += sizeof(a.b);}
#define PE_OUTPUT_SECTION(a,b,c)   dprintf("\t+0x%02x  %-20s  0x%08x  "##c"\n" , ulTemp,#b, a->b );ulTemp += sizeof(a->b);
//+00h WORD e_magic  // Magic DOS signature MZ(4Dh 5Ah)   DOS可执行文件标记 
//+ 02h  WORD e_cblp   // Bytes on last page of file  
//+ 04h WORD e_cp   // Pages in file
//+ 06h WORD e_crlc   // Relocations
//+ 08h WORD e_cparhdr   // Size of header in paragraphs
//+ 0ah WORD e_minalloc   // Minimun extra paragraphs needs
//+ 0ch WORD e_maxalloc  // Maximun extra paragraphs needs
//+ 0eh WORD e_ss   // intial(relative)SS value   DOS代码的初始化堆栈SS 
//+ 10h WORD e_sp   // intial SP value   DOS代码的初始化堆栈指针SP 
//+ 12h WORD e_csum   // Checksum 
//+ 14h WORD e_ip   //  intial IP value   DOS代码的初始化指令入口[指针IP] 
//+ 16h WORD e_cs   // intial(relative)CS value   DOS代码的初始堆栈入口 CS
//+ 18h WORD e_lfarlc   // File Address of relocation table 
//+ 1ah WORD e_ovno  //  Overlay number 
//+ 1ch WORD e_res[4]  // Reserved words 
//+ 24h WORD e_oemid   //  OEM identifier(for e_oeminfo) 
//+ 26h WORD e_oeminfo  //  OEM information;e_oemid specific  
//+ 29h WORD e_res2[10]  //  Reserved words 
//+ 3ch LONG  e_lfanew  // Offset to start of PE header   指向PE文件头 
HRESULT PE_PrintDosHeard(ULONG_PTR * pulBaseAddress ,BOOL bPrintDosHeard  )
{
	HRESULT                      result = S_OK;
	IMAGE_DOS_HEADER             imageDosHeard = { 0 };
	ULONG                        ulReadSize = 0;
	ULONG                        ulOffset = 0;
	result = g_ExtDataSpaces->ReadVirtual(*pulBaseAddress, &imageDosHeard, sizeof(IMAGE_DOS_HEADER), &ulReadSize);
	if (result != S_OK)
	{
		//dprintf("Read Virtual Memory %x is  Error", ulBaseAddress);
		dprintf("读取虚拟地址 %x 错误 \n", *pulBaseAddress);
		return result;
	}
	if (ulReadSize != sizeof(IMAGE_DOS_HEADER))
	{
		//dprintf("Read Buffer Len is Errror");
		dprintf("读取数据长度错误。 \n");
		return S_FALSE;
	}
	if (imageDosHeard.e_magic != IMAGE_DOS_SIGNATURE)
	{
		//dprintf("Address is not PE file Image");
		dprintf("地址不是PE映像 \n");
		return S_FALSE;
	}
	if (bPrintDosHeard)
	{
		dprintf("Dos头: _IMAGE_DOS_HEADER\n  虚拟地址:%x\n ", *pulBaseAddress);
		PE_OUTPUT_STRUCT(imageDosHeard, e_magic);
		PE_OUTPUT_STRUCT(imageDosHeard, e_cblp);
		PE_OUTPUT_STRUCT(imageDosHeard, e_cp);
		PE_OUTPUT_STRUCT(imageDosHeard, e_crlc);
		PE_OUTPUT_STRUCT(imageDosHeard, e_cparhdr);
		PE_OUTPUT_STRUCT(imageDosHeard, e_minalloc);
		PE_OUTPUT_STRUCT(imageDosHeard, e_maxalloc);
		PE_OUTPUT_STRUCT(imageDosHeard, e_ss);
		PE_OUTPUT_STRUCT(imageDosHeard, e_sp);
		PE_OUTPUT_STRUCT(imageDosHeard, e_csum);
		PE_OUTPUT_STRUCT(imageDosHeard, e_ip);
		PE_OUTPUT_STRUCT(imageDosHeard, e_cs);
		PE_OUTPUT_STRUCT(imageDosHeard, e_lfarlc);
		PE_OUTPUT_STRUCT(imageDosHeard, e_ovno);
		PE_OUTPUT_STRUCT(imageDosHeard, e_res);
		PE_OUTPUT_STRUCT(imageDosHeard, e_oemid);
		PE_OUTPUT_STRUCT(imageDosHeard, e_oeminfo);
		PE_OUTPUT_STRUCT(imageDosHeard, e_res2);
		PE_OUTPUT_STRUCT(imageDosHeard, e_lfanew);
	}

	*pulBaseAddress += imageDosHeard.e_lfanew;
	return result;
}
//typedef struct _IMAGE_FILE_HEADER
//{
//	+04h WORD Machine; // 运行平台 
//	+06h WORD NumberOfSections; // 文件的区块数目 
//	+08h DWORD TimeDateStamp; // 文件创建日期和时间 
//	+0Ch DWORD PointerToSymbolTable; // 指向COFF符号表(主要用于调试) 
//	+10h DWORD NumberOfSymbols; // COFF符号表中符号个数(同上) 
//	+14h WORD SizeOfOptionalHeader; // IMAGE_OPTIONAL_HEADER32 结构大小 
//	+16h WORD Characteristics; // 文件属性 
//} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
//typedef struct _IMAGE_OPTIONAL_HEADER
//{
//	//
//	// Standard fields. 
//	//
//	+18h WORD Magic; // 标志字, ROM 映像（0107h）,普通可执行文件（010Bh）
//	+1Ah BYTE MajorLinkerVersion; // 链接程序的主版本号
//	+1Bh BYTE MinorLinkerVersion; // 链接程序的次版本号
//	+1Ch DWORD SizeOfCode; // 所有含代码的节的总大小
//	+20h DWORD SizeOfInitializedData; // 所有含已初始化数据的节的总大小
//	+24h DWORD SizeOfUninitializedData; // 所有含未初始化数据的节的大小
//	+28h DWORD AddressOfEntryPoint; // 程序执行入口RVA
//	+2Ch DWORD BaseOfCode; // 代码的区块的起始RVA
//	+30h DWORD BaseOfData; // 数据的区块的起始RVA
//	//
//	// NT additional fields. 以下是属于NT结构增加的领域。
//	//
//	+34h DWORD ImageBase; // 程序的首选装载地址
//	+38h DWORD SectionAlignment; // 内存中的区块的对齐大小
//	+3Ch DWORD FileAlignment; // 文件中的区块的对齐大小
//	+40h WORD MajorOperatingSystemVersion; // 要求操作系统最低版本号的主版本号
//	+42h WORD MinorOperatingSystemVersion; // 要求操作系统最低版本号的副版本号
//	+44h WORD MajorImageVersion; // 可运行于操作系统的主版本号
//	+46h WORD MinorImageVersion; // 可运行于操作系统的次版本号
//	+48h WORD MajorSubsystemVersion; // 要求最低子系统版本的主版本号
//	+4Ah WORD MinorSubsystemVersion; // 要求最低子系统版本的次版本号
//	+4Ch DWORD Win32VersionValue; // 莫须有字段，不被病毒利用的话一般为0
//	+50h DWORD SizeOfImage; // 映像装入内存后的总尺寸
//	+54h DWORD SizeOfHeaders; // 所有头 + 区块表的尺寸大小
//	+58h DWORD CheckSum; // 映像的校检和
//	+5Ch WORD Subsystem; // 可执行文件期望的子系统
//	+5Eh WORD DllCharacteristics; // DllMain()函数何时被调用，默认为 0
//	+60h DWORD SizeOfStackReserve; // 初始化时的栈大小
//	+64h DWORD SizeOfStackCommit; // 初始化时实际提交的栈大小
//	+68h DWORD SizeOfHeapReserve; // 初始化时保留的堆大小
//	+6Ch DWORD SizeOfHeapCommit; // 初始化时实际提交的堆大小
//	+70h DWORD LoaderFlags; // 与调试有关，默认为 0
//	+74h DWORD NumberOfRvaAndSizes; // 下边数据目录的项数，Windows NT 发布是16
//	+78h IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
//	// 数据目录表
//} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
HRESULT PE_PrintNtHeard(ULONG_PTR * pulBaseAddress, BOOL bPrintNtHeard, ULONG *pukSetionCount, IMAGE_DATA_DIRECTORY  DataDirectory[], PULONG_PTR pulImageSize)
{
	HRESULT                      result = S_OK;
	IMAGE_NT_HEADERS32           imageNtHreard = { 0 };
	ULONG                        ulReadSize = 0;
	ULONG                        ulOffset = 0;
	ULONG                        ulTemp = 0;
	char                         *pNote = NULL;
	result = g_ExtDataSpaces->ReadVirtual(*pulBaseAddress, &imageNtHreard, sizeof(IMAGE_NT_HEADERS32), &ulReadSize);
	if (result != S_OK)
	{
		dprintf("读取虚拟地址 %x 错误 \n", *pulBaseAddress);
		return result;
	}
	if (ulReadSize != sizeof(IMAGE_NT_HEADERS32))
	{
		dprintf("读取数据长度错误。 \n");
		return S_FALSE;
	}
	if (imageNtHreard.Signature != IMAGE_NT_SIGNATURE)
	{
		dprintf("地址不是PE映像 \n");
		return S_FALSE;
	}
	if (imageNtHreard.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		dprintf("不是 PE 32 i386 \n");
		return S_FALSE;
	}
	if ( bPrintNtHeard)
	{
		dprintf("NT头: _IMAGE_NT_HEADERS\n  虚拟地址:%x\n ", *pulBaseAddress);
		PE_OUTPUT_STRUCT(imageNtHreard, Signature  );
		PE_OUTPUT_STRUCT(imageNtHreard, FileHeader);
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, Machine,  "运行平台");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, NumberOfSections, "文件的区块数目");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, TimeDateStamp, "文件创建日期和时间");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, PointerToSymbolTable, "指向COFF符号表(主要用于调试)");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, NumberOfSymbols, "COFF符号表中符号个数(同上)");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, SizeOfOptionalHeader, "IMAGE_OPTIONAL_HEADER32 结构大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, Characteristics, "文件属性");
		PE_OUTPUT_STRUCT(imageNtHreard, OptionalHeader);
		ulTemp = 0;

		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Magic, "标志字, ROM 映像（0107h）,普通可执行文件（010Bh）");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorLinkerVersion, "链接程序的主版本号");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorLinkerVersion, "链接程序的次版本号");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfCode, "所有含代码的节的总大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfInitializedData, "所有含已初始化数据的节的总大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfUninitializedData, "所有含未初始化数据的节的大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, AddressOfEntryPoint, "程序执行入口RVA");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, BaseOfCode, "代码的区块的起始RVA");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, BaseOfData, "数据的区块的起始RVA");

		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, ImageBase, "程序的首选装载地址");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SectionAlignment, "内存中的区块的对齐大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, FileAlignment, "文件中的区块的对齐大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorOperatingSystemVersion, "要求操作系统最低版本号的主版本号");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorOperatingSystemVersion, "要求操作系统最低版本号的副版本号");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorImageVersion, "可运行于操作系统的主版本号");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorImageVersion, "可运行于操作系统的次版本号");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorSubsystemVersion, "要求最低子系统版本的主版本号");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorSubsystemVersion, "要求最低子系统版本的次版本号");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Win32VersionValue, "莫须有字段，不被病毒利用的话一般为0");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfImage, "映像装入内存后的总尺寸");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeaders, "所有头 + 区块表的尺寸大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, CheckSum, "映像的校检和");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Subsystem, "可执行文件期望的子系统");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, DllCharacteristics, "DllMain()函数何时被调用，默认为 0");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfStackReserve, "初始化时的栈大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfStackCommit, "初始化时实际提交的栈大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeapReserve, "初始化时保留的堆大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeapCommit, "初始化时实际提交的堆大小");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, LoaderFlags, "与调试有关，默认为 0");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, NumberOfRvaAndSizes, "下边数据目录的项数，Windows NT 发布是16");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, DataDirectory, "数据目录表");

		int i = 0;
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_EXPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_IMPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_RESOURCE", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_EXCEPTION", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_SECURITY", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_BASERELOC", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_DEBUG", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_GLOBALPTR", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_TLS", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_IAT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n ", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n ", "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
	}
	memcpy(DataDirectory, imageNtHreard.OptionalHeader.DataDirectory, sizeof(IMAGE_DATA_DIRECTORY)*IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
	*pukSetionCount = imageNtHreard.FileHeader.NumberOfSections;
	*pulBaseAddress += sizeof(IMAGE_NT_HEADERS32);
	*pulImageSize = imageNtHreard.OptionalHeader.SizeOfImage;
	return result;
}

//typedef struct _IMAGE_SECTION_HEADER
//
//{
//	+0h BYTE Name[IMAGE_SIZEOF_SHORT_NAME]; // 节表名称,如“.text” 
//	//IMAGE_SIZEOF_SHORT_NAME=8
//	union
//		+ 8h {
//		DWORD PhysicalAddress; // 物理地址
//		DWORD VirtualSize; // 真实长度，这两个值是一个联合结构，可以使用其中的任何一个，一
//		// 般是取后一个
//	} Misc;
//	+ch DWORD VirtualAddress; // 节区的 RVA 地址
//	+10h DWORD SizeOfRawData; // 在文件中对齐后的尺寸
//	+14h DWORD PointerToRawData; // 在文件中的偏移量
//	+18h DWORD PointerToRelocations; // 在OBJ文件中使用，重定位的偏移
//	+1ch DWORD PointerToLinenumbers; // 行号表的偏移（供调试使用地）
//	+1eh WORD NumberOfRelocations; // 在OBJ文件中使用，重定位项数目
//	+20h WORD NumberOfLinenumbers; // 行号表中行号的数目
//	+24h DWORD Characteristics; // 节属性如可读，可写，可执行等
//} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
HRESULT PE_PrintSection(ULONG_PTR * pulBaseAddress, ULONG ulSetionCount, BOOL bSection)
{
	HRESULT                      result = S_OK;
	PIMAGE_SECTION_HEADER        pSetion = NULL;
	ULONG                        ulReadSize = 0;
	ULONG                        ulTemp = 0;
	ULONG                        ulBufLen = 0;

	ulBufLen = sizeof(IMAGE_SECTION_HEADER)*ulSetionCount;
	pSetion = (PIMAGE_SECTION_HEADER)malloc(ulBufLen);
	if (pSetion == NULL)
	{
		dprintf("无法申请内存 \n");
		return S_FALSE;
	}
	result = g_ExtDataSpaces->ReadVirtual(*pulBaseAddress, pSetion, ulBufLen, &ulReadSize);
	if (result != S_OK)
	{
		dprintf("读取虚拟地址 %x 错误 \n", *pulBaseAddress);
		return result;
	}
	if (ulReadSize != ulBufLen)
	{
		dprintf("读取数据长度错误。 \n");
		return S_FALSE;
	}

	if (bSection)
	{
		for (UINT i = 0; i < ulSetionCount; i++)
		{
			dprintf("Section%d  _IMAGE_SECTION_HEADER  虚拟地址:0x%08x \n", i + 1, *pulBaseAddress);
			dprintf("\t+0x%02x  %-20s  %s  节表名称\n", ulTemp, "Name", pSetion->Name); ulTemp += sizeof(pSetion->Name);
			PE_OUTPUT_SECTION(pSetion, Misc.VirtualSize, "真实长度，这两个值是一个联合结构，可以使用其中的任何一个，一般是取后一个");
			PE_OUTPUT_SECTION(pSetion, SizeOfRawData, "在文件中对齐后的尺寸");
			PE_OUTPUT_SECTION(pSetion, PointerToRawData, "在文件中的偏移量");
			PE_OUTPUT_SECTION(pSetion, PointerToRelocations, "在OBJ文件中使用，重定位的偏移");
			PE_OUTPUT_SECTION(pSetion, PointerToLinenumbers, "行号表的偏移（供调试使用地）");
			PE_OUTPUT_SECTION(pSetion, NumberOfRelocations, "在OBJ文件中使用，重定位项数目");
			PE_OUTPUT_SECTION(pSetion, NumberOfLinenumbers, "行号表中行号的数目");
			PE_OUTPUT_SECTION(pSetion, Characteristics, "节属性如可读，可写，可执行等");
			*pulBaseAddress += sizeof(IMAGE_SECTION_HEADER);
			ulTemp = 0;
			pSetion++;
		}
	}
	return result;
}

HRESULT PE_PrintImport(PBYTE pBase, IMAGE_DATA_DIRECTORY DataImport, BOOL bImport)
{
	HRESULT                      result = S_OK;
	PIMAGE_IMPORT_DESCRIPTOR     pImportBlack = NULL;
	PIMAGE_THUNK_DATA32 	 	 pFirstThunkData32 = NULL;
	PIMAGE_THUNK_DATA32 	   	 pOriginalThunkData32 = NULL;
	PIMAGE_IMPORT_BY_NAME 		 pImageImportByName = NULL;
	pImportBlack = PIMAGE_IMPORT_DESCRIPTOR(pBase + DataImport.VirtualAddress);

	if (!pImportBlack || !DataImport.Size)
	{
		dprintf("没有导入表 \n");
		return S_OK ;
	}
	char                       *pDllName = NULL;
	if (bImport)
	{
		while (pImportBlack->Name != 0 && pImportBlack->Characteristics != 0)
		{
			pFirstThunkData32 = (PIMAGE_THUNK_DATA32)((ULONG)pBase + (ULONG)(pImportBlack->FirstThunk));
			pOriginalThunkData32 = (PIMAGE_THUNK_DATA32)((ULONG)pBase + (ULONG)(pImportBlack->OriginalFirstThunk));
			pDllName = (PCHAR)((ULONG_PTR)pBase + (ULONG_PTR)pImportBlack->Name);
			dprintf("DLL  name  is  %s\n", pDllName);
			dprintf("序号      相对偏移      函数地址      函数名称 \n");
			while (pOriginalThunkData32->u1.Ordinal != 0)
			{
				if (IMAGE_SNAP_BY_ORDINAL32(pOriginalThunkData32->u1.Ordinal))
				{
					dprintf("%04d    0x%08x    0x%08x    无\n", IMAGE_ORDINAL32(pOriginalThunkData32->u1.Ordinal), (ULONG_PTR)pOriginalThunkData32 - (ULONG_PTR)pBase, *pFirstThunkData32);
				}
				else
				{
					pImageImportByName = (PIMAGE_IMPORT_BY_NAME)((UCHAR*)pBase + pOriginalThunkData32->u1.AddressOfData);
					dprintf("%04d    0x%08x    0x%08x    %s\n", pImageImportByName->Hint, (ULONG_PTR)pOriginalThunkData32->u1.AddressOfData, *pFirstThunkData32, pImageImportByName->Name);
				}
				pOriginalThunkData32++;
				pFirstThunkData32++;
			}
			pImportBlack++;
		}
	}
	return result;
}

HRESULT PE_PrintExport(PBYTE pBase, IMAGE_DATA_DIRECTORY DataExport,ULONG_PTR ulBase ,BOOL bExport)
{
	HRESULT                      result = S_OK;
	char                       * pName = NULL;
	ULONG                        Funstart = 0;
	ULONG                        FunEnd = 0;
	PIMAGE_EXPORT_DIRECTORY      pExportBlack = NULL;
	WORD                        *pAddressOfNameOrdinals = NULL;
	ULONG                       *pAddressOfNames = NULL;
	ULONG                       *pAddressOfFunctions = NULL;
	UINT                         j = 0;
	pExportBlack = PIMAGE_EXPORT_DIRECTORY(pBase + DataExport.VirtualAddress);

	if (!pExportBlack || !DataExport.Size)
	{
		dprintf("没有导出表 \n");
		return S_OK;
	}
	if (!bExport)
	{
		return S_OK;
	}
	pAddressOfNameOrdinals = (PWORD)((PUCHAR)pBase + pExportBlack->AddressOfNameOrdinals);
	pAddressOfNames = (PULONG)((PUCHAR)pBase + pExportBlack->AddressOfNames);
	pAddressOfFunctions = (PULONG)((PUCHAR)pBase + pExportBlack->AddressOfFunctions);
	Funstart = DataExport.VirtualAddress;
	FunEnd = DataExport.VirtualAddress + DataExport.Size;
	pName = (PCHAR)pBase + pExportBlack->Name;
	dprintf("DLL  导出名是  %s\n", pName);
	dprintf("序号    函数相对偏移    函数地址      函数名称 \n");
	for (UINT i = 0; i < pExportBlack->NumberOfFunctions; i++)
	{
		if ((*pAddressOfFunctions >Funstart) &&(*pAddressOfFunctions < FunEnd))
		{
			pName = (char *)(pBase + *pAddressOfFunctions);
			dprintf("%04d    0x%08x    0x%08x    %s\n", pExportBlack->Base + i, (PULONG)((PUCHAR)ulBase + pExportBlack->AddressOfFunctions) + i , ulBase + *(pAddressOfFunctions + i), (char *)(pBase + *pAddressOfFunctions));
			continue;
		}
		for (j = 0; j < pExportBlack->NumberOfNames; j++)
		{
			if (*(pAddressOfNameOrdinals +j) == i)
			{
				pName = (char *)pBase + *(pAddressOfNames + j);
				dprintf("%04d    0x%08x    0x%08x    %s\n", pExportBlack->Base + i, (PULONG)((PUCHAR)ulBase + pExportBlack->AddressOfFunctions) + i, ulBase + *(pAddressOfFunctions + i), (char *)pBase + *(pAddressOfNames + j));
				break;
			}
		}
		if (*(pAddressOfNameOrdinals + j) !=  i)
		{
			dprintf("%04d    0x%08x    0x%08x    无\n", pExportBlack->Base + i, (PULONG)((PUCHAR)ulBase + pExportBlack->AddressOfFunctions) + i, ulBase + *(pAddressOfFunctions + i));
		}


	}
	return result;
}



ULONG64 str2ull(const char *nptr, char **endptr, int base)
{
	const char *s = nptr;
	unsigned long acc;
	int c;
	unsigned long cutoff;
	int neg = 0, any, cutlim;

	do {
		c = *s++;
	} while (isspace(c));
	//if (c == '-')
	//{
	//	neg = 1;
	//	c = *s++;
	//}
	//else if (c == '+')
	//	c = *s++;
	if ((base == 0 || base == 16) &&
		c == '0' && (*s == 'x' || *s == 'X'))
	{
		c = s[1];
		s += 2;
		base = 16;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;

	//cutoff = neg ? ((ULONG64)0xffffffff + 1) : LONG_MAX;
	cutoff = 0xffffffff;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for (acc = 0, any = 0;; c = *s++)
	{
		if (isdigit(c))
			c -= '0';
		else if (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
			any = -1;
		else
		{
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0)
	{
		acc = neg ? LONG_MIN : LONG_MAX;

	}
	else if (neg)
		acc = 0 - acc;
	if (endptr != 0)
		*endptr = any ? (char *)((size_t)(s - 1)) : (char *)((size_t)nptr);
	return acc;
}




HRESULT CALLBACK pe(PDEBUG_CLIENT4 Client, PCSTR args)
{
	INIT_API();
	ULONG_PTR        ulAddress = 0;
	ULONG_PTR        ulBase = 0;
	ULONG_PTR        ulImageSize = 0;
	HRESULT          result = S_OK;
	ULONG            ulSetionCount = 0;
	BOOL             bAllPrint = TRUE;
	BOOL             bPrintDosHeard = FALSE;
	BOOL             bPrintNtHeard = FALSE;
	BOOL             bSection = FALSE;
	BOOL             bImport = FALSE;
	BOOL             bExport = FALSE;

	IMAGE_DATA_DIRECTORY  DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = { 0 };
	if ( args == NULL)
	{
		result = S_FALSE;
		goto ex;
	}do
	{
		const char * split = " ";
		char * p = NULL, *params = NULL, *next = NULL;
		params = new char[strlen(args) + 1];
		if (params == NULL)
		{
			result = S_FALSE;
			goto ex;
		}
		_try
		{
			memset(params, 0, strlen(args) + 1);
			strcpy_s(params, strlen(args) + 1, args);
			p = strtok_s(params, split, &next);
			while (p != NULL)
			{
				if (_stricmp(p, "-section") == 0)
				{
					bAllPrint = FALSE;
					bSection = TRUE;
				}
				else if (_stricmp(p, "-dos") == 0)
				{
					bAllPrint = FALSE;
					bPrintDosHeard = TRUE;
				}
				else if (_stricmp(p, "-nt") == 0)
				{
					bAllPrint = FALSE;
					bPrintNtHeard = TRUE;
				}
				else if (_stricmp(p, "-import") == 0)
				{
					bAllPrint = FALSE;
					bImport = TRUE;
				}
				else if (_stricmp(p, "-export") == 0)
				{
					bAllPrint = FALSE;
					bExport = TRUE;
				}
				else if (p)
				{
					char *endptr = NULL;
					ulAddress = str2ull(p, &endptr, 16);
					ulBase = ulAddress;
				}
				p = strtok_s(NULL, split, &next);
			}
		}_finally
		{
			if (params)
			{
				delete[]params;
				params = NULL;
			}
		}
	} while (FALSE);

	if (ulAddress == 0)
	{
		result = S_FALSE;
		goto ex;
	}
	if (result = PE_PrintDosHeard(&ulAddress, bAllPrint | bPrintDosHeard) != S_OK)
	{
		goto ex;
	}
	if (result = PE_PrintNtHeard(&ulAddress, bAllPrint | bPrintNtHeard, &ulSetionCount, DataDirectory, &ulImageSize) != S_OK)
	{
		goto ex;
	}
	if (result = PE_PrintSection(&ulAddress, ulSetionCount, bAllPrint | bSection) != S_OK)
	{
		goto ex;
	}
	PBYTE    pImage = new BYTE[ulImageSize];
	if (pImage == NULL)
	{
		result = S_FALSE;
		goto ex;
	}
	_try
	{
		ULONG   ulReadSize = 0;
		memset(pImage, 0, ulImageSize);
		result = g_ExtDataSpaces->ReadVirtual(ulBase, pImage, ulImageSize, &ulReadSize);
		if (result != S_OK)
		{
			dprintf("读取虚拟地址 %x 错误 \n", ulBase);
			goto ex;
		}
		if (ulReadSize != ulImageSize)
		{
			dprintf("读取数据长度错误。 \n");
			result = S_FALSE;
			goto ex;
		}
		if (result = PE_PrintImport(pImage, DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT], bAllPrint | bImport) != S_OK)
		{
			goto ex;
		}
		if (result = PE_PrintExport(pImage, DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT], ulBase, bAllPrint | bExport) != S_OK)
		{
			goto ex;
		}
	}_finally
	{
		if (pImage)
		{
			delete[]pImage;
			pImage = NULL;
		}
	}

ex:

	EXIT_API();
	return result;
}

