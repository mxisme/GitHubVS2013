// PE.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include <locale.h>
#define PE_OUTPUT_STRUCT(a,b)      dprintf("\t+0x%02x  %-15s  0x%x\n" , ulOffset,#b, a.b);ulOffset += sizeof(a.b);
#define PE_OUTPUT_STRUCT_2(a,b,c)  {dprintf("\t\t+0x%02x  %-30s  0x%08x  "##c"\n" , ulTemp,#b, a.b );ulTemp += sizeof(a.b);}
#define PE_OUTPUT_SECTION(a,b,c)   dprintf("\t+0x%02x  %-20s  0x%08x  "##c"\n" , ulTemp,#b, a->b );ulTemp += sizeof(a->b);
//+00h WORD e_magic  // Magic DOS signature MZ(4Dh 5Ah)   DOS��ִ���ļ���� 
//+ 02h  WORD e_cblp   // Bytes on last page of file  
//+ 04h WORD e_cp   // Pages in file
//+ 06h WORD e_crlc   // Relocations
//+ 08h WORD e_cparhdr   // Size of header in paragraphs
//+ 0ah WORD e_minalloc   // Minimun extra paragraphs needs
//+ 0ch WORD e_maxalloc  // Maximun extra paragraphs needs
//+ 0eh WORD e_ss   // intial(relative)SS value   DOS����ĳ�ʼ����ջSS 
//+ 10h WORD e_sp   // intial SP value   DOS����ĳ�ʼ����ջָ��SP 
//+ 12h WORD e_csum   // Checksum 
//+ 14h WORD e_ip   //  intial IP value   DOS����ĳ�ʼ��ָ�����[ָ��IP] 
//+ 16h WORD e_cs   // intial(relative)CS value   DOS����ĳ�ʼ��ջ��� CS
//+ 18h WORD e_lfarlc   // File Address of relocation table 
//+ 1ah WORD e_ovno  //  Overlay number 
//+ 1ch WORD e_res[4]  // Reserved words 
//+ 24h WORD e_oemid   //  OEM identifier(for e_oeminfo) 
//+ 26h WORD e_oeminfo  //  OEM information;e_oemid specific  
//+ 29h WORD e_res2[10]  //  Reserved words 
//+ 3ch LONG  e_lfanew  // Offset to start of PE header   ָ��PE�ļ�ͷ 
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
		dprintf("��ȡ�����ַ %x ���� \n", *pulBaseAddress);
		return result;
	}
	if (ulReadSize != sizeof(IMAGE_DOS_HEADER))
	{
		//dprintf("Read Buffer Len is Errror");
		dprintf("��ȡ���ݳ��ȴ��� \n");
		return S_FALSE;
	}
	if (imageDosHeard.e_magic != IMAGE_DOS_SIGNATURE)
	{
		//dprintf("Address is not PE file Image");
		dprintf("��ַ����PEӳ�� \n");
		return S_FALSE;
	}
	if (bPrintDosHeard)
	{
		dprintf("Dosͷ: _IMAGE_DOS_HEADER\n  �����ַ:%x\n ", *pulBaseAddress);
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
//	+04h WORD Machine; // ����ƽ̨ 
//	+06h WORD NumberOfSections; // �ļ���������Ŀ 
//	+08h DWORD TimeDateStamp; // �ļ��������ں�ʱ�� 
//	+0Ch DWORD PointerToSymbolTable; // ָ��COFF���ű�(��Ҫ���ڵ���) 
//	+10h DWORD NumberOfSymbols; // COFF���ű��з��Ÿ���(ͬ��) 
//	+14h WORD SizeOfOptionalHeader; // IMAGE_OPTIONAL_HEADER32 �ṹ��С 
//	+16h WORD Characteristics; // �ļ����� 
//} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
//typedef struct _IMAGE_OPTIONAL_HEADER
//{
//	//
//	// Standard fields. 
//	//
//	+18h WORD Magic; // ��־��, ROM ӳ��0107h��,��ͨ��ִ���ļ���010Bh��
//	+1Ah BYTE MajorLinkerVersion; // ���ӳ�������汾��
//	+1Bh BYTE MinorLinkerVersion; // ���ӳ���Ĵΰ汾��
//	+1Ch DWORD SizeOfCode; // ���к�����Ľڵ��ܴ�С
//	+20h DWORD SizeOfInitializedData; // ���к��ѳ�ʼ�����ݵĽڵ��ܴ�С
//	+24h DWORD SizeOfUninitializedData; // ���к�δ��ʼ�����ݵĽڵĴ�С
//	+28h DWORD AddressOfEntryPoint; // ����ִ�����RVA
//	+2Ch DWORD BaseOfCode; // ������������ʼRVA
//	+30h DWORD BaseOfData; // ���ݵ��������ʼRVA
//	//
//	// NT additional fields. ����������NT�ṹ���ӵ�����
//	//
//	+34h DWORD ImageBase; // �������ѡװ�ص�ַ
//	+38h DWORD SectionAlignment; // �ڴ��е�����Ķ����С
//	+3Ch DWORD FileAlignment; // �ļ��е�����Ķ����С
//	+40h WORD MajorOperatingSystemVersion; // Ҫ�����ϵͳ��Ͱ汾�ŵ����汾��
//	+42h WORD MinorOperatingSystemVersion; // Ҫ�����ϵͳ��Ͱ汾�ŵĸ��汾��
//	+44h WORD MajorImageVersion; // �������ڲ���ϵͳ�����汾��
//	+46h WORD MinorImageVersion; // �������ڲ���ϵͳ�Ĵΰ汾��
//	+48h WORD MajorSubsystemVersion; // Ҫ�������ϵͳ�汾�����汾��
//	+4Ah WORD MinorSubsystemVersion; // Ҫ�������ϵͳ�汾�Ĵΰ汾��
//	+4Ch DWORD Win32VersionValue; // Ī�����ֶΣ������������õĻ�һ��Ϊ0
//	+50h DWORD SizeOfImage; // ӳ��װ���ڴ����ܳߴ�
//	+54h DWORD SizeOfHeaders; // ����ͷ + ������ĳߴ��С
//	+58h DWORD CheckSum; // ӳ���У���
//	+5Ch WORD Subsystem; // ��ִ���ļ���������ϵͳ
//	+5Eh WORD DllCharacteristics; // DllMain()������ʱ�����ã�Ĭ��Ϊ 0
//	+60h DWORD SizeOfStackReserve; // ��ʼ��ʱ��ջ��С
//	+64h DWORD SizeOfStackCommit; // ��ʼ��ʱʵ���ύ��ջ��С
//	+68h DWORD SizeOfHeapReserve; // ��ʼ��ʱ�����ĶѴ�С
//	+6Ch DWORD SizeOfHeapCommit; // ��ʼ��ʱʵ���ύ�ĶѴ�С
//	+70h DWORD LoaderFlags; // ������йأ�Ĭ��Ϊ 0
//	+74h DWORD NumberOfRvaAndSizes; // �±�����Ŀ¼��������Windows NT ������16
//	+78h IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
//	// ����Ŀ¼��
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
		dprintf("��ȡ�����ַ %x ���� \n", *pulBaseAddress);
		return result;
	}
	if (ulReadSize != sizeof(IMAGE_NT_HEADERS32))
	{
		dprintf("��ȡ���ݳ��ȴ��� \n");
		return S_FALSE;
	}
	if (imageNtHreard.Signature != IMAGE_NT_SIGNATURE)
	{
		dprintf("��ַ����PEӳ�� \n");
		return S_FALSE;
	}
	if (imageNtHreard.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		dprintf("���� PE 32 i386 \n");
		return S_FALSE;
	}
	if ( bPrintNtHeard)
	{
		dprintf("NTͷ: _IMAGE_NT_HEADERS\n  �����ַ:%x\n ", *pulBaseAddress);
		PE_OUTPUT_STRUCT(imageNtHreard, Signature  );
		PE_OUTPUT_STRUCT(imageNtHreard, FileHeader);
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, Machine,  "����ƽ̨");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, NumberOfSections, "�ļ���������Ŀ");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, TimeDateStamp, "�ļ��������ں�ʱ��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, PointerToSymbolTable, "ָ��COFF���ű�(��Ҫ���ڵ���)");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, NumberOfSymbols, "COFF���ű��з��Ÿ���(ͬ��)");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, SizeOfOptionalHeader, "IMAGE_OPTIONAL_HEADER32 �ṹ��С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, Characteristics, "�ļ�����");
		PE_OUTPUT_STRUCT(imageNtHreard, OptionalHeader);
		ulTemp = 0;

		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Magic, "��־��, ROM ӳ��0107h��,��ͨ��ִ���ļ���010Bh��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorLinkerVersion, "���ӳ�������汾��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorLinkerVersion, "���ӳ���Ĵΰ汾��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfCode, "���к�����Ľڵ��ܴ�С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfInitializedData, "���к��ѳ�ʼ�����ݵĽڵ��ܴ�С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfUninitializedData, "���к�δ��ʼ�����ݵĽڵĴ�С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, AddressOfEntryPoint, "����ִ�����RVA");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, BaseOfCode, "������������ʼRVA");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, BaseOfData, "���ݵ��������ʼRVA");

		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, ImageBase, "�������ѡװ�ص�ַ");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SectionAlignment, "�ڴ��е�����Ķ����С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, FileAlignment, "�ļ��е�����Ķ����С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorOperatingSystemVersion, "Ҫ�����ϵͳ��Ͱ汾�ŵ����汾��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorOperatingSystemVersion, "Ҫ�����ϵͳ��Ͱ汾�ŵĸ��汾��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorImageVersion, "�������ڲ���ϵͳ�����汾��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorImageVersion, "�������ڲ���ϵͳ�Ĵΰ汾��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorSubsystemVersion, "Ҫ�������ϵͳ�汾�����汾��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorSubsystemVersion, "Ҫ�������ϵͳ�汾�Ĵΰ汾��");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Win32VersionValue, "Ī�����ֶΣ������������õĻ�һ��Ϊ0");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfImage, "ӳ��װ���ڴ����ܳߴ�");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeaders, "����ͷ + ������ĳߴ��С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, CheckSum, "ӳ���У���");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Subsystem, "��ִ���ļ���������ϵͳ");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, DllCharacteristics, "DllMain()������ʱ�����ã�Ĭ��Ϊ 0");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfStackReserve, "��ʼ��ʱ��ջ��С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfStackCommit, "��ʼ��ʱʵ���ύ��ջ��С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeapReserve, "��ʼ��ʱ�����ĶѴ�С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeapCommit, "��ʼ��ʱʵ���ύ�ĶѴ�С");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, LoaderFlags, "������йأ�Ĭ��Ϊ 0");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, NumberOfRvaAndSizes, "�±�����Ŀ¼��������Windows NT ������16");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, DataDirectory, "����Ŀ¼��");

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
//	+0h BYTE Name[IMAGE_SIZEOF_SHORT_NAME]; // �ڱ�����,�硰.text�� 
//	//IMAGE_SIZEOF_SHORT_NAME=8
//	union
//		+ 8h {
//		DWORD PhysicalAddress; // ������ַ
//		DWORD VirtualSize; // ��ʵ���ȣ�������ֵ��һ�����Ͻṹ������ʹ�����е��κ�һ����һ
//		// ����ȡ��һ��
//	} Misc;
//	+ch DWORD VirtualAddress; // ������ RVA ��ַ
//	+10h DWORD SizeOfRawData; // ���ļ��ж����ĳߴ�
//	+14h DWORD PointerToRawData; // ���ļ��е�ƫ����
//	+18h DWORD PointerToRelocations; // ��OBJ�ļ���ʹ�ã��ض�λ��ƫ��
//	+1ch DWORD PointerToLinenumbers; // �кű���ƫ�ƣ�������ʹ�õأ�
//	+1eh WORD NumberOfRelocations; // ��OBJ�ļ���ʹ�ã��ض�λ����Ŀ
//	+20h WORD NumberOfLinenumbers; // �кű����кŵ���Ŀ
//	+24h DWORD Characteristics; // ��������ɶ�����д����ִ�е�
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
		dprintf("�޷������ڴ� \n");
		return S_FALSE;
	}
	result = g_ExtDataSpaces->ReadVirtual(*pulBaseAddress, pSetion, ulBufLen, &ulReadSize);
	if (result != S_OK)
	{
		dprintf("��ȡ�����ַ %x ���� \n", *pulBaseAddress);
		return result;
	}
	if (ulReadSize != ulBufLen)
	{
		dprintf("��ȡ���ݳ��ȴ��� \n");
		return S_FALSE;
	}

	if (bSection)
	{
		for (UINT i = 0; i < ulSetionCount; i++)
		{
			dprintf("Section%d  _IMAGE_SECTION_HEADER  �����ַ:0x%08x \n", i + 1, *pulBaseAddress);
			dprintf("\t+0x%02x  %-20s  %s  �ڱ�����\n", ulTemp, "Name", pSetion->Name); ulTemp += sizeof(pSetion->Name);
			PE_OUTPUT_SECTION(pSetion, Misc.VirtualSize, "��ʵ���ȣ�������ֵ��һ�����Ͻṹ������ʹ�����е��κ�һ����һ����ȡ��һ��");
			PE_OUTPUT_SECTION(pSetion, SizeOfRawData, "���ļ��ж����ĳߴ�");
			PE_OUTPUT_SECTION(pSetion, PointerToRawData, "���ļ��е�ƫ����");
			PE_OUTPUT_SECTION(pSetion, PointerToRelocations, "��OBJ�ļ���ʹ�ã��ض�λ��ƫ��");
			PE_OUTPUT_SECTION(pSetion, PointerToLinenumbers, "�кű���ƫ�ƣ�������ʹ�õأ�");
			PE_OUTPUT_SECTION(pSetion, NumberOfRelocations, "��OBJ�ļ���ʹ�ã��ض�λ����Ŀ");
			PE_OUTPUT_SECTION(pSetion, NumberOfLinenumbers, "�кű����кŵ���Ŀ");
			PE_OUTPUT_SECTION(pSetion, Characteristics, "��������ɶ�����д����ִ�е�");
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
		dprintf("û�е���� \n");
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
			dprintf("���      ���ƫ��      ������ַ      �������� \n");
			while (pOriginalThunkData32->u1.Ordinal != 0)
			{
				if (IMAGE_SNAP_BY_ORDINAL32(pOriginalThunkData32->u1.Ordinal))
				{
					dprintf("%04d    0x%08x    0x%08x    ��\n", IMAGE_ORDINAL32(pOriginalThunkData32->u1.Ordinal), (ULONG_PTR)pOriginalThunkData32 - (ULONG_PTR)pBase, *pFirstThunkData32);
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
		dprintf("û�е����� \n");
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
	dprintf("DLL  ��������  %s\n", pName);
	dprintf("���    �������ƫ��    ������ַ      �������� \n");
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
			dprintf("%04d    0x%08x    0x%08x    ��\n", pExportBlack->Base + i, (PULONG)((PUCHAR)ulBase + pExportBlack->AddressOfFunctions) + i, ulBase + *(pAddressOfFunctions + i));
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
			dprintf("��ȡ�����ַ %x ���� \n", ulBase);
			goto ex;
		}
		if (ulReadSize != ulImageSize)
		{
			dprintf("��ȡ���ݳ��ȴ��� \n");
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
