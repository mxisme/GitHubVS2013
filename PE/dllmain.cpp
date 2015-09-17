// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

HRESULT CALLBACK help(PDEBUG_CLIENT4 Client, PCSTR args)
{
	INIT_API();

	dprintf("Help for PE.dll\n"
		"  help                = Shows this help\n"
		"  !pe  [params1] [params2] ... [paramsn]  address \n"
		"  params: 可选  \n"
		"    -dos      显示dos头 \n"
		"    -nt       显示ne头 \n"
		"    -section  显示节表 \n"
		"    -import   显示导入表 \n"
		"    -export   显示导出表 \n"
		"  address ：\n"
		"    16进制\n"
		"  例如  ：\n"
		"    !pe -dos -section  0x10000000 \n"
		"    !pe   0x10000000 \n"
		);
			
	EXIT_API();
	return S_OK;
}
