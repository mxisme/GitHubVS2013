
#pragma once
#include "DbgEngTemplate.h"

WINDBG_EXTENSION_APIS                ExtensionApis = { 0 };
PDEBUG_CLIENT4                       g_ExtClient = NULL;
PDEBUG_CONTROL4                      g_ExtControl = NULL;
PDEBUG_SYMBOLS2                      g_ExtSymbols = NULL;
PDEBUG_DATA_SPACES4                  g_ExtDataSpaces = NULL;
extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
	IDebugClient *DebugClient;
	PDEBUG_CONTROL DebugControl;
	HRESULT Hr;

	*Version = DEBUG_EXTENSION_VERSION(1, 0);
	*Flags = 0;
	Hr = S_OK;

	if ((Hr = DebugCreate(__uuidof(IDebugClient), (void **)&DebugClient)) != S_OK)
	{
		return Hr;
	}
	if ((Hr = DebugClient->QueryInterface(__uuidof(IDebugControl),	(void **)&DebugControl)) == S_OK)
	{
		ExtensionApis.nSize = sizeof(ExtensionApis);
		Hr = DebugControl->GetWindbgExtensionApis64(&ExtensionApis);
		DebugControl->Release();
	}
	DebugClient->Release();
	return Hr;
}


extern "C" void CALLBACK DebugExtensionUninitialize(void)
{

	return;
}

extern "C"
void
CALLBACK
DebugExtensionNotify(ULONG Notify, ULONG64 Argument)
{
	UNREFERENCED_PARAMETER(Argument);

	switch (Notify)
	{
		case DEBUG_NOTIFY_SESSION_ACTIVE :   //调试会话被激活
		break;
		case DEBUG_NOTIFY_SESSION_INACTIVE: //没有被激活的调试会话
		break;
		case DEBUG_NOTIFY_SESSION_ACCESSIBLE : //调试会话被中断并可访问
		break;
		case DEBUG_NOTIFY_SESSION_INACCESSIBLE : //调试会话恢复执行并不能访问
		break;
	default:
		break;
	}
	 
	return;
}


extern "C"
HRESULT
CALLBACK
KnownStructOutput(
_In_ ULONG Flag,
_In_ ULONG64 Address,
_In_ PSTR StructName,
_Out_writes_opt_(*BufferSize) PSTR Buffer,
_Inout_opt_ _When_(Flag == DEBUG_KNOWN_STRUCT_GET_NAMES, _Notnull_) _When_(Flag == DEBUG_KNOWN_STRUCT_GET_SINGLE_LINE_OUTPUT, _Notnull_) PULONG BufferSize
)
{
	HRESULT Hr = S_OK;

	switch (Flag )
	{
		case DEBUG_KNOWN_STRUCT_GET_NAMES :   // 当调试引擎最初加载调试扩展时传递给函数，调试扩展应该返回一组它所支持定制输出的结构名字
		break;
		case DEBUG_KNOWN_STRUCT_SUPPRESS_TYPE_NAME :  //传递给函数以查询它是否希望自动输出类型的名字
		break;
		case DEBUG_KNOWN_STRUCT_GET_SINGLE_LINE_OUTPUT : //当调试扩展执行求值时传递给函数
		break;
	default:
		break;
	}
	
	return Hr;
}
 
 
// Queries for all debugger interfaces.
HRESULT ExtQuery(PDEBUG_CLIENT4 Client)
{
	HRESULT Status;

	if ((Status = Client->QueryInterface(__uuidof(IDebugControl4),
		(void **)&g_ExtControl)) != S_OK)
	{
		goto Fail;
	}
	if ((Status = Client->QueryInterface(__uuidof(IDebugSymbols2),
		(void **)&g_ExtSymbols)) != S_OK)
	{
		goto Fail;
	}
	if ((Status = Client->QueryInterface(__uuidof(IDebugDataSpaces4),
		(void **)&g_ExtDataSpaces)) != S_OK)
	{
		goto Fail;
	}
	ExtensionApis.nSize = sizeof(ExtensionApis);
	Status = g_ExtControl->GetWindbgExtensionApis64(&ExtensionApis);
	if ( Status != S_OK)
	{
		goto Fail;  
	}

	g_ExtClient = Client;

	return S_OK;

Fail:
	ExtRelease();
	return Status;
}

// Cleans up all debugger interfaces.
void ExtRelease(void)
{
	g_ExtClient = NULL;
	EXT_RELEASE(g_ExtControl);
	EXT_RELEASE(g_ExtSymbols);
}