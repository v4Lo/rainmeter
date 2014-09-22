/*
  Copyright (C) 2005 Kimmo Pekkola

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
  */

#include <windows.h>
#include <string>
#include <Ipexport.h>
#include <Icmpapi.h>
#include "ws2tcpip.h"
#include "../../Library/Export.h"	// Rainmeter's exported functions


struct MeasureData
{
	struct addrinfo* destAddr;
	DWORD timeout;
	double timeoutValue;
	DWORD updateRate;
	DWORD updateCounter;
	bool threadActive;
	double value;
	std::wstring finishAction;
	void* skin;

	MeasureData() :
		destAddr(nullptr),
		timeout(),
		timeoutValue(),
		updateRate(),
		updateCounter(),
		threadActive(false),
		value(),
		finishAction(),
		skin(nullptr)
	{
	}
};

static CRITICAL_SECTION g_CriticalSection;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		InitializeCriticalSection(&g_CriticalSection);

		// Disable DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls.
		DisableThreadLibraryCalls(hinstDLL);
		break;

	case DLL_PROCESS_DETACH:
		DeleteCriticalSection(&g_CriticalSection);
		break;
	}

	return TRUE;
}

PLUGIN_EXPORT void Initialize(void** data, void* rm)
{
	MeasureData* measure = new MeasureData;
	*data = measure;
}

PLUGIN_EXPORT void Reload(void* data, void* rm, double* maxValue)
{
	MeasureData* measure = (MeasureData*)data;

	LPCWSTR value = RmReadString(rm, L"DestAddress", L"");
	if (*value)
	{
		int strLen = (int)wcslen(value) + 1;
		int bufLen = WideCharToMultiByte(CP_ACP, 0, value, strLen, nullptr, 0, nullptr, nullptr);
		if (bufLen > 0)
		{
			char* buffer = new char[bufLen];
			WideCharToMultiByte(CP_ACP, 0, value, strLen, buffer, bufLen, nullptr, nullptr);
			int error;
			WORD wVersionRequested = MAKEWORD(2, 2);
			WSADATA wsaData;
			if (WSAStartup(wVersionRequested, &wsaData) == 0) {
				if ((error = getaddrinfo(buffer, NULL, NULL, &measure->destAddr)) != 0){
						{
							RmLogF(nullptr, LOG_WARNING, L"PingPlugin.dll: getaddrinfo failed %d", error);
						}
				}
				WSACleanup();
			}
			delete[] buffer;
		}
	}

	measure->updateRate = RmReadInt(rm, L"UpdateRate", 32);
	measure->timeout = RmReadInt(rm, L"Timeout", 30000);
	measure->timeoutValue = RmReadDouble(rm, L"TimeoutValue", 30000.0);
	measure->finishAction = RmReadString(rm, L"FinishAction", L"", false);
	measure->skin = RmGetSkin(rm);
}

DWORD WINAPI NetworkThreadProc(void* pParam)
{
	// NOTE: Do not use CRT functions (since thread was created by CreateThread())!

	MeasureData* measure = (MeasureData*)pParam;


	double value = 0.0;
	if (measure->destAddr != nullptr) {
		if (measure->destAddr->ai_family == AF_INET6) {
			HANDLE hIcmpFile = Icmp6CreateFile();
			if (hIcmpFile != INVALID_HANDLE_VALUE) {
				struct sockaddr_in6 source;
				memset(&source, 0, sizeof(source));
				source.sin6_addr = in6addr_any;
				source.sin6_family = AF_INET6;
				
				sockaddr_in6 dest;
				memset(&dest, 0, sizeof(dest));
				dest.sin6_addr = ((sockaddr_in6 *)measure->destAddr->ai_addr)->sin6_addr;
				dest.sin6_family = AF_INET6;
				
				const int REQUEST_DATA_SIZE = 6;
				char* requestData = new char[REQUEST_DATA_SIZE];
				strcpy(requestData, "HELLO");
				const int reply_data_size = sizeof(ICMPV6_ECHO_REPLY) + REQUEST_DATA_SIZE;
				BYTE buffer[reply_data_size];
				Icmp6SendEcho2(hIcmpFile, 0, 0, 0, &source, &dest, requestData, 5, nullptr, buffer, reply_data_size, measure->timeout);
				IcmpCloseHandle(hIcmpFile);

				ICMPV6_ECHO_REPLY* reply = (ICMPV6_ECHO_REPLY*)buffer;
				value = (reply->Status != IP_SUCCESS) ? measure->timeoutValue : reply->RoundTripTime;
				delete[] requestData;
				if (!measure->finishAction.empty())
				{
					RmExecute(measure->skin, measure->finishAction.c_str());
				}

			}
		}
		else if (measure->destAddr->ai_family == AF_INET) {
			HANDLE hIcmpFile = IcmpCreateFile();
			if (hIcmpFile != INVALID_HANDLE_VALUE)
			{
				in_addr inaddr = ((sockaddr_in *)measure->destAddr->ai_addr)->sin_addr;
				IPAddr ipaddr;
				memcpy(&ipaddr, &inaddr, sizeof(ipaddr));
				const DWORD bufferSize = sizeof(ICMP_ECHO_REPLY) + 32;
				BYTE buffer[bufferSize];

				IcmpSendEcho(hIcmpFile, ipaddr, nullptr, 0, nullptr, buffer, bufferSize, measure->timeout);
				IcmpCloseHandle(hIcmpFile);

				ICMP_ECHO_REPLY* reply = (ICMP_ECHO_REPLY*)buffer;
				value = (reply->Status != IP_SUCCESS) ? measure->timeoutValue : reply->RoundTripTime;

				if (!measure->finishAction.empty())
				{
					RmExecute(measure->skin, measure->finishAction.c_str());
				}
			}
		}
	}
	HMODULE module = nullptr;

	EnterCriticalSection(&g_CriticalSection);
	if (measure->threadActive)
	{
		measure->value = value;
		measure->threadActive = false;
	}
	else
	{
		// Thread is not attached to an existing measure any longer, so delete
		// unreferenced data.
		freeaddrinfo(measure->destAddr);
		delete measure;

		DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
		GetModuleHandleEx(flags, (LPCWSTR)DllMain, &module);
	}
	LeaveCriticalSection(&g_CriticalSection);

	if (module)
	{
		// Decrement the ref count and possibly unload the module if this is
		// the last instance.
		FreeLibraryAndExitThread(module, 0);
	}
	return 0;
}

PLUGIN_EXPORT double Update(void* data)
{
	MeasureData* measure = (MeasureData*)data;

	EnterCriticalSection(&g_CriticalSection);
	if (!measure->threadActive)
	{
		if (measure->updateCounter == 0)
		{
			// Launch a new thread to fetch the web data
			DWORD id;
			HANDLE thread = CreateThread(nullptr, 0, NetworkThreadProc, measure, 0, &id);
			if (thread)
			{
				CloseHandle(thread);
				measure->threadActive = true;
			}
		}

		measure->updateCounter++;
		if (measure->updateCounter >= measure->updateRate)
		{
			measure->updateCounter = 0;
		}
	}

	double value = measure->value;
	LeaveCriticalSection(&g_CriticalSection);

	return value;
}

PLUGIN_EXPORT void Finalize(void* data)
{
	MeasureData* measure = (MeasureData*)data;

	EnterCriticalSection(&g_CriticalSection);
	if (measure->threadActive)
	{
		// Increment ref count of this module so that it will not be unloaded prior to
		// thread completion.
		DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS;
		HMODULE module;
		GetModuleHandleEx(flags, (LPCWSTR)DllMain, &module);

		// Thread will perform cleanup.
		measure->threadActive = false;
	}
	else
	{
		delete measure;
	}
	LeaveCriticalSection(&g_CriticalSection);
}
