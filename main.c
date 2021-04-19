#define WINVER 0x0600
#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <shlwapi.h>

#ifdef _DEBUG
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#endif

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

#define TIPROMPTPIDENV L"TIPROMPTPID"

DWORD getenvpid(void);
int copytoken(DWORD pid);
int main_func(void);

void mainCRTStartup()
{
	DWORD pid = getenvpid();
	if(pid)
	{
		ExitProcess(copytoken(pid));
	}
	ExitProcess(main_func());
}

DWORD getenvpid(void)
{
	WCHAR str[16];
	DWORD pid = 0;
	if(GetEnvironmentVariableW(TIPROMPTPIDENV, str, 16))
	{
		pid = (DWORD)StrToIntW(str);
	}
	return pid;
}

int copytoken(DWORD pid)
{
	HANDLE proc, token, primtoken, tokencopy;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))
	{
		return 0;
	}
	if(!DuplicateTokenEx(token, 0, NULL, SecurityImpersonation, TokenPrimary, &primtoken))
	{
		CloseHandle(token);
		return 0;
	}
	CloseHandle(token);
	proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
	if(!proc)
	{
		CloseHandle(primtoken);
		return 0;
	}
	if(!DuplicateHandle(GetCurrentProcess(), primtoken, proc, &tokencopy, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		CloseHandle(primtoken);
		CloseHandle(proc);
		return 0;
	}
	CloseHandle(primtoken);
	CloseHandle(proc);
	return (int)(INT_PTR)tokencopy;
}

int main_func(void)
{
	WCHAR cmdpath[] = L"cmd.exe";
	WCHAR *pstr;
	WCHAR *cmdl=NULL;
	WCHAR mpath[MAX_PATH];
	HANDLE hscm, hservice;
	SERVICE_STATUS_PROCESS ssp;
	DWORD bNeeded;
	HANDLE proc, token=NULL, usertoken=NULL;
	PROCESS_INFORMATION pi;
	BOOL ret;
	STARTUPINFOEXW si;
	LUID luid;
	TOKEN_PRIVILEGES tokenPriv;
	LPPROC_THREAD_ATTRIBUTE_LIST ptal;
	SIZE_T ptsize=0;

	cmdl=(WCHAR*)GetCommandLineW();
	if(cmdl)
	{
		pstr=cmdl;
		if(cmdl[0]==L'\"')
		{
			pstr++;
			while((*pstr!=L'\"')&&(*pstr!=L'\0'))
			{
				pstr++;
			}
			if(*pstr==L'\"')
			{
				pstr++;
				while((*pstr==' ')||(*pstr=='\t'))
				{
					pstr++;
				}
			}
			if(*pstr==L'\0')
			{
				pstr=cmdpath;
			}
		}
		else
		{
			while((*pstr!=L' ')&&(*pstr!=L'\0'))
			{
				pstr++;
			}
			if(*pstr==L' ')
			{
				while((*pstr==L' ')||(*pstr==L'\t'))
				{
					pstr++;
				}
			}
			if(*pstr==L'\0')
			{
				pstr=cmdpath;
			}
		}
	}
	else
	{
		pstr=cmdpath;
	}
	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&token))
	{
		return 1;
	}
	if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&luid))
	{
		CloseHandle(token);
		return 2;
	}
	tokenPriv.PrivilegeCount=1;
	tokenPriv.Privileges[0].Luid=luid;
	tokenPriv.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	if(!AdjustTokenPrivileges(token,FALSE,&tokenPriv,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
	{
		CloseHandle(token);
		return 3;
	}
	CloseHandle(token);
	hscm = OpenSCManagerW(NULL, NULL, STANDARD_RIGHTS_READ);
	if(!hscm)
	{
		return 4;
	}
	hservice = OpenServiceW(hscm, L"TrustedInstaller", SERVICE_START|SERVICE_QUERY_STATUS);
	if(!hservice)
	{
		CloseHandle(hscm);
		return 5;
	}
	if(!StartServiceW(hservice, 0, NULL))
	{
		if(GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
		{
			CloseHandle(hservice);
			CloseHandle(hscm);
			return 6;
		}
	}
	bNeeded = 0;
	if(!QueryServiceStatusEx(hservice, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bNeeded))
	{
		CloseHandle(hservice);
		CloseHandle(hscm);
		return 7;
	}
	CloseHandle(hservice);
	CloseHandle(hscm);
	wsprintfW(mpath, L"%u", (unsigned int)GetCurrentProcessId());
	if(!SetEnvironmentVariableW(TIPROMPTPIDENV, mpath))
	{
		return 9;
	}
	if(!GetModuleFileNameW(NULL, mpath, MAX_PATH))
	{
		return 10;
	}
	proc = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ssp.dwProcessId);
	if(!proc)
	{
		return 8;
	}
	ZeroMemory(&si, sizeof(si));
	si.StartupInfo.cb = sizeof(si);
	InitializeProcThreadAttributeList(NULL,1,0,&ptsize);
	ptal=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,ptsize);
	if(!ptal)
	{
		CloseHandle(proc);
		return 11;
	}
	if(!InitializeProcThreadAttributeList(ptal,1,0,&ptsize))
	{
		HeapFree(GetProcessHeap(), 0, ptal);
		CloseHandle(proc);
		return 12;
	}
	if(!UpdateProcThreadAttribute(ptal,0,PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,&proc,sizeof(HANDLE),NULL,NULL))
	{
		HeapFree(GetProcessHeap(), 0, ptal);
		CloseHandle(proc);
		return 13;
	}
	si.lpAttributeList = ptal;
	ret = CreateProcessW(NULL, mpath, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT|DETACHED_PROCESS, NULL, NULL,(STARTUPINFOW*)&si, &pi);
	DeleteProcThreadAttributeList(ptal);
	if(!ret)
	{
		HeapFree(GetProcessHeap(), 0, ptal);
		CloseHandle(proc);
		return 14;
	}
	HeapFree(GetProcessHeap(), 0, ptal);
	CloseHandle(proc);
	CloseHandle(pi.hThread);
	SetEnvironmentVariableW(TIPROMPTPIDENV, NULL);
	if(WaitForSingleObject(pi.hProcess, INFINITE))
	{
		CloseHandle(pi.hProcess);
		return 15;
	}
	if(!GetExitCodeProcess(pi.hProcess, (LPDWORD)&usertoken))
	{
		CloseHandle(pi.hProcess);
		return 16;
	}
	CloseHandle(pi.hProcess);
	if(!usertoken)
	{
		return 17;
	}
	if(!ImpersonateLoggedOnUser(usertoken))
	{
		return 18;
	}
	if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &token))
	{
		return 19;
	}
	if(!LookupPrivilegeValue(NULL,SE_ASSIGNPRIMARYTOKEN_NAME,&luid))
	{
		CloseHandle(token);
		return 20;
	}
	tokenPriv.PrivilegeCount=1;
	tokenPriv.Privileges[0].Luid=luid;
	tokenPriv.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	if(!AdjustTokenPrivileges(token,FALSE,&tokenPriv,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
	{
		CloseHandle(token);
		return 21;
	}
	CloseHandle(token);
	ZeroMemory(&si.StartupInfo, sizeof(STARTUPINFOW));
	si.StartupInfo.cb = sizeof(STARTUPINFOW);
	if(!CreateProcessAsUserW(usertoken, NULL, pstr, NULL, NULL, TRUE, 0, NULL, NULL, &si.StartupInfo, &pi))
	{
		return 22;
	}
	RevertToSelf();
	CloseHandle(usertoken);
	CloseHandle(pi.hThread);
	if(!WaitForSingleObject(pi.hProcess, INFINITE))
	{
		CloseHandle(pi.hProcess);
		return 23;
	}
	CloseHandle(pi.hProcess);
	return 0;
}
