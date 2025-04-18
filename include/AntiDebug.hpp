/* ************************************************************************** */

/*
	- License: GNU GENERAL PUBLIC LICENSE v3.0
	- Author: https://github.com/Arty3
	- Requires: C++20 or above, requires Windows 10 or above
*/

#pragma once

#ifndef _MSC_VER
# error "This translation unit requires the MSVC compiler"
#endif

#ifndef _WIN64
# error "This translation unit requires an x64 platform"
#endif

#if !_HAS_CXX20 && defined(_MSVC_LANG) && _MSVC_LANG < 202002L
# error "This translation unit requires C++20 or later."
#endif

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "kernel32.lib")

#include "Stack-Obfuscator.hpp"

#include <Windows.h>

#include <winternl.h>
#include <TlHelp32.h>
#include <Intrin.h>
#include <Psapi.h>
#include <tchar.h>
#include <random>

#ifndef		ThreadHideFromDebugger
# define	ThreadHideFromDebugger (THREADINFOCLASS)0x11
#endif

namespace AntiDebug
{
#pragma region DEFINITIONS

	typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
		HANDLE				ProcessHandle,
		PROCESSINFOCLASS	ProcessInformationClass,
		PVOID				ProcessInformation,
		ULONG				ProcessInformationLength,
		PULONG				ReturnLength
	);

	typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(
		ULONG		Privilege,
		BOOLEAN		Enable,
		BOOLEAN		CurrentThread,
		PBOOLEAN	Enabled
	);

	typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(
		NTSTATUS	ErrorStatus,
		ULONG		NumberOfParameters,
		ULONG		UnicodeStringParameterMask OPTIONAL,
		PULONG_PTR	Parameters,
		ULONG		ResponseOption,
		PULONG		Response
	);

#pragma endregion DEFINITIONS

	static bool CheckHardwareBreakpoints(void)
	{
		OBFUSCATE_FUNCTION;

		bool	found	= false;
		CONTEXT	ctx		= {};

		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (OBFUSCATE_STDCALL(BOOL, GetThreadContext)(
			OBFUSCATE_STDCALL(HANDLE, GetCurrentThread)(),
			&ctx) && (ctx.Dr0 || ctx.Dr1 ||
				ctx.Dr2 || ctx.Dr3 || ctx.Dr7))
			found = true;

		return found;
	}

	static bool CheckPEB(void)
	{
		OBFUSCATE_FUNCTION;

		PEB* pPeb = reinterpret_cast<PEB*>(__readgsqword(0x60));

		if (pPeb && (pPeb->BeingDebugged || (*(ULONG*)((BYTE*)pPeb + 0xBC) & 70)))
			return true;

		HANDLE hProcess = OBFUSCATE_STDCALL(HANDLE, GetCurrentProcess)();

		pNtQueryInformationProcess	QueryInfoProcess;

		HMODULE hNtdll = OBFUSCATE_STDCALL(HMODULE, GetModuleHandleW)(L"ntdll.dll");

		if (!hNtdll)
			return false;

		QueryInfoProcess = reinterpret_cast<pNtQueryInformationProcess>(
				OBFUSCATE_STDCALL(FARPROC, GetProcAddress)(
					hNtdll, "NtQueryInformationProcess")
		);

		if (!QueryInfoProcess)
			return false;

		ULONG retLen	= 0;
		ULONG dbgPort	= 0;

		NTSTATUS status = OBFUSCATE_STDCALL(
			NTSTATUS, QueryInfoProcess)(
				hProcess,
				ProcessDebugPort,
				&dbgPort,
				sizeof(ULONG),
				&retLen
		);

		if (status == ERROR_SUCCESS && dbgPort)
			return true;

		return false;
	}

#pragma region TIMING_CHECK

	static __forceinline DWORD64 getCPUClockSpeed(void)
	{
		OBFUSCATE_FUNCTION;

		LARGE_INTEGER freq;

		if (OBFUSCATE_STDCALL(BOOL, QueryPerformanceFrequency)(&freq))
			return static_cast<DWORD64>(freq.QuadPart);

		DWORD64	start, end;

		start	= __rdtsc();
		Sleep(100);
		end		= __rdtsc();

		return (end - start) * 10;
	}

	bool TimingCheck(void)
	{
		OBFUSCATE_FUNCTION;

		static const DWORD64 CYCLE_THRESHOLD = (getCPUClockSpeed() / 10) * 3;

		uint64_t start	= __rdtsc();

		volatile int x = 0;
		for (int i = 0; i < 1000; ++i) ++x;

		uint64_t end	= __rdtsc();

		return (end - start) > CYCLE_THRESHOLD;
	}

#pragma endregion TIMING_CHECK

	bool IsRunningInVM(void)
	{
		OBFUSCATE_FUNCTION;

		int	cpuInfo[4] = { 0 };

		__cpuid(cpuInfo, 1);

		return (cpuInfo[2] >> 31) & 1;
	}

#pragma region HOOK_REMOTE_THREAD

	constexpr static inline size_t	HOOK_SIZE					= 12;
	static inline BYTE				originalBytes[HOOK_SIZE]	= { 0 };
	static inline FARPROC			originalFunction			= NULL;

	static HANDLE WINAPI HookedCreateRemoteThread(
		HANDLE					hProcess,
		LPSECURITY_ATTRIBUTES	lpThreadAttributes,
		SIZE_T					dwStackSize,
		LPTHREAD_START_ROUTINE	lpStartAddress,
		LPVOID					lpParameter,
		DWORD					dwCreationFlags,
		LPDWORD					lpThreadId
	)
	{
		OBFUSCATE_FUNCTION;

		OBFUSCATE_STDCALL(void, SetLastError)(ERROR_ACCESS_DENIED);

		return NULL;
	}

	static bool HookCreateRemoteThread(void)
	{
		OBFUSCATE_FUNCTION;

		HMODULE hKernel32 = OBFUSCATE_STDCALL(
			HMODULE, GetModuleHandle)(L"kernel32.dll");

		if (!hKernel32)
			return false;

		FARPROC pCreateRemoteThread = OBFUSCATE_STDCALL(
			FARPROC, GetProcAddress)(hKernel32, "CreateRemoteThread");

		if (!pCreateRemoteThread)
			return false;

		originalFunction = pCreateRemoteThread;

#pragma pack(push, 1)
		struct
		{
			BYTE		movRax[2];
			BYTE		jmpRax[2];
			uintptr_t	addr;
		}	jumpCode = {
			{0x48, 0xB8},
			{0xFF, 0xE0},
			(uintptr_t)HookedCreateRemoteThread
		};
#pragma pack(pop)

		static_assert(sizeof(jumpCode) == HOOK_SIZE, "HOOK_SIZE Mismatch");

		DWORD	oldProtect;
		SIZE_T	bytesWritten;

		if (!OBFUSCATE_STDCALL(BOOL, ReadProcessMemory)(
				OBFUSCATE_STDCALL(HANDLE, GetCurrentProcess)(),
				pCreateRemoteThread,
				originalBytes,
				sizeof(originalBytes),
				NULL))
			return false;

		if (!OBFUSCATE_STDCALL(BOOL, VirtualProtect)(
				pCreateRemoteThread,
				sizeof(jumpCode),
				PAGE_EXECUTE_READWRITE,
				&oldProtect))
			return false;

		if (!OBFUSCATE_STDCALL(BOOL, WriteProcessMemory)(
				OBFUSCATE_STDCALL(HANDLE, GetCurrentProcess)(),
				pCreateRemoteThread,
				&jumpCode,
				sizeof(jumpCode),
				&bytesWritten))
		{
			OBFUSCATE_STDCALL(BOOL, VirtualProtect)(
				pCreateRemoteThread, sizeof(jumpCode),
				oldProtect, &oldProtect);
			return false;
		}

		if (!OBFUSCATE_STDCALL(BOOL, VirtualProtect)(
				pCreateRemoteThread,
				sizeof(jumpCode),
				oldProtect,
				&oldProtect))
			return false;

		OBFUSCATE_STDCALL(BOOL, FlushInstructionCache)(
			OBFUSCATE_STDCALL(HANDLE, GetCurrentProcess)(),
			pCreateRemoteThread,
			sizeof(jumpCode));

		return bytesWritten == sizeof(jumpCode);
	}

	static void UnhookCreateRemoteThread(void)
	{
		OBFUSCATE_FUNCTION;

		if (!originalFunction || originalBytes[0] == 0)
			return;

		DWORD	oldProtect;
		SIZE_T	bytesWritten;
		BOOL	result;

		if (!OBFUSCATE_STDCALL(BOOL, VirtualProtect)(
				originalFunction,
				HOOK_SIZE,
				PAGE_EXECUTE_READWRITE,
				&oldProtect))
			return;

		result = OBFUSCATE_STDCALL(BOOL, WriteProcessMemory)(
					OBFUSCATE_STDCALL(HANDLE, GetCurrentProcess)(),
					originalFunction,
					originalBytes,
					HOOK_SIZE,
					&bytesWritten);

		OBFUSCATE_STDCALL(BOOL, VirtualProtect)(
			originalFunction, HOOK_SIZE,
			oldProtect, &oldProtect);

		if (result)
			OBFUSCATE_STDCALL(BOOL, FlushInstructionCache)(
				OBFUSCATE_STDCALL(HANDLE, GetCurrentProcess)(),
				originalFunction,
				HOOK_SIZE);

		return;
	}

#pragma endregion HOOK_REMOTE_THREAD

	static bool DetectRemoteDebug(void)
	{
		OBFUSCATE_FUNCTION;

		HANDLE hSnapshot = OBFUSCATE_STDCALL(
			HANDLE, CreateToolhelp32Snapshot)
			(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot == INVALID_HANDLE_VALUE)
			return false;

		PROCESSENTRY32 pe32 = { 0 };
		pe32.dwSize	= sizeof(pe32);

		if (OBFUSCATE_STDCALL(BOOL, Process32First)(hSnapshot, &pe32))
		{
			do
			{
				if (pe32.th32ProcessID == OBFUSCATE_STDCALL(DWORD, GetCurrentProcessId)())
					continue;

				HANDLE hProcess = OBFUSCATE_STDCALL(HANDLE, OpenProcess)(
					PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID
				);

				if (hProcess != NULL)
				{
					BOOL isDebugged = FALSE;

					if (OBFUSCATE_STDCALL(BOOL, CheckRemoteDebuggerPresent)
						(hProcess, &isDebugged) && isDebugged)
						return true;

					OBFUSCATE_STDCALL(BOOL, CloseHandle)(hProcess);
				}
			}	while (OBFUSCATE_STDCALL(BOOL, Process32Next)(hSnapshot, &pe32));
		}
		OBFUSCATE_STDCALL(BOOL, CloseHandle)(hSnapshot);

		return false;
	}

	static bool CheckInt3(void)
	{
		OBFUSCATE_FUNCTION;

		bool found = true;

		__try
		{
			__debugbreak();
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			found = false;
		}

		return found;
	}

	static bool CheckInt2D(void)
	{
		OBFUSCATE_FUNCTION;

		bool found = true;

		__try
		{
			__asm volatile int 0x2D;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			found = false;
		}

		return found;
	}

	static bool CheckForKnownDebuggers(void)
	{
		OBFUSCATE_FUNCTION;

		constexpr const TCHAR* debuggers[] = {
			L"idaq.exe",
			L"ollydbg.exe",
			L"idaq64.exe",
			L"ollydbg64.exe",
			L"ida.exe",
			L"idaw.exe",
			L"idaw64.exe",
			L"ida64.exe",
			L"windbg.exe",
			L"x64dbg.exe",
			L"radare2.exe",
			L"ImmunityDebugger.exe",
			L"cheatengine-x86_64.exe"
		};

		DWORD	processIds[1024], cbNeeded, cProcesses, processId;

		TCHAR	processName[MAX_PATH];
		HANDLE	hProcess;
		HMODULE	hMod;

		if (!OBFUSCATE_STDCALL(BOOL, EnumProcesses)(
			processIds, sizeof(processIds), &cbNeeded))
			return false;

		cProcesses = cbNeeded / sizeof(DWORD);

		for (DWORD i = 0; i < cProcesses; ++i)
		{
			processId = processIds[i];

			if (!processId)
				continue;

			hProcess = OBFUSCATE_STDCALL(HANDLE, OpenProcess)(
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId
			);

			if (!hProcess)
				continue;

			if (OBFUSCATE_STDCALL(BOOL, EnumProcessModules)(
				hProcess, &hMod, sizeof(hMod), &cbNeeded) &&
				OBFUSCATE_STDCALL(DWORD, GetModuleFileNameEx)(
					hProcess, hMod, processName,
					sizeof(processName) / sizeof(TCHAR)))
			{
				for (const TCHAR* debugger : debuggers)
				{
					if (_tcsicmp(processName, debugger) == 0)
					{
						OBFUSCATE_STDCALL(BOOL, CloseHandle)(hProcess);
						return true;
					}
				}
			}
			OBFUSCATE_STDCALL(BOOL, CloseHandle)(hProcess);
		}

		return false;
	}

	void PreventThreadInjection(void)
	{
		OBFUSCATE_FUNCTION;

		// THREAD_QUERY_LIMITED_INFORMATION
		DWORD flags = 1;

		OBFUSCATE_STDCALL(NTSTATUS, NtSetInformationThread)(
			OBFUSCATE_STDCALL(HANDLE, GetCurrentThread)(),
			ThreadHideFromDebugger, &flags, sizeof(flags));

		HookCreateRemoteThread();

		static std::once_flag flag;

		std::call_once(flag, []
		{
			std::atexit(UnhookCreateRemoteThread);
		});
	}

	void PreventMemoryDump(void)
	{
		OBFUSCATE_FUNCTION;

		OBFUSCATE_STDCALL(BOOL, SetProcessWorkingSetSize)
			(OBFUSCATE_STDCALL(HANDLE, GetCurrentProcess)(), -1, -1);
	}

	bool IsDumperPresent(void)
	{
		OBFUSCATE_FUNCTION;

		MEMORY_BASIC_INFORMATION mbi;

		OBFUSCATE_STDCALL(SIZE_T, VirtualQuery)(
			VirtualQuery, &mbi, sizeof(mbi));
		return (mbi.Protect & PAGE_GUARD);
	}

	bool IsDebuggerDetected(void)
	{
		OBFUSCATE_FUNCTION;

		if (IsDumperPresent())
			return true;

		return	IsDebuggerPresent()			||
				CheckHardwareBreakpoints()	||
				CheckInt3()					||
				CheckInt2D()				||
				DetectRemoteDebug()			||
				CheckPEB()					||
				IsRunningInVM()				||
				CheckForKnownDebuggers()	||
				TimingCheck();
	}

	void SetRandomWindowTitle(void)
	{
		OBFUSCATE_FUNCTION;

		constexpr const size_t	titleSize	= 25;
		constexpr const auto	characters	= TEXT(
			"2s119sf3f59gga60473wxyzABCf"
			"DEFGHIJKLMNOPQRSTUVWXYZ1234567890"
		);

		TCHAR	title[titleSize + 1] = {};

		std::random_device				rd;
		std::mt19937					gen(rd());
		std::uniform_int_distribution<>	dist(0, 45);

		for (size_t i = 0; i < titleSize; ++i)
			title[i] = characters[dist(gen)];

		OBFUSCATE_STDCALL(BOOL, SetConsoleTitle)(title);
	}

	// Bluescreen of death
	[[noreturn]] static void BSOD(void)
	{
		OBFUSCATE_FUNCTION;

		static constexpr const int	SHUTDOWN_PRIVILEGE	= 19;
		static constexpr const int	OPTION_SHUTDOWN		= 6;

		BOOLEAN	bEnabled;
		ULONG	uResp;

		HMODULE	hNtdll = OBFUSCATE_STDCALL(HMODULE, LoadLibraryA)("ntdll.dll");

		if (!hNtdll)
			__fastfail(1);

		LPVOID lpFuncAddress1 = (LPVOID)OBFUSCATE_STDCALL(FARPROC, GetProcAddress)(hNtdll, "RtlAdjustPrivilege");
		LPVOID lpFuncAddress2 = (LPVOID)OBFUSCATE_STDCALL(FARPROC, GetProcAddress)(hNtdll, "NtRaiseHardError");

		if (!lpFuncAddress1 || !lpFuncAddress2)
			__fastfail(1);

		pdef_RtlAdjustPrivilege RtlAdjustPrivilege	= (pdef_RtlAdjustPrivilege)lpFuncAddress1;
		pdef_NtRaiseHardError NtRaiseHardError		= (pdef_NtRaiseHardError)lpFuncAddress2;

		OBFUSCATE_STDCALL(NTSTATUS, RtlAdjustPrivilege)(
			SHUTDOWN_PRIVILEGE, TRUE, FALSE, &bEnabled);
		OBFUSCATE_STDCALL(NTSTATUS, NtRaiseHardError)(
			STATUS_FLOAT_MULTIPLE_FAULTS, 0,
			0, 0, OPTION_SHUTDOWN, &uResp);

		__fastfail(1);
	}

	__forceinline void DoAllChecksAndPreventions(void)
	{
		OBFUSCATE_FUNCTION;

		SetRandomWindowTitle();

		PreventThreadInjection();
		PreventMemoryDump();

		if (IsDumperPresent() || IsDebuggerDetected())
			BSOD();
	}
}
