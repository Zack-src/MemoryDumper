#include "Include.h"
DWORD ExplPID;

bool Check_Explorer(DWORD pid);
std::vector<std::future<void>> vectorThread;
void PrintID(DWORD processID)
{
    if (Check_Explorer(processID)) {
        std::string File = std::to_string(processID);
        vectorThread.emplace_back(std::async(std::launch::async, Save_Mem, processID, File));
    }
}

BOOL GetPrivilege(std::string perm)
{
	const char* permchar = perm.c_str();
	HANDLE tokenhandle;
	LUID permissionidentifier;
	TOKEN_PRIVILEGES tokenpriv{};
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenhandle))
	{
		if (LookupPrivilegeValue(NULL, permchar, &permissionidentifier))
		{
			tokenpriv.PrivilegeCount = 1;
			tokenpriv.Privileges[0].Luid = permissionidentifier;
			tokenpriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (AdjustTokenPrivileges(tokenhandle, false, &tokenpriv, sizeof(tokenpriv), NULL, NULL)) { return true; }
			else { return false; }
		}
		else { return false; }
	}
	else { return false; }
	CloseHandle(tokenhandle);
}

DWORD getPid(std::string name)
{
	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(hSnapshot, &entry);
	if (name.compare(entry.szExeFile) == 0)
		return entry.th32ProcessID;

	while (Process32Next(hSnapshot, &entry))
		if (name.compare(entry.szExeFile) == 0)
		{
			CloseHandle(hSnapshot);
			return entry.th32ProcessID;
		}


	CloseHandle(hSnapshot);
	return 0;
}

bool Check_Explorer(DWORD pid)
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try {
        if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;

        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));

    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE)
            CloseHandle(hSnapshot);
    }

    if (ExplPID != ppid) return true;

    return false;
}

int main()
{
	SetConsoleTitleA("MemoryDumper 1.0 - MBZ");

    GetPrivilege(SE_SECURITY_NAME);
    GetPrivilege(SE_DEBUG_NAME);

	ExplPID = getPid("explorer.exe");

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) return 1;
    cProcesses = cbNeeded / sizeof(DWORD);

    unsigned __int64 ms1 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            PrintID(aProcesses[i]);
        }
    }

	for (auto&& task : vectorThread) {
		task.get();
	}

    unsigned __int64 ms2 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::cout << "End in : " << ms2 - ms1 << "ms\n\n";
    std::cin.get();

	return 0;
}

