#include "Include.h"
#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(LONG, BOOLEAN, BOOLEAN, PBOOLEAN);

void Save_Mem(int procs_id, std::string saveFile)
{
    
    static const auto ntdll = GetModuleHandleA("ntdll.dll"); //chad module!

    using qm = NTSTATUS(NTAPI*)(HANDLE, PVOID, BYTE, PVOID, SIZE_T, PSIZE_T);
    static qm query_vmem = (qm)GetProcAddress(ntdll, "NtQueryVirtualMemory");

    using rvm = NTSTATUS(__stdcall*)(HANDLE, LPVOID, PVOID, SIZE_T, PSIZE_T);
    static rvm read_vmem = (rvm)GetProcAddress(ntdll, "NtReadVirtualMemory");

    static BOOLEAN PRIV = NULL;
    RtlAdjustPrivilege(0x14, TRUE, FALSE, &PRIV);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procs_id);

    if (hProcess != 0) {
        std::ofstream outfile(saveFile + ".txt");

        unsigned __int64 x = (long)NULL;
        std::map<std::string, int> Lmap;

        std::string* print = new std::string("");
        int* _printable = new int;
        *_printable = false;

        for (MEMORY_BASIC_INFORMATION m{}; query_vmem(hProcess, (PVOID)x, 0, &m, sizeof(m), 0) >= 0; x += m.RegionSize)
        {

            if (m.State != 4096 || m.Protect == 01 || m.Protect == 256) continue;
            if (m.Type & MEM_IMAGE) continue;

            std::string dump;
            dump.resize(m.RegionSize);

            size_t b = 0;

            if (read_vmem(hProcess, (PVOID)x, &dump[0], m.RegionSize, &b) < 0) continue;

            static const auto c_valid = [&](char x) {
                return x > 31 && x < 127;
            };

            std::string pars; pars.resize(m.RegionSize);
            int pars_pos = 0;

            for (int y = 0; y < m.RegionSize; ++y)
            {

                if (c_valid(dump[y])) {

                    print->push_back(dump[y]), * _printable = 0x1;
                }
                else if (_printable)
                {
                    if (c_valid(dump[static_cast<std::basic_string<char, std::char_traits<char>, std::allocator<char>>::size_type>(y) + 1])) *_printable = true;
                    else
                    {
                        if (print->length() > 4)
                        {
                            print->push_back('\n');
                            for (int z = 0; z < print->length(); ++z)
                            {
                                if (static_cast<unsigned long long>(pars_pos) + z > m.RegionSize) break;
                                else pars[static_cast<std::basic_string<char, std::char_traits<char>, std::allocator<char>>::size_type>(pars_pos) + z] = print->operator[](z);

                            }
                            pars_pos += print->length();
                        }

                        *print = "", * _printable = false;
                    }
                }
            }
            pars.resize(pars_pos);
            outfile.write(pars.c_str(), pars.length());

        }

        delete print;
        delete _printable;
        outfile.close();
    }

    CloseHandle(hProcess);
    return;
}