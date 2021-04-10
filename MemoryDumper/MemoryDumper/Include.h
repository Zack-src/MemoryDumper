#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <map>
#include <stdio.h>
#include <thread>
#include <future>
#include <tchar.h>
#include <psapi.h>

void Save_Mem(int procs_id, std::string saveFile);