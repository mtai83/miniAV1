#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <psapi.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <fstream>
#include <mstask.h>

#pragma comment(lib, "Advapi32.lib")

std::vector<std::string> malware_hashes = {
    "760371c64725a4cbb9427f5a19b1b2830d20edde88047462d5f98082f13c31ab"  
    
};

void EnableTaskManager() {
    HKEY hKey;
    DWORD data = 0;  // 0 = Enable Task Manager
    LONG resultHKCU;
    LONG reusultHKLM;

    resultHKCU = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (resultHKCU == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "DisableTaskMgr", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 1) {
                std::cout << "[!] Task Manager was disable !! fixing...\n";
                resultHKCU = RegSetValueExA(hKey, "DisableTaskMgr", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
                if (resultHKCU == ERROR_SUCCESS) {
                    std::cout << "[+] Task Manager able\n";
                }
                else {
                    std::cerr << "[-] Can't update value key\n";
                }
            }
            else {
                std::cout << "[+] Task Manager nomarly\n";
            }
        }
        RegCloseKey(hKey);
    }
    
    reusultHKLM = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (reusultHKLM == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "DisableTaskMgr", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 1) {
                std::cout << "[!] Task Manager was disable !! fixing...\n";
                reusultHKLM = RegSetValueExA(hKey, "DisableTaskMgr", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
                if (reusultHKLM == ERROR_SUCCESS) {
                    std::cout << "[+] Task Manager able\n";
                }
                else {
                    std::cerr << "[-] Can't update value key\n";
                }
            }
            else {
                std::cout << "[+] Task Manager nomarly\n";
            }
        }
        RegCloseKey(hKey);
    }
}

void EnableRegistrytTool() {
    HKEY hKey;
    DWORD data = 0;  
    LONG resultHKCU;
    LONG reusultHKLM;

        resultHKCU = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (resultHKCU == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "DisableRegistryTools", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 1) {
                std::cout << "[!] RegistryTools was disable !! fixing ...\n";
                resultHKCU = RegSetValueExA(hKey, "DisableRegistryTools", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
                if (resultHKCU == ERROR_SUCCESS) {
                    std::cout << "[+] RegistryTools able\n";
                }
                else {
                    std::cerr << "[-] Can't update value key\n";
                }
            }
            else {
                std::cout << "[+] RegistryTools nomarly\n";
            }
        }
        RegCloseKey(hKey);
    }

    reusultHKLM = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (reusultHKLM == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "DisableRegistryTools", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 1) {
                std::cout << "[!] RegistryTools was disable !! fixing ...\n";
                reusultHKLM = RegSetValueExA(hKey, "DisableRegistryTools", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
                if (reusultHKLM == ERROR_SUCCESS) {
                    std::cout << "[+] RegistryTools able\n";
                }
                else {
                    std::cerr << "[-] Can't update value key\n";
                }
            }
            else {
                std::cout << "[+] RegistryTools nomarly\n";
            }
        }
        RegCloseKey(hKey);
    }
    
}

void EnableFolderOptions() {
    HKEY hKey;
    DWORD data = 0;  
    LONG resultHKCU;
    LONG reusultHKLM;

    resultHKCU = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (resultHKCU == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "NoFolderOptions", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 1) {
                std::cout << "[!] FolderOptions was disable !! fixing ...\n";
                resultHKCU = RegSetValueExA(hKey, "NoFolderOptions", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
                if (resultHKCU == ERROR_SUCCESS) {
                    std::cout << "[+] FolderOptions able\n";
                }
                else {
                    std::cerr << "[-] Can't update value key\n";
                }
            }
            else {
                std::cout << "[+] FolderOptions nomarly\n";
            }
        }
        RegCloseKey(hKey);
    }

    reusultHKLM = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (reusultHKLM == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "NoFolderOptions", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 1) {
                std::cout << "[!] FolderOptions was disable !! fixing ...\n";
                reusultHKLM = RegSetValueExA(hKey, "NoFolderOptions", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
                if (reusultHKLM == ERROR_SUCCESS) {
                    std::cout << "[+] FolderOptions able\n";
                }
                else {
                    std::cerr << "[-] Can't update value key\n";
                }
            }
            else {
                std::cout << "[+] FolderOptions nomarly\n";
            }
        }
        RegCloseKey(hKey);
    }


}

void EnableHiddenItem() {
    HKEY hKey;
    DWORD data = 2;
    LONG resultHKCU;
    LONG reusultHKLM;

    resultHKCU = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (resultHKCU == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "Hidden", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 0) {
                resultHKCU = RegSetValueExA(hKey, "Hidden", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
            }
        }
        RegCloseKey(hKey);
    }

    reusultHKLM = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (reusultHKLM == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "Hidden", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 0) {
                reusultHKLM = RegSetValueExA(hKey, "Hidden", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
            }
            RegCloseKey(hKey);
        }
    }

    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", SMTO_ABORTIFHUNG, 5000, nullptr);

    reusultHKLM = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (reusultHKLM == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "Hidden", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 0) {
                reusultHKLM = RegSetValueExA(hKey, "Hidden", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
            }
            RegCloseKey(hKey);
        }
    }

    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", SMTO_ABORTIFHUNG, 5000, nullptr);
}

void EnableHiddenExt() {
    HKEY hKey;
    DWORD data = 1;
    LONG resultHKCU;
    LONG reusultHKLM;

    resultHKCU = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (resultHKCU == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "HideFileExt", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 0) {
                resultHKCU = RegSetValueExA(hKey, "HideFileExt", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
            }
        }
        RegCloseKey(hKey);
    }

    reusultHKLM = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (reusultHKLM == ERROR_SUCCESS) {
        // Đọc giá trị hiện tại
        DWORD currentValue, dataSize = sizeof(currentValue);
        if (RegQueryValueExA(hKey, "HideFileExt", nullptr, nullptr, (LPBYTE)&currentValue, &dataSize) == ERROR_SUCCESS) {
            if (currentValue == 0) {
                reusultHKLM = RegSetValueExA(hKey, "HideFileExt", 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
            }
            RegCloseKey(hKey);
        }
    }
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", SMTO_ABORTIFHUNG, 5000, nullptr);
}

void DeleteRegistryKey(HKEY hKeyRoot, const char* subKey, const char* valueName) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(hKeyRoot, subKey, 0, KEY_SET_VALUE, &hKey);

    if (result == ERROR_SUCCESS) {
        result = RegDeleteValueA(hKey, valueName);
        RegCloseKey(hKey);
    }
}

void DeleteScheduledTask(const char* taskName) {
    std::string command = "schtasks /delete /tn \"";
    command += taskName;
    command += "\" /f";  // /f để xóa mà không cần xác nhận

    int result = system(command.c_str());
}


bool KillProcessByName(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create process snapshot\n";
        return false;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    std::wcout << L"Killing process: " << processName << L" (PID: " << pe.th32ProcessID << L")\n";
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
                else {
                    std::wcerr << L"Failed to open process: " << processName << L"\n";
                }
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return true;
}

// Hàm chuyển đổi từ std::string sang std::wstring
std::wstring StringToWString(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    if (size_needed <= 0) return L"";

    std::wstring wstr(size_needed - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);
    return wstr;
}

// Hàm chuyển từ std::wstring sang std::string an toàn
std::string WStringToString(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    if (size_needed <= 0) return "";

    std::string str(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size_needed, NULL, NULL);
    return str;
}

// Hàm tính SHA-256 của một file
std::string calculate_sha256(const std::string& file_path) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open file " << file_path << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }

    std::vector<char> buffer(65536); // Đọc 64KB mỗi lần để tối ưu tốc độ
    while (file.read(buffer.data(), buffer.size()) || file.gcount()) {
        if (!EVP_DigestUpdate(ctx, buffer.data(), file.gcount())) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }

    if (!EVP_DigestFinal_ex(ctx, hash, NULL)) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    // Chuyển hash thành chuỗi hex
    std::string result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", hash[i]);
        result += buf;
    }
    return result;
}

// Hàm quét và xóa malware
void scanAndDeleteMalware(const std::string& directory) {
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind;
    std::wstring searchPath = StringToWString(directory) + L"\\*";

    hFind = FindFirstFileW(searchPath.c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Error: Cannot access directory " << searchPath << std::endl;
        return;
    }

    do {
        std::wstring name = findFileData.cFileName;
        std::wstring fullPath = StringToWString(directory) + L"\\" + name;

        if (name == L"." || name == L"..") continue;

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scanAndDeleteMalware(WStringToString(fullPath));  // Đệ quy vào thư mục con
        }
        else if (name.size() > 4 && name.substr(name.size() - 4) == L".exe") {
            std::string fullPathStr = WStringToString(fullPath);
            std::string fileHash = calculate_sha256(fullPathStr);
            if (fileHash.empty()) continue;

            for (const auto& malware_hash : malware_hashes) {
                if (fileHash == malware_hash) {
                    std::wcout << L"Malware detected: " << fullPath << L" (SHA-256: " << fileHash.c_str() << L")" << std::endl;
                    if (DeleteFileW(fullPath.c_str())) {
                        std::wcout << L"Deleted: " << fullPath << std::endl;
                    }
                    else {
                        std::wcerr << L"Failed to delete: " << fullPath << std::endl;
                    }
                    break;
                }
            }
        }
    } while (FindNextFileW(hFind, &findFileData));

    FindClose(hFind);
}



void Deletefile(const char* fileName) {
    SetFileAttributesA(fileName, FILE_ATTRIBUTE_NORMAL);
    DeleteFileA(fileName);
}

int main() {
    EnableTaskManager();
    EnableRegistrytTool();
    EnableFolderOptions();
    EnableHiddenItem();
    EnableHiddenExt();

    KillProcessByName(L"SysUpdate.exe");

    Deletefile("C:\\autorun.inf");
    Deletefile("C:\\Users\\DELL\\AppData\\Roaming\\SysUpdate.exe");

    DeleteRegistryKey(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SysUpdate");
    DeleteRegistryKey(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "SysUpdate");
    DeleteRegistryKey(HKEY_CLASSES_ROOT,
        "regfile\\shell\\open\\command\\", "(Default)");
    DeleteScheduledTask("SysUpdate");
    DeleteScheduledTask("Client");
    scanAndDeleteMalware("C:");
    return 0;
}
