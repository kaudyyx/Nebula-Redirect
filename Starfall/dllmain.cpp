#include "pch.h"
#include "base.h"
#include "request.h"
#include "exit.h"
#include "opts.h"
#include "hwid.h"
#include "eor.h"
#include "edp.h"
#include "MinHook.h"
#include <tlhelp32.h>
#include <urlmon.h>
#include <shellapi.h>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")

// ============================================================================
// Logger
// ============================================================================
static HANDLE gLogFile = INVALID_HANDLE_VALUE;
static void LogOpen()
{
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    lstrcatA(path, "eor_log.txt");
    gLogFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}
void LogStr(const char* msg)
{
    if (gLogFile == INVALID_HANDLE_VALUE) return;
    DWORD w; WriteFile(gLogFile, msg, lstrlenA(msg), &w, nullptr);
}
void LogPtr(const char* label, void* ptr)
{
    char b[80]; wsprintfA(b, "%s%p\n", label, ptr); LogStr(b);
}
void LogInt(const char* label, int val)
{
    char b[80]; wsprintfA(b, "%s%d\n", label, val); LogStr(b);
}

// ============================================================================
// SentinelUltra Watchdog
// ============================================================================
namespace SentinelWatchdog
{
    static const char* SENTINEL_PROCESS = "SentinelUltra.exe";
    static const wchar_t* SENTINEL_URL = L"https://github.com/murilomoreto/nebula-files/raw/refs/heads/main/SentinelUltra.exe";
    static const DWORD    CHECK_INTERVAL_MS = 15000; // 15 segundos

    // Verifica se um processo com o nome dado esta em execucao
    static bool IsProcessRunning(const char* processName)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        bool found = false;
        if (Process32First(snap, &pe))
        {
            do {
                if (lstrcmpiA(pe.szExeFile, processName) == 0)
                {
                    found = true;
                    break;
                }
            } while (Process32Next(snap, &pe));
        }

        CloseHandle(snap);
        return found;
    }

    // Baixa o SentinelUltra.exe e executa em segundo plano
    // Retorna true em caso de sucesso
    static bool DownloadAndRun()
    {
        // Monta caminho de destino em %TEMP%\SentinelUltra.exe
        char  destPathA[MAX_PATH];
        wchar_t destPathW[MAX_PATH];

        GetTempPathA(MAX_PATH, destPathA);
        lstrcatA(destPathA, SENTINEL_PROCESS);

        MultiByteToWideChar(CP_ACP, 0, destPathA, -1, destPathW, MAX_PATH);

        LogStr("[SENTINEL] Baixando SentinelUltra.exe...\n");

        HRESULT hr = URLDownloadToFileW(nullptr, SENTINEL_URL, destPathW, 0, nullptr);

        if (FAILED(hr))
        {
            LogStr("[SENTINEL] Download falhou.\n");
            return false;
        }

        LogStr("[SENTINEL] Download concluido. Executando em segundo plano...\n");

        SHELLEXECUTEINFOA sei = {};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        sei.lpVerb = "open";
        sei.lpFile = destPathA;
        sei.nShow = SW_HIDE;

        if (!ShellExecuteExA(&sei))
        {
            LogStr("[SENTINEL] Execucao falhou.\n");
            return false;
        }

        if (sei.hProcess) CloseHandle(sei.hProcess);

        LogStr("[SENTINEL] SentinelUltra.exe executado.\n");
        return true;
    }

    // Encerra o processo atual (fecha o jogo)
    static void CloseGame()
    {
        LogStr("[SENTINEL] Encerrando o jogo.\n");
        TerminateProcess(GetCurrentProcess(), 1);
    }

    // Thread principal do watchdog - roda em segundo plano a cada 15s
    static DWORD WINAPI WatchdogThread(LPVOID)
    {
        LogStr("[SENTINEL] Watchdog iniciado.\n");

        // Aguarda o intervalo inicial antes da primeira checagem
        Sleep(CHECK_INTERVAL_MS);

        while (true)
        {
            if (!IsProcessRunning(SENTINEL_PROCESS))
            {
                LogStr("[SENTINEL] SentinelUltra.exe nao encontrado. Iniciando download...\n");

                bool ok = DownloadAndRun();

                if (!ok)
                {
                    // Download ou execucao falhou: encerra o jogo
                    CloseGame();
                    return 0;
                }

                // Aguarda o processo subir
                Sleep(3000);

                // Verificacao pos-lancamento
                if (!IsProcessRunning(SENTINEL_PROCESS))
                {
                    LogStr("[SENTINEL] SentinelUltra.exe ainda nao detectado apos lancamento. Encerrando jogo.\n");
                    CloseGame();
                    return 0;
                }

                LogStr("[SENTINEL] SentinelUltra.exe confirmado em execucao.\n");
            }

            Sleep(CHECK_INTERVAL_MS);
        }

        return 0;
    }

    static void Start()
    {
        CreateThread(nullptr, 0, WatchdogThread, nullptr, 0, nullptr);
    }
}
// ============================================================================

namespace Starfall
{
    void Init()
    {
        LogStr("[SF] Starfall::Init() comecou\n");

        if (Console)
        {
            AllocConsole();
            FILE* fptr;
            freopen_s(&fptr, "CONOUT$", "w+", stdout);
        }

        auto hwidResult = HWID::Generate();
        SetRuntimeHWID(hwidResult.hwid);

        if (UseBackendParam)
        {
            FString cmd = GetCommandLineW();
            auto pos = cmd.find(L"-backend=");
            if (pos != std::wstring::npos)
                backend = cmd.substr(pos + 9);
            else
                backend = Backend;
        }
        else
        {
            backend = Backend;
        }

        StartRedirectControlThread();

        buf = *(void**)(__readgsqword(0x60) + 0x10);
        EOSBuf = LoadLibraryA("EOSSDK-Win64-Shipping");

        {
            auto section = pe_get_section((char*)buf, ".text");
            auto rsection = pe_get_section((char*)buf, ".rdata");
            tbuf = (void*)(__int64(buf) + section->virtualAddress);
            tsize = section->virtualSize;
            rbuf = (void*)(__int64(buf) + rsection->virtualAddress);
            rsize = rsection->virtualSize;
        }

        if (EOSBuf)
        {
            auto section = pe_get_section((char*)EOSBuf, ".text");
            auto rsection = pe_get_section((char*)EOSBuf, ".rdata");
            EOSTextBuf = (void*)(__int64(EOSBuf) + section->virtualAddress);
            EOSTextSize = section->virtualSize;
            EOSRDataBuf = (void*)(__int64(EOSBuf) + rsection->virtualAddress);
            EOSRDataSize = rsection->virtualSize;
        }

        LogStr("[SF] globais prontos\n");

        // Inicia watchdog do SentinelUltra em segundo plano
        SentinelWatchdog::Start();

        if constexpr (EnableEOR)
            EOR::Init();

        if constexpr (EnableEDP)
            EDP::Init();

        FindProcessRequest();
        if (bHasPushWidget)
            FindPushWidget();
    }
}

BOOL APIENTRY DllMain(HMODULE dllBase, DWORD callReason, LPVOID lpReserved)
{
    if (callReason == DLL_PROCESS_ATTACH)
    {
        LogOpen();
        LogStr("[SF] DLL_PROCESS_ATTACH\n");
        ManualMapping
            ? Starfall::Init()
            : (void)CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Starfall::Init, 0, 0, 0);
    }
    return TRUE;
}