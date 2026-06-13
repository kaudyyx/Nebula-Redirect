#include "pch.h"
#include "base.h"
#include "hooking.h"
#include "url.h"
#include "request.h"
#include "redirection.h"
#include <array>
#include <string>
#include <algorithm>
#include <cctype>
#include <winhttp.h>
#include "opts.h"
extern void LogStr(const char* msg);
#include <time.h>
#include <sys/timeb.h>
#include "SDK.h"
#define STARFALL_MINHOOK_IMPL
#include "MinHook.h"

#pragma comment(lib, "winhttp.lib")
#define CallVirt(T, vt, offset, ...) ((T) vt[offset])(__VA_ARGS__)

namespace Unreal
{
    FString FCurlHttpRequest::GetURL()
    {
        return ((FString & (*)(FCurlHttpRequest*, FString))VTable[0])(this, FString());
    }
}

struct FUIExtension final
{
public:
    uint8 Slot;
    uint8 Pad_1[0x7];
    USDK::TSoftClassPtr<class UClass> WidgetClass;
};

namespace Starfall
{
    static std::string RuntimeHWIDAnsi;
    static std::wstring RuntimeHWIDWide;
    static std::wstring RuntimeAccountId;
    static HANDLE RedirectControlThreadHandle = nullptr;
    static volatile LONG RedirectCutEnabled = 0;
    static constexpr const wchar_t* DeadBackend = L"http://127.0.0.1:9";

    static std::wstring ToWide(const std::string& v)
    {
        return std::wstring(v.begin(), v.end());
    }

    static std::wstring ToWide(const FString& v)
    {
        if (!v.String) return L"";
        return std::wstring(v.String);
    }

    static std::wstring GetBackendBase()
    {
        if (backend.String && backend.String[0]) return std::wstring(backend.String);
        return std::wstring(Backend.String);
    }

    static std::wstring UrlEncode(const std::wstring& value)
    {
        std::wstring out;
        wchar_t buf[4] = {};
        for (wchar_t ch : value)
        {
            if ((ch >= L'0' && ch <= L'9') || (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') || ch == L'-' || ch == L'_' || ch == L'.' || ch == L'~')
            {
                out.push_back(ch);
            }
            else
            {
                swprintf_s(buf, L"%%%02X", (unsigned int)(unsigned char)ch);
                out += buf;
            }
        }
        return out;
    }

    static bool StartsWith(const std::wstring& value, const std::wstring& prefix)
    {
        return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
    }

    static bool ContainsInsensitive(const std::string& value, const char* needle)
    {
        std::string lower = value;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        std::string n = needle;
        std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        return lower.find(n) != std::string::npos;
    }

    static std::wstring GetQueryValue(const std::wstring& query, const std::wstring& key)
    {
        if (query.empty()) return L"";
        std::wstring q = query;
        if (!q.empty() && q[0] == L'?') q.erase(0, 1);
        const std::wstring marker = key + L"=";
        size_t start = 0;
        while (start < q.size())
        {
            size_t end = q.find(L'&', start);
            std::wstring part = q.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
            if (StartsWith(part, marker))
            {
                return part.substr(marker.size());
            }
            if (end == std::wstring::npos) break;
            start = end + 1;
        }
        return L"";
    }

    static void ReplaceQuery(URL* url, const std::wstring& newQuery)
    {
        if (url->Query.String) url->Query.Dealloc();
        if (newQuery.empty())
        {
            url->Query = FString();
            return;
        }
        url->Query = FString((wchar_t*)newQuery.c_str());
    }

    static void AppendQueryParam(URL* url, const std::wstring& key, const std::wstring& value)
    {
        if (value.empty()) return;
        std::wstring query = url->Query.String ? std::wstring(url->Query.String) : L"";
        const std::wstring marker = key + L"=";
        if (query.find(marker) != std::wstring::npos) return;
        if (query.empty()) query = L"?" + key + L"=" + UrlEncode(value);
        else query += L"&" + key + L"=" + UrlEncode(value);
        ReplaceQuery(url, query);
    }

    static bool ShouldAttachHWID(const std::wstring& path)
    {
        return path == L"/account/api/oauth/token" ||
            path == L"/auth/v1/oauth/token" ||
            path == L"/epic/oauth/v2/token" ||
            path == L"/launcher/ban-check" ||
            path == L"/nebula/gs/ticket" ||
            path == L"/api/store-hwid" ||
            path == L"/anticheat/hwid" ||
            path == L"/anticheat/detected";
    }

    static void CaptureAccountId(URL* url)
    {
        const std::wstring path = ToWide(url->Path);
        const std::wstring query = ToWide(url->Query);

        const std::wstring prefix = L"/fortnite/api/game/v2/profile/";
        if (StartsWith(path, prefix))
        {
            const size_t start = prefix.size();
            const size_t end = path.find(L'/', start);
            if (end != std::wstring::npos && end > start)
            {
                RuntimeAccountId = path.substr(start, end - start);
                return;
            }
        }

        std::wstring fromQuery = GetQueryValue(query, L"accountId");
        if (!fromQuery.empty())
        {
            RuntimeAccountId = fromQuery;
            return;
        }

        fromQuery = GetQueryValue(query, L"account_id");
        if (!fromQuery.empty())
        {
            RuntimeAccountId = fromQuery;
            return;
        }
    }

    static bool HttpGetString(const std::wstring& fullUrl, std::string& out)
    {
        URL_COMPONENTS comp{};
        comp.dwStructSize = sizeof(comp);
        comp.dwSchemeLength = (DWORD)-1;
        comp.dwHostNameLength = (DWORD)-1;
        comp.dwUrlPathLength = (DWORD)-1;
        comp.dwExtraInfoLength = (DWORD)-1;

        if (!WinHttpCrackUrl(fullUrl.c_str(), 0, 0, &comp)) return false;

        const std::wstring host(comp.lpszHostName, comp.dwHostNameLength);
        std::wstring path(comp.lpszUrlPath, comp.dwUrlPathLength);
        if (comp.dwExtraInfoLength) path += std::wstring(comp.lpszExtraInfo, comp.dwExtraInfoLength);

        HINTERNET hSession = WinHttpOpen(L"Starfall/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        WinHttpSetTimeouts(hSession, 2500, 2500, 2500, 2500);

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), comp.nPort, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return false;
        }

        DWORD flags = comp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        bool ok = false;
        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(hRequest, nullptr))
        {
            DWORD status = 0;
            DWORD statusSize = sizeof(status);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
            if (status >= 200 && status < 300)
            {
                out.clear();
                for (;;)
                {
                    DWORD available = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &available) || available == 0) break;
                    std::string chunk;
                    chunk.resize(available);
                    DWORD read = 0;
                    if (!WinHttpReadData(hRequest, chunk.data(), available, &read) || read == 0) break;
                    chunk.resize(read);
                    out += chunk;
                }
                ok = true;
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return ok;
    }

    static std::wstring BuildRedirectControlUrl()
    {
        std::wstring base = GetBackendBase();
        if (base.empty() || RuntimeHWIDWide.empty() || RuntimeAccountId.empty()) return L"";
        if (!base.empty() && base.back() == L'/') base.pop_back();
        return base + L"/launcher/redirect-control?accountId=" + UrlEncode(RuntimeAccountId) + L"&hwid=" + UrlEncode(RuntimeHWIDWide);
    }

    static void HardDisconnect()
    {
        InterlockedExchange(&RedirectCutEnabled, 1);
        Sleep(150);
        TerminateProcess(GetCurrentProcess(), 0);
    }

    static DWORD WINAPI RedirectControlThreadProc(LPVOID)
    {
        for (;;)
        {
            Sleep(3000);
            if (RuntimeHWIDWide.empty() || RuntimeAccountId.empty()) continue;
            const std::wstring url = BuildRedirectControlUrl();
            if (url.empty()) continue;
            std::string body;
            if (!HttpGetString(url, body)) continue;
            if (ContainsInsensitive(body, "\"disconnect\":true") || ContainsInsensitive(body, "\"disconnect\": true"))
            {
                HardDisconnect();
                return 0;
            }
        }
    }

    void SetRuntimeHWID(const std::string& hwid)
    {
        RuntimeHWIDAnsi = hwid;
        RuntimeHWIDWide = ToWide(hwid);
    }

    void StartRedirectControlThread()
    {
        if (RedirectControlThreadHandle) return;
        RedirectControlThreadHandle = CreateThread(nullptr, 0, RedirectControlThreadProc, nullptr, 0, nullptr);
    }

    bool IsRedirectCutEnabled()
    {
        return InterlockedCompareExchange(&RedirectCutEnabled, 0, 0) != 0;
    }

    bool setupMemLeak = false;
    void SetupRequest(FCurlHttpRequest* Request)
    {
        static int NumRequests = 0;
        NumRequests++;
        if (FCurlHttpRequest::SetURLIdx == 0)
        {
            void* GetFunc = *Request->VTable;
            uint32_t URLOffset = 0;
            for (int i = 0; i < 100; i++)
            {
                if (CheckBytes<0x48, 0x8D, 0x91>(GetFunc, i))
                {
                    URLOffset = *(uint32_t*)(__int64(GetFunc) + i + 3);
                    break;
                }
            }

            if (URLOffset == 0) goto def;
            for (int64_t i = 0; i < ((__int64(FCurlHttpRequest::ProcessRequestVT) - __int64(Request->VTable)) / 8); i++)
            {
                auto func = Request->VTable[i];
                for (int j = 0; j < 100; j++)
                {
                    if (CheckBytes<0x48, 0x81, 0xC1>(func, j))
                    {
                        if (*(uint32_t*)(__int64(func) + j + 3) == URLOffset)
                        {
                            FCurlHttpRequest::SetURLIdx = i;
                            return;
                        }
                    }
                }
            }
        def:
            FCurlHttpRequest::SetURLIdx = 10;
        }
        else if (!setupMemLeak && FixMemLeak)
        {
            constexpr static struct pf_patch_t ml_patch = pf_construct_patch_sig("48 8B 01 4C 8D 41 08 48 FF 60 20", Ret0Callback);
            constexpr static struct pf_patch_t ml_patch2 = pf_construct_patch_sig("48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 01 4C 8B C2 48 8D 54 24", Ret0Callback);

            constexpr static struct pf_patch_t patches[] = {
                ml_patch,
                ml_patch2
            };

            constexpr static struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t));

            pf_patchset_emit(tbuf, tsize, patchset);
            setupMemLeak = true;
        }
        else if (NumRequests == 5)
        {
            auto ArenaUI = USDK::Conv_StringToName(L"/Game/UI/Competitive/Arena/ArenaScoringHUD.ArenaScoringHUD_C");
            FUIExtension ArenaUIExtension{};
            ArenaUIExtension.Slot = 0;
            ArenaUIExtension.WidgetClass.ObjectID.AssetPathName = ArenaUI;
            auto ShowdownUI = USDK::Conv_StringToName(L"/Game/UI/Frontend/Showdown/ShowdownScoringHUD.ShowdownScoringHUD_C");
            FUIExtension ShowdownUIExtension{};
            ShowdownUIExtension.Slot = 0;
            ShowdownUIExtension.WidgetClass.ObjectID.AssetPathName = ShowdownUI;
            auto AIKillsUI = USDK::Conv_StringToName(L"/Game/Athena/HUD/AthenaAIKillsWidget.AthenaAIKillsWidget_C");
            FUIExtension AIKillsUIExtension{};
            AIKillsUIExtension.Slot = 2;
            AIKillsUIExtension.WidgetClass.ObjectID.AssetPathName = AIKillsUI;
            USDK::TArray<FUIExtension> ArenaExtensions, ShowdownExtensions;
            ArenaExtensions.Add(ArenaUIExtension);
            ShowdownExtensions.Add(ShowdownUIExtension);
            ShowdownExtensions.Add(AIKillsUIExtension);
            auto PlaylistClass = USDK::TUObjectArray::FindObject<USDK::UClass>("FortPlaylistAthena");
            for (int i = 0; i < USDK::TUObjectArray::Num(); i++)
            {
                auto Object = USDK::TUObjectArray::GetObjectByIndex(i);
                if (Object && Object->IsA((USDK::UClass*)PlaylistClass))
                {
                    if (Object->Name.ToString().contains("Showdown"))
                    {
                        Object->Get<"UIExtensions", USDK::TArray<FUIExtension>>() = Object->Name.ToString().contains("ShowdownAlt") ? ArenaExtensions : ShowdownExtensions;
                    }
                }
            }
        }
    }

    FString backend;

    namespace Hooks {
        bool (*ProcessRequestOG)(FCurlHttpRequest* Request);
        bool (*EOSProcessRequestOG)(FCurlHttpRequest* Request);

        bool InternalProcessRequest(FCurlHttpRequest* Request, decltype(ProcessRequestOG) OG)
        {
            SetupRequest(Request);
            auto urlS = Request->GetURL();
            auto url = (URL*)_malloca(sizeof(URL));
            if (!url) return false;
            url->Construct(urlS);

            CaptureAccountId(url);

            if (shouldRedirect(url))
            {
                const std::wstring path = ToWide(url->Path);

                if (ShouldAttachHWID(path) && !RuntimeHWIDWide.empty())
                {
                    AppendQueryParam(url, L"hwid", RuntimeHWIDWide);

                    // Primeira requisicao de auth = engine e lobby prontos
                    // Ativa os hooks EOR agora, que e o momento seguro
                    static bool eorEnabled = false;
                    if (!eorEnabled)
                    {
                        eorEnabled = true;
                        LogStr("[EOR] enabling hooks");
                            MH_EnableHook(MH_ALL_HOOKS);
                        LogStr("[EOR] hooks enabled");
                    }
                }

                if (IsRedirectCutEnabled())
                {
                    url->SetHost(FString((wchar_t*)DeadBackend));
                }
                else if (UseBackendParam)
                {
                    url->SetHost(backend);
                }
                else
                {
                    __URL_SetHost(url, Backend);
                }

                FString str = *url;
                ((void (*)(FCurlHttpRequest*, FString))Request->VTable[OG == EOSProcessRequestOG ? 10 : FCurlHttpRequest::SetURLIdx])(Request, str);
                free(str.String);

                if (UseBackendParam || IsRedirectCutEnabled()) url->Dealloc();
                else url->DeallocPathQuery();
            }
            else
            {
                url->Dealloc();
            }

            return OG(Request);
        }

        bool ProcessRequestHook(FCurlHttpRequest* Request)
        {
            return InternalProcessRequest(Request, ProcessRequestOG);
        }

        bool EOSProcessRequestHook(FCurlHttpRequest* Request)
        {
            return InternalProcessRequest(Request, EOSProcessRequestOG);
        }
    }

    namespace Callbacks {
        bool PtrCallback(struct pf_patch_t* patch, void* stream)
        {
            FCurlHttpRequest::ProcessRequestVT = (void**)stream;
            VTHook((void**)stream, ProcessRequestHook, (void**)&ProcessRequestOG);
            return true;
        }

        bool EOSPtrCallback(struct pf_patch_t* patch, void* stream)
        {
            VTHook((void**)stream, EOSProcessRequestHook, (void**)&EOSProcessRequestOG);
            return true;
        }

        constexpr static char ptrMasks[] = {
            (char)0xff,
            (char)0xff,
            (char)0xff,
            (char)0xff,
            (char)0xff,
            (char)0xff,
            (char)0xff,
            (char)0xff
        };

        __forceinline void* checkStream(void* stream, bool bEOS)
        {
            for (int i = 0; i < 2048; i++)
            {
                if (bEOS)
                {
                    if (CheckBytes<0x48, 0x89, 0x5C>(stream, i, true))
                    {
                        goto setStream;
                    }
                }
                else
                {
                    if (CheckBytes<0x4C, 0x8B, 0xDC>(stream, i, true))
                    {
                        goto setStream;
                    }
                    else if (CheckBytes<0x48, 0x8B, 0xC4>(stream, i, true))
                    {
                    setStream:
                        return (uint8_t*)stream - i;
                    }
                    else if (CheckBytes<0x48, 0x81, 0xEC>(stream, i, true) || CheckBytes<0x48, 0x83, 0xEC>(stream, i, true))
                    {
                        for (int x = 0; x < 50; x++)
                        {
                            if (CheckBytes<0x40>(stream, i + x, true))
                            {
                                return (uint8_t*)stream - i - x;
                            }
                            else if (CheckBytes<0x4C, 0x8B, 0xDC>(stream, i + x, true) || CheckBytes<0x48, 0x8B, 0xC4>(stream, i + x, true) || CheckBytes<0x48, 0x89, 0x5C>(stream, i + x, true))
                                break;
                        }
                    }
                }
            }
            return nullptr;
        }

        bool InternalCallback(void* stream, void* rbuf, size_t rsize, bool (*callback)(pf_patch_t*, void*), bool bEOS)
        {
            void* saddr = (void*)((__int64(stream) + 7) + *(int32_t*)(__int64(stream) + 3));
            void* newStream = nullptr;
            if (__int64(saddr) >= __int64(rbuf) && __int64(saddr) < (__int64(rbuf) + (int64_t)rsize))
                if (wcscmp((wchar_t*)saddr, L"STAT_FCurlHttpRequest_ProcessRequest") == 0 || wcscmp((wchar_t*)saddr, L"%p: request (easy handle:%p) has been added to threaded queue for processing") == 0)
                    if (newStream = checkStream(stream, bEOS)) goto Out;
            return false;

        Out:
            char* ptrMatches = (char*)&newStream;

            auto patch2 = pf_construct_patch(ptrMatches, (void*)ptrMasks, 8, callback);

            struct pf_patch_t patches2[] = {
                patch2
            };

            struct pf_patchset_t patchset2 = pf_construct_patchset(patches2, sizeof(patches2) / sizeof(struct pf_patch_t));
            while (!pf_patchset_emit(rbuf, rsize, patchset2));
            return true;
        }

        bool StringCallback(struct pf_patch_t* patch, void* stream)
        {
            return InternalCallback(stream, rbuf, rsize, PtrCallback, false);
        }

        bool EOSStringCallback(struct pf_patch_t* patch, void* stream)
        {
            return InternalCallback(stream, EOSRDataBuf, EOSRDataSize, EOSPtrCallback, true);
        }
    }

    namespace Finders {
        void FindProcessRequest()
        {
            constexpr static std::array<uint8_t, 2> matches = {
                0x48,
                0x8d
            };
            constexpr static std::array<uint8_t, 2> masks = {
                0xfb,
                0xff
            };
            {
                constexpr static auto patch = pf_construct_patch((void*)matches.data(), (void*)masks.data(), 2, StringCallback);

                constexpr static pf_patch_t patches[] = {
                    patch
                };

                constexpr static struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t));

                while (!pf_patchset_emit(tbuf, tsize, patchset));
            }

            if (EOSBuf)
            {
                constexpr static auto patch = pf_construct_patch((void*)matches.data(), (void*)masks.data(), 2, EOSStringCallback);

                constexpr static pf_patch_t patches[] = {
                    patch
                };

                constexpr static struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t));

                while (!pf_patchset_emit(EOSTextBuf, EOSTextSize, patchset));
            }
        }
    }
}