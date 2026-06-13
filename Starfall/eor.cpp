#include "pch.h"
#include "eor.h"
#include "base.h"
#include "opts.h"
#include "MinHook.h"
extern void LogStr(const char* msg);
extern void LogPtr(const char* label, void* ptr);

namespace EOR {

    bool Active = false;
    void* LastA1 = nullptr;
    void* CompleteEditAddr = nullptr;

    static void* (*SelectEdit)(void*) = nullptr;
    static void* (*SelectReset)(void*) = nullptr;
    static char   (*CompleteEdit)(void*) = nullptr;
    static wchar_t* VersionString = nullptr;

    static void* (*SelectEditOG)(void*) = nullptr;
    static void* (*SelectResetOG)(void*) = nullptr;

    __declspec(noinline) static bool InternalCheckBytes(void* ptr, const uint8_t* bytes, size_t sz) {
        for (size_t i = 0; i < sz; i++)
            if (((uint8_t*)ptr)[i] != bytes[i]) return false;
        return true;
    }

    template <uint8_t... Data>
    struct CB {
        constexpr static uint8_t bytes[sizeof...(Data)] = { Data... };
        static bool At(void* ptr) { return InternalCheckBytes(ptr, bytes, sizeof...(Data)); }
    };

    static bool StringCallback(pf_patch_t*, void* stream) {
        void* saddr = FollowRelative<void>(stream, 3);
        if (__int64(saddr) < __int64(rbuf) || __int64(saddr) >= __int64(rbuf) + (int64_t)rsize)
            return SelectEdit && SelectReset && CompleteEdit && VersionString;

        if (wcscmp((wchar_t*)saddr, L"EditModeInputComponent0") == 0 && !SelectEdit && !SelectReset) {
            int sc = 0;
            for (int i = 1; i < 2048; i++) {
                auto sI = (uint8_t*)stream + i;
                if (CB<0x48, 0x8D, 0x05>::At(sI)) {
                    switch (sc) {
                    case 1:
                        SelectEdit = FollowRelative<decltype(SelectEdit)>(sI, 3);
                        break;
                    case 2:
                        SelectReset = FollowRelative<decltype(SelectReset)>(sI, 3);
                        for (int x = 1; x < 2048; x++) {
                            auto sX = sI + x;
                            if (CB<0x48, 0x8D>::At(sX) || CB<0x4C, 0x8D>::At(sX)) {
                                void* naddr = FollowRelative<void>(sX, 3);
                                if (__int64(naddr) >= __int64(rbuf) &&
                                    __int64(naddr) < __int64(rbuf) + (int64_t)rsize &&
                                    strcmp((char*)naddr, "CompleteBuildingEditInteraction") == 0) {
                                    for (int y = 1; y < 2048; y++) {
                                        auto sY = sX - y;
                                        if (CB<0x48, 0x8D>::At(sY) || CB<0x4C, 0x8D>::At(sY)) {
                                            CompleteEdit = FollowRelative<decltype(CompleteEdit)>(sY, 3);
                                            CompleteEditAddr = (void*)CompleteEdit;
                                            goto found_complete;
                                        }
                                    }
                                }
                            }
                        }
                    found_complete:
                        break;
                    }
                    sc++;
                }
            }
        }
        else if (wcsncmp((wchar_t*)saddr, L"++Fortnite+Release-", 19) == 0 && !VersionString) {
            VersionString = (wchar_t*)saddr;
        }

        return SelectEdit && SelectReset && CompleteEdit && VersionString;
    }

    static void* __fastcall SelectEditHook(void* a1) {
        void* result = SelectEditOG(a1);
        if (Active) CompleteEdit(a1);
        return result;
    }

    static void* __fastcall SelectResetHook(void* a1) {
        LastA1 = a1;
        void* result = SelectResetOG(a1);
        if (Active) CompleteEdit(a1);
        return result;
    }

    // Called early from Starfall::Init() after tbuf/rbuf are ready.
    // Only REGISTERS hooks with MH_CreateHook — does NOT enable them.
    // MH_EnableHook(MH_ALL_HOOKS) in request.cpp fires them at the right time
    // (first auth request = engine + lobby fully ready).
    void Init() {
        LogStr("[EOR] Init  ");
        constexpr static std::array<uint8_t, 2> matches = { 0x48, 0x8D };
        constexpr static std::array<uint8_t, 2> masks = { 0xFB, 0xFF };
        constexpr static auto patch = pf_construct_patch((void*)matches.data(), (void*)masks.data(), 2, StringCallback);
        constexpr static pf_patch_t patches[] = { patch };
        constexpr static pf_patchset_t patchset = pf_construct_patchset((pf_patch_t*)patches, 1);

        while (!pf_patchset_emit(tbuf, tsize, patchset));

        LogPtr("[EOR] SR=", SelectReset);
        LogPtr("[EOR] CE=", CompleteEdit);
        if (!SelectReset || !CompleteEdit) {
            LogStr("[EOR] scan failed "); return;
        }

        // Parse version
        auto VStart = wcschr(VersionString, L'-') + 1;
        auto VEnd = wcschr(VStart, L'-');
        if (!VEnd) VEnd = wcschr(VStart, L'\0');
        char verBuf[32] = {};
        WideCharToMultiByte(CP_ACP, 0, VStart, (int)(VEnd - VStart), verBuf, 31, nullptr, nullptr);
        double FNVer = atof(verBuf);

        MH_Initialize();
        if (FNVer < 11.00 && SelectEdit)
            MH_CreateHook(SelectEdit, (void*)SelectEditHook, (LPVOID*)&SelectEditOG);
        if (SelectReset)
            MH_CreateHook(SelectReset, (void*)SelectResetHook, (LPVOID*)&SelectResetOG);
        // NOTE: do NOT call MH_EnableHook here.
        // request.cpp calls MH_EnableHook(MH_ALL_HOOKS) on first auth request.

        LogStr("[EOR] hooks registered ");
        if (strstr(GetCommandLineA(), "-eor")) {
            Active = true;
            LogStr("[EOR] Active=true ");
        }
    }

} // namespace EOR