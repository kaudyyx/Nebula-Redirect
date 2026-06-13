#include "pch.h"
#include "edp.h"
#include "base.h"
#include "opts.h"
#include "MinHook.h"

extern void LogStr(const char* msg);
extern void LogPtr(const char* label, void* ptr);

namespace EDP {

    bool Active = false;

    static constexpr int PREVIEW_MARKER_OFF = 0x1208;
    static constexpr int PREVIEW_MARKER_EXTRA_OFF = 0x1210;
    static constexpr int TARGETED_BUILDING_OFF = 0x1318;

    static void* (*SelectEditOG)(void*) = nullptr;
    static char  (*CompleteEditFn)(void*) = nullptr;

    static void* s_SelectEdit = nullptr;
    static void* s_SelectReset = nullptr;

    template<uint8_t... B> struct CB {
        constexpr static uint8_t bytes[sizeof...(B)] = { B... };
        static bool At(void* p) {
            for (int i = 0; i < (int)sizeof...(B); i++)
                if (((uint8_t*)p)[i] != bytes[i]) return false;
            return true;
        }
    };

    static bool IsPreEdit(void* a1) {
        if (!a1 || (uintptr_t)a1 < 0x10000) return false;
        void* tb = nullptr, * pm1 = nullptr, * pm2 = nullptr;
        __try {
            tb = *(void**)((uint8_t*)a1 + TARGETED_BUILDING_OFF);
            pm1 = *(void**)((uint8_t*)a1 + PREVIEW_MARKER_OFF);
            pm2 = *(void**)((uint8_t*)a1 + PREVIEW_MARKER_EXTRA_OFF);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        return tb && (tb == pm1 || (pm2 && tb == pm2));
    }

    static bool ScanCb(pf_patch_t*, void* stream) {
        void* saddr = FollowRelative<void>(stream, 3);
        if (__int64(saddr) < __int64(rbuf) || __int64(saddr) >= __int64(rbuf) + (int64_t)rsize)
            return s_SelectEdit && s_SelectReset && CompleteEditFn;

        if (wcscmp((wchar_t*)saddr, L"EditModeInputComponent0") == 0 && !s_SelectEdit) {
            int sc = 0;
            for (int i = 1; i < 2048; i++) {
                auto* sI = (uint8_t*)stream + i;
                if (CB<0x48, 0x8D, 0x05>::At(sI)) {
                    switch (sc) {
                    case 1:
                        s_SelectEdit = FollowRelative<void>(sI, 3);
                        break;
                    case 2:
                        s_SelectReset = FollowRelative<void>(sI, 3);
                        for (int x = 1; x < 2048 && !CompleteEditFn; x++) {
                            auto* sX = sI + x;
                            if (!CB<0x48, 0x8D>::At(sX) && !CB<0x4C, 0x8D>::At(sX)) continue;
                            void* naddr = FollowRelative<void>(sX, 3);
                            if (__int64(naddr) < __int64(rbuf) || __int64(naddr) >= __int64(rbuf) + (int64_t)rsize) continue;
                            if (strcmp((char*)naddr, "CompleteBuildingEditInteraction") != 0) continue;
                            for (int y = 1; y < 2048; y++) {
                                auto* sY = sX - y;
                                if (!CB<0x48, 0x8D>::At(sY) && !CB<0x4C, 0x8D>::At(sY)) continue;
                                CompleteEditFn = FollowRelative<decltype(CompleteEditFn)>(sY, 3);
                                break;
                            }
                        }
                        break;
                    }
                    sc++;
                }
            }
        }
        return s_SelectEdit && s_SelectReset && CompleteEditFn;
    }

    // Quando o player solta o mouse no pre-edit (tentando confirmar uma selecao),
    // chamamos CompleteEdit diretamente para fechar o grid sem aplicar a edicao.
    // CompleteEdit com selecao vazia = fecha o grid sem editar a construcao.
    static void* __fastcall SelectEditHook(void* a1) {
        if (Active && IsPreEdit(a1)) {
            LogStr("[EDP] pre-edit bloqueado\n");
            if (CompleteEditFn) CompleteEditFn(a1);
            return nullptr;
        }
        return SelectEditOG(a1);
    }

    void Init() {
        LogStr("[EDP] Init\n");

        constexpr static std::array<uint8_t, 2> m = { 0x48, 0x8D }, k = { 0xFB, 0xFF };
        constexpr static auto p = pf_construct_patch((void*)m.data(), (void*)k.data(), 2, ScanCb);
        constexpr static pf_patch_t  pa[] = { p };
        constexpr static pf_patchset_t ps = pf_construct_patchset((pf_patch_t*)pa, 1);
        while (!pf_patchset_emit(tbuf, tsize, ps));

        LogPtr("[EDP] SelectEdit=", s_SelectEdit);
        LogPtr("[EDP] SelectReset=", s_SelectReset);
        LogPtr("[EDP] CompleteEdit=", (void*)CompleteEditFn);

        if (!s_SelectEdit) { LogStr("[EDP] SelectEdit nao encontrado\n"); return; }

        MH_Initialize();
        MH_CreateHook(s_SelectEdit, (void*)SelectEditHook, (LPVOID*)&SelectEditOG);

        LogStr("[EDP] hooks registrados\n");
        if (strstr(GetCommandLineA(), "-edp")) { Active = true; LogStr("[EDP] Active=true\n"); }
    }

} // namespace EDP