// dllmain.cpp : Defines the entry point for the DLL application.
#include "pe/module.h"
#include <xorstr/include/xorstr.hpp>
#include <pluginsdk.h>
#include <searchers.h>
#include "Detours/include/detours.h"
#include "enums.h"
#include "structs.h"

UEngine* GEngine;

typedef UObject* (__fastcall* f_StaticConstructObject_Internal)(
    UClass* Class,
    UObject* InOuter,
    void* Name,
    EObjectFlags SetFlags,
    EInternalObjectFlags InternalSetFlags,
    UObject* Template,
    bool  bCopyTransientsFromClassDefaults,
    void* InstanceGraph,
    bool  bAssumeTemplateIsArchetype
    );
static f_StaticConstructObject_Internal StaticConstructObject_Internal;


typedef void(__cdecl* _ExecuteConsoleCommandNoHistory)(const wchar_t* szCmd);
_ExecuteConsoleCommandNoHistory ExecuteConsoleCommandNoHistory;

// Notification Function
typedef void(__cdecl* _AddInstantNotification)(
    uintptr_t* thisptr,
    const wchar_t* text,
    const wchar_t* particleRef,
    const wchar_t* sound,
    char track,
    bool stopPreviousSound,
    bool headline2,
    bool boss_headline,
    bool chat,
    char category,
    const wchar_t* sound2);
_AddInstantNotification oAddInstantNotification;

class BInstance {
public:
    char pad[0xA0];
    uintptr_t* World;
    char padd[0x10];
    uintptr_t* PresentationWorld;
};

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 0
typedef NTSTATUS(NTAPI* tLdrRegisterDllNotification)(ULONG, PVOID, PVOID, PVOID);
void NTAPI DllNotification(ULONG notification_reason, const LDR_DLL_NOTIFICATION_DATA* notification_data, PVOID context);

uintptr_t GetAddress(uintptr_t AddressOfCall, int index, int length)
{
    if (!AddressOfCall)
        return 0;

    long delta = *(long*)(AddressOfCall + index);
    return (AddressOfCall + delta + length);
}

uintptr_t* BNSClientInstance = NULL;
BInstance* BNSInstance;

bool(__fastcall* oProcessChatFunctionWorldByEnterKey)(uintptr_t* thisptr, const wchar_t* szText);
bool __fastcall hkProcessChatFunctionWorldByEnterKey(uintptr_t* thisptr, const wchar_t* szText) {
    if (szText) {
        if (wcsncmp(szText, L"cmd:", 4) == 0) {
            std::wstring text(szText);

            if (isspace(szText[4]))
                text.erase(0, 5);
            else
                text.erase(0, 4);

            if (text.empty()) {
                oAddInstantNotification(
                    BNSInstance->World, // Instance Ptr (Should be Game World Ptr)
                    L"Command is empty", // Msg
                    L"", // Particle Ref
                    L"", // Sound
                    0, // Track
                    false, // Stop Previous Sound
                    false, // Headline2
                    false, // Boss Headline
                    true, // Chat
                    0x16, // Other Category type if none of the above (0 = Scrolling Text headline)
                    L"" // Sound 2
                );
                return 0;
            }

            auto cmd = text.c_str();
            ExecuteConsoleCommandNoHistory(cmd);

            std::wstring message;
            message = L"Executing CMD: " + text;

            oAddInstantNotification(
                BNSInstance->World, // Instance Ptr (Should be Game World Ptr)
                message.c_str(), // Msg
                L"", // Particle Ref
                L"", // Sound
                0, // Track
                false, // Stop Previous Sound
                false, // Headline2
                false, // Boss Headline
                true, // Chat
                0x16, // Other Category type if none of the above (0 = Scrolling Text headline)
                L"00003805.Signal_UI.S_Sys_VoiceChat_InCue" // Sound 2
            );
            return 0;
        }
    }
    return oProcessChatFunctionWorldByEnterKey(thisptr, szText);
}

void buildConsole() {
    if (const auto module = pe::get_module()) {
        uintptr_t handle = module->handle();

        const auto sections = module->segments();
        const auto& s1 = std::find_if(sections.begin(), sections.end(), [](const IMAGE_SECTION_HEADER& x) {
            return x.Characteristics & IMAGE_SCN_CNT_CODE;
            });
        const auto data = s1->as_bytes();
        uintptr_t GEngine_Address = NULL;

        auto gaddr = std::search(data.begin(), data.end(), pattern_searcher(xorstr_("48 8D 4D EF 48 89 4D 77 48 89 7D EF 48 89 7D F7")));
        if (gaddr != data.end())
            GEngine_Address = GetAddress((uintptr_t)&gaddr[0] - 0x1c, 3, 7);

        GEngine = *(UEngine**)GEngine_Address;

        auto sCOID_ADDR = std::search(data.begin(), data.end(), pattern_searcher(xorstr_("40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC C0 01 00 00 48 C7 44 24 48FE FF FF FF 48 89 9C 24")));
        uintptr_t SCOI_Address = NULL;
        if (sCOID_ADDR != data.end())
            SCOI_Address = (uintptr_t)&sCOID_ADDR[0];

        StaticConstructObject_Internal = (f_StaticConstructObject_Internal)(SCOI_Address);

        UConsole* Console = reinterpret_cast<UConsole*>(StaticConstructObject_Internal(
            GEngine->ConsoleClass,
            reinterpret_cast<UObject*>(GEngine->GameViewportClient),
            nullptr,
            EObjectFlags::RF_NoFlags,
            EInternalObjectFlags::None,
            nullptr,
            false,
            nullptr,
            false
        ));

        GEngine->GameViewportClient->ViewportConsole = Console;

        if (*BNSClientInstance) {
            if (!BNSInstance)
                BNSInstance = *(BInstance**)BNSClientInstance;
        }
    }
}

void NTAPI DllNotification(ULONG notification_reason, const LDR_DLL_NOTIFICATION_DATA* notification_data, PVOID context)
{
    if (notification_reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
        if (wcsncmp(notification_data->Loaded.BaseDllName->Buffer, L"wlanapi", 7) == 0) {
            buildConsole();
        }

    return;
}

bool __cdecl init([[maybe_unused]] const Version client_version)
{
    NtCurrentPeb()->BeingDebugged = FALSE;

    static PVOID cookie;
    if (tLdrRegisterDllNotification LdrRegisterDllNotification = reinterpret_cast<tLdrRegisterDllNotification>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrRegisterDllNotification")))
        LdrRegisterDllNotification(0, DllNotification, NULL, &cookie); //Set a callback for when Dll's are loaded/unloaded
    if (const auto module = pe::get_module()) {
        DetourTransactionBegin();
        DetourUpdateThread(NtCurrentThread());
        uintptr_t handle = module->handle();

        const auto sections = module->segments();
        const auto& s1 = std::find_if(sections.begin(), sections.end(), [](const IMAGE_SECTION_HEADER& x) {
            return x.Characteristics & IMAGE_SCN_CNT_CODE;
            });
        const auto data = s1->as_bytes();

        auto sExecCmd = std::search(data.begin(), data.end(), pattern_searcher(xorstr_("48 8B C3 0F 1F 44 00 00 48 FF C0 66 83 3C 41 00 75 ?? 48 85 C0  0F 84 1E 01 00 00")));
        if (sExecCmd != data.end()) {
            ExecuteConsoleCommandNoHistory = module->rva_to<std::remove_pointer_t<decltype(ExecuteConsoleCommandNoHistory)>>((uintptr_t)&sExecCmd[0] - 0x28 - handle);
        } else
            MessageBox(NULL, L"Could not find the function ExecuteConsoleNoHistory", L"Search Error", MB_OK);

        auto sProcessChat = std::search(data.begin(), data.end(), pattern_searcher(xorstr_("4C 8B E2 4C 8B F9 33 DB 44 8B EB 89 5C 24 44 48 85 D2")));
        if (sProcessChat != data.end()) {
            oProcessChatFunctionWorldByEnterKey = module->rva_to<std::remove_pointer_t<decltype(oProcessChatFunctionWorldByEnterKey)>>((uintptr_t)&sProcessChat[0] - 0x3C - handle);
            DetourAttach(&(PVOID&)oProcessChatFunctionWorldByEnterKey, &hkProcessChatFunctionWorldByEnterKey);
        } else
            MessageBox(NULL, L"Could not find the function ProcessChatInput", L"Search Error", MB_OK);

        // Used for sending notifications about certain actions
        auto sAddNotif = std::search(data.begin(), data.end(), pattern_searcher(xorstr_("45 33 DB 41 8D 42 F4 3C 02 BB 05 00 00 00 41 0F 47 DB")));
        if (sAddNotif != data.end()) {
            oAddInstantNotification = module->rva_to<std::remove_pointer_t<decltype(oAddInstantNotification)>>((uintptr_t)&sAddNotif[0] - 0x68 - handle);
        }

        auto sBShowHud = std::search(data.begin(), data.end(), pattern_searcher(xorstr_("45 32 D2 32 DB 48 89 6C 24 38 44 8B CE 85")));
        if (sBShowHud != data.end()) {
            BNSClientInstance = (uintptr_t*)GetAddress((uintptr_t)&sBShowHud[0] + 0x5A, 3, 7);
        }

        DetourTransactionCommit();
    }
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) PluginInfo GPluginInfo = {
  .hide_from_peb = true,
  .erase_pe_header = true,
  .init = init,
  .priority = 1,
  .target_apps = L"BNSR.exe"
};
