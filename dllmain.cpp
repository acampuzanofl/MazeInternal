#include "pch.h"
#include <iostream>
#define NOP 0x90
#define PAGE 0x1000
#define TWO_GB 0x80000000
// "hook.h"

//------------------------------------------------------------------------------------
// Create hook function

struct _codeCave
{
    void* returnAddress = 0;
    void* caveAddress = 0;
    BYTE* originalInstruction = 0;
    BYTE returnJMP[5] = { 0xE9, 0x00, 0x00 , 0x00 , 0x00 };
    int lengthOfOverwrite = 0;
};

_codeCave x64hookAndAlloc(void* hookToAddress, int lengthOfOverwrite)
{
    //check that length is large enough to insert a jump
    _codeCave codeCave;
    if (lengthOfOverwrite < 5) { std::cout << "length of overwrite too small\n";  return codeCave; }
    //BYTE* originalInstruction = new BYTE[lengthOfOverwrite];
    codeCave.originalInstruction = new BYTE[lengthOfOverwrite];

    //find free memory -2gb to +2gb of hook address
    const uintptr_t lowerRegion = (uintptr_t)hookToAddress - TWO_GB;
    const uintptr_t upperRegion = (uintptr_t)hookToAddress + TWO_GB;

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    uintptr_t addressToQuery = 0x00;
    addressToQuery = lowerRegion;
    while (addressToQuery < upperRegion)
    {
        VirtualQuery((LPCVOID)addressToQuery, &mbi, sizeof(mbi));
        if (mbi.State == MEM_FREE && mbi.RegionSize >= PAGE) 
        {
            //std::cout << mbi.RegionSize << std::endl;
            //std::cout << mbi.BaseAddress << std::endl;
            if ((uintptr_t)mbi.BaseAddress > lowerRegion && (uintptr_t)mbi.BaseAddress < upperRegion) //check if BaseAddress is within bounds
            {
                if (((uintptr_t)mbi.BaseAddress & 0xFFFF) == 0) { break; } //check if 64k alligned
            }
        }
        addressToQuery += mbi.RegionSize;
    }
    if (addressToQuery > upperRegion) { std::cout << "No free memory in range"; return codeCave; }
    //std::cout << (void*)addressToQuery << std::endl;
    //initialize cave in free memory found
    void* allocAddress = VirtualAlloc((LPVOID)addressToQuery, PAGE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocAddress)
    {
        std::cout << "could not alloc memory: " << GetLastError(); return codeCave;
    }

    //prepare hook region to be writable
    DWORD oldProtection = 0;
    if (!VirtualProtect(hookToAddress, lengthOfOverwrite, PAGE_EXECUTE_READWRITE, &oldProtection))
    {
        std::cout << "could not change permissions: " << GetLastError();
    }
    memcpy(codeCave.originalInstruction, hookToAddress, lengthOfOverwrite);
    memset(hookToAddress, NOP, lengthOfOverwrite);

    //write jmp to cave
    BYTE JMP[] = { 0xE9, 0x00, 0x00 , 0x00 , 0x00 };
    uintptr_t jmpOffset = (uintptr_t)allocAddress - (uintptr_t)hookToAddress - 5; //location of where i want to jump to - location of where i am - instruction size(jmp = 1, offset = 4)
    //std::cout << hookToAddress << std::endl << allocAddress << std::endl << (void*)jmpOffset;
    
    memcpy((JMP + 1), &jmpOffset, 4);
    memcpy(hookToAddress, JMP, 5);

    codeCave.caveAddress = allocAddress;
    codeCave.returnAddress = (void*)((uintptr_t)hookToAddress + lengthOfOverwrite);
    codeCave.lengthOfOverwrite = lengthOfOverwrite;
    //jmpOffset = (uintptr_t)hookToAddress - (uintptr_t)allocAddress;
    //memcpy((codeCave.returnJMP + 1), &jmpOffset, 4);
    return codeCave;
}
//------------------------------------------------------------------------------------

//Declare function pointer------------------------------------------------------------
typedef void(_fastcall* _showEmoji)(void* pObject, unsigned short emoji);
_showEmoji showEmoji;

typedef void(_fastcall* _someFunc)(void* pObject);
_someFunc someFunc;

typedef void(_fastcall* _ColliderSetEnabled)(void* pObject, bool flag);
_ColliderSetEnabled ColliderSetEnabled;

typedef void(_fastcall* _gotCheckpoint)(void* pObject, int checkpoint_id, float time);
_gotCheckpoint gotCheckpoint;

struct serverManager {
    typedef void(_fastcall* _showAnimation)(void* pObject);
    _showAnimation showAnimation;
};

//-------------------------------------------------------------------------------------

//init injection point
uintptr_t getCollision_detour = 0x00;
uintptr_t getRaceManager_detour = 0x00;

//init this pointer
void* pObject = nullptr;



DWORD WINAPI HackThread(HMODULE hModule)
{
    //create console
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    std::cout << "Hello there, we are injected!\n";

    uintptr_t moduleBase = (uintptr_t)GetModuleHandle(L"gameassembly.dll");

    //moduleBase = gameassembly.dll
    //send emoji packet
    //someFunc = (_someFunc)(moduleBase + 0x4E8E00);
    showEmoji = (_showEmoji)(moduleBase + 0x6D5720);
    
    //turn of collision for walls touching
    ColliderSetEnabled = (_ColliderSetEnabled)(moduleBase + 0x660F00);
    getCollision_detour = (uintptr_t)(moduleBase + 0x6C5F15);
    //uintptr_t collisionObject = NULL;
    //void* pcollisionObject = &collisionObject;
    //_codeCave codeCave = x64hookAndAlloc((void*)getCollision_detour, 6);
    

    //get Race Manager
    getRaceManager_detour = (uintptr_t)(moduleBase + 0x6C810B);
    uintptr_t raceManagerObject = NULL;
    void* praceManagerObject = &raceManagerObject;
    _codeCave codeCave = x64hookAndAlloc((void*)getRaceManager_detour, 5);

    //write into cave
    BYTE shell[] = { 0x48, 0x8B, 0xC7 };
    BYTE movRaxToContainer[] = { 0x48, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy((movRaxToContainer + 2), &praceManagerObject, 8);
    memcpy(codeCave.caveAddress, shell, 3);
    memcpy((void*)((uintptr_t)codeCave.caveAddress+3), movRaxToContainer, 10);
    memcpy((void*)((uintptr_t)codeCave.caveAddress + 13), codeCave.originalInstruction, codeCave.lengthOfOverwrite);
    uintptr_t jmpOffset = (uintptr_t)codeCave.returnAddress - ((uintptr_t)codeCave.caveAddress + 18) - 5; //location of where i want to jump to - location of where i am - instruction size(jmp = 1, offset = 4)
    memcpy((codeCave.returnJMP + 1), &jmpOffset, 4);
    memcpy((void*)((uintptr_t)codeCave.caveAddress + 18), codeCave.returnJMP, 5);
    //std::cout << &colliderObject << std::endl << colliderObject << std::endl;
    //std::cout << (void*)((uintptr_t)codeCave.caveAddress + 16) << std::endl << codeCave.returnAddress << std::endl << (void*)jmpOffset << std::endl;
    

    //serverManager functions
    serverManager serverManager;
    serverManager.showAnimation = (serverManager::_showAnimation)(moduleBase + 0x6D4420);

    //checkpoint
    gotCheckpoint = (_gotCheckpoint)(moduleBase + 0x6C7F80);
    
    
    //assign pObject
    pObject = (void*)0x000002838A3D26E0;

    //debug
    //std::cout << gotCheckpoint;
    std::cout << (void*)raceManagerObject << std::endl;

    //hack loop
    while (true)
    {
        uintptr_t* pServerManager = (uintptr_t*)(raceManagerObject + 0x20);
        //uintptr_t* pcolliderObject = (uintptr_t*)(collisionObject + 0x30);
        if (GetAsyncKeyState(VK_DELETE) & 1) { break; }
        if (GetAsyncKeyState(VK_NUMPAD1) & 1) { if (!(*pServerManager == 0)) { std::cout << (void*)*pServerManager << std::endl; serverManager.showAnimation((void*)*pServerManager); } }
        //if (GetAsyncKeyState(VK_NUMPAD8) & 1) { gotCheckpoint(pObject,0,1350); }
        //if (GetAsyncKeyState(VK_NUMPAD3) & 1) { someFunc(pObject); showEmoji(pObject, 0xD); }
        //if (GetAsyncKeyState(VK_NUMPAD4) & 1) { if (!(collisionObject==0)) { ColliderSetEnabled((void*)*pcolliderObject, 0); }}
        Sleep(10);
    }
    fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)HackThread, hModule, 0, nullptr));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

