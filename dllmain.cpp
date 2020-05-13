#include "pch.h"
#include <iostream>
#include "Tlhelp32.h"
#include "Psapi.h"
//#include "Winternl.h"


#define NOP 0x90
#define PAGE 0x1000
#define TWO_GB 0x80000000
// "hook.h"

//------------------------------------------------------------------------------------
// Create hook function x64
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

//------------------------------------------------------------------------------------
//define Thread Info Class
typedef LONG NTSTATUS;
typedef DWORD KPRIORITY;
typedef WORD UWORD;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS    ExitStatus;
	PVOID       TebBaseAddress;
	CLIENT_ID   ClientId;
	KAFFINITY   AffinityMask;
	KPRIORITY   Priority;
	KPRIORITY   BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

enum THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadQuerySetWin32StartAddress = 9, //not really sure why?
};

//typedef struct _PEB {
//    BYTE                          Reserved1[2];
//    BYTE                          BeingDebugged;
//    BYTE                          Reserved2[1];
//    PVOID                         Reserved3[2];
//    PPEB_LDR_DATA                 Ldr;
//    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
//    PVOID                         Reserved4[3];
//    PVOID                         AtlThunkSListPtr;
//    PVOID                         Reserved5;
//    ULONG                         Reserved6;
//    PVOID                         Reserved7;
//    ULONG                         Reserved8;
//    ULONG                         AtlThunkSListPtr32;
//    PVOID                         Reserved9[45];
//    BYTE                          Reserved10[96];
//    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
//    BYTE                          Reserved11[128];
//    PVOID                         Reserved12[1];
//    ULONG                         SessionId;
//} PEB, * PPEB;
//define TEB struct
typedef struct _TEB {
	PVOID Reserved1[12];
	//PPEB  ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

//find Thread Base Address x64
void* GetThreadBaseAddress(HANDLE hThread)
{
	bool loadedManually = false;
	HMODULE module = GetModuleHandle(L"ntdll.dll");
	if (!module)
	{
		module = LoadLibrary(L"ntdll.dll");
		loadedManually = true;
	}

	NTSTATUS(_stdcall * NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	NtQueryInformationThread = reinterpret_cast<decltype(NtQueryInformationThread)>(GetProcAddress(module, "NtQueryInformationThread"));

	if (NtQueryInformationThread)
	{
		NT_TIB tib = { 0 };
		THREAD_BASIC_INFORMATION tbi = { 0 };
		uintptr_t threadEntry = 0;
		//NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		NTSTATUS status = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &threadEntry, sizeof(threadEntry), nullptr);
		if (status >= 0)
		{
			if (loadedManually) { FreeLibrary(module); }
			return (void*)threadEntry;
		}
	}

	if (loadedManually) { FreeLibrary(module); }
	return nullptr;

}
//get thread information x64
THREAD_BASIC_INFORMATION GetThreadInfo(HANDLE hThread)
{
	bool loadedManually = false;
	HMODULE module = GetModuleHandle(L"ntdll.dll");
	if (!module)
	{
		module = LoadLibrary(L"ntdll.dll");
		loadedManually = true;
	}

	NTSTATUS(_stdcall * NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	NtQueryInformationThread = reinterpret_cast<decltype(NtQueryInformationThread)>(GetProcAddress(module, "NtQueryInformationThread"));

	THREAD_BASIC_INFORMATION tbi = { 0 };
	if (NtQueryInformationThread)
	{
		NT_TIB tib = { 0 };
		NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		if (status >= 0)
		{
			if (loadedManually) { FreeLibrary(module); }
			return tbi;
		}
	}

	if (loadedManually) { FreeLibrary(module); }
	return tbi;

}
//copy teb of target thread to hack thread, make to copy certain tls, or copy all
void copyTebToCurrentDLL(void* TebBaseAddress, int index)
{
	TEB* targetTeb = (TEB*)TebBaseAddress;
	TEB* currentTeb = NtCurrentTeb();
	if (index > 0)
	{
		currentTeb->TlsSlots[index] = targetTeb->TlsSlots[index];
		return;
	}
	for (int index = 0; index < 64; index++)
	{
		currentTeb->TlsSlots[index] = targetTeb->TlsSlots[index];
	}

}

//------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------
// Thread Walking function x64
void* findTeb() //findTeb(moduelBase)
{
	//get handle to snapshot of threads from injected process
	HANDLE snapshotHandle;
	snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshotHandle == INVALID_HANDLE_VALUE) { std::cout << "error getting handle: " << GetLastError(); }

	//find first thread in process
	THREADENTRY32 te;
	//MODULEENTRY32 me;
	te.dwSize = sizeof(te);
	//me.dwSize = sizeof(me);
	if (!Thread32First(snapshotHandle, &te)) { std::cout << "could not get thread" << GetLastError(); }
	//if (!Module32First(snapshotHandle, &me)) { std::cout << "could not get module" << GetLastError(); }

	MODULEINFO moduleInfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(L"GameAssembly.dll"), &moduleInfo, sizeof(moduleInfo));

	//walk through all threads found in snapshot
	while (Thread32Next(snapshotHandle, &te))
	{
		//find threads created by injected process
		if (GetCurrentProcessId() == te.th32OwnerProcessID)
		{
			uintptr_t threadEntry = (uintptr_t)GetThreadBaseAddress(OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID));
			if ((threadEntry > (uintptr_t)moduleInfo.lpBaseOfDll) && (threadEntry < ((uintptr_t)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage)))
			{
				THREAD_BASIC_INFORMATION tbi = GetThreadInfo(OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID));
				if (tbi.BasePriority >= 2) { CloseHandle(snapshotHandle);  return tbi.TebBaseAddress; }
			}
		}
	}

	return nullptr;
	CloseHandle(snapshotHandle);
}
//------------------------------------------------------------------------------------
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

typedef void* (_fastcall* _getCurDomain)(void);
_getCurDomain getCurDomain;

typedef void* (_fastcall* _loadAsm)(void* appDomain, const char* assembly);
_loadAsm loadAsm;

typedef void* (_fastcall* _unknownFunction)(uintptr_t staticObject, int id);
_unknownFunction unknownFunction;

struct serverManager {
	typedef void(_fastcall* _showAnimation)(void* pObject);
	_showAnimation showAnimation;

	typedef void(_fastcall* _delayedStart)(void* pObject);
	_delayedStart delayedStart;

	typedef void(_fastcall* _onDestroy)(void* pObject);
	_delayedStart onDestroy;

	typedef void(_fastcall* _teleportForward)(void* pObject);
	_teleportForward teleportForward;

	typedef void(_fastcall* _toggleAIHuman)(void* pObject);
	_toggleAIHuman toggleAIHuman;

	typedef void(_fastcall* _login)(void* pObject);
	_login login;

	typedef void(_fastcall* _loginLoop)(void* pObject);
	_loginLoop loginLoop;

	typedef char* (_fastcall* _getSecret)(void* pObject);
	_getSecret getSecret;

	typedef void(_fastcall* _showText)(void* pObject, std::string msg);
	_showText showText;

	typedef void(_fastcall* _updateServerPosition)(void* pObject, bool force);
	_updateServerPosition updateServerPosition;

	typedef void(_fastcall* _sendEmoji)(void* pObject, short _emoji);
	_sendEmoji sendEmoji;

	typedef void(_fastcall* _sendInfoRequest)(void* pObject, unsigned int uid);
	_sendInfoRequest sendInfoRequest;

	typedef void(_fastcall* _sendHeartbeat)(void* pObject);
	_sendHeartbeat sendHeartbeat;

	typedef void(_fastcall* _setGroundedBlend)(void* pObject, float blend);
	_setGroundedBlend setGroundedBlend;

	typedef void(_fastcall* _setNotGroundedBlend)(void* pObject, float blend);
	_setNotGroundedBlend setNotGroundedBlend;

	typedef void(_fastcall* _setAnimationBlend)(void* pObject, float grounded, float notGrounded);
	_setAnimationBlend setAnimationBlend;

	typedef void(_fastcall* _recieveDataThread)(void* pObject);
	_recieveDataThread recieveDataThread;

	typedef void(_fastcall* _setTriggerGrounded)(void* pObject);
	_setTriggerGrounded setTriggerGrounded;

	typedef void(_fastcall* _setTriggerNotGrounded)(void* pObject);
	_setTriggerNotGrounded setTriggerNotGrounded;

	typedef void(_fastcall* _setTriggerAttack1)(void* pObject);
	_setTriggerAttack1 setTriggerAttack1;

	typedef void(_fastcall* _setTriggerAttack2)(void* pObject);
	_setTriggerAttack2 setTriggerAttack2;

	typedef void(_fastcall* _setTriggerGroundWall)(void* pObject);
	_setTriggerGroundWall setTriggerGroundWall;

	typedef void(_fastcall* _setTriggerDeath)(void* pObject);
	_setTriggerDeath setTriggerDeath;

	typedef int(_fastcall* _showFlag)(void* pObject);
	_showFlag showFlag;

	typedef int(_fastcall* _showDiscover)(void* pObject);
	_showDiscover showDiscover;

	typedef int(_fastcall* _deathAnimation)(void* pObject);
	_deathAnimation deathAnimation;

	typedef int(_fastcall* _showEmoji)(void* pObject, unsigned short uid);
	_showEmoji showEmoji;

	typedef void(_fastcall* _update)(void* pObject);
	_update update;
};

struct transform {
	typedef void* (_fastcall* _GetParent)(void* transformObject);
	_GetParent GetParent;

	typedef void* (_fastcall* _GetRoot)(void* transformObject);
	_GetRoot GetRoot;
	
	typedef void (_fastcall* _Translate)(void* transformObject, float vector[3]);
	_Translate Translate;
	
	typedef void (_fastcall* _set_position_injected)(void* transformObject,float vector[3]);
	_set_position_injected set_position_injected;
};

//-------------------------------------------------------------------------------------

//init injection point
//uintptr_t getCollision_detour = 0x00;
uintptr_t getRaceManager_detour = 0x00;

//init this pointer
//void* pObject = nullptr;



DWORD WINAPI HackThread(HMODULE hModule)
{
	//create console
	AllocConsole();
	FILE* f;
	freopen_s(&f, "CONOUT$", "w", stdout);
	freopen_s(&f, "CONIN$", "r", stdin);

	std::cout << "Hello there, we are injected!\n";

	uintptr_t moduleBase = (uintptr_t)GetModuleHandle(L"GameAssembly.dll");

	//turn of collision for walls touching
	//ColliderSetEnabled = (_ColliderSetEnabled)(moduleBase + 0x660F00);
	//getCollision_detour = (uintptr_t)(moduleBase + 0x6C5F15);
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
	memcpy((void*)((uintptr_t)codeCave.caveAddress + 3), movRaxToContainer, 10);
	memcpy((void*)((uintptr_t)codeCave.caveAddress + 13), codeCave.originalInstruction, codeCave.lengthOfOverwrite);
	uintptr_t jmpOffset = (uintptr_t)codeCave.returnAddress - ((uintptr_t)codeCave.caveAddress + 18) - 5; //location of where i want to jump to - location of where i am - instruction size(jmp = 1, offset = 4)
	memcpy((codeCave.returnJMP + 1), &jmpOffset, 4);
	memcpy((void*)((uintptr_t)codeCave.caveAddress + 18), codeCave.returnJMP, 5);
	delete codeCave.originalInstruction;
	//std::cout << &colliderObject << std::endl << colliderObject << std::endl;
	//std::cout << (void*)((uintptr_t)codeCave.caveAddress + 16) << std::endl << codeCave.returnAddress << std::endl << (void*)jmpOffset << std::endl;


	//serverManager functions
	serverManager serverManager;
	//serverManager.showAnimation = (serverManager::_showAnimation)(moduleBase + 0x6D4420);
	//serverManager.delayedStart  = (serverManager::_delayedStart)(moduleBase + 0x6D44B0);
	//serverManager.onDestroy = (serverManager::_onDestroy)(moduleBase + 0x6D4540);
	//serverManager.teleportForward = (serverManager::_teleportForward)(moduleBase + 0x6D4590);
	//serverManager.toggleAIHuman = (serverManager::_toggleAIHuman)(moduleBase + 0x6D4810);
	//serverManager.login = (serverManager::_login)(moduleBase + 0x6D48B0);
	//serverManager.loginLoop = (serverManager::_loginLoop)(moduleBase + 0x6D4F90);
	//serverManager.getSecret = (serverManager::_getSecret)(moduleBase + 0x6D50E0); 
	//serverManager.showText = (serverManager::_showText)(moduleBase + 0x6D7440);
	//serverManager.updateServerPosition = (serverManager::_updateServerPosition)(moduleBase + 0x6D50F0);
	serverManager.sendEmoji = (serverManager::_sendEmoji)(moduleBase + 0x6D5720);
	//serverManager.sendData = (serverManager::_sendData)(moduleBase + 0x6D5880);
	//serverManager.sendInfoRequest = (serverManager::_sendInfoRequest)(moduleBase + 0x6D5B00);
	//serverManager.sendHeartbeat = (serverManager::_sendHeartbeat)(moduleBase + 0x6D5CD0);
	//serverManager.setGroundedBlend = (serverManager::_setGroundedBlend)(moduleBase + 0x6D5E80);
	//serverManager.setNotGroundedBlend = (serverManager::_setNotGroundedBlend)(moduleBase + 0x6D5EA0);
	//serverManager.setAnimationBlend = (serverManager::_setAnimationBlend)(moduleBase + 0x6D5EC0);
	//serverManager.recieveDataThread = (serverManager::_recieveDataThread)(moduleBase + 0x6D5F70);
	//serverManager.setTriggerGrounded = (serverManager::_setTriggerGrounded)(moduleBase + 0x6D7520);
	//serverManager.setTriggerNotGrounded = (serverManager::_setTriggerNotGrounded)(moduleBase + 0x6D7540);
	//serverManager.setTriggerAttack1 = (serverManager::_setTriggerAttack1)(moduleBase + 0x6D7560);
	//serverManager.setTriggerAttack2 = (serverManager::_setTriggerAttack2)(moduleBase + 0x6D7580);
	//serverManager.setTriggerGroundWall = (serverManager::_setTriggerGroundWall)(moduleBase + 0x6D75A0);
	//serverManager.setTriggerDeath = (serverManager::_setTriggerDeath)(moduleBase + 0x6D75C0);
	//serverManager.showFlag = (serverManager::_showFlag)(moduleBase + 0x6D75E0);
	//serverManager.showDiscover = (serverManager::_showDiscover)(moduleBase + 0x6D7670);
	//serverManager.deathAnimation = (serverManager::_deathAnimation)(moduleBase + 0x6D7700);
	//serverManager.showEmoji = (serverManager::_showEmoji)(moduleBase + 0x6D5F90);
	//serverManager.update = (serverManager::_update)(moduleBase + 0x6D7A20);

	//unityEngine.Transform
	transform transform;
	transform.GetParent = (transform::_GetParent)(moduleBase + 0x441A70);
	transform.GetRoot = (transform::_GetRoot)(moduleBase + 0x442EB0);
	transform.Translate = (transform::_Translate)(moduleBase + 0x442080);
	transform.set_position_injected = (transform::_set_position_injected)(moduleBase + 0x4433D0);


	//checkpoint
	gotCheckpoint = (_gotCheckpoint)(moduleBase + 0x6C7F80);

	//AppDomian
	getCurDomain = (_getCurDomain)(moduleBase + 0x2CD110);
	loadAsm = (_loadAsm)(moduleBase + 0x2CD590);

	//unknown function
	unknownFunction = (_unknownFunction)(moduleBase + 0x56b60);

	//assign Object
	//pObject = (void*)0x000002838A3D26E0;
	void* transformObject = (void*)0x1E51C0C54E0;
	uintptr_t* pUnknownObject = (uintptr_t*)(moduleBase + 0xAE78C8);


	//debug

	//hack loop
	int checkpoint_id = 0;
	while (true)
	{
		uintptr_t* pServerManager = (uintptr_t*)(raceManagerObject + 0x20);
		//uintptr_t* pcolliderObject = (uintptr_t*)(collisionObject + 0x30);
		if (GetAsyncKeyState(VK_DELETE) & 1) { break; }
		if (GetAsyncKeyState(VK_NUMPAD1) & 1) { copyTebToCurrentDLL(findTeb(), 0); std::cout << "TEB Copied\n"; }
		if (GetAsyncKeyState(VK_NUMPAD2) & 1)
		{
			unsigned short emoji = 0;
			std::cout << "Input Emoji: ";
			std::cin >> std::hex >> emoji;
			if (!(*pServerManager == 0))
			{
				serverManager.sendEmoji((void*)*pServerManager, emoji);
			}
		}
		if (GetAsyncKeyState(VK_NUMPAD3) & 1)
		{
			if (!(raceManagerObject == 0))
			{

				float* pTime = (float*)((uintptr_t)*pServerManager + 0x180);
				gotCheckpoint((void*)raceManagerObject, checkpoint_id, *pTime);
				std::cout << "Checkpoint: " << checkpoint_id << " Time: " << *pTime << std::endl;
				if (checkpoint_id++ > 11) { checkpoint_id = 0; }
				
				
			}

		}
		if (GetAsyncKeyState(VK_NUMPAD4) & 1)
		{
			const char* path = "mscorlib";
			void* curAppDomain = getCurDomain();
			void* mainTEB = (void*)0x0000001DD76D1000;
			std::cout << curAppDomain << std::endl;
			copyTebToCurrentDLL(mainTEB,0);
			void* instance = loadAsm(curAppDomain, path);
			std::cout << instance;
		}
		if (GetAsyncKeyState(VK_NUMPAD9) & 1)
		{
			float vector[] = { 204,1,194 };
			std::cout << transform.GetRoot(transformObject) << std::endl;
			transform.set_position_injected(transform.GetRoot(transformObject),vector);
		}
		if (GetAsyncKeyState(VK_NUMPAD7) & 1)
		{
			std::cout << unknownFunction(*pUnknownObject, 0x12) << std::endl;
			std::cout << unknownFunction(*pUnknownObject, 0x2a) << std::endl;

		}
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
		//repair hook
		break;
	}
	return TRUE;
}

