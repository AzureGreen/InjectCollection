# InjectCollection
A collection of injection via vc++ in ring3.

1.By the way of creating new thread in the target process to execute the kernel32 export function -- "LoadLibrary" to realize our aim of injection!
   
        Three functions I find can be used ：CreateRemoteThread、NtCreateThreadEx、RtlCreateUserThread

2.By the way of suspending one thread of our target process, and then change thread context of eip or rip to our shellcode, last resume thread. so target process will stop to execute our shellcode, our aim will also be achieved!
        
        some functions are needed, such as SuspendThread, GetThreadContext, SetThreadContext, ResumeThread

3.By the way of queueing apc in the thread apc queue, for this method request the thread should be alertable, so I queue this apc in all thread of our target process by force, but it seems to be not steady.

        main function been used is QueueUserApc
        
4.By the way of setting registry value to set global hook, almost all process being created will load our dll!

        in the HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows directory,
        set the value AppInit_DLLs to be our dll full path, 
        and set the value LoadAppInit_DLLs to be 0x1
        
These 4 methods above could use the dll named "NormalDll" I write for test.

5.By the way of Hooking the window message, once our target process triggered the hooked message, then it will execute export function in our dll!

        mainly used the SetWindowHookEx which is MS's API

This method should use the dll named "WindowHookDll" I write for test.

6.By the way of writing dll in the memory space of target process, and then create a thread in target thread to execute an export function in the dll we just wrote in target process. This export funcion mainly realize "LoadLibrary" by itself, so it requset the knowledge of PE structure!
