# InjectCollection
A collection of injection via vc++.

1.By the way of creating thread in target process to execute the kernel32 export function -- "LoadLibrary" to realize our aim of injection
   
    Three functions I find can be used ：CreateRemoteThread、NtCreateThreadEx、RtlCreateUserThread
