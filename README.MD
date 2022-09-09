# RUST_SYSCALLS
Single stub direct and indirect syscalling with runtime SSN resolving for windows.

---

## Features:
* One single line for all your syscalls
* Function name hashing at compilation time
* Direct or indirect sycalls
* x86_64, WOW64 and x86 native support
* Designed to allow the implementation of custom SSN fetching methods (check the end of this readme for more info)
  
---

## How to use:
1. Add the git repository / local path to the library to your dependencies:
   
   > `rust_syscalls = {git = "https://github.com/janoglezcampos/rust_syscalls"}`

   or

   > `rust_syscalls = {path = <path to library folder>}`

2. Choose direct or indirect method by setting `_DIRECT_` or `_INDIRECT_` as a feature:

    > `rust_syscalls = {path = <path to library folder>}, features = ["_INDIRECT_"]}`

3. Import
   
   > `use rust_syscalls::syscall;`

4.  Syscall:
   
    > `NTSTATUS status = syscall!("NtClose", handle);`

---
## Example:

    #![allow(non_snake_case)]
    use ntapi::ntapi_base::CLIENT_ID;
    use rust_syscalls::syscall;

    use winapi::shared::ntdef::{OBJECT_ATTRIBUTES, HANDLE, NULL, NTSTATUS, PVOID};
    use winapi::um::winnt::{PROCESS_VM_WRITE, PROCESS_VM_READ, MEMORY_BASIC_INFORMATION};
    use std::mem::size_of;
    
    fn main(){
        let pid             : u64      = 3268; //Process PID
        let currentProcess  : HANDLE = -1isize as _;
        let mem_info_len    : usize = size_of::<MEMORY_BASIC_INFORMATION>() as _;

        let mut handle      : HANDLE   = NULL;
        let mut status      : NTSTATUS;
    
        let mem_info: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION {
            BaseAddress: NULL,
            AllocationBase: NULL,
            AllocationProtect: 0,
            RegionSize: 0,
            State: 0,
            Protect: 0,
            Type: 0,
        };

        let oa : OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as _,
            RootDirectory: NULL,
            ObjectName: NULL as _,
            Attributes: 0,
            SecurityDescriptor: NULL,
            SecurityQualityOfService: NULL
        };

        let cid : CLIENT_ID = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: 0 as _
        };

        unsafe {
            status = syscall!("NtOpenProcess", &mut handle, PROCESS_VM_WRITE | PROCESS_VM_READ, &oa, &cid);
        }
        
        println!("\n\t[-] NtOpenProcess status: {:#02X}", status);

        if status != 0 {
            return;
        }

        unsafe {
            status = syscall!("NtQueryVirtualMemory", currentProcess, &pid, 0, &mem_info, mem_info_len, NULL as PVOID);
        }
        
        println!("\n\t[-] NtQueryVirtualMemory status: {:#02X}", status);
        
        if status != 0 {
            return;
        }

        println!("\n\t[-] Protect value: {:#02X}\n\t", mem_info.Protect);

        unsafe {
            status = syscall!("NtClose", handle);
        }
        
        println!("\t[-] NtClose       status: {:#02X}", status);
    }


## Implementing new SSN and syscall addresses runtime resolving methods:

All the code required to do the SSN and address fetching is included in the file `src\syscall_resolve.rs`.

There one core function used to retrieve the values called get_ssn, with 4 implementations, where the receive argument is the result of calling `crate::obf!(\<your function name\>)`, and the return values are the ssn (u16), and, in case of indirect syscalling, the address of the syscall/sysenter instruction that you want to use.

* x86_64 direct:
  
    > fn get_ssn(hash: u32) -> (u16);

* x86_64 indirect:

    > fn get_ssn(hash: u32) -> (u16, u64);

* x86 direct:

    > fn get_ssn(hash: u32) -> (u16);

* x86 indirect:

    > fn get_ssn(hash: u32) -> (u16, u32);

Just reimplement this functions with your desired fetching method.

---

**Thanks to [SysWhispers3](https://github.com/klezVirus/SysWhispers3) for being a strong pilar on the development of this library**
