# Fox-Hunter
A knowledge base for Silver Fox countermeasures.

Given the rapidly evolving and highly sophisticated countermeasures employed by the Silver Fox malware, I have established a knowledge base for Silver Fox countermeasures to facilitate understanding, searching, and learning (please do not use for illegal purposes). This knowledge base will be continuously updated as it evolves. It is intended for advanced red teams, malware analysts, and incident responders. I believe those who need this knowledge base understand its purpose, so I will not provide detailed annotations for the techniques included. Instead, I will only provide links for reference.

【Countermeasures】

--> Lazy Importer 
是一种延迟加载技术，主要用于优化程序的启动速度和内存使用效率。它通过在需要使用模块或函数时才真正加载它们，而不是在程序启动时一次性加载所有模块，从而减少不必要的资源消耗
用于以隐藏的、不利于逆向工程的方式从dll导入函数的库
通过哈希函数名和模块名，在编译时生成动态导入代码，避免在可执行文件中保留导入表

获取内存加载 PE 文件过程需要的系统函数，其部分 HASH 映射如下：

0xC9F93D32 ---> RtlCopyMemory
0x9E5A8833 ---> VirtualAlloc
0xF8B7108D ---> LoadLibraryA
0x88F6B891 ---> GetProcAddress
0x4FAEF192 ---> VirtualFree
0xF477A895 ---> GetProcessHeap
0x57C818E1 ---> lstrcmpi
0xC9A1412D ---> RtlGetFileMUIPath
0x862F81FA ---> VirtualProtect
0x7BAC0721 ---> IsBadReadPtr
内存加载 PE 文件后，查找并调用具名导出函数run

https://github.com/JustasMasiulis/lazy_importer



--> PoolParty
一组利用 Windows 线程池的完全不可检测的进程注入技术
https://github.com/SafeBreach-Labs/PoolParty
https://www.blackhat.com/eu-23/briefings/schedule/#the-pool-party-you-will-never-forget-new-process-injection-techniques-using-windows-thread-pools-35446



--> Donut
生成x86、x64或AMD64+x86位置无关的shellcode
https://github.com/TheWover/donut



--> BootExecute EDR Bypass
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecute" /t REG_MULTI_SZ /d "autocheck autochk *\0BEB" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecuteNoPnpSync" /t REG_MULTI_SZ /d "BEB" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "SetupExecute" /t REG_MULTI_SZ /d "BEB" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "PlatformExecute" /t REG_MULTI_SZ /d "BEB" /f
https://github.com/rad9800/BootExecuteEDR/tree/main



--> PAGE_GUARD
创建PAGE_GUARD属性的内存页，用于反逆向和反调试
监控和保护特定的内存页面，防止未经授权的访问或修改，它通常用于调试、内存管理或防止程序错误导致的数据损坏
PAGE_GUARD主要通过操作系统的内存管理功能实现，操作系统会为特定的内存页面设置保护标志（如PAGE_GUARD），当程序访问这些页面时，操作系统会触发异常或中断
在某些情况下，PAGE_GUARD可以通过软件机制实现，例如通过监控内存访问指令或使用特殊的内存管理单元（MMU）配置



NtQuerySystemInformation - CreateToolHelp32Snapshot、Process32First、Process32Next的内核函数



CoCreateInstance - 创建COM对象实例，可以根据提供的CLSID或接口标识符来创建COM对象的实例，用于COM枚举进程配合DLL注入



GetDiskFreeSpaceExW - 查询硬盘大小来判定是否运行在虚拟机中，检索有关磁盘卷上可用空间量的信息，即总空间量、可用空间总量以及与调用线程关联的用户可用的可用空间总量，函数原型参考：
https://learn.microsoft.com/zh-cn/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw



GetTickCount64 - 检索自系统启动以来经过的毫秒数，函数原型参考：
https://learn.microsoft.com/zh-cn/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64



LookupPrivilegeValue - 检索指定系统上用于本地表示指定特权名称 (LUID) 本地唯一标识符，函数原型参考：
https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew



GetTimeZoneInformation - 检索当前时区设置，这些设置控制协调世界时 (UTC) 和本地时间之间的转换，函数原型参考：
https://learn.microsoft.com/zh-cn/windows/win32/api/timezoneapi/nf-timezoneapi-gettimezoneinformation



SetWindowsHookExA - 将应用程序定义的挂钩过程安装到挂钩链中，将安装挂钩过程来监视系统的某些类型的事件，这些事件与特定线程相关联，或者与调用线程位于同一桌面中的所有线程相关联，函数原型参考：
https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-setwindowshookexa



ShellExecuteExW - 对指定文件执行操作，函数原型参考：
https://learn.microsoft.com/zh-cn/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw
指向一个SHELLEXECUTEINFO结构：
https://learn.microsoft.com/zh-cn/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow



SetFileAttributesW - 设置文件或目录的属性，用于将文件属性设置为隐藏，函数原型参考：
https://learn.microsoft.com/zh-cn/windows/win32/api/fileapi/nf-fileapi-setfileattributesw



NtCreateUserProcess - 不做解释，懂得都懂，参考：
https://bbs.kanxue.com/thread-272798.htm



--> AppDomainManager Injection 
https://www.cnblogs.com/suv789/p/18657782
