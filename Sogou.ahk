#NoEnv
#SingleInstance
#Persistent

Running = 1
Shown = 0

SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.
DetectHiddenWindows, On

Menu, Tray, Icon, Sogou.ico
Menu, Tray, Tip, Sogou Proxy
Menu, Tray, NoStandard
Menu, Tray, Add, &Show, ShowWindow
Menu, Tray, Add, &Hide, HideWindow
Menu, Tray, Add
Menu, Tray, Add, E&xit, CloseWindow

OnExit, CloseWindow

while (Running > 0)
{
    if (Shown > 0)
    {
        Run, proxy.exe,,UseErrorLevel, procPid
        Gosub MenusShow
    }
    else
    {
        Run, proxy.exe,,Hide UseErrorLevel, procPid
        Gosub MenusHide
    }
    WinWait, ahk_pid %procPid% ahk_class ConsoleWindowClass
    WinGet activeWindow, ID, ahk_pid %procPid% ahk_class ConsoleWindowClass
    Process, WaitClose, %procPid%
}
return

ShowWindow:
    WinShow, ahk_id %activeWindow%
    WinActivate, ahk_id %activeWindow%
    Shown = 1
    Gosub MenusShow
return

MenusShow:
    Menu, Tray, Disable, &Show
    Menu, Tray, Enable, &Hide
    Menu, Tray, Default, &Hide
return

HideWindow:
    Shown = 0
    WinHide, ahk_id %activeWindow%
    Gosub MenusHide
return

MenusHide:
    Menu, Tray, Disable, &Hide
    Menu, Tray, Enable, &Show
    Menu, Tray, Default, &Show
return

CloseWindow:
    Running = 0
    Process, Close, %procPid%
    ExitApp, 0
return