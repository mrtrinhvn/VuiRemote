//go:build windows

package main

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procSetProcessDPIAware       = user32.NewProc("SetProcessDPIAware")
	procGetSystemMetrics         = user32.NewProc("GetSystemMetrics")
	procGetDC                    = user32.NewProc("GetDC")
	procReleaseDC                = user32.NewProc("ReleaseDC")
	procSetCursorPos             = user32.NewProc("SetCursorPos")
	procGetCursorPos             = user32.NewProc("GetCursorPos")
	procGetCursorInfo            = user32.NewProc("GetCursorInfo")
	procDrawIconEx               = user32.NewProc("DrawIconEx")
	procMouseEvent               = user32.NewProc("mouse_event")
	procKeybdEvent               = user32.NewProc("keybd_event")
	procSendInput                = user32.NewProc("SendInput")
	procShowWindow               = user32.NewProc("ShowWindow")
	procOpenInputDesktop         = user32.NewProc("OpenInputDesktop")
	procSetThreadDesktop         = user32.NewProc("SetThreadDesktop")
	procCloseDesktop             = user32.NewProc("CloseDesktop")
	procVkKeyScanW               = user32.NewProc("VkKeyScanW")
	procMapVirtualKeyW           = user32.NewProc("MapVirtualKeyW")
	procLockWorkStation          = user32.NewProc("LockWorkStation")
	procPostMessageW             = user32.NewProc("PostMessageW")
	procMessageBoxW              = user32.NewProc("MessageBoxW")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procIsIconic                 = user32.NewProc("IsIconic")
	procIsWindow                 = user32.NewProc("IsWindow")
	procGetWindowTextW           = user32.NewProc("GetWindowTextW")
	procGetWindowRect            = user32.NewProc("GetWindowRect")
	procSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	procBringWindowToTop         = user32.NewProc("BringWindowToTop")
	procGetForegroundWindow      = user32.NewProc("GetForegroundWindow")

	procGetConsoleWindow          = kernel32.NewProc("GetConsoleWindow")
	procSetThreadExecutionState   = kernel32.NewProc("SetThreadExecutionState")
	procWTSGetActiveConsoleSessId = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procGetCurrentProcess         = kernel32.NewProc("GetCurrentProcess")
	procCloseHandle               = kernel32.NewProc("CloseHandle")
	procWaitForSingleObject       = kernel32.NewProc("WaitForSingleObject")
	procTerminateProcess          = kernel32.NewProc("TerminateProcess")

	procOpenProcessToken            = advapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx            = advapi32.NewProc("DuplicateTokenEx")
	procSetTokenInformation         = advapi32.NewProc("SetTokenInformation")
	procCreateProcessAsUserW        = advapi32.NewProc("CreateProcessAsUserW")
	procStartServiceCtrlDispatcherW = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerW = advapi32.NewProc("RegisterServiceCtrlHandlerW")
	procSetServiceStatus            = advapi32.NewProc("SetServiceStatus")

	procShellExecuteW = shell32.NewProc("ShellExecuteW")

	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procSetStretchBltMode      = gdi32.NewProc("SetStretchBltMode")
	procStretchBlt             = gdi32.NewProc("StretchBlt")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
)

const (
	SM_CXSCREEN = 0
	SM_CYSCREEN = 1
	SRCCOPY     = 0x00CC0020
	CAPTUREBLT  = 0x40000000
	HALFTONE    = 4
	DI_NORMAL   = 0x0003

	DESKTOP_ALL_ACCESS = 0x01FF

	MOUSEEVENTF_MOVE       = 0x0001
	MOUSEEVENTF_LEFTDOWN   = 0x0002
	MOUSEEVENTF_LEFTUP     = 0x0004
	MOUSEEVENTF_RIGHTDOWN  = 0x0008
	MOUSEEVENTF_RIGHTUP    = 0x0010
	MOUSEEVENTF_MIDDLEDOWN = 0x0020
	MOUSEEVENTF_MIDDLEUP   = 0x0040
	MOUSEEVENTF_WHEEL      = 0x0800
	MOUSEEVENTF_HWHEEL     = 0x01000

	KEYEVENTF_EXTENDEDKEY = 0x0001
	KEYEVENTF_KEYUP       = 0x0002
	KEYEVENTF_UNICODE     = 0x0004
	KEYEVENTF_SCANCODE    = 0x0008
	INPUT_KEYBOARD        = 1

	ES_SYSTEM_REQUIRED  = 0x00000001
	ES_DISPLAY_REQUIRED = 0x00000002
	ES_CONTINUOUS       = 0x80000000

	HWND_BROADCAST  = 0xFFFF
	WM_SYSCOMMAND   = 0x0112
	SC_MONITORPOWER = 0xF170

	TOKEN_ALL_ACCESS       = 0xF01FF
	MAXIMUM_ALLOWED        = 0x02000000
	SecurityIdentification = 1
	TokenPrimary           = 1
	TokenSessionId         = 12
	CREATE_NO_WINDOW       = 0x08000000
	CREATE_UNICODE_ENV     = 0x00000400
	NORMAL_PRIORITY_CLASS  = 0x00000020

	SERVICE_WIN32_OWN_PROCESS = 0x00000010
	SERVICE_ACCEPT_STOP       = 0x00000001
	SERVICE_ACCEPT_SHUTDOWN   = 0x00000004
	SERVICE_RUNNING           = 0x00000004
	SERVICE_STOPPED           = 0x00000001
	SERVICE_CONTROL_STOP      = 0x00000001
	SERVICE_CONTROL_SHUTDOWN  = 0x00000005
)

type winPoint struct {
	X, Y int32
}

type cursorInfo struct {
	CbSize      uint32
	Flags       uint32
	HCursor     uintptr
	PtScreenPos winPoint
}

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type bitmapInfo struct {
	BmiHeader bitmapInfoHeader
	BmiColors [1]uint32
}

type serviceTableEntryW struct {
	ServiceName *uint16
	ServiceProc uintptr
}

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type startupInfoW struct {
	Cb              uint32
	LpReserved      *uint16
	LpDesktop       *uint16
	LpTitle         *uint16
	DwX             uint32
	DwY             uint32
	DwXSize         uint32
	DwYSize         uint32
	DwXCountChars   uint32
	DwYCountChars   uint32
	DwFillAttribute uint32
	DwFlags         uint32
	WShowWindow     uint16
	CbReserved2     uint16
	LpReserved2     *byte
	HStdInput       uintptr
	HStdOutput      uintptr
	HStdError       uintptr
}

type processInformation struct {
	HProcess    uintptr
	HThread     uintptr
	DwProcessId uint32
	DwThreadId  uint32
}

var (
	svcStatusHandle uintptr
	svcStopChan     = make(chan struct{})
	winDisplayAsleep int32
)

func sysSetPriority(pid int, prio int) {}
func sysSetsidAndIgnoreSignals()       {}
func sysIoctl(fd *os.File, req uint, arg uintptr) error {
	return fmt.Errorf("not supported on windows")
}

// switchToInputDesktop attaches the current OS thread to whichever desktop is currently active
// on the physical screen:
//   - "WinSta0\Default" when unlocked
//   - "WinSta0\Winlogon" when on the Windows 11 Lock Screen / PIN / Password prompt / UAC dialog!
// When running as NT AUTHORITY\SYSTEM in the active console session, this allows VuiRemote to
// both capture the live Password/PIN login screen and inject keystrokes/mouse clicks into it.
func switchToInputDesktop() {
	runtime.LockOSThread()
	hDesk, _, _ := procOpenInputDesktop.Call(0, 0, DESKTOP_ALL_ACCESS)
	if hDesk != 0 {
		procSetThreadDesktop.Call(hDesk)
		procCloseDesktop.Call(hDesk)
	}
}

func isAdminProcess() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func winGetScreenSize() (int, int) {
	switchToInputDesktop()
	w, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
	h, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
	sw, sh := int(w), int(h)
	if sw <= 0 {
		sw = 1920
	}
	if sh <= 0 {
		sh = 1080
	}
	atomic.StoreInt32(&detectedWidth, int32(sw))
	atomic.StoreInt32(&detectedHeight, int32(sh))
	return sw, sh
}

func winSmartSleep() {
	atomic.StoreInt32(&winDisplayAsleep, 1)
	switchToInputDesktop()
	// Keep network/CPU awake in low-power state so Wi-Fi never drops while screen is off
	procSetThreadExecutionState.Call(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
	// Lock workstation for security
	procLockWorkStation.Call()
	time.Sleep(250 * time.Millisecond)
	// Power off laptop/PC display backlight (SC_MONITORPOWER = 2)
	procPostMessageW.Call(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)
}

func winWakeDisplay() {
	wasAsleep := atomic.SwapInt32(&winDisplayAsleep, 0)
	switchToInputDesktop()
	procSetThreadExecutionState.Call(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED)
	if wasAsleep == 1 {
		procPostMessageW.Call(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, ^uintptr(0)) // -1 = Turn display ON
		procMouseEvent.Call(MOUSEEVENTF_MOVE, 1, 1, 0, 0)
		time.Sleep(40 * time.Millisecond)
		procMouseEvent.Call(MOUSEEVENTF_MOVE, ^uintptr(0), ^uintptr(0), 0, 0)
	}
}

func winServiceCtrlHandler(control uint32) uintptr {
	switch control {
	case SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN:
		st := serviceStatus{
			ServiceType:  SERVICE_WIN32_OWN_PROCESS,
			CurrentState: SERVICE_STOPPED,
		}
		procSetServiceStatus.Call(svcStatusHandle, uintptr(unsafe.Pointer(&st)))
		select {
		case <-svcStopChan:
		default:
			close(svcStopChan)
		}
	}
	return 0
}

func spawnSystemAgentInConsoleSession(exePath string, sessionId uint32) uintptr {
	curProc, _, _ := procGetCurrentProcess.Call()
	var hToken uintptr
	r1, _, _ := procOpenProcessToken.Call(curProc, TOKEN_ALL_ACCESS, uintptr(unsafe.Pointer(&hToken)))
	if r1 == 0 || hToken == 0 {
		return 0
	}
	defer procCloseHandle.Call(hToken)

	var hDupToken uintptr
	r2, _, _ := procDuplicateTokenEx.Call(
		hToken,
		MAXIMUM_ALLOWED,
		0,
		SecurityIdentification,
		TokenPrimary,
		uintptr(unsafe.Pointer(&hDupToken)),
	)
	if r2 == 0 || hDupToken == 0 {
		return 0
	}
	defer procCloseHandle.Call(hDupToken)

	sess := sessionId
	r3, _, _ := procSetTokenInformation.Call(
		hDupToken,
		TokenSessionId,
		uintptr(unsafe.Pointer(&sess)),
		4,
	)
	if r3 == 0 {
		return 0
	}

	var si startupInfoW
	si.Cb = uint32(unsafe.Sizeof(si))
	desk, _ := syscall.UTF16PtrFromString(`winsta0\default`)
	si.LpDesktop = desk

	cmdLine, _ := syscall.UTF16PtrFromString(`"` + exePath + `" --system-agent`)
	var pi processInformation

	r4, _, _ := procCreateProcessAsUserW.Call(
		hDupToken,
		0,
		uintptr(unsafe.Pointer(cmdLine)),
		0,
		0,
		0,
		CREATE_NO_WINDOW|NORMAL_PRIORITY_CLASS,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r4 == 0 {
		return 0
	}
	if pi.HThread != 0 {
		procCloseHandle.Call(pi.HThread)
	}
	return pi.HProcess
}

func winServiceMain(argc uint32, argv uintptr) uintptr {
	svcName, _ := syscall.UTF16PtrFromString("VuiRemoteSvc")
	svcStatusHandle, _, _ = procRegisterServiceCtrlHandlerW.Call(
		uintptr(unsafe.Pointer(svcName)),
		syscall.NewCallback(winServiceCtrlHandler),
	)

	st := serviceStatus{
		ServiceType:      SERVICE_WIN32_OWN_PROCESS,
		CurrentState:     SERVICE_RUNNING,
		ControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
	}
	procSetServiceStatus.Call(svcStatusHandle, uintptr(unsafe.Pointer(&st)))

	exePath, err := os.Executable()
	if err != nil || exePath == "" {
		exePath = `C:\ProgramData\VuiRemote\VuiRemote.exe`
	}

	var childProc uintptr
	var activeSess uint32 = 0xFFFFFFFF

	for {
		select {
		case <-svcStopChan:
			if childProc != 0 {
				procTerminateProcess.Call(childProc, 0)
				procCloseHandle.Call(childProc)
			}
			return 0
		default:
		}

		sessRaw, _, _ := procWTSGetActiveConsoleSessId.Call()
		sess := uint32(sessRaw)

		needSpawn := false
		if sess != 0xFFFFFFFF {
			if childProc == 0 {
				needSpawn = true
			} else if sess != activeSess {
				procTerminateProcess.Call(childProc, 0)
				procCloseHandle.Call(childProc)
				childProc = 0
				needSpawn = true
			} else {
				// Check if childProc is still running (WAIT_TIMEOUT = 258)
				waitRes, _, _ := procWaitForSingleObject.Call(childProc, 0)
				if waitRes != 258 {
					procCloseHandle.Call(childProc)
					childProc = 0
					needSpawn = true
				}
			}
		}

		if needSpawn {
			hProc := spawnSystemAgentInConsoleSession(exePath, sess)
			if hProc != 0 {
				childProc = hProc
				activeSess = sess
			}
		}

		time.Sleep(2 * time.Second)
	}
}

func installAndStartWindowsSystemService(exePath string, silent bool) {
	installDir := `C:\ProgramData\VuiRemote`
	os.MkdirAll(installDir, 0755)
	targetExe := filepath.Join(installDir, "VuiRemote.exe")

	// Stop existing service and old processes before copying binary
	exec.Command("sc", "stop", "VuiRemoteSvc").Run()
	exec.Command("reg", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "VuiRemote", "/f").Run()

	myPid := os.Getpid()
	exec.Command("taskkill", "/F", "/FI", fmt.Sprintf("PID ne %d", myPid), "/IM", "VuiRemote.exe").Run()
	exec.Command("taskkill", "/F", "/FI", fmt.Sprintf("PID ne %d", myPid), "/IM", "VuiRemote_Win11.exe").Run()
	exec.Command("taskkill", "/F", "/FI", fmt.Sprintf("PID ne %d", myPid), "/IM", "VuiRemote_Windows11.exe").Run()
	time.Sleep(400 * time.Millisecond)

	if !strings.EqualFold(exePath, targetExe) {
		if data, err := os.ReadFile(exePath); err == nil {
			_ = os.WriteFile(targetExe, data, 0755)
		}
	}

	// Open Windows Firewall for VuiRemote TCP 8090 & UDP 19888
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=VuiRemote").Run()
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=VuiRemote", "dir=in", "action=allow", "program="+targetExe, "enable=yes").Run()
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=VuiRemote", "dir=in", "action=allow", "protocol=TCP", "localport=8090", "enable=yes").Run()
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=VuiRemote", "dir=in", "action=allow", "protocol=UDP", "localport=19888", "enable=yes").Run()

	// Prevent laptop AC/DC standby from dropping Wi-Fi connection unexpectedly
	exec.Command("powercfg", "/change", "standby-timeout-ac", "0").Run()
	exec.Command("powercfg", "/change", "hibernate-timeout-ac", "0").Run()

	// Create and start VuiRemoteSvc as LocalSystem (NT AUTHORITY\SYSTEM)
	exec.Command("sc", "delete", "VuiRemoteSvc").Run()
	time.Sleep(300 * time.Millisecond)
	binPathArg := fmt.Sprintf(`"%s" --service`, targetExe)
	exec.Command("sc", "create", "VuiRemoteSvc", "binPath=", binPathArg, "start=", "auto", "DisplayName=", "VuiRemote System Service").Run()
	exec.Command("sc", "failure", "VuiRemoteSvc", "reset=", "0", "actions=", "restart/2000/restart/2000/restart/2000").Run()
	exec.Command("sc", "start", "VuiRemoteSvc").Run()

	if !silent {
		title, _ := syscall.UTF16PtrFromString("VuiRemote Windows 11 - Đã Hòa Mạng Hệ Thống")
		msg, _ := syscall.UTF16PtrFromString(
			"✅ Đã cài đặt dịch vụ hệ thống VuiRemote (Quyền SYSTEM) thành công!\n\n" +
				"• Tự động hiển thị & cho phép nhập Mật khẩu / Mã PIN ngay tại Màn hình khóa (Lock Screen)\n" +
				"• Tự chạy ngầm ngay từ khi bật máy (trước cả khi đăng nhập Windows)\n" +
				"• Chế độ Ngủ thông minh: Khóa máy & tắt màn hình tiết kiệm điện nhưng giữ kết nối Wi-Fi để bật lại tức thì từ điện thoại!",
		)
		procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(title)), 0x00000040) // MB_ICONINFORMATION
	}
}

func winInitPlatform() {
	args := strings.Join(os.Args, " ")

	// Mode 1: Running as Windows Service in Session 0 (--service)
	if strings.Contains(args, "--service") {
		svcName, _ := syscall.UTF16PtrFromString("VuiRemoteSvc")
		table := [2]serviceTableEntryW{
			{ServiceName: svcName, ServiceProc: syscall.NewCallback(winServiceMain)},
			{ServiceName: nil, ServiceProc: 0},
		}
		procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
		os.Exit(0)
	}

	// Mode 2: Interactive launch by user or --install -> Elevate to Admin & install VuiRemoteSvc
	if !strings.Contains(args, "--system-agent") && !strings.Contains(args, "--background") {
		exePath, _ := os.Executable()
		if !isAdminProcess() {
			verb, _ := syscall.UTF16PtrFromString("runas")
			file, _ := syscall.UTF16PtrFromString(exePath)
			param, _ := syscall.UTF16PtrFromString("--install")
			dir, _ := syscall.UTF16PtrFromString(filepath.Dir(exePath))
			procShellExecuteW.Call(
				0,
				uintptr(unsafe.Pointer(verb)),
				uintptr(unsafe.Pointer(file)),
				uintptr(unsafe.Pointer(param)),
				uintptr(unsafe.Pointer(dir)),
				1,
			)
			os.Exit(0)
		}
		installAndStartWindowsSystemService(exePath, strings.Contains(args, "--silent"))
		os.Exit(0)
	}

	// Mode 3: Running as Console Session Agent (--system-agent or --background)
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, 0) // SW_HIDE
	}

	procSetProcessDPIAware.Call()
	procSetThreadExecutionState.Call(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
	sw, sh := winGetScreenSize()
	fmt.Printf("[WINDOWS 11 SYSTEM AGENT] Screen resolution: %dx%d (User: %s)\n", sw, sh, os.Getenv("USERNAME"))

	// Register self-update HTTP handler so Windows 11 can update itself remotely with 1 click
	http.HandleFunc("/api/selfupdate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		go func() {
			client := &http.Client{Timeout: 25 * time.Second}
			urls := []string{
				"http://192.168.1.154:8090/windows",
				"http://192.168.1.88:8080/windows",
			}
			for _, u := range urls {
				resp, err := client.Get(u)
				if err != nil || resp.StatusCode != 200 {
					if resp != nil {
						resp.Body.Close()
					}
					continue
				}
				data, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || len(data) < 1000000 {
					continue
				}
				tmpExe := `C:\Windows\Temp\VuiRemote_Update.exe`
				if os.WriteFile(tmpExe, data, 0755) == nil {
					exec.Command(tmpExe, "--install", "--silent").Start()
					return
				}
			}
		}()
		w.Write([]byte(`{"ok":true,"status":"updating"}`))
	})

	// Register remote PowerShell / command execution handler for diagnostics and automation
	http.HandleFunc("/api/exec", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		if !requireAuth(w, r) {
			return
		}
		cmdStr := r.URL.Query().Get("cmd")
		if cmdStr == "" && r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			cmdStr = strings.TrimSpace(string(b))
		}
		if cmdStr == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"missing cmd"}`))
			return
		}
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmdStr)
		out, err := cmd.CombinedOutput()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		w.Write([]byte(fmt.Sprintf(`{"ok":%t,"error":%q,"output":%q}`, err == nil, errStr, string(out))))
	})
}

type winRect struct {
	Left, Top, Right, Bottom int32
}

var winEnumList []PCWindowInfo

func winEnumProc(hwnd uintptr, lparam uintptr) uintptr {
	vis, _, _ := procIsWindowVisible.Call(hwnd)
	if vis == 0 {
		return 1
	}
	var buf [256]uint16
	n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 255)
	if n == 0 {
		return 1
	}
	title := syscall.UTF16ToString(buf[:n])
	titleTrim := strings.TrimSpace(title)
	if titleTrim == "" || titleTrim == "Program Manager" || titleTrim == "Windows Input Experience" || titleTrim == "Settings" && n < 4 {
		return 1
	}
	var rc winRect
	r, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	if r == 0 {
		return 1
	}
	w := int(rc.Right - rc.Left)
	h := int(rc.Bottom - rc.Top)
	if w < 140 || h < 90 {
		return 1
	}
	idStr := fmt.Sprintf("%d", hwnd)
	icon, appName, prio := classifyWindowTitle(titleTrim, "")
	winEnumList = append(winEnumList, PCWindowInfo{
		ID:       idStr,
		Title:    titleTrim,
		App:      appName,
		Icon:     icon,
		X:        int(rc.Left),
		Y:        int(rc.Top),
		W:        w,
		H:        h,
		Priority: prio,
		Active:   getActivePCWindowID() == idStr,
	})
	return 1
}

var winEnumCallback = syscall.NewCallback(winEnumProc)

func winListWindows() []PCWindowInfo {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	switchToInputDesktop()
	winEnumList = nil
	procEnumWindows.Call(winEnumCallback, 0)
	out := make([]PCWindowInfo, len(winEnumList))
	copy(out, winEnumList)
	sortPCWindows(out)
	return out
}

func winGetWindowBounds(id string) (int, int, int, int, bool) {
	if id == "" {
		return 0, 0, 0, 0, false
	}
	var hwndVal uint64
	if _, err := fmt.Sscanf(id, "%d", &hwndVal); err != nil || hwndVal == 0 {
		return 0, 0, 0, 0, false
	}
	hwnd := uintptr(hwndVal)
	isW, _, _ := procIsWindow.Call(hwnd)
	if isW == 0 {
		return 0, 0, 0, 0, false
	}
	iconic, _, _ := procIsIconic.Call(hwnd)
	if iconic != 0 {
		return 0, 0, 0, 0, false
	}
	var rc winRect
	r, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	if r == 0 {
		return 0, 0, 0, 0, false
	}
	sw, sh := winGetScreenSize()
	x := int(rc.Left)
	y := int(rc.Top)
	w := int(rc.Right - rc.Left)
	h := int(rc.Bottom - rc.Top)
	if x < 0 {
		w += x
		x = 0
	}
	if y < 0 {
		h += y
		y = 0
	}
	if x+w > sw {
		w = sw - x
	}
	if y+h > sh {
		h = sh - y
	}
	if w < 100 || h < 80 {
		return 0, 0, 0, 0, false
	}
	return x, y, w, h, true
}

func winFocusWindow(id string, maximize bool) bool {
	var hwndVal uint64
	if _, err := fmt.Sscanf(id, "%d", &hwndVal); err != nil || hwndVal == 0 {
		return false
	}
	hwnd := uintptr(hwndVal)
	switchToInputDesktop()
	isW, _, _ := procIsWindow.Call(hwnd)
	if isW == 0 {
		return false
	}
	if maximize {
		procShowWindow.Call(hwnd, 3) // SW_MAXIMIZE = 3
	} else {
		iconic, _, _ := procIsIconic.Call(hwnd)
		if iconic != 0 {
			procShowWindow.Call(hwnd, 9) // SW_RESTORE = 9
		}
	}
	procBringWindowToTop.Call(hwnd)
	procSetForegroundWindow.Call(hwnd)
	return true
}

func winCaptureScreenJpeg(targetW int) ([]byte, error) {
	switchToInputDesktop()

	fullW, fullH := winGetScreenSize()
	srcX, srcY, srcW, srcH := 0, 0, fullW, fullH
	if winID := getActivePCWindowID(); winID != "" {
		if wx, wy, ww, wh, ok := winGetWindowBounds(winID); ok {
			srcX, srcY, srcW, srcH = wx, wy, ww, wh
		} else {
			setActivePCWindowID("")
		}
	}

	dstW := targetW
	if dstW <= 0 || dstW > srcW {
		dstW = srcW
	}
	dstH := int(float64(srcH) * float64(dstW) / float64(srcW))
	if dstH <= 0 {
		dstH = srcH
	}

	// Use GetDC(0) (entire active desktop screen, including Winlogon secure desktop!)
	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil, fmt.Errorf("GetDC(0) failed")
	}
	defer procReleaseDC.Call(0, hdcScreen)

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(hdcMem)

	hbm, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, uintptr(dstW), uintptr(dstH))
	if hbm == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(hbm)

	oldObj, _, _ := procSelectObject.Call(hdcMem, hbm)
	defer procSelectObject.Call(hdcMem, oldObj)

	procSetStretchBltMode.Call(hdcMem, HALFTONE)
	ret, _, _ := procStretchBlt.Call(
		hdcMem, 0, 0, uintptr(dstW), uintptr(dstH),
		hdcScreen, uintptr(srcX), uintptr(srcY), uintptr(srcW), uintptr(srcH),
		SRCCOPY|CAPTUREBLT,
	)
	if ret == 0 {
		return nil, fmt.Errorf("StretchBlt failed")
	}

	// Draw mouse cursor onto scaled frame
	var ci cursorInfo
	ci.CbSize = uint32(unsafe.Sizeof(ci))
	if r, _, _ := procGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r != 0 && ci.Flags == 1 {
		relX := int(ci.PtScreenPos.X) - srcX
		relY := int(ci.PtScreenPos.Y) - srcY
		if relX >= 0 && relX <= srcW && relY >= 0 && relY <= srcH {
			cx := int(float64(relX) * float64(dstW) / float64(srcW))
			cy := int(float64(relY) * float64(dstH) / float64(srcH))
			procDrawIconEx.Call(hdcMem, uintptr(cx), uintptr(cy), ci.HCursor, 0, 0, 0, 0, DI_NORMAL)
		}
	}

	var bi bitmapInfo
	bi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bi.BmiHeader))
	bi.BmiHeader.BiWidth = int32(dstW)
	bi.BmiHeader.BiHeight = -int32(dstH) // top-down DIB
	bi.BmiHeader.BiPlanes = 1
	bi.BmiHeader.BiBitCount = 32
	bi.BmiHeader.BiCompression = 0 // BI_RGB

	buf := make([]byte, dstW*dstH*4)
	lines, _, _ := procGetDIBits.Call(
		hdcMem, hbm, 0, uintptr(dstH),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bi)),
		0,
	)
	if lines == 0 {
		return nil, fmt.Errorf("GetDIBits failed")
	}

	img := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	pix := img.Pix
	for i := 0; i < len(buf); i += 4 {
		pix[i] = buf[i+2]   // R
		pix[i+1] = buf[i+1] // G
		pix[i+2] = buf[i]   // B
		pix[i+3] = 255      // A
	}

	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 88}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func winCoordToPixel(px, py float64) (int, int) {
	sw, sh := winGetScreenSize()
	if winID := getActivePCWindowID(); winID != "" {
		if wx, wy, ww, wh, ok := winGetWindowBounds(winID); ok {
			x := wx + int(math.Max(0, math.Min(float64(ww-1), px*float64(ww))))
			y := wy + int(math.Max(0, math.Min(float64(wh-1), py*float64(wh))))
			return x, y
		}
	}
	x := int(math.Max(0, math.Min(float64(sw-1), px*float64(sw))))
	y := int(math.Max(0, math.Min(float64(sh-1), py*float64(sh))))
	return x, y
}

func winTouchTap(px, py float64) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	x, y := winCoordToPixel(px, py)
	procSetCursorPos.Call(uintptr(x), uintptr(y))
	time.Sleep(8 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
	time.Sleep(10 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
	invalidateScreenCache()
}

func winDoubleTap(px, py float64) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	if px >= 0 && py >= 0 {
		x, y := winCoordToPixel(px, py)
		procSetCursorPos.Call(uintptr(x), uintptr(y))
		time.Sleep(8 * time.Millisecond)
	}
	procMouseEvent.Call(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
	time.Sleep(10 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
	time.Sleep(55 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
	time.Sleep(10 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
	invalidateScreenCache()
}

func winRightClick(px, py float64) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	if px >= 0 && py >= 0 {
		x, y := winCoordToPixel(px, py)
		procSetCursorPos.Call(uintptr(x), uintptr(y))
		time.Sleep(8 * time.Millisecond)
	}
	procMouseEvent.Call(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0)
	time.Sleep(10 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0)
	invalidateScreenCache()
}

func winMiddleClick(px, py float64) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	if px >= 0 && py >= 0 {
		x, y := winCoordToPixel(px, py)
		procSetCursorPos.Call(uintptr(x), uintptr(y))
		time.Sleep(8 * time.Millisecond)
	}
	procMouseEvent.Call(MOUSEEVENTF_MIDDLEDOWN, 0, 0, 0, 0)
	time.Sleep(10 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_MIDDLEUP, 0, 0, 0, 0)
	invalidateScreenCache()
}

func winDragStart(px, py float64) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	x, y := winCoordToPixel(px, py)
	procSetCursorPos.Call(uintptr(x), uintptr(y))
	time.Sleep(8 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
	invalidateScreenCache()
}

func winDragMove(px, py float64) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	switchToInputDesktop()
	x, y := winCoordToPixel(px, py)
	procSetCursorPos.Call(uintptr(x), uintptr(y))
	invalidateScreenCache()
}

func winDragEnd(px, py float64) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	switchToInputDesktop()
	x, y := winCoordToPixel(px, py)
	procSetCursorPos.Call(uintptr(x), uintptr(y))
	time.Sleep(8 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
	invalidateScreenCache()
}

func winDragAtomic(px1, py1, px2, py2 float64) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	x1, y1 := winCoordToPixel(px1, py1)
	x2, y2 := winCoordToPixel(px2, py2)
	procSetCursorPos.Call(uintptr(x1), uintptr(y1))
	time.Sleep(8 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
	steps := 8
	for i := 1; i <= steps; i++ {
		time.Sleep(14 * time.Millisecond)
		t := float64(i) / float64(steps)
		cx := int(float64(x1) + float64(x2-x1)*t)
		cy := int(float64(y1) + float64(y2-y1)*t)
		procSetCursorPos.Call(uintptr(cx), uintptr(cy))
	}
	time.Sleep(15 * time.Millisecond)
	procMouseEvent.Call(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
	invalidateScreenCache()
}

func winScrollXY(px, py, dx, dy float64, steps int) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	if px > 0 || py > 0 {
		x, y := winCoordToPixel(px, py)
		procSetCursorPos.Call(uintptr(x), uintptr(y))
	}
	if math.Abs(dy) >= math.Abs(dx) {
		if steps <= 0 {
			steps = int(math.Abs(dy) / 0.045)
		}
		if steps < 1 {
			steps = 2
		} else if steps > 8 {
			steps = 8
		}
		delta := int32(-120 * steps)
		if dy > 0 {
			delta = int32(120 * steps)
		}
		procMouseEvent.Call(MOUSEEVENTF_WHEEL, 0, 0, uintptr(uint32(delta)), 0)
	} else {
		if steps <= 0 {
			steps = int(math.Abs(dx) / 0.05)
		}
		if steps < 1 {
			steps = 2
		} else if steps > 8 {
			steps = 8
		}
		delta := int32(120 * steps)
		if dx > 0 {
			delta = int32(-120 * steps)
		}
		procMouseEvent.Call(MOUSEEVENTF_HWHEEL, 0, 0, uintptr(uint32(delta)), 0)
	}
	invalidateScreenCache()
}

func winScroll(up bool) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	delta := int32(-360)
	if up {
		delta = 360
	}
	procMouseEvent.Call(MOUSEEVENTF_WHEEL, 0, 0, uintptr(uint32(delta)), 0)
	invalidateScreenCache()
}

func winRelMouse(dx, dy int) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	var pt winPoint
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetCursorPos.Call(uintptr(int(pt.X)+dx), uintptr(int(pt.Y)+dy))
	invalidateScreenCache()
}

func winMouseButton(btn int) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	if btn == 273 {
		procMouseEvent.Call(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0)
		procMouseEvent.Call(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0)
	} else if btn == 274 {
		procMouseEvent.Call(MOUSEEVENTF_MIDDLEDOWN, 0, 0, 0, 0)
		procMouseEvent.Call(MOUSEEVENTF_MIDDLEUP, 0, 0, 0, 0)
	} else {
		procMouseEvent.Call(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
		procMouseEvent.Call(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
	}
	invalidateScreenCache()
}

func winKeyDownVK(vk byte) {
	scan, _, _ := procMapVirtualKeyW.Call(uintptr(vk), 0)
	procKeybdEvent.Call(uintptr(vk), scan, 0, 0)
}

func winKeyUpVK(vk byte) {
	scan, _, _ := procMapVirtualKeyW.Call(uintptr(vk), 0)
	procKeybdEvent.Call(uintptr(vk), scan, KEYEVENTF_KEYUP, 0)
}

func winTapVK(vk byte) {
	winKeyDownVK(vk)
	time.Sleep(18 * time.Millisecond)
	winKeyUpVK(vk)
}

func winSendKey(androidCode int) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	switch androidCode {
	case 26:
		// Power key toggles Smart Sleep / Wake Display
		if atomic.LoadInt32(&winDisplayAsleep) == 1 {
			winWakeDisplay()
		} else {
			winSmartSleep()
		}
		return
	case 19:
		winTapVK(0x26) // VK_UP
	case 20:
		winTapVK(0x28) // VK_DOWN
	case 21:
		winTapVK(0x25) // VK_LEFT
	case 22:
		winTapVK(0x27) // VK_RIGHT
	case 23, 66:
		winTapVK(0x0D) // VK_RETURN
	case 4, 111:
		winTapVK(0x1B) // VK_ESCAPE
	case 3:
		winTapVK(0x5B) // VK_LWIN
	case 82, 187:
		winKeyDownVK(0x12) // VK_MENU (Alt)
		winTapVK(0x09)     // VK_TAB
		winKeyUpVK(0x12)
	case 24:
		winTapVK(0xAF) // VK_VOLUME_UP
	case 25:
		winTapVK(0xAE) // VK_VOLUME_DOWN
	case 164:
		winTapVK(0xAD) // VK_VOLUME_MUTE
	case 67:
		winTapVK(0x08) // VK_BACK
	case 112:
		winTapVK(0x2E) // VK_DELETE
	case 61:
		winTapVK(0x09) // VK_TAB
	case 122:
		winTapVK(0x24) // VK_HOME
	case 123:
		winTapVK(0x23) // VK_END
	case 92:
		winTapVK(0x21) // VK_PRIOR (PageUp)
	case 93:
		winTapVK(0x22) // VK_NEXT (PageDown)
	case 85, 62:
		winTapVK(0x20) // VK_SPACE
	default:
		winTapVK(0x0D)
	}
	invalidateScreenCache()
}

func sendUinputHotkeyCombo(combo string) bool {
	return false
}

func winHotkeyTokenToVK(tok string) (byte, bool, bool) {
	t := strings.ToLower(strings.TrimSpace(tok))
	switch t {
	case "ctrl", "control", "ctrl_l", "control_l":
		return 0x11, true, true // VK_CONTROL
	case "shift", "shift_l":
		return 0x10, true, true // VK_SHIFT
	case "alt", "alt_l":
		return 0x12, true, true // VK_MENU
	case "super", "super_l", "meta", "win":
		return 0x5B, true, true // VK_LWIN
	case "return", "enter", "kp_enter":
		return 0x0D, false, true // VK_RETURN
	case "tab", "iso_left_tab":
		return 0x09, false, true // VK_TAB
	case "backspace", "bksp":
		return 0x08, false, true // VK_BACK
	case "delete", "del":
		return 0x2E, false, true // VK_DELETE
	case "escape", "esc":
		return 0x1B, false, true // VK_ESCAPE
	case "space":
		return 0x20, false, true // VK_SPACE
	case "left", "arrowleft":
		return 0x25, false, true // VK_LEFT
	case "up", "arrowup":
		return 0x26, false, true // VK_UP
	case "right", "arrowright":
		return 0x27, false, true // VK_RIGHT
	case "down", "arrowdown":
		return 0x28, false, true // VK_DOWN
	case "home":
		return 0x24, false, true // VK_HOME
	case "end":
		return 0x23, false, true // VK_END
	case "page_up", "pageup", "prior":
		return 0x21, false, true // VK_PRIOR
	case "page_down", "pagedown", "next":
		return 0x22, false, true // VK_NEXT
	case "f1":
		return 0x70, false, true
	case "f2":
		return 0x71, false, true
	case "f3":
		return 0x72, false, true
	case "f4":
		return 0x73, false, true
	case "f5":
		return 0x74, false, true
	case "f6":
		return 0x75, false, true
	case "f7":
		return 0x76, false, true
	case "f8":
		return 0x77, false, true
	case "f9":
		return 0x78, false, true
	case "f10":
		return 0x79, false, true
	case "f11":
		return 0x7A, false, true
	case "f12":
		return 0x7B, false, true
	case "slash", "/":
		return 0xBF, false, true
	case "backslash", "\\":
		return 0xDC, false, true
	case "minus", "-":
		return 0xBD, false, true
	case "equal", "plus", "=":
		return 0xBB, false, true
	case "bracketleft", "[":
		return 0xDB, false, true
	case "bracketright", "]":
		return 0xDD, false, true
	case "semicolon", ";":
		return 0xBA, false, true
	case "apostrophe", "'":
		return 0xDE, false, true
	case "grave", "`":
		return 0xC0, false, true
	case "comma", ",":
		return 0xBC, false, true
	case "period", ".":
		return 0xBE, false, true
	}
	if len(t) == 1 {
		ch := t[0]
		if ch >= 'a' && ch <= 'z' {
			return ch - 'a' + 'A', false, true
		}
		if ch >= '0' && ch <= '9' {
			return ch, false, true
		}
	}
	return 0, false, false
}

func winSendHotkey(combo string) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()
	parts := strings.Split(strings.TrimSpace(combo), "+")
	var mods []byte
	var mainVK byte
	for _, p := range parts {
		if p == "" {
			continue
		}
		vk, isMod, ok := winHotkeyTokenToVK(p)
		if !ok {
			continue
		}
		if isMod && len(parts) > 1 {
			mods = append(mods, vk)
		} else {
			mainVK = vk
		}
	}
	if mainVK == 0 && len(mods) == 1 {
		mainVK = mods[0]
		mods = nil
	}
	if mainVK != 0 {
		for _, m := range mods {
			winKeyDownVK(m)
		}
		winTapVK(mainVK)
		for i := len(mods) - 1; i >= 0; i-- {
			winKeyUpVK(mods[i])
		}
	}
	invalidateScreenCache()
}

type kbInput struct {
	Type uint32
	Ki   struct {
		WVk         uint16
		WScan       uint16
		DwFlags     uint32
		Time        uint32
		DwExtraInfo uintptr
		Padding     [8]byte
	}
}

func winSendText(text string) {
	winSendTextDelta(text, 0, 0, 0, false)
}

func winSendTextEx(text string, bksp int, direct bool) {
	winSendTextDelta(text, bksp, 0, 0, direct)
}

func winMoveCaretVK(delta int) {
	if delta == 0 {
		return
	}
	vk := byte(0x27) // VK_RIGHT
	count := delta
	if delta < 0 {
		vk = 0x25 // VK_LEFT
		count = -delta
	}
	for i := 0; i < count; i++ {
		winKeyDownVK(vk)
		time.Sleep(4 * time.Millisecond)
		winKeyUpVK(vk)
		time.Sleep(4 * time.Millisecond)
	}
}

func winSendTextDelta(text string, bksp int, moveBefore int, moveAfter int, direct bool) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	winWakeDisplay()

	if moveBefore != 0 {
		winMoveCaretVK(moveBefore)
		time.Sleep(8 * time.Millisecond)
	}

	for i := 0; i < bksp; i++ {
		winKeyDownVK(0x08) // VK_BACK
		time.Sleep(5 * time.Millisecond)
		winKeyUpVK(0x08)
		time.Sleep(5 * time.Millisecond)
	}

	if text == "" {
		if moveAfter != 0 {
			winMoveCaretVK(moveAfter)
		}
		invalidateScreenCache()
		return
	}

	fgHwnd, _, _ := procGetForegroundWindow.Call()
	pureASCIIPassword := !direct && (fgHwnd == 0)
	for _, r := range text {
		if r < 0x21 || r > 0x7E {
			pureASCIIPassword = false
			break
		}
	}

	for _, r := range text {
		if r == '\n' {
			winTapVK(0x0D) // VK_RETURN
			time.Sleep(8 * time.Millisecond)
			continue
		}
		if r == '\r' {
			continue
		}
		// Only use hardware Virtual Key + ScanCode for single-token ASCII PINs/Passwords (e.g., Windows 11 Lock Screen).
		// When typing sentences, direct mode, or Vietnamese text, use KEYEVENTF_UNICODE for all characters so UniKey/EVKey does not
		// intercept ASCII letters (s, f, r, x, j, w, a, e, o, d) and corrupt already-accented Vietnamese words!
		if pureASCIIPassword && r >= 0x21 && r <= 0x7E {
			vkRes, _, _ := procVkKeyScanW.Call(uintptr(r))
			vkShort := int16(vkRes)
			if vkShort != -1 {
				vk := byte(vkShort & 0xFF)
				shift := byte((vkShort >> 8) & 0xFF)
				if (shift & 1) != 0 {
					winKeyDownVK(0x10) // VK_SHIFT
					time.Sleep(8 * time.Millisecond)
				}
				winTapVK(vk)
				if (shift & 1) != 0 {
					time.Sleep(8 * time.Millisecond)
					winKeyUpVK(0x10)
				}
				time.Sleep(14 * time.Millisecond)
				continue
			}
		}

		// For Vietnamese / Unicode characters and normal sentences, use KEYEVENTF_UNICODE
		u16 := utf16.Encode([]rune{r})
		for _, ch := range u16 {
			var inDown, inUp kbInput
			inDown.Type = INPUT_KEYBOARD
			inDown.Ki.WScan = ch
			inDown.Ki.DwFlags = KEYEVENTF_UNICODE

			inUp.Type = INPUT_KEYBOARD
			inUp.Ki.WScan = ch
			inUp.Ki.DwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP

			procSendInput.Call(1, uintptr(unsafe.Pointer(&inDown)), unsafe.Sizeof(inDown))
			procSendInput.Call(1, uintptr(unsafe.Pointer(&inUp)), unsafe.Sizeof(inUp))
			time.Sleep(5 * time.Millisecond)
		}
	}
	if moveAfter != 0 {
		time.Sleep(8 * time.Millisecond)
		winMoveCaretVK(moveAfter)
	}
	invalidateScreenCache()
}

func winSendImageClipboard(pngPath string, autoPaste bool) error {
	cmd := exec.Command("powershell.exe", "-Sta", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
		`Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $img = [System.Drawing.Image]::FromFile($env:VUI_IMG_PATH); [System.Windows.Forms.Clipboard]::SetImage($img); $img.Dispose()`)
	cmd.Env = append(os.Environ(), "VUI_IMG_PATH="+pngPath)
	if err := cmd.Run(); err != nil {
		return err
	}
	if autoPaste {
		time.Sleep(60 * time.Millisecond)
		winSendHotkey("ctrl+v")
	}
	return nil
}

var procLoadCursorW = user32.NewProc("LoadCursorW")

func winIsTextInputActive() bool {
	shown, _, _ := winGetTextInputState()
	return shown
}

func winGetTextInputState() (bool, float64, float64) {
	switchToInputDesktop()
	var ci cursorInfo
	ci.CbSize = uint32(unsafe.Sizeof(ci))
	if r, _, _ := procGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r != 0 && ci.Flags == 1 {
		hIBeam, _, _ := procLoadCursorW.Call(0, 32513) // IDC_IBEAM = 32513
		if hIBeam != 0 && ci.HCursor == hIBeam {
			sw, sh := winGetScreenSize()
			x, y := int(ci.PtScreenPos.X), int(ci.PtScreenPos.Y)
			if winID := getActivePCWindowID(); winID != "" {
				if wx, wy, ww, wh, ok := winGetWindowBounds(winID); ok && ww > 0 && wh > 0 {
					px := math.Max(0, math.Min(1, float64(x-wx)/float64(ww)))
					py := math.Max(0, math.Min(1, float64(y-wy)/float64(wh)))
					return true, px, py
				}
			}
			px := math.Max(0, math.Min(1, float64(x)/float64(sw)))
			py := math.Max(0, math.Min(1, float64(y)/float64(sh)))
			return true, px, py
		}
	}
	return false, -1, -1
}

func resolveLinuxDisplayAndXauth() (string, string, bool, bool) {
	return "", "", false, false
}

func isLinuxX11SessionReady() bool {
	return false
}

func isLinuxLoginOrLockScreen() bool {
	return false
}

func sendDirectLinuxPCKeyViaUinput(androidCode int) bool {
	return false
}

func sendDirectLinuxTextViaUinput(text string, pressEnter bool) bool {
	return false
}

func ensureLinuxUnlockPromptReady() bool {
	return false
}

func linuxRenderLoginScreenPlaceholder() ([]byte, error) {
	return nil, fmt.Errorf("not linux")
}
