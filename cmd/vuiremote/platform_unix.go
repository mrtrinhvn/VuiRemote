//go:build !windows

package main

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func sysSetPriority(pid int, prio int) {
	syscall.Setpriority(syscall.PRIO_PROCESS, pid, prio)
}

func sysSetsidAndIgnoreSignals() {
	syscall.Setsid()
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE, syscall.SIGTERM, syscall.SIGINT)
}

func sysIoctl(fd *os.File, req uint, arg uintptr) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), uintptr(req), arg)
	if err != 0 {
		return err
	}
	return nil
}

var (
	linuxDpyCacheMu      sync.Mutex
	linuxDpyChecked      time.Time
	linuxCachedDpy       string
	linuxCachedXauth     string
	linuxCachedIsGDM     bool
	linuxCachedDpyReady  bool
)

func resolveLinuxDisplayAndXauth() (string, string, bool, bool) {
	linuxDpyCacheMu.Lock()
	if time.Since(linuxDpyChecked) < 1200*time.Millisecond && linuxCachedDpyReady {
		d, x, g, r := linuxCachedDpy, linuxCachedXauth, linuxCachedIsGDM, linuxCachedDpyReady
		linuxDpyCacheMu.Unlock()
		return d, x, g, r
	}
	linuxDpyCacheMu.Unlock()

	d, x, g, r := resolveLinuxDisplayAndXauthUncached()
	linuxDpyCacheMu.Lock()
	linuxDpyChecked = time.Now()
	linuxCachedDpy = d
	linuxCachedXauth = x
	linuxCachedIsGDM = g
	linuxCachedDpyReady = r
	linuxDpyCacheMu.Unlock()
	return d, x, g, r
}

func resolveLinuxDisplayAndXauthUncached() (string, string, bool, bool) {
	uid := os.Getuid()
	userXauth := os.Getenv("XAUTHORITY")
	if userXauth == "" {
		userXauth = fmt.Sprintf("/run/user/%d/gdm/Xauthority", uid)
	}
	if info, err := os.Stat(userXauth); err == nil && !info.IsDir() && info.Size() > 0 {
		dpy := os.Getenv("DISPLAY")
		if dpy != "" {
			sock := "/tmp/.X11-unix/X" + strings.TrimPrefix(dpy, ":")
			if _, err := os.Stat(sock); err == nil {
				return dpy, userXauth, false, true
			}
		}
		if _, err := os.Stat("/tmp/.X11-unix/X1"); err == nil {
			return ":1", userXauth, false, true
		}
		if _, err := os.Stat("/tmp/.X11-unix/X0"); err == nil {
			return ":0", userXauth, false, true
		}
		return ":1", userXauth, false, true
	}

	gdmXauth := "/dev/shm/vui_gdm_Xauthority"
	if info, err := os.Stat(gdmXauth); err == nil && !info.IsDir() && info.Size() > 0 {
		if _, err := os.Stat("/tmp/.X11-unix/X0"); err == nil {
			return ":0", gdmXauth, true, true
		}
		if _, err := os.Stat("/tmp/.X11-unix/X1"); err == nil {
			return ":1", gdmXauth, true, true
		}
		return ":0", gdmXauth, true, true
	}

	return ":0", "", true, false
}

func isLinuxX11SessionReady() bool {
	_, _, _, ready := resolveLinuxDisplayAndXauth()
	return ready
}

var (
	linuxLockScreenMu         sync.Mutex
	linuxLockScreenChecked    time.Time
	linuxLockScreenVal        bool
	linuxLockScreenRefreshing bool
)

func getLinuxSessionLockAndLeader() (bool, string) {
	uidLine := fmt.Sprintf("UID=%d", os.Getuid())
	entries, err := os.ReadDir("/run/systemd/sessions")
	if err != nil {
		return false, ""
	}
	var leaderPID string
	lockedOrInactive := false
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || strings.HasSuffix(name, ".ref") {
			continue
		}
		data, err := os.ReadFile("/run/systemd/sessions/" + name)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		isTargetUser := false
		isDisplay := false
		isLockedHint := false
		isActive := true
		var curLeader string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			switch {
			case line == uidLine:
				isTargetUser = true
			case line == "IS_DISPLAY=1" || line == "TYPE=x11" || line == "TYPE=wayland":
				isDisplay = true
			case line == "LOCKED_HINT=1":
				isLockedHint = true
			case line == "ACTIVE=0":
				isActive = false
			case strings.HasPrefix(line, "LEADER="):
				curLeader = strings.TrimPrefix(line, "LEADER=")
			}
		}
		if isTargetUser && isDisplay {
			if curLeader != "" {
				leaderPID = curLeader
			}
			if isLockedHint || !isActive {
				lockedOrInactive = true
			}
		}
	}
	return lockedOrInactive, leaderPID
}

func isLinuxGdmPasswordPromptReady() (bool, time.Duration) {
	_, leaderPID := getLinuxSessionLockAndLeader()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, 0
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid := ent.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' || pid == leaderPID {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil || len(cmdline) == 0 {
			continue
		}
		if bytes.Contains(cmdline, []byte("gdm-password")) {
			if info, errStat := os.Stat("/proc/" + pid); errStat == nil {
				return true, time.Since(info.ModTime())
			}
			return true, 2 * time.Second
		}
	}
	return false, 0
}

func refreshLinuxLockScreenStatus() bool {
	_, _, isGDM, ready := resolveLinuxDisplayAndXauth()
	if !ready || isGDM {
		linuxLockScreenMu.Lock()
		linuxLockScreenChecked = time.Now()
		linuxLockScreenVal = true
		linuxLockScreenRefreshing = false
		linuxLockScreenMu.Unlock()
		return true
	}
	if lockedBySession, _ := getLinuxSessionLockAndLeader(); lockedBySession {
		linuxLockScreenMu.Lock()
		linuxLockScreenChecked = time.Now()
		linuxLockScreenVal = true
		linuxLockScreenRefreshing = false
		linuxLockScreenMu.Unlock()
		return true
	}
	locked := false
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gdbus", "call", "--session",
		"--dest", "org.gnome.ScreenSaver",
		"--object-path", "/org/gnome/ScreenSaver",
		"--method", "org.gnome.ScreenSaver.GetActive")
	cmd.Env = append(os.Environ(), fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Getuid()))
	if out, err := cmd.Output(); err == nil && strings.Contains(string(out), "true") {
		locked = true
	}
	linuxLockScreenMu.Lock()
	linuxLockScreenChecked = time.Now()
	linuxLockScreenVal = locked
	linuxLockScreenRefreshing = false
	linuxLockScreenMu.Unlock()
	return locked
}

func isLinuxLoginOrLockScreen() bool {
	linuxLockScreenMu.Lock()
	if !linuxLockScreenChecked.IsZero() {
		v := linuxLockScreenVal
		age := time.Since(linuxLockScreenChecked)
		if age >= 1200*time.Millisecond && !linuxLockScreenRefreshing {
			linuxLockScreenRefreshing = true
			go refreshLinuxLockScreenStatus()
		}
		linuxLockScreenMu.Unlock()
		return v
	}
	linuxLockScreenRefreshing = true
	linuxLockScreenMu.Unlock()
	return refreshLinuxLockScreenStatus()
}

func sendUinputKeyCombo(code uint16, shift bool) bool {
	locked := !isAndroid() && isLinuxLoginOrLockScreen()
	eventMu.Lock()
	defer eventMu.Unlock()
	if keyboardFd == nil {
		return false
	}
	ok := true
	writeEv := func(typ, c uint16, val int32) {
		var b bytes.Buffer
		writeKernelInputEvent(&b, time.Now(), typ, c, val)
		if _, err := keyboardFd.Write(b.Bytes()); err != nil {
			fmt.Printf("[UINPUT WRITE ERR] code=%d err=%v\n", c, err)
			ok = false
		}
	}
	modWait := 900 * time.Microsecond
	holdWait := 800 * time.Microsecond
	postWait := 700 * time.Microsecond
	if locked {
		modWait = 6 * time.Millisecond
		holdWait = 10 * time.Millisecond
		postWait = 8 * time.Millisecond
	}
	if shift {
		writeEv(1, 42, 1) // KEY_LEFTSHIFT down
		writeEv(0, 0, 0)
		time.Sleep(modWait)
	}
	writeEv(1, code, 1)
	writeEv(0, 0, 0)
	time.Sleep(holdWait)
	writeEv(1, code, 0)
	writeEv(0, 0, 0)
	if shift {
		time.Sleep(modWait)
		writeEv(1, 42, 0) // KEY_LEFTSHIFT up
		writeEv(0, 0, 0)
	}
	time.Sleep(postWait)
	return ok
}

func hotkeyTokenToLinuxKeycode(tok string) (uint16, bool, bool) {
	t := strings.ToLower(strings.TrimSpace(tok))
	switch t {
	case "ctrl", "control", "ctrl_l", "control_l":
		return 29, true, true // KEY_LEFTCTRL
	case "shift", "shift_l":
		return 42, true, true // KEY_LEFTSHIFT
	case "alt", "alt_l":
		return 56, true, true // KEY_LEFTALT
	case "super", "super_l", "meta", "win":
		return 125, true, true // KEY_LEFTMETA
	case "return", "enter", "kp_enter":
		return 28, false, true // KEY_ENTER
	case "tab", "iso_left_tab":
		return 15, false, true // KEY_TAB
	case "backspace", "bksp":
		return 14, false, true // KEY_BACKSPACE
	case "delete", "del":
		return 111, false, true // KEY_DELETE
	case "escape", "esc":
		return 1, false, true // KEY_ESC
	case "space":
		return 57, false, true // KEY_SPACE
	case "up", "arrowup":
		return 103, false, true // KEY_UP
	case "down", "arrowdown":
		return 108, false, true // KEY_DOWN
	case "left", "arrowleft":
		return 105, false, true // KEY_LEFT
	case "right", "arrowright":
		return 106, false, true // KEY_RIGHT
	case "home":
		return 102, false, true // KEY_HOME
	case "end":
		return 107, false, true // KEY_END
	case "page_up", "pageup", "prior":
		return 104, false, true // KEY_PAGEUP
	case "page_down", "pagedown", "next":
		return 109, false, true // KEY_PAGEDOWN
	case "f1":
		return 59, false, true
	case "f2":
		return 60, false, true
	case "f3":
		return 61, false, true
	case "f4":
		return 62, false, true
	case "f5":
		return 63, false, true
	case "f6":
		return 64, false, true
	case "f7":
		return 65, false, true
	case "f8":
		return 66, false, true
	case "f9":
		return 67, false, true
	case "f10":
		return 68, false, true
	case "f11":
		return 87, false, true
	case "f12":
		return 88, false, true
	case "slash":
		return 53, false, true
	case "backslash":
		return 43, false, true
	case "minus":
		return 12, false, true
	case "equal", "plus":
		return 13, false, true
	case "bracketleft":
		return 26, false, true
	case "bracketright":
		return 27, false, true
	case "semicolon":
		return 39, false, true
	case "apostrophe", "quotedbl":
		return 40, false, true
	case "grave", "asciitilde":
		return 41, false, true
	case "comma":
		return 51, false, true
	case "period":
		return 52, false, true
	}
	runes := []rune(t)
	if len(runes) == 1 {
		if code, _, ok := asciiToLinuxKeycode(runes[0]); ok {
			return code, false, true
		}
	}
	return 0, false, false
}

func sendUinputHotkeyCombo(combo string) bool {
	if keyboardFd == nil {
		return false
	}
	parts := strings.Split(strings.TrimSpace(combo), "+")
	var mods []uint16
	var mainKey uint16
	for _, p := range parts {
		if p == "" {
			continue
		}
		code, isMod, ok := hotkeyTokenToLinuxKeycode(p)
		if !ok {
			return false
		}
		if isMod && len(parts) > 1 {
			already := false
			for _, m := range mods {
				if m == code {
					already = true
					break
				}
			}
			if !already {
				mods = append(mods, code)
			}
		} else {
			mainKey = code
		}
	}
	if mainKey == 0 && len(mods) == 1 {
		mainKey = mods[0]
		mods = nil
	}
	if mainKey == 0 {
		return false
	}

	eventMu.Lock()
	defer eventMu.Unlock()
	ok := true
	writeEv := func(typ, c uint16, val int32) {
		var b bytes.Buffer
		writeKernelInputEvent(&b, time.Now(), typ, c, val)
		if _, err := keyboardFd.Write(b.Bytes()); err != nil {
			fmt.Printf("[UINPUT HOTKEY ERR] code=%d err=%v\n", c, err)
			ok = false
		}
	}

	for _, m := range mods {
		writeEv(1, m, 1)
		writeEv(0, 0, 0)
		time.Sleep(2 * time.Millisecond)
	}
	writeEv(1, mainKey, 1)
	writeEv(0, 0, 0)
	time.Sleep(4 * time.Millisecond)
	writeEv(1, mainKey, 0)
	writeEv(0, 0, 0)
	for i := len(mods) - 1; i >= 0; i-- {
		time.Sleep(2 * time.Millisecond)
		writeEv(1, mods[i], 0)
		writeEv(0, 0, 0)
	}
	time.Sleep(2 * time.Millisecond)
	return ok
}

var (
	linuxUnlockPrepMu      sync.Mutex
	lastLinuxLockPrepAt    time.Time
	lastLinuxCurtainLiftAt time.Time
)

func ensureLinuxUnlockPromptReady() bool {
	if keyboardFd == nil {
		return false
	}
	linuxUnlockPrepMu.Lock()
	needPrep := time.Since(lastLinuxLockPrepAt) > 5*time.Second
	if needPrep {
		lastLinuxLockPrepAt = time.Now()
	}
	linuxUnlockPrepMu.Unlock()

	if needPrep {
		if dpy, xauth, _, ready := resolveLinuxDisplayAndXauth(); ready {
			go func(d, x string) {
				ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
				defer cancel()
				cmd := exec.CommandContext(ctx, "xset", "dpms", "force", "on")
				cmd.Env = append(os.Environ(), "DISPLAY="+d, "XAUTHORITY="+x)
				_ = cmd.Run()
			}(dpy, xauth)
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
			defer cancel()
			cmd := exec.CommandContext(ctx, "ibus", "engine", "xkb:us::eng")
			cmd.Env = append(os.Environ(), fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Getuid()))
			_ = cmd.Run()
		}()
	}

	ready, age := isLinuxGdmPasswordPromptReady()
	wasReady := ready
	if !ready {
		linuxUnlockPrepMu.Lock()
		canLift := time.Since(lastLinuxCurtainLiftAt) > 4*time.Second
		if canLift {
			lastLinuxCurtainLiftAt = time.Now()
		}
		linuxUnlockPrepMu.Unlock()

		if canLift {
			fmt.Println("[LINUX LOCK INPUT] Lifting GNOME Lock Screen curtain via uinput KEY_SPACE (57)...")
			sendUinputKeyCombo(57, false)
			for i := 0; i < 30; i++ {
				time.Sleep(45 * time.Millisecond)
				if r, _ := isLinuxGdmPasswordPromptReady(); r {
					ready = true
					break
				}
			}
			// Wait for GNOME Shell CROSSFADE_TIME (300ms) + PAM AskQuestion("Password:") focus grab
			time.Sleep(550 * time.Millisecond)
		}
	} else if age < 600*time.Millisecond {
		time.Sleep(600*time.Millisecond - age)
	}
	return wasReady
}

func asciiToLinuxKeycode(r rune) (uint16, bool, bool) {
	switch r {
	case 'a', 'A':
		return 30, r == 'A', true
	case 'b', 'B':
		return 48, r == 'B', true
	case 'c', 'C':
		return 46, r == 'C', true
	case 'd', 'D':
		return 32, r == 'D', true
	case 'e', 'E':
		return 18, r == 'E', true
	case 'f', 'F':
		return 33, r == 'F', true
	case 'g', 'G':
		return 34, r == 'G', true
	case 'h', 'H':
		return 35, r == 'H', true
	case 'i', 'I':
		return 23, r == 'I', true
	case 'j', 'J':
		return 36, r == 'J', true
	case 'k', 'K':
		return 37, r == 'K', true
	case 'l', 'L':
		return 38, r == 'L', true
	case 'm', 'M':
		return 50, r == 'M', true
	case 'n', 'N':
		return 49, r == 'N', true
	case 'o', 'O':
		return 24, r == 'O', true
	case 'p', 'P':
		return 25, r == 'P', true
	case 'q', 'Q':
		return 16, r == 'Q', true
	case 'r', 'R':
		return 19, r == 'R', true
	case 's', 'S':
		return 31, r == 'S', true
	case 't', 'T':
		return 20, r == 'T', true
	case 'u', 'U':
		return 22, r == 'U', true
	case 'v', 'V':
		return 47, r == 'V', true
	case 'w', 'W':
		return 17, r == 'W', true
	case 'x', 'X':
		return 45, r == 'X', true
	case 'y', 'Y':
		return 21, r == 'Y', true
	case 'z', 'Z':
		return 44, r == 'Z', true
	case '1':
		return 2, false, true
	case '!':
		return 2, true, true
	case '2':
		return 3, false, true
	case '@':
		return 3, true, true
	case '3':
		return 4, false, true
	case '#':
		return 4, true, true
	case '4':
		return 5, false, true
	case '$':
		return 5, true, true
	case '5':
		return 6, false, true
	case '%':
		return 6, true, true
	case '6':
		return 7, false, true
	case '^':
		return 7, true, true
	case '7':
		return 8, false, true
	case '&':
		return 8, true, true
	case '8':
		return 9, false, true
	case '*':
		return 9, true, true
	case '9':
		return 10, false, true
	case '(':
		return 10, true, true
	case '0':
		return 11, false, true
	case ')':
		return 11, true, true
	case '-':
		return 12, false, true
	case '_':
		return 12, true, true
	case '=':
		return 13, false, true
	case '+':
		return 13, true, true
	case '[':
		return 26, false, true
	case '{':
		return 26, true, true
	case ']':
		return 27, false, true
	case '}':
		return 27, true, true
	case '\\':
		return 43, false, true
	case '|':
		return 43, true, true
	case ';':
		return 39, false, true
	case ':':
		return 39, true, true
	case '\'':
		return 40, false, true
	case '"':
		return 40, true, true
	case '`':
		return 41, false, true
	case '~':
		return 41, true, true
	case ',':
		return 51, false, true
	case '<':
		return 51, true, true
	case '.':
		return 52, false, true
	case '>':
		return 52, true, true
	case '/':
		return 53, false, true
	case '?':
		return 53, true, true
	case ' ':
		return 57, false, true
	case '\n', '\r':
		return 28, false, true
	}
	return 0, false, false
}

var vnRuneToTelexMap = map[rune]string{
	'á': "as", 'à': "af", 'ả': "ar", 'ã': "ax", 'ạ': "aj",
	'ă': "aw", 'ắ': "aws", 'ằ': "awf", 'ẳ': "awr", 'ẵ': "awx", 'ặ': "awj",
	'â': "aa", 'ấ': "aas", 'ầ': "aaf", 'ẩ': "aar", 'ẫ': "aax", 'ậ': "aaj",
	'é': "es", 'è': "ef", 'ẻ': "er", 'ẽ': "ex", 'ẹ': "ej",
	'ê': "ee", 'ế': "ees", 'ề': "eef", 'ể': "eer", 'ễ': "eex", 'ệ': "eej",
	'í': "is", 'ì': "if", 'ỉ': "ir", 'ĩ': "ix", 'ị': "ij",
	'ó': "os", 'ò': "of", 'ỏ': "or", 'õ': "ox", 'ọ': "oj",
	'ô': "oo", 'ố': "oos", 'ồ': "oof", 'ổ': "oor", 'ỗ': "oox", 'ộ': "ooj",
	'ơ': "ow", 'ớ': "ows", 'ờ': "owf", 'ở': "owr", 'ỡ': "owx", 'ợ': "owj",
	'ú': "us", 'ù': "uf", 'ủ': "ur", 'ũ': "ux", 'ụ': "uj",
	'ư': "uw", 'ứ': "uws", 'ừ': "uwf", 'ử': "uwr", 'ữ': "uwx", 'ự': "uwj",
	'ý': "ys", 'ỳ': "yf", 'ỷ': "yr", 'ỹ': "yx", 'ỵ': "yj",
	'đ': "dd",
	'Á': "As", 'À': "Af", 'Ả': "Ar", 'Ã': "Ax", 'Ạ': "Aj",
	'Ă': "Aw", 'Ắ': "Aws", 'Ằ': "Awf", 'Ẳ': "Awr", 'Ẵ': "Awx", 'Ặ': "Awj",
	'Â': "Aa", 'Ấ': "Aas", 'Ầ': "Aaf", 'Ẩ': "Aar", 'Ẫ': "Aax", 'Ậ': "Aaj",
	'É': "Es", 'È': "Ef", 'Ẻ': "Er", 'Ẽ': "Ex", 'Ẹ': "Ej",
	'Ê': "Ee", 'Ế': "Ees", 'Ề': "Eef", 'Ể': "Eer", 'Ễ': "Eex", 'Ệ': "Eej",
	'Í': "Is", 'Ì': "If", 'Ỉ': "Ir", 'Ĩ': "Ix", 'Ị': "Ij",
	'Ó': "Os", 'Ò': "Of", 'Ỏ': "Or", 'Õ': "Ox", 'Ọ': "Oj",
	'Ô': "Oo", 'Ố': "Oos", 'Ồ': "Oof", 'Ổ': "Oor", 'Ỗ': "Oox", 'Ộ': "Ooj",
	'Ơ': "Ow", 'Ớ': "Ows", 'Ờ': "Owf", 'Ở': "Owr", 'Ỡ': "Owx", 'Ợ': "Owj",
	'Ú': "Us", 'Ù': "Uf", 'Ủ': "Ur", 'Ũ': "Ux", 'Ụ': "Uj",
	'Ư': "Uw", 'Ứ': "Uws", 'Ừ': "Uwf", 'Ử': "Uwr", 'Ữ': "Uwx", 'Ự': "Uwj",
	'Ý': "Ys", 'Ỳ': "Yf", 'Ỷ': "Yr", 'Ỹ': "Yx", 'Ỵ': "Yj",
	'Đ': "Dd",
}

func expandVnToTelexASCII(s string) string {
	var b strings.Builder
	for _, r := range s {
		if rep, ok := vnRuneToTelexMap[r]; ok {
			b.WriteString(rep)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var (
	lastXsetWakeMu sync.Mutex
	lastXsetWakeAt time.Time
)

func sendDirectLinuxPCKeyViaUinput(androidCode int) bool {
	if keyboardFd == nil {
		return false
	}
	lastXsetWakeMu.Lock()
	shouldWakeDpms := time.Since(lastXsetWakeAt) > 15*time.Second
	if shouldWakeDpms {
		lastXsetWakeAt = time.Now()
	}
	lastXsetWakeMu.Unlock()
	if shouldWakeDpms {
		if dpy, xauth, _, ready := resolveLinuxDisplayAndXauth(); ready {
			go func(d, x string) {
				ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
				defer cancel()
				cmd := exec.CommandContext(ctx, "xset", "dpms", "force", "on")
				cmd.Env = append(os.Environ(), "DISPLAY="+d, "XAUTHORITY="+x)
				_ = cmd.Run()
			}(dpy, xauth)
		}
	}
	var linuxCode uint16
	switch androidCode {
	case 19:
		linuxCode = 103 // UP
	case 20:
		linuxCode = 108 // DOWN
	case 21:
		linuxCode = 105 // LEFT
	case 22:
		linuxCode = 106 // RIGHT
	case 23, 66:
		linuxCode = 28 // ENTER
	case 4, 111:
		linuxCode = 1 // ESC
	case 3:
		linuxCode = 125 // LEFTMETA (Super)
	case 67:
		linuxCode = 14 // BACKSPACE
	case 112:
		linuxCode = 111 // DELETE
	case 61:
		linuxCode = 15 // TAB
	case 122:
		linuxCode = 102 // HOME
	case 123:
		linuxCode = 107 // END
	case 92:
		linuxCode = 104 // PAGEUP
	case 93:
		linuxCode = 109 // PAGEDOWN
	case 85, 62:
		linuxCode = 57 // SPACE
	default:
		linuxCode = 28 // ENTER
	}
	return sendUinputKeyCombo(linuxCode, false)
}

func sendDirectLinuxTextViaUinput(text string, pressEnter bool) bool {
	if keyboardFd == nil {
		return false
	}
	if strings.Trim(text, "\r\n") != "" && (!isLinuxX11SessionReady() || isLinuxLoginOrLockScreen()) {
		ensureLinuxUnlockPromptReady()
	}
	expanded := expandVnToTelexASCII(text)
	sentAny := false
	for _, r := range expanded {
		if code, shift, ok := asciiToLinuxKeycode(r); ok {
			if sendUinputKeyCombo(code, shift) {
				sentAny = true
			}
		}
	}
	if pressEnter {
		time.Sleep(50 * time.Millisecond)
		if sendUinputKeyCombo(28, false) { // KEY_ENTER
			sentAny = true
		}
	}
	fmt.Printf("[LINUX LOCK INPUT] Text via uinput: runes=%d expanded=%d enter=%t ok=%t\n", len([]rune(text)), len(expanded), pressEnter, sentAny)
	return sentAny
}

var (
	linuxLoginJpegMu   sync.Mutex
	linuxLoginJpegData []byte
)

var font5x7 = map[rune][7]uint8{
	'A': {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
	'B': {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E},
	'C': {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E},
	'D': {0x1C, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1C},
	'E': {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F},
	'F': {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10},
	'G': {0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F},
	'H': {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
	'I': {0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E},
	'J': {0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0C},
	'K': {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11},
	'L': {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F},
	'M': {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11},
	'N': {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11},
	'O': {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
	'P': {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10},
	'Q': {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D},
	'R': {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11},
	'S': {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E},
	'T': {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
	'U': {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
	'V': {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04},
	'W': {0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11},
	'X': {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11},
	'Y': {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04},
	'Z': {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F},
	'0': {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E},
	'1': {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E},
	'2': {0x0E, 0x11, 0x01, 0x06, 0x08, 0x10, 0x1F},
	'3': {0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E},
	'4': {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02},
	'5': {0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E},
	'6': {0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E},
	'7': {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08},
	'8': {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E},
	'9': {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C},
	'-': {0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00},
	':': {0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00},
	'.': {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C},
	'(': {0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02},
	')': {0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08},
	'/': {0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10},
	'!': {0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04},
	'[': {0x0E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0E},
	']': {0x0E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0E},
}

func drawText5x7(img *image.RGBA, text string, y int, scale int, col color.RGBA) {
	upper := strings.ToUpper(text)
	runes := []rune(upper)
	charW := 6 * scale
	totalW := len(runes) * charW
	startX := (img.Bounds().Dx() - totalW) / 2
	if startX < 10 {
		startX = 10
	}
	for idx, r := range runes {
		glyph, ok := font5x7[r]
		if !ok {
			continue
		}
		ox := startX + idx*charW
		for row := 0; row < 7; row++ {
			bits := glyph[row]
			for colIdx := 0; colIdx < 5; colIdx++ {
				if (bits & (1 << (4 - colIdx))) != 0 {
					for sy := 0; sy < scale; sy++ {
						for sx := 0; sx < scale; sx++ {
							img.SetRGBA(ox+colIdx*scale+sx, y+row*scale+sy, col)
						}
					}
				}
			}
		}
	}
}

func linuxRenderLoginScreenPlaceholder() ([]byte, error) {
	linuxLoginJpegMu.Lock()
	defer linuxLoginJpegMu.Unlock()
	if len(linuxLoginJpegData) > 0 {
		return linuxLoginJpegData, nil
	}

	w, h := 1280, 720
	img := image.NewRGBA(image.Rect(0, 0, w, h))

	// Dark slate background with blue border card
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{13, 18, 30, 255})
		}
	}
	cardX0, cardY0, cardX1, cardY1 := 140, 110, 1140, 610
	for y := cardY0; y <= cardY1; y++ {
		for x := cardX0; x <= cardX1; x++ {
			if y == cardY0 || y == cardY1 || x == cardX0 || x == cardX1 ||
				y == cardY0+1 || y == cardY1-1 || x == cardX0+1 || x == cardX1-1 {
				img.SetRGBA(x, y, color.RGBA{59, 130, 246, 255})
			} else {
				img.SetRGBA(x, y, color.RGBA{22, 30, 49, 255})
			}
		}
	}

	drawText5x7(img, "POP-OS LINUX: MAN HINH DANG NHAP", 180, 4, color.RGBA{96, 165, 250, 255})
	drawText5x7(img, "TRANG THAI: MAY DA BAT (ONLINE) - CHO MO KHOA", 245, 3, color.RGBA{74, 222, 128, 255})
	drawText5x7(img, "BUOC 1: BAM NUT [OK] DE MO O NHAP MAT KHAU", 340, 3, color.RGBA{241, 245, 249, 255})
	drawText5x7(img, "BUOC 2: BAM [GO CHU] -> NHAP MAT KHAU -> GUI", 405, 3, color.RGBA{251, 191, 36, 255})
	drawText5x7(img, "(VUIKEYBOARD KERNEL UINPUT SAN SANG)", 505, 2, color.RGBA{148, 163, 184, 255})

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 82}); err != nil {
		return nil, err
	}
	linuxLoginJpegData = buf.Bytes()
	return linuxLoginJpegData, nil
}

func winInitPlatform() {}

func winCaptureScreenJpeg(targetW int) ([]byte, error) {
	return nil, fmt.Errorf("not windows")
}

func winSendKey(androidCode int)                          {}
func winSendHotkey(combo string)                          {}
func winTouchTap(px, py float64)                          {}
func winDoubleTap(px, py float64)                         {}
func winRightClick(px, py float64)                        {}
func winMiddleClick(px, py float64)                       {}
func winDragStart(px, py float64)                         {}
func winDragMove(px, py float64)                          {}
func winDragEnd(px, py float64)                           {}
func winDragAtomic(px1, py1, px2, py2 float64)            {}
func winScrollXY(px, py, dx, dy float64, steps int)       {}
func winScroll(up bool)                                   {}
func winRelMouse(dx, dy int)                              {}
func winMouseButton(btn int)                              {}
func winSendText(text string)                                                    {}
func winSendTextEx(text string, bksp int, direct bool)                           {}
func winSendTextDelta(text string, bksp int, moveBefore int, moveAfter int, direct bool) {}
func winSmartSleep()                                      {}
func winWakeDisplay()                                     {}

func winListWindows() []PCWindowInfo {
	return nil
}

func winGetWindowBounds(id string) (int, int, int, int, bool) {
	return 0, 0, 0, 0, false
}

func winFocusWindow(id string, maximize bool) bool {
	return false
}

func winSendImageClipboard(pngPath string, autoPaste bool) error {
	return fmt.Errorf("not windows")
}

func winIsTextInputActive() bool {
	return false
}

func winGetTextInputState() (bool, float64, float64) {
	return false, -1, -1
}


