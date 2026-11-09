package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type InputEvent struct {
	Sec   int32
	Usec  int32
	Type  uint16
	Code  uint16
	Value int32
}

func writeKernelInputEvent(buf *bytes.Buffer, now time.Time, typ, code uint16, val int32) {
	sec := now.Unix()
	usec := (now.UnixNano() % 1e9) / 1000
	if strconv.IntSize == 64 {
		binary.Write(buf, binary.LittleEndian, struct {
			Sec   int64
			Usec  int64
			Type  uint16
			Code  uint16
			Value int32
		}{sec, usec, typ, code, val})
	} else {
		binary.Write(buf, binary.LittleEndian, InputEvent{
			Sec:   int32(sec),
			Usec:  int32(usec),
			Type:  typ,
			Code:  code,
			Value: val,
		})
	}
}

var (
	eventMu      sync.Mutex
	eventFd      *os.File
	mouseFd      *os.File
	touchFd      *os.File
	keyboardFd   *os.File
	myDeviceType = "tx3" // "tx3" or "projector" or "kaw"
	myIP         = ""
	shSem        = make(chan struct{}, 2)
)

type KeystoneData struct {
	mu         sync.RWMutex
	lastCheck  time.Time
	lastPosStr string
	active     bool
	matrix     [9]float64
	lut        []int32
	srcW, srcH int
	dstW, dstH int
}

type authFailureState struct {
	failures    int
	lockedUntil time.Time
	lastAttempt time.Time
}

var (
	globalKeystone  KeystoneData
	globalKawSource = "internal"
	kawSourceMu     sync.RWMutex
	cachedPinMu     sync.Mutex
	cachedPin       = ""
	authSecret      = "vuiremote_auth_v1"
	authAttemptMu   sync.Mutex
	authAttempts    = make(map[string]*authFailureState)
)

func getPinFilePaths() []string {
	paths := []string{"/data/local/tmp/vuiremote_pin.txt"}
	if home := os.Getenv("HOME"); home != "" {
		paths = append([]string{filepath.Join(home, ".config", "vuiremote", "pin.txt")}, paths...)
	}
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		paths = append([]string{filepath.Join(userProfile, ".config", "vuiremote", "pin.txt")}, paths...)
	}
	return paths
}

func generateRandomPin() string {
	for i := 0; i < 10; i++ {
		var b [2]byte
		if _, err := rand.Read(b[:]); err == nil {
			num := (uint32(b[0])<<8 | uint32(b[1])) % 9000
			pin := fmt.Sprintf("%04d", 1000+num)
			if pin != "1111" && pin != "2222" && pin != "8888" && pin != "1234" && pin != "0000" {
				return pin
			}
		}
	}
	return fmt.Sprintf("%04d", 1000+(time.Now().UnixNano()%8999))
}

func saveActivePin(newPin string) error {
	newPin = strings.TrimSpace(newPin)
	cachedPinMu.Lock()
	cachedPin = newPin
	cachedPinMu.Unlock()
	if isAndroid() {
		return os.WriteFile("/data/local/tmp/vuiremote_pin.txt", []byte(newPin+"\n"), 0600)
	}
	paths := getPinFilePaths()
	target := paths[0]
	_ = os.MkdirAll(filepath.Dir(target), 0700)
	return os.WriteFile(target, []byte(newPin+"\n"), 0600)
}

func getActivePin() string {
	if envP := strings.TrimSpace(os.Getenv("VUI_PIN")); envP != "" {
		return envP
	}
	for _, p := range getPinFilePaths() {
		if b, err := os.ReadFile(p); err == nil {
			val := strings.TrimSpace(string(b))
			if val != "" {
				return val
			}
		}
	}
	cachedPinMu.Lock()
	if cachedPin != "" {
		p := cachedPin
		cachedPinMu.Unlock()
		return p
	}
	newPin := generateRandomPin()
	cachedPin = newPin
	cachedPinMu.Unlock()
	_ = saveActivePin(newPin)
	return newPin
}

func computeAuthToken(pin string) string {
	h := sha256.New()
	h.Write([]byte(pin + ":" + authSecret))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func getClientIP(r *http.Request) string {
	if cfIP := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); cfIP != "" {
		return cfIP
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func isRequestFromInternet(r *http.Request) bool {
	return r.Header.Get("Cf-Ray") != "" || r.Header.Get("Cf-Connecting-Ip") != "" || r.Header.Get("X-Forwarded-Proto") != ""
}

func checkAuthRateLimit(ip string) (bool, int) {
	authAttemptMu.Lock()
	defer authAttemptMu.Unlock()
	st, ok := authAttempts[ip]
	if !ok {
		return true, 0
	}
	now := time.Now()
	if now.Before(st.lockedUntil) {
		remSec := int(st.lockedUntil.Sub(now).Seconds())
		if remSec < 1 {
			remSec = 1
		}
		return false, remSec
	}
	if now.Sub(st.lastAttempt) > 10*time.Minute {
		st.failures = 0
	}
	return true, 0
}

func recordAuthResult(ip string, success bool) int {
	authAttemptMu.Lock()
	defer authAttemptMu.Unlock()
	if success {
		delete(authAttempts, ip)
		return 5
	}
	st, ok := authAttempts[ip]
	if !ok {
		st = &authFailureState{}
		authAttempts[ip] = st
	}
	st.failures++
	st.lastAttempt = time.Now()
	if st.failures >= 5 {
		st.lockedUntil = time.Now().Add(15 * time.Minute)
		return 0
	}
	return 5 - st.failures
}

func isLegacySessionHex(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < 32; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isRequestAuthenticated(r *http.Request) bool {
	if !isRequestFromInternet(r) {
		return true
	}

	pin := getActivePin()
	if pin == "" || pin == "none" {
		// Never allow unauthenticated access from the public Internet
		return false
	}

	expectedToken := computeAuthToken(pin)

	if cookie, err := r.Cookie("vui_session"); err == nil && cookie != nil {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(expectedToken)) == 1 {
			return true
		}
		if pin == "8888" && isLegacySessionHex(cookie.Value) {
			return true
		}
	}

	if qAuth := r.URL.Query().Get("auth"); qAuth != "" {
		if subtle.ConstantTimeCompare([]byte(qAuth), []byte(expectedToken)) == 1 {
			return true
		}
		if pin == "8888" && isLegacySessionHex(qAuth) {
			return true
		}
	}
	if hAuth := r.Header.Get("X-Vui-Auth"); hAuth != "" {
		if subtle.ConstantTimeCompare([]byte(hAuth), []byte(expectedToken)) == 1 {
			return true
		}
		if pin == "8888" && isLegacySessionHex(hAuth) {
			return true
		}
	}

	return false
}

func requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if !isRequestAuthenticated(r) {
		fmt.Printf("[AUTH REJECT] path=%s ip=%s cookie=%q\n", r.URL.Path, getClientIP(r), r.Header.Get("Cookie"))
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","pin_required":true}`))
		return false
	}
	return true
}

func getPerspectiveTransform(src [4][2]float64, dst [4][2]float64) [9]float64 {
	x0, y0 := src[0][0], src[0][1]
	x1, y1 := src[1][0], src[1][1]
	x2, y2 := src[2][0], src[2][1]
	x3, y3 := src[3][0], src[3][1]

	dx1 := x1 - x2
	dy1 := y1 - y2
	dx2 := x3 - x2
	dy2 := y3 - y2
	sx := x0 - x1 + x2 - x3
	sy := y0 - y1 + y2 - y3

	denom := dx1*dy2 - dy1*dx2
	if math.Abs(denom) < 1e-7 {
		return [9]float64{1, 0, 0, 0, 1, 0, 0, 0, 1}
	}

	g := (sx*dy2 - sy*dx2) / denom
	h := (dx1*sy - dy1*sx) / denom
	a := x1 - x0 + g*x1
	b := x3 - x0 + h*x3
	c := x0
	d := y1 - y0 + g*y1
	e := y3 - y0 + h*y3
	f := y0

	W := dst[2][0]
	H := dst[2][1]
	if W <= 0 {
		W = 1
	}
	if H <= 0 {
		H = 1
	}

	return [9]float64{
		a / W, b / H, c,
		d / W, e / H, f,
		g / W, h / H, 1.0,
	}
}

func parseKawOffset(line string) (int, int, bool) {
	parts := strings.Split(line, "=")
	if len(parts) != 2 {
		return 0, 0, false
	}
	val := strings.TrimSpace(parts[1])
	sub := strings.Split(val, ":")
	if len(sub) != 2 {
		return 0, 0, false
	}
	xStr := strings.TrimPrefix(strings.TrimSpace(sub[0]), "0x")
	yStr := strings.TrimPrefix(strings.TrimSpace(sub[1]), "0x")
	x, err1 := strconv.ParseInt(xStr, 16, 64)
	y, err2 := strconv.ParseInt(yStr, 16, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return int(x), int(y), true
}

func detectKawSource() (bool, string, string, string) {
	focusOut, err := exec.Command("/system/bin/sh", "-c", "dumpsys window | grep -m 1 mCurrentFocus").Output()
	isHdmi := false
	if err == nil {
		s := string(focusOut)
		if strings.Contains(s, "com.mediatek.wwtv.tvcenter") || strings.Contains(s, "TurnkeyUiMainActivity") || strings.Contains(s, "com.rjpj.inputpanel") || strings.Contains(s, "SourceHDMI") {
			isHdmi = true
		}
	}
	if !isHdmi {
		return false, "internal", "Nội bộ", ""
	}

	activePort := "HDMI"
	tvIn, errIn := exec.Command("/system/bin/sh", "-c", "dumpsys tv_input | grep -m 1 'inputId:.*HW'").Output()
	if errIn == nil {
		sIn := string(tvIn)
		if strings.Contains(sIn, "HW6") {
			activePort = "HDMI 2"
		} else if strings.Contains(sIn, "HW5") {
			activePort = "HDMI 1"
		}
	} else {
		hdmiIn, _ := exec.Command("/system/bin/sh", "-c", "dumpsys hdmi_control | grep mActiveRoutingPath").Output()
		if strings.Contains(string(hdmiIn), "0x2000") {
			activePort = "HDMI 2"
		} else if strings.Contains(string(hdmiIn), "0x1000") {
			activePort = "HDMI 1"
		}
	}

	cecName := ""
	cecOut, err := exec.Command("/system/bin/sh", "-c", "dumpsys hdmi_control | grep -E 'display_name:.*port_id: [12]'").Output()
	if err == nil && len(cecOut) > 0 {
		re := regexp.MustCompile(`display_name:\s*([^ \r\n]+)`)
		m := re.FindStringSubmatch(string(cecOut))
		if len(m) > 1 && m[1] != "A70Pro" {
			cecName = m[1]
		}
	}

	label := activePort
	targetDev := ""
	if strings.Contains(activePort, "2") {
		if cecName != "" {
			label = fmt.Sprintf("HDMI 2 (%s)", cecName)
		} else {
			label = "HDMI 2 (TV360)"
		}
		targetDev = "tv360"
	} else if strings.Contains(activePort, "1") {
		if cecName != "" {
			label = fmt.Sprintf("HDMI 1 (%s)", cecName)
		} else {
			label = "HDMI 1"
		}
	}

	return true, activePort, label, targetDev
}

func detectProjectorSource() (bool, string, string) {
	focusOut, err := exec.Command("/system/bin/sh", "-c", "dumpsys window | grep -m 1 mCurrentFocus").Output()
	if err == nil {
		s := string(focusOut)
		if strings.Contains(s, "tvinput") || strings.Contains(s, "tvplayer") || strings.Contains(s, "SourceHDMI") {
			if strings.Contains(s, "HDMI2") || strings.Contains(s, "hdmi2") {
				return true, "HDMI 2", "HDMI 2"
			}
			return true, "HDMI 1", "HDMI 1"
		}
	}
	return false, "internal", "Nội bộ"
}

func checkAndUpdateKeystone(srcW, srcH, dstW, dstH int) {
	if myDeviceType != "projector" && myDeviceType != "kaw" {
		globalKeystone.mu.Lock()
		globalKeystone.active = false
		globalKeystone.mu.Unlock()
		return
	}

	globalKeystone.mu.Lock()
	defer globalKeystone.mu.Unlock()

	now := time.Now()
	if now.Sub(globalKeystone.lastCheck) < 2000*time.Millisecond &&
		globalKeystone.srcW == srcW && globalKeystone.srcH == srcH &&
		globalKeystone.dstW == dstW && globalKeystone.dstH == dstH {
		return
	}
	globalKeystone.lastCheck = now

	if myDeviceType == "kaw" {
		// On KAW A70, keystone unwarping is ONLY applied when HDMI external input is displayed!
		// Internal Android apps are already rendered 100% rectangular.
		isHdmi, activePort, _, _ := detectKawSource()
		if !isHdmi {
			kawSourceMu.Lock()
			globalKawSource = "internal"
			kawSourceMu.Unlock()
			globalKeystone.active = false
			globalKeystone.lastPosStr = "kaw_internal"
			return
		}

		kawSourceMu.Lock()
		globalKawSource = activePort
		kawSourceMu.Unlock()

		iniData, err := os.ReadFile("/data/trapezoid/trapezoidcorrect_points_offset.ini")
		if err != nil {
			globalKeystone.active = false
			return
		}
		iniStr := string(iniData)
		if iniStr == globalKeystone.lastPosStr &&
			globalKeystone.srcW == srcW && globalKeystone.srcH == srcH &&
			globalKeystone.dstW == dstW && globalKeystone.dstH == dstH &&
			len(globalKeystone.lut) == dstW*dstH {
			return
		}

		var lbOffX, lbOffY, rbOffX, rbOffY, rtOffX, rtOffY, ltOffX, ltOffY int
		lines := strings.Split(iniStr, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "lb") {
				lbOffX, lbOffY, _ = parseKawOffset(line)
			} else if strings.HasPrefix(line, "rb") {
				rbOffX, rbOffY, _ = parseKawOffset(line)
			} else if strings.HasPrefix(line, "rt") {
				rtOffX, rtOffY, _ = parseKawOffset(line)
			} else if strings.HasPrefix(line, "lt") {
				ltOffX, ltOffY, _ = parseKawOffset(line)
			}
		}

		if lbOffX == 0 && lbOffY == 0 && rbOffX == 0 && rbOffY == 0 &&
			rtOffX == 0 && rtOffY == 0 && ltOffX == 0 && ltOffY == 0 {
			globalKeystone.active = false
			globalKeystone.lastPosStr = iniStr
			return
		}

		ltX := float64(ltOffX) * float64(srcW) / 1920.0
		ltY := float64(ltOffY) * float64(srcH) / 1080.0
		rtX := float64(1920-rtOffX) * float64(srcW) / 1920.0
		rtY := float64(rtOffY) * float64(srcH) / 1080.0
		rbX := float64(1920-rbOffX) * float64(srcW) / 1920.0
		rbY := float64(1080-rbOffY) * float64(srcH) / 1080.0
		lbX := float64(lbOffX) * float64(srcW) / 1920.0
		lbY := float64(1080-lbOffY) * float64(srcH) / 1080.0

		srcPts := [4][2]float64{
			{ltX, ltY},
			{rtX, rtY},
			{rbX, rbY},
			{lbX, lbY},
		}
		dstPts := [4][2]float64{
			{0, 0},
			{float64(dstW), 0},
			{float64(dstW), float64(dstH)},
			{0, float64(dstH)},
		}

		M := getPerspectiveTransform(srcPts, dstPts)
		m0, m1, m2 := M[0], M[1], M[2]
		m3, m4, m5 := M[3], M[4], M[5]
		m6, m7, m8 := M[6], M[7], M[8]

		lut := make([]int32, dstW*dstH)
		srcStride := srcW * 4
		idx := 0
		for y := 0; y < dstH; y++ {
			fy := float64(y)
			t0 := m1*fy + m2
			t1 := m4*fy + m5
			t2 := m7*fy + m8
			for x := 0; x < dstW; x++ {
				fx := float64(x)
				denom := m6*fx + t2
				if math.Abs(denom) < 1e-7 {
					denom = 1e-7
				}
				wInv := 1.0 / denom
				sx := int((m0*fx+t0)*wInv + 0.5)
				sy := int((m3*fx+t1)*wInv + 0.5)
				if sx >= 0 && sx < srcW && sy >= 0 && sy < srcH {
					lut[idx] = int32(sy*srcStride + sx*4)
				} else {
					lut[idx] = -1
				}
				idx++
			}
		}

		globalKeystone.matrix = M
		globalKeystone.lut = lut
		globalKeystone.lastPosStr = iniStr
		globalKeystone.srcW = srcW
		globalKeystone.srcH = srcH
		globalKeystone.dstW = dstW
		globalKeystone.dstH = dstH
		globalKeystone.active = true
		fmt.Printf("[KEYSTONE LUT OK] KAW HDMI unwarp LUT built! lt(%.0f,%.0f) rt(%.0f,%.0f) rb(%.0f,%.0f) lb(%.0f,%.0f) -> %dx%d\n",
			ltX, ltY, rtX, rtY, rbX, rbY, lbX, lbY, dstW, dstH)
		return
	}


	enOut, err := exec.Command("/system/bin/getprop", "persist.sys.keystone.enable").Output()
	if err != nil || strings.TrimSpace(string(enOut)) != "true" {
		globalKeystone.active = false
		globalKeystone.lastPosStr = ""
		return
	}

	posOut, err := exec.Command("/system/bin/getprop", "persist.sys.keystone.positions").Output()
	if err != nil {
		globalKeystone.active = false
		return
	}
	posStr := strings.TrimSpace(string(posOut))
	if posStr == "" || posStr == "0,720|1280,720|0,0|1280,0" {
		globalKeystone.active = false
		globalKeystone.lastPosStr = posStr
		return
	}

	if posStr == globalKeystone.lastPosStr &&
		globalKeystone.srcW == srcW && globalKeystone.srcH == srcH &&
		globalKeystone.dstW == dstW && globalKeystone.dstH == dstH &&
		len(globalKeystone.lut) == dstW*dstH {
		return
	}

	// Format on Hyundai Hi3751V553: "ltX,ltY_gl|rtX,rtY_gl|lbX,lbY_gl|rbX,rbY_gl" in 1280x720 GL space (y_img = 720 - y_gl)
	parts := strings.Split(posStr, "|")
	if len(parts) != 4 || srcW <= 0 || srcH <= 0 || dstW <= 0 || dstH <= 0 {
		globalKeystone.active = false
		return
	}

	parseCorner := func(s string) (float64, float64, bool) {
		xy := strings.Split(strings.TrimSpace(s), ",")
		if len(xy) != 2 {
			return 0, 0, false
		}
		x, err1 := strconv.ParseFloat(strings.TrimSpace(xy[0]), 64)
		yGl, err2 := strconv.ParseFloat(strings.TrimSpace(xy[1]), 64)
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		sx := x * float64(srcW) / 1280.0
		sy := (720.0 - yGl) * float64(srcH) / 720.0
		return sx, sy, true
	}

	ltX, ltY, ok0 := parseCorner(parts[0])
	rtX, rtY, ok1 := parseCorner(parts[1])
	lbX, lbY, ok2 := parseCorner(parts[2])
	rbX, rbY, ok3 := parseCorner(parts[3])
	if !ok0 || !ok1 || !ok2 || !ok3 {
		globalKeystone.active = false
		return
	}

	srcPts := [4][2]float64{
		{ltX, ltY},
		{rtX, rtY},
		{rbX, rbY},
		{lbX, lbY},
	}
	dstPts := [4][2]float64{
		{0, 0},
		{float64(dstW), 0},
		{float64(dstW), float64(dstH)},
		{0, float64(dstH)},
	}

	M := getPerspectiveTransform(srcPts, dstPts)
	m0, m1, m2 := M[0], M[1], M[2]
	m3, m4, m5 := M[3], M[4], M[5]
	m6, m7, m8 := M[6], M[7], M[8]

	lut := make([]int32, dstW*dstH)
	srcStride := srcW * 4
	idx := 0
	for y := 0; y < dstH; y++ {
		fy := float64(y)
		t0 := m1*fy + m2
		t1 := m4*fy + m5
		t2 := m7*fy + m8
		for x := 0; x < dstW; x++ {
			fx := float64(x)
			denom := m6*fx + t2
			if math.Abs(denom) < 1e-7 {
				denom = 1e-7
			}
			wInv := 1.0 / denom
			sx := int((m0*fx + t0)*wInv + 0.5)
			sy := int((m3*fx + t1)*wInv + 0.5)
			if sx >= 0 && sx < srcW && sy >= 0 && sy < srcH {
				lut[idx] = int32(sy*srcStride + sx*4)
			} else {
				lut[idx] = -1
			}
			idx++
		}
	}

	globalKeystone.matrix = M
	globalKeystone.lut = lut
	globalKeystone.lastPosStr = posStr
	globalKeystone.srcW = srcW
	globalKeystone.srcH = srcH
	globalKeystone.dstW = dstW
	globalKeystone.dstH = dstH
	globalKeystone.active = true
	fmt.Printf("[KEYSTONE LUT OK] Hyundai unwarp LUT built! lt(%.0f,%.0f) rt(%.0f,%.0f) rb(%.0f,%.0f) lb(%.0f,%.0f) -> %dx%d\n",
		ltX, ltY, rtX, rtY, rbX, rbY, lbX, lbY, dstW, dstH)
}

func unwarpRgbaWithLUT(raw []byte, dstW, dstH int, lut []int32) *image.RGBA {
	out := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	dstPix := out.Pix
	rawLen := len(raw)
	dstIdx := 0
	for i := 0; i < len(lut); i++ {
		sIdx := int(lut[i])
		if sIdx >= 0 && sIdx+3 < rawLen {
			dstPix[dstIdx] = raw[sIdx]
			dstPix[dstIdx+1] = raw[sIdx+1]
			dstPix[dstIdx+2] = raw[sIdx+2]
			dstPix[dstIdx+3] = 255
		} else {
			dstPix[dstIdx] = 0
			dstPix[dstIdx+1] = 0
			dstPix[dstIdx+2] = 0
			dstPix[dstIdx+3] = 255
		}
		dstIdx += 4
	}
	return out
}

func remapTouchToScreen(px, py float64) (float64, float64) {
	// Android WindowManager and TouchInputMapper (VuiTouch) on TX3, KAW, and Hyundai all operate in
	// unwarped 16:9 logical frame coordinates [0..1, 0..1], which match our unwarped 16:9 image 1-to-1!
	return px, py
}

var (
	screenMu                sync.Mutex
	cachedScreen            []byte
	lastGoodScreen          []byte
	lastCaptureTime         time.Time
	lastScreenReqUnixNano   int64
	lastInputInvalidateNano int64
	lastTargetW             int32 = 1280
	detectedWidth           int32 = 1280
	detectedHeight          int32 = 720
	captureWaitMu           sync.Mutex
	captureInFlight         bool
	captureDoneCh           chan struct{}
	captureWakeCh           = make(chan struct{}, 1)
)

func getScreenDimensions() (int, int) {
	return int(atomic.LoadInt32(&detectedWidth)), int(atomic.LoadInt32(&detectedHeight))
}

func invalidateScreenCache() {
	atomic.StoreInt64(&lastInputInvalidateNano, time.Now().UnixNano())
	screenMu.Lock()
	lastCaptureTime = time.Time{}
	screenMu.Unlock()
	select {
	case captureWakeCh <- struct{}{}:
	default:
	}
}

func boostProcessPriority() {
	if !isAndroid() {
		return
	}
	os.WriteFile("/proc/self/oom_score_adj", []byte("-900"), 0644)
	sysSetPriority(0, -15)
	entries, err := os.ReadDir("/proc/self/task")
	if err == nil {
		for _, e := range entries {
			if tid, err := strconv.Atoi(e.Name()); err == nil && tid > 0 {
				sysSetPriority(tid, -15)
			}
		}
	}

	// Protect foreground launcher across TX3 Mini, Hyundai Projector, and KAW Projector, plus gost proxy on TX3
	gatewayAlive := false
	procEntries, err := os.ReadDir("/proc")
	if err == nil {
		for _, pe := range procEntries {
			name := pe.Name()
			if len(name) == 0 || name[0] < '0' || name[0] > '9' {
				continue
			}
			cmdline, err := os.ReadFile("/proc/" + name + "/cmdline")
			if err != nil || len(cmdline) == 0 {
				continue
			}
			fullCmd := string(bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '}))
			firstArg := cmdline
			if nulIdx := bytes.IndexByte(cmdline, 0); nulIdx >= 0 {
				firstArg = cmdline[:nulIdx]
			}
			pkg := strings.TrimSpace(string(firstArg))

			isLauncher := (pkg == "com.spocky.projengmenu" || pkg == "com.newlink.overseaslauncher" || pkg == "io.freemytv" || pkg == "io.freemytv:home")
			if isLauncher {
				if pid, err := strconv.Atoi(name); err == nil && pid > 0 {
					sysSetPriority(pid, -10)
				}
				if oomBytes, err := os.ReadFile("/proc/" + name + "/oom_score_adj"); err == nil {
					if oomVal, err := strconv.Atoi(strings.TrimSpace(string(oomBytes))); err == nil && oomVal >= 400 {
						os.WriteFile("/proc/"+name+"/oom_score_adj", []byte("100"), 0644)
					}
				}
			} else if myDeviceType == "tx3" && (strings.Contains(pkg, "/gost") || strings.Contains(fullCmd, "run_dnse_gateway.sh")) {
				gatewayAlive = true
				// Lock gost proxy & watchdog script at oom_score_adj = -900 (immune to OOM killer) and nice -10
				os.WriteFile("/proc/"+name+"/oom_score_adj", []byte("-900"), 0644)
				if pid, err := strconv.Atoi(name); err == nil && pid > 0 {
					sysSetPriority(pid, -10)
				}
			}
		}
	}
	if myDeviceType == "tx3" {
		if !gatewayAlive {
			exec.Command("/system/bin/sh", "-c", "nohup /data/local/dnse_gateway/run_dnse_gateway.sh >/dev/null 2>&1 &").Start()
		}
		maintainTX3NetworkFailover()
		// Ensure cloudflared tunnel is running on TX3 Mini
		tunnelAlive := false
		if procEntries, err := os.ReadDir("/proc"); err == nil {
			for _, pe := range procEntries {
				name := pe.Name()
				if len(name) == 0 || name[0] < '0' || name[0] > '9' {
					continue
				}
				cmdline, err := os.ReadFile("/proc/" + name + "/cmdline")
				if err == nil && strings.Contains(string(cmdline), "cloudflared") {
					tunnelAlive = true
					break
				}
			}
		}
		if !tunnelAlive {
			if _, err := os.Stat("/data/local/tmp/cloudflared"); err == nil {
				exec.Command("/system/bin/sh", "-c", "export SSL_CERT_FILE=/data/local/tmp/cacert.pem; nohup /data/local/tmp/cloudflared tunnel --url http://127.0.0.1:8080 --no-autoupdate >/data/local/tmp/cloudflared.log 2>&1 &").Start()
			}
		}
		go syncTunnelURLToGist()
	}
}

var (
	gistSyncMu          sync.Mutex
	lastSyncedTunnelURL string
)

type GistSyncConfig struct {
	GistID   string `json:"gist_id"`
	Token    string `json:"token"`
	ShortURL string `json:"short_url"`
}

func getTunnelLogPaths() []string {
	paths := []string{"/data/local/tmp/cloudflared.log", "/tmp/cloudflared.log"}
	if home := os.Getenv("HOME"); home != "" {
		paths = append([]string{filepath.Join(home, ".config", "vuiremote", "cloudflared.log")}, paths...)
	}
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		paths = append([]string{filepath.Join(userProfile, ".config", "vuiremote", "cloudflared.log")}, paths...)
	}
	return paths
}

func getGistSyncConfigPaths() []string {
	paths := []string{"/data/local/tmp/vui_gist_sync.json"}
	if home := os.Getenv("HOME"); home != "" {
		paths = append([]string{filepath.Join(home, ".config", "vuiremote", "vui_gist_sync.json")}, paths...)
	}
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		paths = append([]string{filepath.Join(userProfile, ".config", "vuiremote", "vui_gist_sync.json")}, paths...)
	}
	return paths
}

func readActiveTunnelURL() string {
	re := regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)
	for _, p := range getTunnelLogPaths() {
		if logBytes, err := os.ReadFile(p); err == nil {
			matches := re.FindAllString(string(logBytes), -1)
			if len(matches) > 0 {
				return matches[len(matches)-1]
			}
		}
	}
	return ""
}

func readGistSyncConfig() GistSyncConfig {
	var cfg GistSyncConfig
	for _, p := range getGistSyncConfigPaths() {
		if cfgBytes, err := os.ReadFile(p); err == nil {
			if json.Unmarshal(cfgBytes, &cfg) == nil && (cfg.GistID != "" || cfg.ShortURL != "") {
				break
			}
		}
	}
	if envShort := strings.TrimSpace(os.Getenv("VUI_SHORT_URL")); envShort != "" {
		cfg.ShortURL = envShort
	}
	return cfg
}

func syncTunnelURLToGist() {
	gistSyncMu.Lock()
	defer gistSyncMu.Unlock()

	tunnelURL := readActiveTunnelURL()
	if tunnelURL == "" || tunnelURL == lastSyncedTunnelURL {
		return
	}

	cfg := readGistSyncConfig()
	if cfg.GistID == "" || cfg.Token == "" {
		return
	}

	innerContent := fmt.Sprintf(`{"url":"%s","updated":%d}`, tunnelURL, time.Now().Unix())
	payload := map[string]interface{}{
		"files": map[string]interface{}{
			"vui_tunnel.json": map[string]string{
				"content": innerContent,
			},
		},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	req, err := http.NewRequest("PATCH", "https://api.github.com/gists/"+cfg.GistID, bytes.NewReader(bodyBytes))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VuiRemote-Hub")

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			lastSyncedTunnelURL = tunnelURL
			targetLabel := cfg.ShortURL
			if targetLabel == "" {
				targetLabel = "GitHub Gist " + cfg.GistID
			}
			fmt.Printf("[GIST SYNC OK] Synced new Cloudflare URL %s to %s\n", tunnelURL, targetLabel)
		}
	}
}

var lastTX3NetMode string

func maintainTX3NetworkFailover() {
	if !isAndroid() || myDeviceType != "tx3" {
		return
	}
	carrierBytes, err := os.ReadFile("/sys/class/net/eth0/carrier")
	ethPlugged := (err == nil && strings.TrimSpace(string(carrierBytes)) == "1")

	if ethPlugged {
		// Ethernet cable is physically connected: ensure 192.168.1.88 & .140 are on eth0 and NOT hijacked by wlan0
		script := "ip addr del 192.168.1.88/24 dev wlan0 2>/dev/null; " +
			"ip addr del 192.168.1.140/24 dev wlan0 2>/dev/null; " +
			"ip addr add 192.168.1.88/24 brd 192.168.1.255 dev eth0 2>/dev/null; " +
			"ip addr add 192.168.1.140/24 brd 192.168.1.255 dev eth0 2>/dev/null; " +
			"ip route replace 192.168.1.0/24 dev eth0 src 192.168.1.88 table main 2>/dev/null; " +
			"ip route replace default via 192.168.1.1 dev eth0 table main 2>/dev/null; " +
			"ip rule del from all lookup wlan0 pref 9050 2>/dev/null"
		exec.Command("/system/bin/sh", "-c", script).Run()
		if lastTX3NetMode != "eth0" {
			lastTX3NetMode = "eth0"
			fmt.Println("[TX3 NET FAILOVER] Active link: Ethernet (eth0 -> 192.168.1.88)")
			exec.Command("/system/bin/sh", "-c", "while ip rule del from all lookup main pref 9000 2>/dev/null; do :; done; ip rule add from all lookup main pref 9000 2>/dev/null; ping -c 1 -W 1 192.168.1.1 >/dev/null 2>&1 &").Start()
		}
	} else {
		// Ethernet cable unplugged ("tuột dây LAN"): automatically fail over to Wi-Fi (wlan0) keeping 192.168.1.88!
		script := "svc wifi enable 2>/dev/null; " +
			"ip addr del 192.168.1.88/24 dev eth0 2>/dev/null; " +
			"ip addr del 192.168.1.140/24 dev eth0 2>/dev/null; " +
			"ip addr add 192.168.1.88/24 brd 192.168.1.255 dev wlan0 2>/dev/null; " +
			"ip addr add 192.168.1.140/24 brd 192.168.1.255 dev wlan0 2>/dev/null; " +
			"ip route replace 192.168.1.0/24 dev wlan0 src 192.168.1.88 table main 2>/dev/null; " +
			"ip route replace default via 192.168.1.1 dev wlan0 table main 2>/dev/null; " +
			"ip rule del from all lookup wlan0 pref 9050 2>/dev/null; " +
			"ip rule add from all lookup wlan0 pref 9050 2>/dev/null"
		exec.Command("/system/bin/sh", "-c", script).Run()
		if lastTX3NetMode != "wlan0" {
			lastTX3NetMode = "wlan0"
			fmt.Println("[TX3 NET FAILOVER] Ethernet unplugged! Switched to Wi-Fi (wlan0 -> 192.168.1.88)")
			exec.Command("/system/bin/sh", "-c", "ping -c 1 -W 1 192.168.1.1 >/dev/null 2>&1; ping -c 1 -W 1 192.168.1.154 >/dev/null 2>&1 &").Start()
		}
	}
}

func isLauncherInForeground() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		name := e.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + name + "/cmdline")
		if err != nil || len(cmdline) == 0 {
			continue
		}
		if nulIdx := bytes.IndexByte(cmdline, 0); nulIdx >= 0 {
			cmdline = cmdline[:nulIdx]
		}
		pkg := strings.TrimSpace(string(cmdline))
		if pkg == "com.spocky.projengmenu" || pkg == "me.efesser.projectivy" ||
			pkg == "com.newlink.overseaslauncher" || pkg == "io.freemytv:home" || pkg == "io.freemytv" ||
			pkg == "com.example.trapezoid" || pkg == "com.google.android.tvlauncher" ||
			pkg == "com.google.android.leanbacklauncher" || pkg == "com.actions.atv.launcher" ||
			pkg == "com.mstar.tv.tvplayer.ui" {
			oom, err := os.ReadFile("/proc/" + name + "/oom_score_adj")
			if err == nil {
				oomVal, err := strconv.Atoi(strings.TrimSpace(string(oom)))
				if err == nil && oomVal <= 750 {
					return true
				}
			}
		}
	}
	return false
}

func doCaptureScreenJpeg(targetW int) ([]byte, error) {
	captureWaitMu.Lock()
	if captureInFlight {
		ch := captureDoneCh
		captureWaitMu.Unlock()
		<-ch
		screenMu.Lock()
		res := lastGoodScreen
		screenMu.Unlock()
		if len(res) > 0 {
			return res, nil
		}
		return nil, fmt.Errorf("concurrent capture failed")
	}
	captureInFlight = true
	captureDoneCh = make(chan struct{})
	captureWaitMu.Unlock()

	defer func() {
		captureWaitMu.Lock()
		captureInFlight = false
		close(captureDoneCh)
		captureWaitMu.Unlock()
	}()

	sysSetPriority(0, -15)

	if !isAndroid() {
		out, err := captureScreenLinuxPC(targetW)
		if err == nil && len(out) > 100 {
			screenMu.Lock()
			cachedScreen = out
			lastGoodScreen = out
			lastCaptureTime = time.Now()
			screenMu.Unlock()
			return out, nil
		}
		screenMu.Lock()
		fallback := lastGoodScreen
		screenMu.Unlock()
		if len(fallback) > 0 {
			return fallback, nil
		}
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()

	// Screencap inherits nice -15 from the calling Go OS thread
	cmd := exec.CommandContext(ctx, "/system/bin/screencap")
	out, err := cmd.Output()
	if err != nil || len(out) < 12 {
		screenMu.Lock()
		fallback := lastGoodScreen
		screenMu.Unlock()
		if len(fallback) > 0 {
			return fallback, nil
		}
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("screencap output too short: %d", len(out))
	}

	w := int(binary.LittleEndian.Uint32(out[0:4]))
	h := int(binary.LittleEndian.Uint32(out[4:8]))
	if w <= 0 || h <= 0 || len(out) < 12+w*h*4 {
		screenMu.Lock()
		fallback := lastGoodScreen
		screenMu.Unlock()
		if len(fallback) > 0 {
			return fallback, nil
		}
		return nil, fmt.Errorf("invalid screen dimensions: %dx%d", w, h)
	}

	atomic.StoreInt32(&detectedWidth, int32(w))
	atomic.StoreInt32(&detectedHeight, int32(h))

	scale := 1
	if w >= 1920 && targetW > 0 && targetW <= 1024 {
		scale = 2
	}

	dstW := w / scale
	dstH := h / scale

	checkAndUpdateKeystone(w, h, dstW, dstH)

	globalKeystone.mu.RLock()
	keystoneActive := globalKeystone.active
	lut := globalKeystone.lut
	globalKeystone.mu.RUnlock()

	var img image.Image
	raw := out[12 : 12+w*h*4]

	if keystoneActive && len(lut) == dstW*dstH {
		img = unwarpRgbaWithLUT(raw, dstW, dstH, lut)
	} else if scale == 1 {
		// Zero-copy full HD RGBA wrapper for maximum sharpness and speed
		img = &image.RGBA{
			Pix:    raw,
			Stride: w * 4,
			Rect:   image.Rect(0, 0, w, h),
		}
	} else {
		dstW := w / scale
		dstH := h / scale
		rgba := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
		pix := rgba.Pix
		dstIdx := 0
		for y := 0; y < dstH; y++ {
			rowOffset := (y * scale) * w * 4
			for x := 0; x < dstW; x++ {
				idx := rowOffset + (x*scale)*4
				if idx+3 < len(raw) {
					pix[dstIdx] = raw[idx]
					pix[dstIdx+1] = raw[idx+1]
					pix[dstIdx+2] = raw[idx+2]
					pix[dstIdx+3] = 255
				}
				dstIdx += 4
			}
		}
		img = rgba
	}

	var buf bytes.Buffer
	err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 88})
	if err != nil {
		return nil, err
	}

	encoded := buf.Bytes()
	now := time.Now()
	lastIn := atomic.LoadInt64(&lastInputInvalidateNano)
	screenMu.Lock()
	cachedScreen = encoded
	lastGoodScreen = encoded
	if now.UnixNano() > lastIn {
		lastCaptureTime = now
	}
	screenMu.Unlock()
	return encoded, nil
}

func startScreenCaptureLoop() {
	if !isAndroid() && runtime.GOOS == "linux" {
		// Linux PC uses an on-demand low-latency MJPEG stream in getLinuxPCMjpegStreamFrame;
		// running a separate background polling loop wastes CPU and contends on captureWaitMu.
		return
	}
	_, _ = doCaptureScreenJpeg(1920)
	for {
		lastReq := time.Unix(0, atomic.LoadInt64(&lastScreenReqUnixNano))
		if time.Since(lastReq) > 3500*time.Millisecond {
			select {
			case <-captureWakeCh:
			case <-time.After(1500 * time.Millisecond):
				continue
			}
		}
		tw := int(atomic.LoadInt32(&lastTargetW))
		if tw <= 0 {
			tw = 1920
		}
		start := time.Now()
		_, _ = doCaptureScreenJpeg(tw)
		elapsed := time.Since(start)
		minInterval := 95 * time.Millisecond
		lastIn := time.Unix(0, atomic.LoadInt64(&lastInputInvalidateNano))
		if time.Since(lastIn) < 4*time.Second {
			minInterval = 40 * time.Millisecond
		}
		if elapsed < minInterval {
			select {
			case <-captureWakeCh:
			case <-time.After(minInterval - elapsed):
			}
		}
	}
}

func captureScreenJpeg(targetW int) ([]byte, error) {
	atomic.StoreInt64(&lastScreenReqUnixNano, time.Now().UnixNano())
	if targetW > 0 {
		atomic.StoreInt32(&lastTargetW, int32(targetW))
	}
	if !isAndroid() && runtime.GOOS == "linux" {
		return captureScreenLinuxPC(targetW)
	}
	select {
	case captureWakeCh <- struct{}{}:
	default:
	}

	lastIn := atomic.LoadInt64(&lastInputInvalidateNano)
	screenMu.Lock()
	fresh := time.Since(lastCaptureTime) < 65*time.Millisecond && lastCaptureTime.UnixNano() > lastIn && len(cachedScreen) > 0
	if fresh {
		res := cachedScreen
		screenMu.Unlock()
		return res, nil
	}
	hasFallback := len(lastGoodScreen) > 0
	screenMu.Unlock()

	// If we already have a previous frame (e.g. on Hyundai where screencap takes ~1.6s),
	// wait up to 750ms for the new frame; if still capturing, return lastGoodScreen immediately
	// so HTTP /api/screen never times out, while the background loop finishes the new frame!
	if hasFallback {
		done := make(chan struct{})
		go func() {
			_, _ = doCaptureScreenJpeg(targetW)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(750 * time.Millisecond):
		}
		screenMu.Lock()
		res := lastGoodScreen
		screenMu.Unlock()
		if len(res) > 0 {
			return res, nil
		}
	}

	return doCaptureScreenJpeg(targetW)
}

type DeviceInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Icon     string `json:"icon"`
	Host     string `json:"host"`
	MAC      string `json:"mac"`
	Type     string `json:"type"`     // "box", "projector", "pc", "tv"
	Platform string `json:"platform"` // "android", "linux", "windows", "darwin"
	Online   bool   `json:"online"`
	HasWOL   bool   `json:"has_wol"`
	LastSeen int64  `json:"last_seen"`
}

var (
	deviceRegistryMu sync.RWMutex
	deviceRegistry   = make(map[string]*DeviceInfo)
)

func isAndroid() bool {
	_, err := os.Stat("/system/bin/sh")
	return err == nil
}

func getHostName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "PC"
}

func getLocalMAC() string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
				return iface.HardwareAddr.String()
			}
		}
	}
	return "e4:54:e8:8c:69:30"
}

func getDevicesFilePath() string {
	if envPath := strings.TrimSpace(os.Getenv("VUI_DEVICES_FILE")); envPath != "" {
		return envPath
	}
	if info, err := os.Stat("devices.json"); err == nil && !info.IsDir() {
		return "devices.json"
	}
	if isAndroid() {
		return "/data/local/tmp/devices.json"
	}
	home := os.Getenv("HOME")
	if home != "" {
		dir := home + "/.config/vuiremote"
		os.MkdirAll(dir, 0755)
		return dir + "/devices.json"
	}
	return "devices.json"
}

func isOwnerDefaultEnvironment() bool {
	h := strings.ToLower(getHostName())
	if h == "pop-os" || h == "laptop-2fdekp1n" {
		return true
	}
	ip := getCurrentLocalIP()
	switch ip {
	case "192.168.1.88", "192.168.1.140", "192.168.1.154", "192.168.1.55", "192.168.1.135", "192.168.1.138":
		return true
	}
	return false
}

func initDefaultDevices() {
	deviceRegistryMu.Lock()
	defer deviceRegistryMu.Unlock()

	loadedFromFile := false
	if data, err := os.ReadFile(getDevicesFilePath()); err == nil {
		var saved map[string]*DeviceInfo
		if err := json.Unmarshal(data, &saved); err == nil && len(saved) > 0 {
			for k, v := range saved {
				if v != nil && v.ID != "" {
					if v.ID == "pc" && v.Host == "192.168.1.161:8090" {
						v.Host = "192.168.1.154:8090"
					}
					deviceRegistry[k] = v
					loadedFromFile = true
				}
			}
		}
	}

	if loadedFromFile {
		return
	}

	if isOwnerDefaultEnvironment() {
		deviceRegistry["tx3"] = &DeviceInfo{
			ID:       "tx3",
			Name:     "Tanix TX3 Mini",
			Icon:     "📺",
			Host:     "192.168.1.88:8080",
			MAC:      "",
			Type:     "box",
			Platform: "android",
			Online:   true,
			HasWOL:   false,
			LastSeen: time.Now().Unix(),
		}
		deviceRegistry["pc"] = &DeviceInfo{
			ID:       "pc",
			Name:     "Máy tính (" + getHostName() + ")",
			Icon:     "💻",
			Host:     "192.168.1.154:8090",
			MAC:      "e4:54:e8:8c:69:30",
			Type:     "pc",
			Platform: "linux",
			Online:   false,
			HasWOL:   true,
			LastSeen: 0,
		}
		deviceRegistry["win11"] = &DeviceInfo{
			ID:       "win11",
			Name:     "Windows 11 (LAPTOP-2FDEKP1N)",
			Icon:     "💻",
			Host:     "192.168.1.55:8090",
			MAC:      "58:6c:25:82:10:7c",
			Type:     "pc",
			Platform: "windows",
			Online:   false,
			HasWOL:   true,
			LastSeen: 0,
		}
		deviceRegistry["projector"] = &DeviceInfo{
			ID:       "projector",
			Name:     "Máy chiếu Hyundai",
			Icon:     "📽",
			Host:     "192.168.1.135:8080",
			MAC:      "",
			Type:     "projector",
			Platform: "android",
			Online:   false,
			HasWOL:   false,
			LastSeen: 0,
		}
		deviceRegistry["kaw"] = &DeviceInfo{
			ID:       "kaw",
			Name:     "Máy chiếu KAW A70 Pro",
			Icon:     "📽",
			Host:     "192.168.1.138:8080",
			MAC:      "",
			Type:     "projector",
			Platform: "android",
			Online:   false,
			HasWOL:   false,
			LastSeen: 0,
		}
		deviceRegistry["tv360"] = &DeviceInfo{
			ID:       "tv360",
			Name:     "Viettel TV360 Box",
			Icon:     "📦",
			Host:     "192.168.1.154:8089",
			MAC:      "",
			Type:     "box",
			Platform: "android",
			Online:   false,
			HasWOL:   false,
			LastSeen: 0,
		}
		return
	}

	self := buildSelfDeviceInfo()
	deviceRegistry[self.ID] = &self
}

func saveDevicesToFile() {
	deviceRegistryMu.RLock()
	defer deviceRegistryMu.RUnlock()
	data, err := json.MarshalIndent(deviceRegistry, "", "  ")
	if err == nil {
		os.WriteFile(getDevicesFilePath(), data, 0644)
	}
}

func getDeviceHost(dev string) string {
	deviceRegistryMu.RLock()
	defer deviceRegistryMu.RUnlock()

	if d, ok := deviceRegistry[dev]; ok && d.Host != "" {
		return d.Host
	}
	if strings.Contains(dev, ":") {
		return dev
	}
	switch dev {
	case "tx3", "192.168.1.88", "192.168.1.140", "192.168.1.67":
		return "192.168.1.88:8080"
	case "kaw", "192.168.1.138":
		return "192.168.1.138:8080"
	case "projector", "192.168.1.135":
		return "192.168.1.135:8080"
	case "pc", "192.168.1.154", "192.168.1.161":
		return "192.168.1.154:8090"
	case "win11", "192.168.1.55":
		return "192.168.1.55:8090"
	case "tv360", "192.168.1.11":
		return "192.168.1.154:8089"
	}
	return ""
}

func getActiveSubnetPrefix() string {
	ip := getCurrentLocalIP()
	if parts := strings.Split(ip, "."); len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.", parts[0], parts[1], parts[2])
	}
	return "192.168.1."
}

func getActiveBroadcastTargets(port int) []string {
	prefix := getActiveSubnetPrefix()
	bcast := fmt.Sprintf("%s255:%d", prefix, port)
	globalBcast := fmt.Sprintf("255.255.255.255:%d", port)
	if prefix != "192.168.1." {
		return []string{bcast, globalBcast, fmt.Sprintf("192.168.1.255:%d", port)}
	}
	return []string{bcast, globalBcast}
}

func sendWoL(macStr string) error {
	macStr = strings.TrimSpace(macStr)
	hwAddr, err := net.ParseMAC(macStr)
	if err != nil {
		return fmt.Errorf("invalid MAC '%s': %w", macStr, err)
	}

	var packet [102]byte
	copy(packet[0:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	for i := 6; i < 102; i += 6 {
		copy(packet[i:i+6], hwAddr)
	}

	targets := append(getActiveBroadcastTargets(9), getActiveBroadcastTargets(7)...)
	var sentCount int
	for _, target := range targets {
		addr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			continue
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			continue
		}
		conn.Write(packet[:])
		conn.Close()
		sentCount++
	}
	if sentCount == 0 {
		return fmt.Errorf("failed to broadcast to any UDP targets")
	}
	return nil
}

func isOwnLocalIP(target string) bool {
	if target == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
		target = h
	}
	if target == "127.0.0.1" || target == "localhost" || target == myIP {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil && ip4.String() == target {
					return true
				}
			}
		}
	}
	return false
}

func getCurrentLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		var lanPrimary, fallback string
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ip := ip4.String()
					if myDeviceType == "tx3" && ip == "192.168.1.88" {
						myIP = ip
						return ip
					}
					if myDeviceType == "pc" && ip == "192.168.1.154" {
						myIP = ip
						return ip
					}
					if strings.HasPrefix(ip, "192.168.1.") && ip != "192.168.1.140" && ip != "192.168.1.161" {
						if lanPrimary == "" {
							lanPrimary = ip
						}
					} else if fallback == "" && !strings.HasPrefix(ip, "172.") && !strings.HasPrefix(ip, "100.") {
						fallback = ip
					}
				}
			}
		}
		if lanPrimary != "" {
			myIP = lanPrimary
			return lanPrimary
		}
		if fallback != "" {
			myIP = fallback
			return fallback
		}
	}
	return myIP
}

func getListenPort() int {
	listenPort := 8080
	if pStr := os.Getenv("PORT"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
			return p
		}
	} else if !isAndroid() {
		listenPort = 8090
	}
	return listenPort
}

func buildSelfDeviceInfo() DeviceInfo {
	curIP := getCurrentLocalIP()
	if curIP == "" {
		if myDeviceType == "tx3" {
			curIP = "192.168.1.88"
		} else {
			curIP = "192.168.1.154"
		}
	}
	hostAddr := fmt.Sprintf("%s:%d", curIP, getListenPort())
	reg := DeviceInfo{
		ID:       myDeviceType,
		Name:     "Máy tính (" + getHostName() + ")",
		Icon:     "💻",
		Host:     hostAddr,
		MAC:      getLocalMAC(),
		Type:     "pc",
		Platform: "linux",
		Online:   true,
		HasWOL:   true,
		LastSeen: time.Now().Unix(),
	}
	if runtime.GOOS == "windows" {
		reg.Name = "Windows 11 (" + getHostName() + ")"
		reg.Platform = "windows"
	} else if isAndroid() {
		reg.Platform = "android"
		reg.HasWOL = false
		switch myDeviceType {
		case "tx3":
			reg.Name = "Tanix TX3 Mini"
			reg.Icon = "📺"
			reg.Type = "box"
		case "projector":
			reg.Name = "Máy chiếu Hyundai"
			reg.Icon = "📽"
			reg.Type = "projector"
		case "kaw":
			reg.Name = "Máy chiếu KAW A70 Pro"
			reg.Icon = "📽"
			reg.Type = "projector"
		default:
			reg.Name = "Thiết bị " + strings.ToUpper(myDeviceType)
			reg.Icon = "📱"
			reg.Type = "box"
		}
	}
	return reg
}

func updatePeerInRegistry(reg DeviceInfo) {
	if reg.ID == "" || reg.Host == "" {
		return
	}
	reg.Online = true
	reg.LastSeen = time.Now().Unix()
	if reg.MAC != "" && reg.Type == "pc" {
		reg.HasWOL = true
	}

	changed := false
	deviceRegistryMu.Lock()
	old, exists := deviceRegistry[reg.ID]
	if !exists || old.Host != reg.Host || (reg.MAC != "" && old.MAC != reg.MAC) {
		changed = true
	}
	deviceRegistry[reg.ID] = &reg
	deviceRegistryMu.Unlock()

	if changed {
		saveDevicesToFile()
		fmt.Printf("[VUI MESH] Discovered/Updated peer '%s' (%s) at %s [MAC: %s]\n", reg.ID, reg.Name, reg.Host, reg.MAC)
	}
}

func startUDPMeshDiscovery() {
	// 1. Listen for UDP mesh beacons on :19888
	go func() {
		addr, err := net.ResolveUDPAddr("udp4", ":19888")
		if err != nil {
			return
		}
		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			fmt.Printf("[VUI MESH WARN] UDP :19888 listen failed: %v\n", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 2048)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil || n <= 0 {
				continue
			}
			var reg DeviceInfo
			if err := json.Unmarshal(buf[:n], &reg); err == nil && reg.ID != "" {
				// If sender IP differs from reported Host IP on LAN, prefer actual packet source IP
				if remoteAddr != nil && remoteAddr.IP != nil && !remoteAddr.IP.IsLoopback() {
					_, port, err := net.SplitHostPort(reg.Host)
					if err != nil || port == "" {
						port = "8080"
					}
					reg.Host = fmt.Sprintf("%s:%s", remoteAddr.IP.String(), port)
				}
				updatePeerInRegistry(reg)
			}
		}
	}()

	// 2. Broadcast our own beacon every 8 seconds so all peers auto-discover our current IP
	go func() {
		time.Sleep(1 * time.Second)
		for {
			selfInfo := buildSelfDeviceInfo()
			updatePeerInRegistry(selfInfo)
			b, err := json.Marshal(selfInfo)
			if err == nil {
				for _, t := range getActiveBroadcastTargets(19888) {
					if raddr, err := net.ResolveUDPAddr("udp4", t); err == nil {
						if c, err := net.DialUDP("udp4", nil, raddr); err == nil {
							c.Write(b)
							c.Close()
						}
					}
				}
			}
			time.Sleep(8 * time.Second)
		}
	}()
}

var (
	subnetScanInFlight int32
	lastSubnetScanUnix int64
)

func discoverMovedPeersOnSubnet() {
	nowUnix := time.Now().Unix()
	if nowUnix-atomic.LoadInt64(&lastSubnetScanUnix) < 90 {
		return
	}
	if !atomic.CompareAndSwapInt32(&subnetScanInFlight, 0, 1) {
		return
	}
	atomic.StoreInt64(&lastSubnetScanUnix, nowUnix)
	defer atomic.StoreInt32(&subnetScanInFlight, 0)

	// Collect ONLY reachable ARP table entries (flag 0x2) + known peer candidate IPs.
	seen := make(map[string]bool)
	var ips []string
	prefix := getActiveSubnetPrefix()
	if arpBytes, err := os.ReadFile("/proc/net/arp"); err == nil {
		lines := strings.Split(string(arpBytes), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 4 && (strings.HasPrefix(fields[0], prefix) || strings.HasPrefix(fields[0], "192.168.") || strings.HasPrefix(fields[0], "10.")) && fields[2] == "0x2" {
				ip := fields[0]
				if !seen[ip] {
					seen[ip] = true
					ips = append(ips, ip)
				}
			}
		}
	}
	if prefix == "192.168.1." {
		for _, hostOctet := range []int{88, 140, 67, 154, 161, 55, 135, 138} {
			ip := fmt.Sprintf("192.168.1.%d", hostOctet)
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 300 * time.Millisecond}

	for _, ip := range ips {
		if isOwnLocalIP(ip) {
			continue
		}
		for _, port := range []int{8080, 8090} {
			wg.Add(1)
			sem <- struct{}{}
			go func(targetIP string, targetPort int) {
				defer wg.Done()
				defer func() { <-sem }()
				host := fmt.Sprintf("%s:%d", targetIP, targetPort)
				conn, err := net.DialTimeout("tcp", host, 180*time.Millisecond)
				if err != nil {
					return
				}
				conn.Close()

				resp, err := client.Get("http://" + host + "/api/status")
				if err != nil {
					return
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
				if err != nil {
					return
				}
				var st struct {
					Status   string `json:"status"`
					Device   string `json:"device"`
					IP       string `json:"ip"`
					MAC      string `json:"mac"`
					Platform string `json:"platform"`
				}
				if err := json.Unmarshal(body, &st); err == nil && st.Status == "online" && st.Device != "" {
					if st.Device == myDeviceType {
						return
					}
					canonicalHost := host
					if st.IP != "" && (strings.HasPrefix(st.IP, prefix) || strings.HasPrefix(st.IP, "192.168.") || strings.HasPrefix(st.IP, "10.")) {
						canonicalHost = fmt.Sprintf("%s:%d", st.IP, targetPort)
					}
					deviceRegistryMu.RLock()
					existing, ok := deviceRegistry[st.Device]
					deviceRegistryMu.RUnlock()
					reg := DeviceInfo{
						ID:       st.Device,
						Host:     canonicalHost,
						MAC:      st.MAC,
						Platform: st.Platform,
						Online:   true,
						LastSeen: time.Now().Unix(),
					}
					if ok && existing != nil {
						reg.Name = existing.Name
						reg.Icon = existing.Icon
						reg.Type = existing.Type
						reg.HasWOL = existing.HasWOL
					} else {
						reg.Name = strings.ToUpper(st.Device)
						reg.Icon = "📱"
					}
					updatePeerInRegistry(reg)
				}
			}(ip, port)
		}
	}
	wg.Wait()
}

func startClientAutoAnnounce() {
	startUDPMeshDiscovery()

	// Fast 4-second Ethernet <-> Wi-Fi failover watchdog on TX3 Mini
	if myDeviceType == "tx3" && isAndroid() {
		go func() {
			for {
				maintainTX3NetworkFailover()
				time.Sleep(4 * time.Second)
			}
		}()
	}

	// Periodic HTTP peer sync + lightweight ARP discovery if core peer changes IP
	go func() {
		time.Sleep(1500 * time.Millisecond)
		client := http.Client{Timeout: 1200 * time.Millisecond}
		for {
			selfInfo := buildSelfDeviceInfo()
			updatePeerInRegistry(selfInfo)
			b, _ := json.Marshal(selfInfo)

			deviceRegistryMu.RLock()
			peers := make([]*DeviceInfo, 0, len(deviceRegistry))
			for _, d := range deviceRegistry {
				cp := *d
				peers = append(peers, &cp)
			}
			deviceRegistryMu.RUnlock()

			needScan := false
			for _, p := range peers {
				if p.ID == myDeviceType || p.ID == "tv360" || p.Host == "" {
					continue
				}
				// Skip polling projector repeatedly when it is offline unless it was seen recently
				if p.ID == "projector" && !p.Online && time.Now().Unix()-p.LastSeen > 120 {
					continue
				}
				resp, err := client.Post("http://"+p.Host+"/api/register", "application/json", bytes.NewReader(b))
				if err == nil {
					resp.Body.Close()
				} else if p.ID == "tx3" || p.ID == "pc" {
					needScan = true
				}
			}
			if needScan {
				go discoverMovedPeersOnSubnet()
			}
			time.Sleep(25 * time.Second)
		}
	}()
}

type PCWindowInfo struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	App      string `json:"app"`
	Icon     string `json:"icon"`
	X        int    `json:"x"`
	Y        int    `json:"y"`
	W        int    `json:"w"`
	H        int    `json:"h"`
	Priority int    `json:"-"`
	Active   bool   `json:"active"`
}

var (
	activePCWinMu sync.RWMutex
	activePCWinID string
)

func getActivePCWindowID() string {
	activePCWinMu.RLock()
	defer activePCWinMu.RUnlock()
	return activePCWinID
}

func setActivePCWindowID(id string) {
	activePCWinMu.Lock()
	activePCWinID = strings.TrimSpace(id)
	activePCWinMu.Unlock()
	invalidateScreenCache()
}

func classifyWindowTitle(title, wmClass string) (string, string, int) {
	lowT := strings.ToLower(title)
	lowC := strings.ToLower(wmClass)
	if strings.Contains(lowC, "antigravity") || strings.Contains(lowT, "antigravity") {
		return "🚀", "Antigravity", 100
	}
	if strings.Contains(lowC, "code") || strings.Contains(lowT, "visual studio code") || strings.Contains(lowC, "cursor") {
		return "💠", "Code Editor", 90
	}
	if strings.Contains(lowC, "terminal") || strings.Contains(lowT, "powershell") || strings.Contains(lowT, "cmd.exe") || strings.Contains(lowT, "pop-os:") {
		return "💻", "Terminal", 85
	}
	if strings.Contains(lowC, "chrome") || strings.Contains(lowT, "google chrome") || strings.Contains(lowC, "brave") || strings.Contains(lowC, "edge") || strings.Contains(lowT, "edge") || strings.Contains(lowC, "firefox") {
		return "🌐", "Trình duyệt", 80
	}
	if strings.Contains(lowC, "vnc") || strings.Contains(lowT, "vnc") || strings.Contains(lowT, "qemu") {
		return "🖥️", "Remote / VNC", 75
	}
	if strings.Contains(lowC, "nautilus") || strings.Contains(lowT, "explorer") || strings.Contains(lowT, "downloads") || strings.Contains(lowT, "home") {
		return "📁", "Thư mục", 60
	}
	return "🪟", "Cửa sổ", 50
}

func sortPCWindows(list []PCWindowInfo) {
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].Priority > list[i].Priority {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
}

var (
	winBoundsCacheMu  sync.Mutex
	winBoundsCacheID  string
	winBoundsCacheAt  time.Time
	winBoundsCacheX   int
	winBoundsCacheY   int
	winBoundsCacheW   int
	winBoundsCacheH   int
	winBoundsCacheOK  bool
	linuxResCacheMu   sync.Mutex
	linuxResCachedAt  time.Time
	linuxResCachedW   int
	linuxResCachedH   int
)

func getLinuxScreenDimensions() (int, int) {
	if envW, envH := os.Getenv("VUI_SCREEN_W"), os.Getenv("VUI_SCREEN_H"); envW != "" && envH != "" {
		w, err1 := strconv.Atoi(envW)
		h, err2 := strconv.Atoi(envH)
		if err1 == nil && err2 == nil && w >= 640 && h >= 480 {
			atomic.StoreInt32(&detectedWidth, int32(w))
			atomic.StoreInt32(&detectedHeight, int32(h))
			return w, h
		}
	}

	linuxResCacheMu.Lock()
	if linuxResCachedW >= 640 && linuxResCachedH >= 480 && time.Since(linuxResCachedAt) < 5*time.Second {
		w, h := linuxResCachedW, linuxResCachedH
		linuxResCacheMu.Unlock()
		return w, h
	}
	linuxResCacheMu.Unlock()

	var w, h int
	if fbBytes, err := os.ReadFile("/sys/class/graphics/fb0/virtual_size"); err == nil {
		parts := strings.Split(strings.TrimSpace(string(fbBytes)), ",")
		if len(parts) == 2 {
			fw, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			fh, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && fw >= 640 && fh >= 480 {
				w, h = fw, fh
			}
		}
	}
	if w < 640 || h < 480 {
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		cmd := exec.CommandContext(ctx, "xdpyinfo")
		cmd.Env = getLinuxX11Env()
		out, err := cmd.Output()
		cancel()
		if err == nil && len(out) > 0 {
			re := regexp.MustCompile(`dimensions:\s+(\d+)x(\d+)\s+pixels`)
			if m := re.FindStringSubmatch(string(out)); len(m) == 3 {
				xw, err1 := strconv.Atoi(m[1])
				xh, err2 := strconv.Atoi(m[2])
				if err1 == nil && err2 == nil && xw >= 640 && xh >= 480 {
					w, h = xw, xh
				}
			}
		}
	}
	if w < 640 || h < 480 {
		curW, curH := getScreenDimensions()
		if curW >= 640 && curH >= 480 {
			w, h = curW, curH
		} else {
			w, h = 2560, 1440
		}
	}

	atomic.StoreInt32(&detectedWidth, int32(w))
	atomic.StoreInt32(&detectedHeight, int32(h))

	linuxResCacheMu.Lock()
	linuxResCachedW = w
	linuxResCachedH = h
	linuxResCachedAt = time.Now()
	linuxResCacheMu.Unlock()
	return w, h
}

func linuxGetWindowBounds(id string) (int, int, int, int, bool) {
	if id == "" {
		return 0, 0, 0, 0, false
	}
	winBoundsCacheMu.Lock()
	if id == winBoundsCacheID && time.Since(winBoundsCacheAt) < 400*time.Millisecond {
		cx, cy, cw, ch, cok := winBoundsCacheX, winBoundsCacheY, winBoundsCacheW, winBoundsCacheH, winBoundsCacheOK
		winBoundsCacheMu.Unlock()
		return cx, cy, cw, ch, cok
	}
	winBoundsCacheMu.Unlock()

	cmd := exec.Command("xdotool", "getwindowgeometry", "--shell", id)
	cmd.Env = getLinuxX11Env()
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, 0, 0, false
	}
	var x, y, w, h int
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "X=") {
			x, _ = strconv.Atoi(strings.TrimPrefix(line, "X="))
		} else if strings.HasPrefix(line, "Y=") {
			y, _ = strconv.Atoi(strings.TrimPrefix(line, "Y="))
		} else if strings.HasPrefix(line, "WIDTH=") {
			w, _ = strconv.Atoi(strings.TrimPrefix(line, "WIDTH="))
		} else if strings.HasPrefix(line, "HEIGHT=") {
			h, _ = strconv.Atoi(strings.TrimPrefix(line, "HEIGHT="))
		}
	}
	scrW, scrH := getLinuxScreenDimensions()
	if x < 0 {
		w += x
		x = 0
	}
	if y < 0 {
		h += y
		y = 0
	}
	if x+w > scrW {
		w = scrW - x
	}
	if y+h > scrH {
		h = scrH - y
	}
	// Make width & height even numbers for ffmpeg MJPEG / YUV420
	w = (w / 2) * 2
	h = (h / 2) * 2
	if w < 100 || h < 80 {
		return 0, 0, 0, 0, false
	}
	winBoundsCacheMu.Lock()
	winBoundsCacheID = id
	winBoundsCacheAt = time.Now()
	winBoundsCacheX = x
	winBoundsCacheY = y
	winBoundsCacheW = w
	winBoundsCacheH = h
	winBoundsCacheOK = true
	winBoundsCacheMu.Unlock()
	return x, y, w, h, true
}

func listPCWindows() []PCWindowInfo {
	if runtime.GOOS == "windows" {
		return winListWindows()
	}
	env := getLinuxX11Env()
	cmd := exec.Command("xprop", "-root", "_NET_CLIENT_LIST_STACKING")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	parts := strings.Split(string(out), "#")
	if len(parts) < 2 {
		return nil
	}
	rawIDs := strings.Split(parts[1], ",")
	var result []PCWindowInfo
	curActive := getActivePCWindowID()
	// Iterate in reverse stacking order (topmost windows first)
	for i := len(rawIDs) - 1; i >= 0; i-- {
		hexID := strings.TrimSpace(rawIDs[i])
		if hexID == "" {
			continue
		}
		val, err := strconv.ParseInt(strings.TrimPrefix(hexID, "0x"), 16, 64)
		if err != nil || val <= 0 {
			continue
		}
		decID := strconv.FormatInt(val, 10)

		nameCmd := exec.Command("xdotool", "getwindowname", decID)
		nameCmd.Env = env
		nameOut, _ := nameCmd.Output()
		title := strings.TrimSpace(string(nameOut))
		if title == "" || strings.HasPrefix(title, "@!") || title == "mutter guard window" {
			continue
		}

		clsCmd := exec.Command("xprop", "-id", decID, "WM_CLASS")
		clsCmd.Env = env
		clsOut, _ := clsCmd.Output()
		wmClass := strings.TrimSpace(string(clsOut))
		if strings.Contains(strings.ToLower(wmClass), `"gjs"`) {
			continue
		}

		wx, wy, ww, wh, ok := linuxGetWindowBounds(decID)
		if !ok {
			continue
		}
		icon, appName, prio := classifyWindowTitle(title, wmClass)
		result = append(result, PCWindowInfo{
			ID:       decID,
			Title:    title,
			App:      appName,
			Icon:     icon,
			X:        wx,
			Y:        wy,
			W:        ww,
			H:        wh,
			Priority: prio,
			Active:   curActive == decID,
		})
	}
	sortPCWindows(result)
	return result
}

func focusPCWindow(id string, maximize bool) bool {
	id = strings.TrimSpace(id)
	setActivePCWindowID("")
	if id == "" || id == "full" || id == "0" {
		return true
	}
	if runtime.GOOS == "windows" {
		return winFocusWindow(id, maximize)
	}
	runXdotool("windowactivate", id)
	runXdotool("windowraise", id)
	if maximize {
		runXdotool("windowsize", id, "100%", "100%")
	}
	return true
}

var (
	linuxStreamMu          sync.Mutex
	linuxStreamCfgKey      string
	linuxStreamRunning     bool
	linuxStreamCancel      context.CancelFunc
	linuxStreamFrame       []byte
	linuxStreamFrameTime   time.Time
	linuxStreamNotifyCh    = make(chan struct{})
	linuxStreamLastReqNano int64
)

func getLinuxPCMjpegStreamFrame(display, xauth, grabSize, grabInput string, scaleW int) ([]byte, bool) {
	atomic.StoreInt64(&linuxStreamLastReqNano, time.Now().UnixNano())
	cfgKey := fmt.Sprintf("%s|%s|%s|%s|%d", display, xauth, grabSize, grabInput, scaleW)

	linuxStreamMu.Lock()
	if !linuxStreamRunning || linuxStreamCfgKey != cfgKey {
		if linuxStreamCancel != nil {
			linuxStreamCancel()
			linuxStreamCancel = nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		linuxStreamCancel = cancel
		linuxStreamCfgKey = cfgKey
		linuxStreamRunning = true
		linuxStreamFrame = nil
		linuxStreamFrameTime = time.Time{}

		go func(myKey string, c context.Context, stopFn context.CancelFunc) {
			defer func() {
				stopFn()
				linuxStreamMu.Lock()
				if linuxStreamCfgKey == myKey {
					linuxStreamRunning = false
				}
				linuxStreamMu.Unlock()
			}()

			scrW, _ := getLinuxScreenDimensions()
			vfArg := "format=yuvj444p"
			if scaleW > 0 && scaleW < scrW {
				vfArg = fmt.Sprintf("scale=%d:-1:flags=lanczos,format=yuvj444p", scaleW)
			}
			cmd := exec.CommandContext(c, "ffmpeg", "-nostats", "-loglevel", "error",
				"-fflags", "nobuffer",
				"-flags", "low_delay",
				"-f", "x11grab",
				"-draw_mouse", "1",
				"-framerate", "30",
				"-video_size", grabSize,
				"-i", grabInput,
				"-vf", vfArg,
				"-vcodec", "mjpeg",
				"-qscale:v", "2",
				"-qmin", "1",
				"-qmax", "3",
				"-flush_packets", "1",
				"-f", "image2pipe",
				"-",
			)
			cmd.Env = append(os.Environ(), "DISPLAY="+display, "XAUTHORITY="+xauth)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return
			}
			if err := cmd.Start(); err != nil {
				return
			}

			go func() {
				tk := time.NewTicker(800 * time.Millisecond)
				defer tk.Stop()
				for {
					select {
					case <-c.Done():
						return
					case <-tk.C:
						lastReq := time.Unix(0, atomic.LoadInt64(&linuxStreamLastReqNano))
						if time.Since(lastReq) > 4500*time.Millisecond {
							stopFn()
							return
						}
					}
				}
			}()

			buf := make([]byte, 0, 524288)
			tmp := make([]byte, 65536)
			for {
				n, rErr := stdout.Read(tmp)
				if n > 0 {
					buf = append(buf, tmp[:n]...)
					for {
						soi := bytes.Index(buf, []byte{0xFF, 0xD8})
						if soi < 0 {
							if len(buf) > 2 {
								buf = buf[len(buf)-2:]
							}
							break
						}
						eoi := bytes.Index(buf[soi+2:], []byte{0xFF, 0xD9})
						if eoi < 0 {
							if soi > 0 {
								buf = buf[soi:]
							}
							break
						}
						endIdx := soi + 2 + eoi + 2
						frame := make([]byte, endIdx-soi)
						copy(frame, buf[soi:endIdx])
						buf = buf[endIdx:]

						if len(frame) > 200 {
							now := time.Now()
							linuxStreamMu.Lock()
							if linuxStreamCfgKey == myKey {
								linuxStreamFrame = frame
								linuxStreamFrameTime = now
								close(linuxStreamNotifyCh)
								linuxStreamNotifyCh = make(chan struct{})
							}
							linuxStreamMu.Unlock()

							screenMu.Lock()
							cachedScreen = frame
							lastGoodScreen = frame
							lastCaptureTime = now
							screenMu.Unlock()
						}
					}
				}
				if rErr != nil {
					break
				}
			}
			_ = cmd.Wait()
		}(cfgKey, ctx, cancel)
	}

	curFrame := linuxStreamFrame
	curTime := linuxStreamFrameTime
	waitCh := linuxStreamNotifyCh
	linuxStreamMu.Unlock()

	if len(curFrame) > 200 && time.Since(curTime) < 450*time.Millisecond {
		return curFrame, true
	}

	// Stream just started: wait up to 220ms for first frame
	select {
	case <-waitCh:
		linuxStreamMu.Lock()
		f := linuxStreamFrame
		linuxStreamMu.Unlock()
		if len(f) > 200 {
			return f, true
		}
	case <-time.After(220 * time.Millisecond):
	}
	return nil, false
}

func captureScreenLinuxPC(targetW int) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return winCaptureScreenJpeg(targetW)
	}
	display, xauth, _, ready := resolveLinuxDisplayAndXauth()
	if !ready {
		return linuxRenderLoginScreenPlaceholder()
	}

	setActivePCWindowID("")
	scrW, scrH := getLinuxScreenDimensions()
	grabSize := fmt.Sprintf("%dx%d", scrW, scrH)
	grabInput := display
	scaleW := scrW

	if frame, ok := getLinuxPCMjpegStreamFrame(display, xauth, grabSize, grabInput, scaleW); ok {
		return frame, nil
	}

	vfArg := "format=yuvj444p"

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ffmpeg", "-nostats", "-loglevel", "error", "-y",
		"-f", "x11grab",
		"-draw_mouse", "1",
		"-video_size", grabSize,
		"-i", grabInput,
		"-vf", vfArg,
		"-vframes", "1",
		"-q:v", "2",
		"-f", "image2",
		"-",
	)
	cmd.Env = append(os.Environ(), "DISPLAY="+display, "XAUTHORITY="+xauth)
	out, err := cmd.Output()
	if err != nil || len(out) < 100 {
		cmdAuto := exec.CommandContext(ctx, "ffmpeg", "-nostats", "-loglevel", "error", "-y",
			"-f", "x11grab",
			"-draw_mouse", "1",
			"-i", display,
			"-vf", vfArg,
			"-vframes", "1",
			"-q:v", "2",
			"-f", "image2",
			"-",
		)
		cmdAuto.Env = append(os.Environ(), "DISPLAY="+display, "XAUTHORITY="+xauth)
		if outAuto, errAuto := cmdAuto.Output(); errAuto == nil && len(outAuto) > 100 {
			return outAuto, nil
		}
	}
	if (err != nil || len(out) < 100) && display != ":0" {
		gdmAuth := "/dev/shm/vui_gdm_Xauthority"
		if _, errStat := os.Stat(gdmAuth); errStat != nil {
			gdmAuth = xauth
		}
		cmd0 := exec.CommandContext(ctx, "ffmpeg", "-nostats", "-loglevel", "error", "-y",
			"-f", "x11grab",
			"-draw_mouse", "1",
			"-i", ":0",
			"-vf", vfArg,
			"-vframes", "1",
			"-q:v", "2",
			"-f", "image2",
			"-",
		)
		cmd0.Env = append(os.Environ(), "DISPLAY=:0", "XAUTHORITY="+gdmAuth)
		if out0, err0 := cmd0.Output(); err0 == nil && len(out0) > 100 {
			return out0, nil
		}
	}
	if err != nil || len(out) < 100 {
		return linuxRenderLoginScreenPlaceholder()
	}
	return out, nil
}

var pcInputMu sync.Mutex

func getLinuxX11Env() []string {
	display, xauth, _, _ := resolveLinuxDisplayAndXauth()
	return append(os.Environ(), "DISPLAY="+display, "XAUTHORITY="+xauth)
}

func runXdotool(args ...string) {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	cmd := exec.Command("xdotool", args...)
	cmd.Env = getLinuxX11Env()
	cmd.Run()
}

func linuxCoordToPixel(px, py float64) (int, int) {
	if winID := getActivePCWindowID(); winID != "" {
		if wx, wy, ww, wh, ok := linuxGetWindowBounds(winID); ok {
			x := wx + int(math.Max(0, math.Min(float64(ww-1), px*float64(ww))))
			y := wy + int(math.Max(0, math.Min(float64(wh-1), py*float64(wh))))
			return x, y
		}
	}
	scrW, scrH := getLinuxScreenDimensions()
	x := int(math.Max(0, math.Min(float64(scrW-1), px*float64(scrW))))
	y := int(math.Max(0, math.Min(float64(scrH-1), py*float64(scrH))))
	return x, y
}

func linuxPixelToCoord(x, y int) (float64, float64) {
	if winID := getActivePCWindowID(); winID != "" {
		if wx, wy, ww, wh, ok := linuxGetWindowBounds(winID); ok && ww > 0 && wh > 0 {
			px := math.Max(0, math.Min(1, float64(x-wx)/float64(ww)))
			py := math.Max(0, math.Min(1, float64(y-wy)/float64(wh)))
			return px, py
		}
	}
	scrW, scrH := getLinuxScreenDimensions()
	px := math.Max(0, math.Min(1, float64(x)/float64(scrW)))
	py := math.Max(0, math.Min(1, float64(y)/float64(scrH)))
	return px, py
}

func sendLinuxPCKey(androidCode int) {
	if runtime.GOOS == "windows" {
		winSendKey(androidCode)
		return
	}
	if androidCode != 24 && androidCode != 25 && androidCode != 164 && androidCode != 82 && androidCode != 187 {
		if sendDirectLinuxPCKeyViaUinput(androidCode) {
			invalidateScreenCache()
			return
		}
		if !isLinuxX11SessionReady() {
			return
		}
	}
	var keyName string
	switch androidCode {
	case 19:
		keyName = "Up"
	case 20:
		keyName = "Down"
	case 21:
		keyName = "Left"
	case 22:
		keyName = "Right"
	case 23, 66:
		keyName = "Return"
	case 4, 111:
		keyName = "Escape"
	case 3:
		keyName = "Super_L"
	case 82, 187:
		keyName = "alt+Tab"
	case 24:
		keyName = "XF86AudioRaiseVolume"
	case 25:
		keyName = "XF86AudioLowerVolume"
	case 164:
		keyName = "XF86AudioMute"
	case 67:
		keyName = "BackSpace"
	case 112:
		keyName = "Delete"
	case 61:
		keyName = "Tab"
	case 122:
		keyName = "Home"
	case 123:
		keyName = "End"
	case 92:
		keyName = "Page_Up"
	case 93:
		keyName = "Page_Down"
	case 85, 62:
		keyName = "space"
	default:
		keyName = "Return"
	}
	runXdotool("key", "--clearmodifiers", keyName)
	invalidateScreenCache()
}

func sendLinuxPCHotkey(combo string) {
	if combo == "" {
		return
	}
	if runtime.GOOS == "windows" {
		winSendHotkey(combo)
		return
	}
	if sendUinputHotkeyCombo(combo) {
		invalidateScreenCache()
		return
	}
	runXdotool("key", "--clearmodifiers", combo)
	invalidateScreenCache()
}

var (
	pcOrderedOnce      sync.Once
	pcOrderedInputCh   chan func()
	pcInputCancelEpoch uint64

	pcSeqMu           sync.Mutex
	pcNextExpectedSeq int64
	pcLastSeqAt       time.Time
	pcPendingSeqMap   = make(map[int64]func())
)

func sendLinuxPCKeyCount(androidCode int, count int, isRepeat bool) {
	if count < 1 {
		count = 1
	} else if count > 12 {
		count = 12
	}
	startEpoch := atomic.LoadUint64(&pcInputCancelEpoch)
	for i := 0; i < count; i++ {
		if isRepeat && atomic.LoadUint64(&pcInputCancelEpoch) != startEpoch {
			break
		}
		sendLinuxPCKey(androidCode)
	}
}

func enqueuePCOrderedInput(fn func()) {
	pcOrderedOnce.Do(func() {
		pcOrderedInputCh = make(chan func(), 256)
		go func() {
			for task := range pcOrderedInputCh {
				if task != nil {
					task()
				}
			}
		}()
	})
	select {
	case pcOrderedInputCh <- fn:
	default:
		go fn()
	}
}

func flushPendingSeqLocked() {
	for {
		nextFn, ok := pcPendingSeqMap[pcNextExpectedSeq]
		if !ok {
			break
		}
		delete(pcPendingSeqMap, pcNextExpectedSeq)
		pcNextExpectedSeq++
		enqueuePCOrderedInput(nextFn)
	}
}

func enqueueSequencedPCInput(seq int64, fn func()) {
	if seq <= 0 {
		enqueuePCOrderedInput(fn)
		return
	}
	pcSeqMu.Lock()
	now := time.Now()
	if pcNextExpectedSeq == 0 || now.Sub(pcLastSeqAt) > 450*time.Millisecond || seq < pcNextExpectedSeq || seq-pcNextExpectedSeq > 32 {
		// Flush any older waiting tasks before resetting sequence window
		if len(pcPendingSeqMap) > 0 {
			for s := pcNextExpectedSeq; s < seq; s++ {
				if oldFn, ok := pcPendingSeqMap[s]; ok {
					delete(pcPendingSeqMap, s)
					enqueuePCOrderedInput(oldFn)
				}
			}
			pcPendingSeqMap = make(map[int64]func())
		}
		pcNextExpectedSeq = seq
	}
	pcLastSeqAt = now

	if seq == pcNextExpectedSeq {
		pcNextExpectedSeq++
		enqueuePCOrderedInput(fn)
		flushPendingSeqLocked()
		pcSeqMu.Unlock()
		return
	}

	pcPendingSeqMap[seq] = fn
	targetSeq := seq
	pcSeqMu.Unlock()

	time.AfterFunc(45*time.Millisecond, func() {
		pcSeqMu.Lock()
		defer pcSeqMu.Unlock()
		if _, stillPending := pcPendingSeqMap[targetSeq]; !stillPending {
			return
		}
		for pcNextExpectedSeq <= targetSeq {
			if waitFn, ok := pcPendingSeqMap[pcNextExpectedSeq]; ok {
				delete(pcPendingSeqMap, pcNextExpectedSeq)
				enqueuePCOrderedInput(waitFn)
			}
			pcNextExpectedSeq++
		}
		flushPendingSeqLocked()
	})
}

func clearPCOrderedInputQueue() {
	atomic.AddUint64(&pcInputCancelEpoch, 1)
	if pcOrderedInputCh == nil {
		return
	}
	for {
		select {
		case <-pcOrderedInputCh:
		default:
			return
		}
	}
}

var (
	pcMouseQueueOnce sync.Once
	pcMouseInputCh   chan func()
)

func enqueuePCMouseInput(fn func()) {
	pcMouseQueueOnce.Do(func() {
		pcMouseInputCh = make(chan func(), 512)
		go func() {
			for task := range pcMouseInputCh {
				if task != nil {
					task()
				}
			}
		}()
	})
	select {
	case pcMouseInputCh <- fn:
	default:
		go fn()
	}
}

func sendLinuxPCTouchTap(px, py float64) {
	if runtime.GOOS == "windows" {
		winTouchTap(px, py)
		return
	}
	if !isLinuxX11SessionReady() {
		sendDirectLinuxPCKeyViaUinput(66)
		invalidateScreenCache()
		return
	}
	if isLinuxLoginOrLockScreen() {
		wasReady := ensureLinuxUnlockPromptReady()
		if !wasReady {
			invalidateScreenCache()
			return
		}
	}
	x, y := linuxCoordToPixel(px, py)
	if !runLinuxX11Mouse("click", x, y, 1, 1) {
		runXdotool("mousemove", strconv.Itoa(x), strconv.Itoa(y), "click", "1")
	}
	invalidateScreenCache()
}

func sendLinuxPCDoubleTap(px, py float64) {
	if runtime.GOOS == "windows" {
		winDoubleTap(px, py)
		return
	}
	x, y := -1, -1
	if px >= 0 && py >= 0 {
		x, y = linuxCoordToPixel(px, py)
	}
	if !runLinuxX11Mouse("dblclick", x, y, 1, 2) {
		if x >= 0 && y >= 0 {
			runXdotool("mousemove", strconv.Itoa(x), strconv.Itoa(y), "click", "--repeat", "2", "--delay", "55", "1")
		} else {
			runXdotool("click", "--repeat", "2", "--delay", "55", "1")
		}
	}
	invalidateScreenCache()
}

func sendLinuxPCRightClick(px, py float64) {
	if runtime.GOOS == "windows" {
		winRightClick(px, py)
		return
	}
	x, y := -1, -1
	if px >= 0 && py >= 0 {
		x, y = linuxCoordToPixel(px, py)
	}
	if !runLinuxX11Mouse("click", x, y, 3, 1) {
		if x >= 0 && y >= 0 {
			runXdotool("mousemove", strconv.Itoa(x), strconv.Itoa(y), "click", "3")
		} else {
			runXdotool("click", "3")
		}
	}
	invalidateScreenCache()
}

func sendLinuxPCMiddleClick(px, py float64) {
	if runtime.GOOS == "windows" {
		winMiddleClick(px, py)
		return
	}
	x, y := -1, -1
	if px >= 0 && py >= 0 {
		x, y = linuxCoordToPixel(px, py)
	}
	if !runLinuxX11Mouse("click", x, y, 2, 1) {
		if x >= 0 && y >= 0 {
			runXdotool("mousemove", strconv.Itoa(x), strconv.Itoa(y), "click", "2")
		} else {
			runXdotool("click", "2")
		}
	}
	invalidateScreenCache()
}

func sendLinuxPCDragStart(px, py float64) {
	if runtime.GOOS == "windows" {
		winDragStart(px, py)
		return
	}
	x, y := linuxCoordToPixel(px, py)
	if !runLinuxX11Mouse("down", x, y, 1, 1) {
		runXdotool("mousemove", strconv.Itoa(x), strconv.Itoa(y), "mousedown", "1")
	}
	invalidateScreenCache()
}

func sendLinuxPCDragMove(px, py float64) {
	if runtime.GOOS == "windows" {
		winDragMove(px, py)
		return
	}
	x, y := linuxCoordToPixel(px, py)
	if !runLinuxX11Mouse("move", x, y, 0, 1) {
		runXdotool("mousemove", strconv.Itoa(x), strconv.Itoa(y))
	}
	invalidateScreenCache()
}

func sendLinuxPCDragEnd(px, py float64) {
	if runtime.GOOS == "windows" {
		winDragEnd(px, py)
		return
	}
	x, y := linuxCoordToPixel(px, py)
	if !runLinuxX11Mouse("up", x, y, 1, 1) {
		runXdotool("mousemove", strconv.Itoa(x), strconv.Itoa(y), "mouseup", "1")
	}
	invalidateScreenCache()
}

func sendLinuxPCDragAtomic(px1, py1, px2, py2 float64) {
	if runtime.GOOS == "windows" {
		winDragAtomic(px1, py1, px2, py2)
		return
	}
	x1, y1 := linuxCoordToPixel(px1, py1)
	x2, y2 := linuxCoordToPixel(px2, py2)

	if runLinuxX11Mouse("down", x1, y1, 1, 1) {
		steps := 8
		for i := 1; i <= steps; i++ {
			time.Sleep(10 * time.Millisecond)
			t := float64(i) / float64(steps)
			cx := int(float64(x1) + float64(x2-x1)*t)
			cy := int(float64(y1) + float64(y2-y1)*t)
			runLinuxX11Mouse("move", cx, cy, 0, 1)
		}
		time.Sleep(10 * time.Millisecond)
		runLinuxX11Mouse("up", x2, y2, 1, 1)
		invalidateScreenCache()
		return
	}

	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	env := getLinuxX11Env()

	cStart := exec.Command("xdotool", "mousemove", strconv.Itoa(x1), strconv.Itoa(y1), "mousedown", "1")
	cStart.Env = env
	cStart.Run()

	steps := 8
	for i := 1; i <= steps; i++ {
		time.Sleep(14 * time.Millisecond)
		t := float64(i) / float64(steps)
		cx := int(float64(x1) + float64(x2-x1)*t)
		cy := int(float64(y1) + float64(y2-y1)*t)
		cMove := exec.Command("xdotool", "mousemove", strconv.Itoa(cx), strconv.Itoa(cy))
		cMove.Env = env
		cMove.Run()
	}

	time.Sleep(15 * time.Millisecond)
	cEnd := exec.Command("xdotool", "mousemove", strconv.Itoa(x2), strconv.Itoa(y2), "mouseup", "1")
	cEnd.Env = env
	cEnd.Run()
	invalidateScreenCache()
}

func sendLinuxPCScrollXY(px, py, dx, dy float64, steps int) {
	if runtime.GOOS == "windows" {
		winScrollXY(px, py, dx, dy, steps)
		return
	}
	x, y := -1, -1
	if px > 0 || py > 0 {
		x, y = linuxCoordToPixel(px, py)
	}

	var btnNum int
	if math.Abs(dy) >= math.Abs(dx) {
		btnNum = 5 // Wheel down (scroll content down when finger moves up dy < 0)
		if dy > 0 {
			btnNum = 4 // Wheel up
		}
		if steps <= 0 {
			steps = int(math.Abs(dy) / 0.045)
		}
		if steps < 1 {
			steps = 2
		} else if steps > 8 {
			steps = 8
		}
	} else {
		btnNum = 7 // Wheel right (when finger moves left dx < 0)
		if dx > 0 {
			btnNum = 6 // Wheel left
		}
		if steps <= 0 {
			steps = int(math.Abs(dx) / 0.05)
		}
		if steps < 1 {
			steps = 2
		} else if steps > 8 {
			steps = 8
		}
	}

	if runLinuxX11Mouse("scroll", x, y, btnNum, steps) {
		invalidateScreenCache()
		return
	}

	args := []string{}
	if x >= 0 && y >= 0 {
		args = append(args, "mousemove", strconv.Itoa(x), strconv.Itoa(y))
	}
	args = append(args, "click", "--repeat", strconv.Itoa(steps), "--delay", "8", strconv.Itoa(btnNum))
	runXdotool(args...)
	invalidateScreenCache()
}

func sendLinuxPCScroll(up bool) {
	if runtime.GOOS == "windows" {
		winScroll(up)
		return
	}
	btnNum := 5
	if up {
		btnNum = 4
	}
	if !runLinuxX11Mouse("scroll", -1, -1, btnNum, 3) {
		runXdotool("click", "--repeat", "3", "--delay", "8", strconv.Itoa(btnNum))
	}
	invalidateScreenCache()
}

func sendLinuxPCRelMouse(dx, dy int) {
	if runtime.GOOS == "windows" {
		winRelMouse(dx, dy)
		return
	}
	if !runLinuxX11Mouse("rel", dx, dy, 0, 1) {
		runXdotool("mousemove_relative", "--", strconv.Itoa(dx), strconv.Itoa(dy))
	}
	invalidateScreenCache()
}

func sendLinuxPCMouseButton(btn int) {
	if runtime.GOOS == "windows" {
		winMouseButton(btn)
		return
	}
	btnNum := 1
	if btn == 273 {
		btnNum = 3
	} else if btn == 274 {
		btnNum = 2
	}
	if !runLinuxX11Mouse("click", -1, -1, btnNum, 1) {
		runXdotool("click", strconv.Itoa(btnNum))
	}
	invalidateScreenCache()
}

func isPureASCIIPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7E {
			return false
		}
	}
	return true
}

func sendLinuxPCText(text string) {
	sendLinuxPCTextDelta(text, 0, 0, 0, false)
}

func sendLinuxPCTextEx(text string, bksp int, direct bool) {
	sendLinuxPCTextDelta(text, bksp, 0, 0, direct)
}

var (
	linuxPasteDaemonCmd    *exec.Cmd
	linuxPasteDaemonStdin  io.WriteCloser
	linuxPasteDaemonStdout *bufio.Reader
	linuxPasteDaemonEnvKey string

	remoteSimMu    sync.Mutex
	remoteSimRunes []rune
	remoteSimCaret int
)

func resetRemoteSimState() {
	remoteSimMu.Lock()
	remoteSimRunes = nil
	remoteSimCaret = 0
	remoteSimMu.Unlock()
}

func getRemoteSimState() (string, int) {
	remoteSimMu.Lock()
	defer remoteSimMu.Unlock()
	return string(remoteSimRunes), remoteSimCaret
}

func applyRemoteSimStep(mb, bksp int, text string, ma int) {
	remoteSimMu.Lock()
	defer remoteSimMu.Unlock()
	caret := remoteSimCaret + mb
	if caret < 0 {
		caret = 0
	}
	if caret > len(remoteSimRunes) {
		caret = len(remoteSimRunes)
	}
	if bksp > 0 {
		delStart := caret - bksp
		if delStart < 0 {
			delStart = 0
		}
		remoteSimRunes = append(remoteSimRunes[:delStart], remoteSimRunes[caret:]...)
		caret = delStart
	}
	if text == "\n" {
		remoteSimRunes = nil
		remoteSimCaret = 0
		return
	}
	if text != "" {
		ins := []rune(text)
		tail := make([]rune, len(remoteSimRunes)-caret)
		copy(tail, remoteSimRunes[caret:])
		remoteSimRunes = append(remoteSimRunes[:caret], append(ins, tail...)...)
		caret += len(ins)
	}
	caret += ma
	if caret < 0 {
		caret = 0
	}
	if caret > len(remoteSimRunes) {
		caret = len(remoteSimRunes)
	}
	remoteSimCaret = caret
}

func applyRemoteSimKey(code int) {
	remoteSimMu.Lock()
	defer remoteSimMu.Unlock()
	switch code {
	case 66, 23: // Enter / DPAD_CENTER
		remoteSimRunes = nil
		remoteSimCaret = 0
	case 67: // Backspace
		if remoteSimCaret > 0 && len(remoteSimRunes) > 0 {
			if remoteSimCaret > len(remoteSimRunes) {
				remoteSimCaret = len(remoteSimRunes)
			}
			remoteSimRunes = append(remoteSimRunes[:remoteSimCaret-1], remoteSimRunes[remoteSimCaret:]...)
			remoteSimCaret--
		}
	case 21: // Left
		if remoteSimCaret > 0 {
			remoteSimCaret--
		}
	case 22: // Right
		if remoteSimCaret < len(remoteSimRunes) {
			remoteSimCaret++
		}
	case 122: // Home
		remoteSimCaret = 0
	case 123: // End
		remoteSimCaret = len(remoteSimRunes)
	}
}

const linuxPasteDaemonPy = `
import sys, os, json, time, threading, subprocess, unicodedata, ctypes, gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gtk, Gdk, GLib

cb = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
cb_pri = Gtk.Clipboard.get(Gdk.SELECTION_PRIMARY)

x11_dpy = None
x11_fast_dpy = None
libX11 = None
libXtst = None
KC_MAP = {}
try:
    libX11 = ctypes.cdll.LoadLibrary("libX11.so.6")
    libX11.XOpenDisplay.argtypes = [ctypes.c_char_p]
    libX11.XOpenDisplay.restype = ctypes.c_void_p
    libX11.XStringToKeysym.argtypes = [ctypes.c_char_p]
    libX11.XStringToKeysym.restype = ctypes.c_ulong
    libX11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    libX11.XKeysymToKeycode.restype = ctypes.c_ubyte
    libX11.XFlush.argtypes = [ctypes.c_void_p]
    libX11.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libXtst = ctypes.cdll.LoadLibrary("libXtst.so.6")
    libXtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
    libXtst.XTestFakeMotionEvent.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
    libXtst.XTestFakeRelativeMotionEvent.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
    libXtst.XTestFakeButtonEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
    x11_dpy = libX11.XOpenDisplay(None)
    x11_fast_dpy = libX11.XOpenDisplay(None)
    if x11_dpy:
        for kname in ("Left", "Right", "BackSpace", "Return", "Control_L", "Shift_L", "v"):
            KC_MAP[kname] = libX11.XKeysymToKeycode(x11_dpy, libX11.XStringToKeysym(kname.encode()))
except Exception:
    x11_dpy = None
    x11_fast_dpy = None

def pump_gtk(duration_sec):
    end_t = time.monotonic() + duration_sec
    while True:
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        rem = end_t - time.monotonic()
        if rem <= 0:
            break
        time.sleep(min(0.0015, rem))

def tap_x11_key(kname, count):
    if count <= 0:
        return
    if x11_dpy and kname in KC_MAP and KC_MAP[kname]:
        kc = KC_MAP[kname]
        for _ in range(count):
            libXtst.XTestFakeKeyEvent(x11_dpy, kc, 1, 0)
            libX11.XFlush(x11_dpy)
            pump_gtk(0.0025)
            libXtst.XTestFakeKeyEvent(x11_dpy, kc, 0, 0)
            libX11.XFlush(x11_dpy)
            pump_gtk(0.0025)
    else:
        subprocess.run(["xdotool", "key", "--clearmodifiers", "--repeat", str(count), "--delay", "6", kname], stderr=subprocess.DEVNULL)
        pump_gtk(0.010)

def trigger_x11_paste_combo(paste_key):
    ctrl_kc = KC_MAP.get("Control_L", 0)
    shift_kc = KC_MAP.get("Shift_L", 0)
    v_kc = KC_MAP.get("v", 0)
    if x11_dpy and ctrl_kc and v_kc:
        use_shift = ("shift" in paste_key) and bool(shift_kc)
        libXtst.XTestFakeKeyEvent(x11_dpy, ctrl_kc, 1, 0)
        if use_shift:
            libXtst.XTestFakeKeyEvent(x11_dpy, shift_kc, 1, 0)
        libXtst.XTestFakeKeyEvent(x11_dpy, v_kc, 1, 0)
        libX11.XFlush(x11_dpy)
        pump_gtk(0.003)
        libXtst.XTestFakeKeyEvent(x11_dpy, v_kc, 0, 0)
        if use_shift:
            libXtst.XTestFakeKeyEvent(x11_dpy, shift_kc, 0, 0)
        libXtst.XTestFakeKeyEvent(x11_dpy, ctrl_kc, 0, 0)
        libX11.XFlush(x11_dpy)
    else:
        subprocess.run(["xdotool", "key", "--clearmodifiers", paste_key], stderr=subprocess.DEVNULL)

def execute_fast_mouse(req):
    d = x11_fast_dpy or x11_dpy
    if not d or not libXtst:
        return False
    mtype = req.get("mtype", "")
    x = int(req.get("x", -1))
    y = int(req.get("y", -1))
    btn = int(req.get("btn", 1))
    cnt = max(1, int(req.get("cnt", 1)))
    if mtype == "move":
        if x >= 0 and y >= 0:
            libXtst.XTestFakeMotionEvent(d, -1, x, y, 0)
            libX11.XFlush(d)
        return True
    if mtype == "rel":
        libXtst.XTestFakeRelativeMotionEvent(d, x, y, 0)
        libX11.XFlush(d)
        return True
    if x >= 0 and y >= 0:
        libXtst.XTestFakeMotionEvent(d, -1, x, y, 0)
        libX11.XSync(d, 0)
        if mtype in ("click", "dblclick", "down"):
            time.sleep(0.008)
    if mtype == "down":
        libXtst.XTestFakeButtonEvent(d, btn, 1, 0)
        libX11.XSync(d, 0)
        return True
    if mtype == "up":
        libXtst.XTestFakeButtonEvent(d, btn, 0, 0)
        libX11.XSync(d, 0)
        return True
    if mtype == "click":
        libXtst.XTestFakeButtonEvent(d, btn, 1, 0)
        libX11.XSync(d, 0)
        time.sleep(0.010)
        libXtst.XTestFakeButtonEvent(d, btn, 0, 0)
        libX11.XSync(d, 0)
        return True
    if mtype == "dblclick":
        for i in range(2):
            if i > 0:
                time.sleep(0.045)
            libXtst.XTestFakeButtonEvent(d, btn, 1, 0)
            libX11.XSync(d, 0)
            time.sleep(0.010)
            libXtst.XTestFakeButtonEvent(d, btn, 0, 0)
            libX11.XSync(d, 0)
        return True
    if mtype == "scroll":
        for i in range(cnt):
            if i > 0:
                time.sleep(0.002)
            libXtst.XTestFakeButtonEvent(d, btn, 1, 0)
            libXtst.XTestFakeButtonEvent(d, btn, 0, 0)
        libX11.XSync(d, 0)
        return True
    return False

_win_cache_ts = 0.0
_win_cache_has = True
_win_cache_paste = "ctrl+v"

def get_window_paste_info():
    global _win_cache_ts, _win_cache_has, _win_cache_paste
    now = time.monotonic()
    if now - _win_cache_ts < 2.5:
        return _win_cache_has, _win_cache_paste
    _win_cache_ts = now
    try:
        wid = subprocess.check_output(["xdotool", "getactivewindow"], stderr=subprocess.DEVNULL).decode().strip()
        if not wid:
            _win_cache_has = False
            _win_cache_paste = "ctrl+v"
            return False, "ctrl+v"
        _win_cache_has = True
        wclass = subprocess.check_output(["xprop", "-id", wid, "WM_CLASS"], stderr=subprocess.DEVNULL).decode().lower()
        if any(t in wclass for t in ["gnome-terminal", "kitty", "alacritty", "wezterm", "xterm", "tilix", "konsole", "terminator", "xfce4-terminal"]):
            _win_cache_paste = "ctrl+shift+v"
        else:
            _win_cache_paste = "ctrl+v"
    except Exception:
        _win_cache_has = False
        _win_cache_paste = "ctrl+v"
    return _win_cache_has, _win_cache_paste

def execute_req(req, done_ev):
    resp_line = "OK\n"
    try:
        mb = int(req.get("mb", 0))
        bksp = int(req.get("bksp", 0))
        ma = int(req.get("ma", 0))
        raw_txt = req.get("text", "")
        is_direct = bool(req.get("direct", False))

        if mb != 0:
            tap_x11_key("Left" if mb < 0 else "Right", abs(mb))
            pump_gtk(0.010)

        if bksp > 0:
            tap_x11_key("BackSpace", bksp)
            if raw_txt != "" or ma != 0:
                pump_gtk(0.016)

        if raw_txt == "\n":
            tap_x11_key("Return", 1)
            pump_gtk(0.012)
        elif raw_txt != "":
            txt = unicodedata.normalize("NFC", raw_txt)
            has_win, paste_key = get_window_paste_info()
            if not has_win:
                subprocess.run(["xdotool", "type", "--clearmodifiers", "--delay", "8", "--", txt], stderr=subprocess.DEVNULL)
                pump_gtk(0.025)
            else:
                cb.set_text(txt, -1)
                cb_pri.set_text(txt, -1)
                pump_gtk(0.010 if is_direct else 0.014)
                subprocess.run(["xdotool", "key", "--clearmodifiers", paste_key], stderr=subprocess.DEVNULL)
                pump_gtk(0.032 if is_direct else 0.085)

        if ma != 0:
            tap_x11_key("Left" if ma < 0 else "Right", abs(ma))
            pump_gtk(0.010)
    except Exception:
        pass
    finally:
        sys.stdout.write(resp_line)
        sys.stdout.flush()
        done_ev.set()
    return False

def stdin_loop():
    sys.stdout.write("READY\n")
    sys.stdout.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            sys.stdout.write("ERR\n")
            sys.stdout.flush()
            continue
        if req.get("op") == "mouse":
            ok = execute_fast_mouse(req)
            sys.stdout.write("OK\n" if ok else "ERR\n")
            sys.stdout.flush()
            continue
        ev = threading.Event()
        GLib.idle_add(execute_req, req, ev)
        ev.wait()
    GLib.idle_add(Gtk.main_quit)

t = threading.Thread(target=stdin_loop, daemon=True)
t.start()
Gtk.main()
`

func stopLinuxPasteDaemonLocked() {
	if linuxPasteDaemonStdin != nil {
		_ = linuxPasteDaemonStdin.Close()
		linuxPasteDaemonStdin = nil
	}
	if linuxPasteDaemonCmd != nil && linuxPasteDaemonCmd.Process != nil {
		_ = linuxPasteDaemonCmd.Process.Kill()
		_, _ = linuxPasteDaemonCmd.Process.Wait()
	}
	linuxPasteDaemonCmd = nil
	linuxPasteDaemonStdout = nil
	linuxPasteDaemonEnvKey = ""
}

func ensureLinuxPasteDaemonLocked(env []string) bool {
	var dpy, xauth string
	for _, kv := range env {
		if strings.HasPrefix(kv, "DISPLAY=") {
			dpy = kv
		} else if strings.HasPrefix(kv, "XAUTHORITY=") {
			xauth = kv
		}
	}
	envKey := dpy + "|" + xauth

	if linuxPasteDaemonCmd != nil {
		if linuxPasteDaemonEnvKey != envKey || linuxPasteDaemonCmd.ProcessState != nil {
			stopLinuxPasteDaemonLocked()
		}
	}
	if linuxPasteDaemonCmd != nil && linuxPasteDaemonStdin != nil && linuxPasteDaemonStdout != nil {
		return true
	}
	cmd := exec.Command("python3", "-c", linuxPasteDaemonPy)
	cmd.Env = env
	stdin, err1 := cmd.StdinPipe()
	stdout, err2 := cmd.StdoutPipe()
	if err1 != nil || err2 != nil {
		return false
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	rd := bufio.NewReader(stdout)
	readyCh := make(chan string, 1)
	go func() {
		line, _ := rd.ReadString('\n')
		readyCh <- strings.TrimSpace(line)
	}()
	select {
	case rLine := <-readyCh:
		if rLine != "READY" {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return false
		}
	case <-time.After(2500 * time.Millisecond):
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return false
	}
	linuxPasteDaemonCmd = cmd
	linuxPasteDaemonStdin = stdin
	linuxPasteDaemonStdout = rd
	linuxPasteDaemonEnvKey = envKey
	return true
}

func runLinuxX11Mouse(mtype string, x, y, btn, cnt int) bool {
	pcInputMu.Lock()
	defer pcInputMu.Unlock()
	env := getLinuxX11Env()
	if !ensureLinuxPasteDaemonLocked(env) {
		return false
	}
	payload, _ := json.Marshal(struct {
		Op    string `json:"op"`
		MType string `json:"mtype"`
		X     int    `json:"x"`
		Y     int    `json:"y"`
		Btn   int    `json:"btn"`
		Cnt   int    `json:"cnt"`
	}{
		Op:    "mouse",
		MType: mtype,
		X:     x,
		Y:     y,
		Btn:   btn,
		Cnt:   cnt,
	})
	payload = append(payload, '\n')

	doneCh := make(chan bool, 1)
	go func(w io.Writer, r *bufio.Reader, data []byte) {
		if _, err := w.Write(data); err != nil {
			doneCh <- false
			return
		}
		line, err := r.ReadString('\n')
		doneCh <- (err == nil && strings.TrimSpace(line) == "OK")
	}(linuxPasteDaemonStdin, linuxPasteDaemonStdout, payload)

	select {
	case ok := <-doneCh:
		if !ok {
			stopLinuxPasteDaemonLocked()
		}
		return ok
	case <-time.After(800 * time.Millisecond):
		stopLinuxPasteDaemonLocked()
		return false
	}
}

func runLinuxPasteDaemonLocked(env []string, text string, bksp int, moveBefore int, moveAfter int, direct bool) bool {
	for attempt := 0; attempt < 2; attempt++ {
		if !ensureLinuxPasteDaemonLocked(env) {
			return false
		}

		payload, _ := json.Marshal(struct {
			Text   string `json:"text"`
			Bksp   int    `json:"bksp"`
			MB     int    `json:"mb"`
			MA     int    `json:"ma"`
			Direct bool   `json:"direct"`
		}{
			Text:   text,
			Bksp:   bksp,
			MB:     moveBefore,
			MA:     moveAfter,
			Direct: direct,
		})
		payload = append(payload, '\n')

		doneCh := make(chan bool, 1)
		go func(w io.Writer, r *bufio.Reader, data []byte) {
			if _, err := w.Write(data); err != nil {
				doneCh <- false
				return
			}
			line, err := r.ReadString('\n')
			doneCh <- (err == nil && strings.TrimSpace(line) == "OK")
		}(linuxPasteDaemonStdin, linuxPasteDaemonStdout, payload)

		select {
		case ok := <-doneCh:
			if ok {
				return true
			}
			stopLinuxPasteDaemonLocked()
		case <-time.After(3500 * time.Millisecond):
			stopLinuxPasteDaemonLocked()
		}
	}
	return false
}

func sendLinuxPCTextDelta(text string, bksp int, moveBefore int, moveAfter int, direct bool) {
	if runtime.GOOS == "windows" {
		winSendTextDelta(text, bksp, moveBefore, moveAfter, direct)
		return
	}
	startEpoch := atomic.LoadUint64(&pcInputCancelEpoch)
	isLoginOrLock := !isLinuxX11SessionReady() || isLinuxLoginOrLockScreen()
	if isLoginOrLock {
		uinputOK := false
		if moveBefore < 0 {
			for i := 0; i < -moveBefore; i++ {
				if sendDirectLinuxPCKeyViaUinput(21) {
					uinputOK = true
				}
			}
		} else if moveBefore > 0 {
			for i := 0; i < moveBefore; i++ {
				if sendDirectLinuxPCKeyViaUinput(22) {
					uinputOK = true
				}
			}
		}
		for i := 0; i < bksp; i++ {
			if i > 0 && atomic.LoadUint64(&pcInputCancelEpoch) != startEpoch {
				break
			}
			if sendDirectLinuxPCKeyViaUinput(67) {
				uinputOK = true
			}
		}
		if text != "" {
			if sendDirectLinuxTextViaUinput(text, false) {
				uinputOK = true
			}
		}
		if moveAfter < 0 {
			for i := 0; i < -moveAfter; i++ {
				if sendDirectLinuxPCKeyViaUinput(21) {
					uinputOK = true
				}
			}
		} else if moveAfter > 0 {
			for i := 0; i < moveAfter; i++ {
				if sendDirectLinuxPCKeyViaUinput(22) {
					uinputOK = true
				}
			}
		}
		if uinputOK || !isLinuxX11SessionReady() {
			invalidateScreenCache()
			return
		}
	}

	pcInputMu.Lock()
	defer pcInputMu.Unlock()

	env := getLinuxX11Env()

	if isLoginOrLock || !runLinuxPasteDaemonLocked(env, text, bksp, moveBefore, moveAfter, direct) {
		if moveBefore != 0 {
			k := "Right"
			cnt := moveBefore
			if moveBefore < 0 {
				k = "Left"
				cnt = -moveBefore
			}
			cMb := exec.Command("xdotool", "key", "--clearmodifiers", "--repeat", strconv.Itoa(cnt), "--delay", "4", k)
			cMb.Env = env
			cMb.Run()
		}
		if bksp > 0 {
			cBk := exec.Command("xdotool", "key", "--clearmodifiers", "--repeat", strconv.Itoa(bksp), "--delay", "4", "BackSpace")
			cBk.Env = env
			cBk.Run()
		}
		if text == "\n" {
			cRet := exec.Command("xdotool", "key", "--clearmodifiers", "Return")
			cRet.Env = env
			cRet.Run()
		} else if text != "" {
			fallback := exec.Command("xdotool", "type", "--clearmodifiers", "--delay", "6", "--", text)
			fallback.Env = env
			fallback.Run()
		}
		if moveAfter != 0 {
			k := "Right"
			cnt := moveAfter
			if moveAfter < 0 {
				k = "Left"
				cnt = -moveAfter
			}
			cMa := exec.Command("xdotool", "key", "--clearmodifiers", "--repeat", strconv.Itoa(cnt), "--delay", "4", k)
			cMa.Env = env
			cMa.Run()
		}
	}
	invalidateScreenCache()
}

func sendLinuxPCImageClipboard(pngPath string, autoPaste bool) error {
	if runtime.GOOS == "windows" {
		return winSendImageClipboard(pngPath, autoPaste)
	}
	pcInputMu.Lock()
	defer pcInputMu.Unlock()

	pyScript := `
import os, subprocess, gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gtk, Gdk, GdkPixbuf, GLib

path = os.environ.get("VUI_IMG_PATH", "")
auto_paste = os.environ.get("VUI_AUTO_PASTE", "1") == "1"
pb = GdkPixbuf.Pixbuf.new_from_file(path)
cb = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
cb.set_image(pb)
cb.store()

def do_paste():
    if auto_paste:
        subprocess.run(["xdotool", "key", "--clearmodifiers", "ctrl+v"], stderr=subprocess.DEVNULL)
        GLib.timeout_add(180, Gtk.main_quit)
    else:
        GLib.timeout_add(80, Gtk.main_quit)
    return False

GLib.timeout_add(60, do_paste)
Gtk.main()
`
	pasteFlag := "0"
	if autoPaste {
		pasteFlag = "1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-c", pyScript)
	cmd.Env = append(getLinuxX11Env(), "VUI_IMG_PATH="+pngPath, "VUI_AUTO_PASTE="+pasteFlag)
	err := cmd.Run()
	invalidateScreenCache()
	return err
}

func sanitizeDeviceID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	res := b.String()
	if len(res) > 18 {
		res = res[:18]
	}
	return res
}

func initDeviceIdentity() {
	if runtime.GOOS == "windows" {
		myDeviceType = "win11"
		winInitPlatform()
	} else if !isAndroid() {
		myDeviceType = "pc"
		atomic.StoreInt32(&detectedWidth, 2560)
		atomic.StoreInt32(&detectedHeight, 1440)
	}
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip := ipnet.IP.String()
					if runtime.GOOS == "windows" {
						if strings.HasPrefix(ip, "192.168.") || (myIP == "" && !strings.HasPrefix(ip, "172.") && !strings.HasPrefix(ip, "169.")) {
							myIP = ip
							if strings.HasPrefix(ip, "192.168.") {
								break
							}
						}
					} else if strings.Contains(ip, "192.168.1.135") {
						myDeviceType = "projector"
						myIP = ip
						break
					} else if strings.Contains(ip, "192.168.1.138") {
						myDeviceType = "kaw"
						myIP = ip
						break
					} else if strings.Contains(ip, "192.168.1.88") || strings.Contains(ip, "192.168.1.140") || strings.Contains(ip, "192.168.1.67") {
						myDeviceType = "tx3"
						myIP = ip
						break
					} else if strings.Contains(ip, "192.168.1.154") {
						myDeviceType = "pc"
						myIP = ip
						break
					} else {
						if myIP == "" && !strings.HasPrefix(ip, "172.") && !strings.HasPrefix(ip, "100.") {
							myIP = ip
						}
					}
				}
			}
		}
	}
	// Auto-assign a unique ID for any new device joining the mesh so it never overwrites existing fixed devices
	hostSlug := sanitizeDeviceID(getHostName())
	if runtime.GOOS == "windows" {
		if !strings.EqualFold(getHostName(), "LAPTOP-2FDEKP1N") && myIP != "192.168.1.55" {
			if hostSlug != "" && hostSlug != "pc" {
				myDeviceType = "win_" + hostSlug
			} else if myIP != "" {
				parts := strings.Split(myIP, ".")
				myDeviceType = "win_" + parts[len(parts)-1]
			}
		}
	} else if !isAndroid() {
		if !strings.EqualFold(getHostName(), "pop-os") && myIP != "192.168.1.154" {
			if hostSlug != "" && hostSlug != "pc" {
				myDeviceType = "pc_" + hostSlug
			} else if myIP != "" {
				parts := strings.Split(myIP, ".")
				myDeviceType = "pc_" + parts[len(parts)-1]
			}
		}
	} else if myDeviceType == "tx3" && myIP != "" && myIP != "192.168.1.88" && myIP != "192.168.1.140" && myIP != "192.168.1.67" {
		parts := strings.Split(myIP, ".")
		myDeviceType = "box_" + parts[len(parts)-1]
	}
	if envType := os.Getenv("VUI_DEV_TYPE"); envType != "" {
		myDeviceType = envType
	}
	fmt.Printf("[DEVICE IDENT] Running as '%s' (IP: %s, OS: %s, Android: %t)\n", myDeviceType, myIP, runtime.GOOS, isAndroid())
}

func createUinputTouch() *os.File {
	fd, err := os.OpenFile("/dev/uinput", os.O_RDWR, 0666)
	if err != nil {
		fmt.Printf("[UINPUT TOUCH WARN] Open /dev/uinput failed: %v\n", err)
		return nil
	}

	ioctl := func(req uint, arg uintptr) error {
		return sysIoctl(fd, req, arg)
	}

	ioctl(0x40045564, uintptr(1))     // UI_SET_EVBIT, EV_KEY
	ioctl(0x40045565, uintptr(0x14a)) // UI_SET_KEYBIT, BTN_TOUCH
	ioctl(0x40045565, uintptr(0x145)) // UI_SET_KEYBIT, BTN_TOOL_FINGER

	ioctl(0x40045564, uintptr(3)) // UI_SET_EVBIT, EV_ABS
	ioctl(0x40045567, uintptr(0)) // UI_SET_ABSBIT, ABS_X
	ioctl(0x40045567, uintptr(1)) // UI_SET_ABSBIT, ABS_Y

	ioctl(0x4004556e, uintptr(1)) // UI_SET_PROPBIT, INPUT_PROP_DIRECT

	type uinputUserDev struct {
		Name         [80]byte
		Bustype      uint16
		Vendor       uint16
		Product      uint16
		Version      uint16
		FfEffectsMax uint32
		Absmax       [64]int32
		Absmin       [64]int32
		Absfuzz      [64]int32
		Absflat      [64]int32
	}

	var dev uinputUserDev
	copy(dev.Name[:], "VuiTouch")
	dev.Bustype = 0x18 // BUS_I2C (internal built-in touchscreen)
	dev.Vendor = 0x1234
	dev.Product = 0x5679
	dev.Version = 1
	dev.Absmin[0] = 0
	dev.Absmax[0] = 4095
	dev.Absmin[1] = 0
	dev.Absmax[1] = 4095

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, dev)
	if _, err := fd.Write(buf.Bytes()); err != nil {
		fmt.Printf("[UINPUT TOUCH WARN] Write uinput dev failed: %v\n", err)
		fd.Close()
		return nil
	}

	if err := ioctl(0x5501, 0); err != nil { // UI_DEV_CREATE
		fmt.Printf("[UINPUT TOUCH WARN] UI_DEV_CREATE failed: %v\n", err)
		fd.Close()
		return nil
	}

	fmt.Println("[UINPUT TOUCH OK] Created virtual touchscreen /dev/uinput (VuiTouch)")
	return fd
}

func createUinputMouse() *os.File {
	fd, err := os.OpenFile("/dev/uinput", os.O_RDWR, 0666)
	if err != nil {
		fmt.Printf("[UINPUT WARN] Open /dev/uinput failed: %v\n", err)
		return nil
	}

	ioctl := func(req uint, arg uintptr) error {
		return sysIoctl(fd, req, arg)
	}

	ioctl(0x40045564, uintptr(1))     // UI_SET_EVBIT, EV_KEY
	ioctl(0x40045565, uintptr(0x110)) // UI_SET_KEYBIT, BTN_LEFT
	ioctl(0x40045565, uintptr(0x111)) // UI_SET_KEYBIT, BTN_RIGHT
	ioctl(0x40045565, uintptr(0x112)) // UI_SET_KEYBIT, BTN_MIDDLE
	for _, k := range []uint16{103, 108, 105, 106, 28, 97, 1, 158, 102, 139, 115, 114, 113, 116, 119, 14} {
		ioctl(0x40045565, uintptr(k))
	}

	ioctl(0x40045564, uintptr(2)) // UI_SET_EVBIT, EV_REL
	ioctl(0x40045566, uintptr(0)) // UI_SET_RELBIT, REL_X
	ioctl(0x40045566, uintptr(1)) // UI_SET_RELBIT, REL_Y
	ioctl(0x40045566, uintptr(8)) // UI_SET_RELBIT, REL_WHEEL

	type uinputUserDev struct {
		Name         [80]byte
		Bustype      uint16
		Vendor       uint16
		Product      uint16
		Version      uint16
		FfEffectsMax uint32
		Absmax       [64]int32
		Absmin       [64]int32
		Absfuzz      [64]int32
		Absflat      [64]int32
	}

	var dev uinputUserDev
	copy(dev.Name[:], "VuiMouse")
	dev.Bustype = 0x03 // BUS_USB
	dev.Vendor = 0x1234
	dev.Product = 0x5678
	dev.Version = 1

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, dev)
	if _, err := fd.Write(buf.Bytes()); err != nil {
		fmt.Printf("[UINPUT WARN] Write uinput dev failed: %v\n", err)
		fd.Close()
		return nil
	}

	if err := ioctl(0x5501, 0); err != nil { // UI_DEV_CREATE
		fmt.Printf("[UINPUT WARN] UI_DEV_CREATE failed: %v\n", err)
		fd.Close()
		return nil
	}

	fmt.Println("[UINPUT OK] Created virtual mouse /dev/uinput (VuiMouse)")
	return fd
}

func createUinputKeyboard() *os.File {
	fd, err := os.OpenFile("/dev/uinput", os.O_RDWR, 0666)
	if err != nil {
		fmt.Printf("[UINPUT WARN] Open /dev/uinput for keyboard failed: %v\n", err)
		return nil
	}

	ioctl := func(req uint, arg uintptr) error {
		return sysIoctl(fd, req, arg)
	}

	ioctl(0x40045564, uintptr(1)) // UI_SET_EVBIT, EV_KEY
	for k := uint16(1); k < 249; k++ {
		ioctl(0x40045565, uintptr(k))
	}
	if isAndroid() {
		for k := uint16(249); k < 255; k++ {
			ioctl(0x40045565, uintptr(k))
		}
		ioctl(0x40045565, uintptr(353)) // KEY_SELECT (DPAD_CENTER in Android Generic.kl)
		ioctl(0x40045565, uintptr(372)) // KEY_ZOOM
		ioctl(0x40045565, uintptr(265)) // FOCUS_UP
		ioctl(0x40045565, uintptr(266)) // FOCUS_DOWN
		ioctl(0x40045565, uintptr(289)) // AUTOFOCUS
		ioctl(0x40045565, uintptr(196)) // AUTO_KEYSTONE
		ioctl(0x40045565, uintptr(270)) // ACTION_WIFI
		ioctl(0x40045565, uintptr(271)) // ACTION_BT
	}

	type uinputUserDev struct {
		Name         [80]byte
		Bustype      uint16
		Vendor       uint16
		Product      uint16
		Version      uint16
		FfEffectsMax uint32
		Absmax       [64]int32
		Absmin       [64]int32
		Absfuzz      [64]int32
		Absflat      [64]int32
	}

	var dev uinputUserDev
	copy(dev.Name[:], "VuiKeyboard")
	dev.Bustype = 0x03 // BUS_USB
	dev.Vendor = 0x1234
	dev.Product = 0x8888
	dev.Version = 1

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, dev)
	if _, err := fd.Write(buf.Bytes()); err != nil {
		fmt.Printf("[UINPUT WARN] Write uinput keyboard dev failed: %v\n", err)
		fd.Close()
		return nil
	}

	if err := ioctl(0x5501, 0); err != nil { // UI_DEV_CREATE
		fmt.Printf("[UINPUT WARN] UI_DEV_CREATE for keyboard failed: %v\n", err)
		fd.Close()
		return nil
	}

	fmt.Println("[UINPUT OK] Created virtual keyboard /dev/uinput (VuiKeyboard)")
	return fd
}

func initInputDevice() {
	initDeviceIdentity()
	if !isAndroid() {
		if runtime.GOOS == "linux" {
			keyboardFd = createUinputKeyboard()
		}
		fmt.Println("[INPUT OK] Linux PC mode active: using xdotool, X11grab, and uinput pre-login keyboard")
		return
	}
	if myDeviceType == "projector" {
		exec.Command("/system/xbin/zu", "0", "sh", "-c", "chmod 666 /dev/uinput /dev/input/event*").Run()
	} else if myDeviceType == "kaw" {
		exec.Command("/system/xbin/rjsu", "0", "sh", "-c", "chmod 666 /dev/uinput /dev/input/event*").Run()
		exec.Command("su", "0", "sh", "-c", "chmod 666 /dev/uinput /dev/input/event*").Run()
	}
	var err error
	eventFd, err = os.OpenFile("/dev/input/event0", os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("[INPUT WARN] Could not open /dev/input/event0: %v\n", err)
	} else {
		fmt.Println("[INPUT OK] Keypad /dev/input/event0 opened successfully")
	}

	touchFd = createUinputTouch()
	keyboardFd = createUinputKeyboard()

	if myDeviceType == "projector" {
		// HiSilicon projector has dedicated mouse node on /dev/input/event1 ("Hi mouse")
		mouseFd, err = os.OpenFile("/dev/input/event1", os.O_WRONLY, 0666)
		if err != nil {
			mouseFd = eventFd
			fmt.Printf("[MOUSE WARN] Projector event1 open failed, fallback to event0: %v\n", err)
		} else {
			fmt.Println("[MOUSE OK] Mouse /dev/input/event1 opened for Projector (Hi mouse)")
		}
	} else if myDeviceType == "kaw" {
		// KAW Projector (MediaTek): create virtual mouse on /dev/uinput
		mouseFd = createUinputMouse()
		if mouseFd == nil {
			mouseFd = eventFd
		}
	} else {
		// TX3 Mini (Amlogic): mouse node is /dev/input/event0 ("aml_keypad")!
		// /dev/input/event1 is gpio_keypad on TX3 Mini, so we MUST use event0.
		mouseFd = eventFd
		fmt.Println("[MOUSE OK] Mouse set to /dev/input/event0 for TX3 Mini (aml_keypad)")
	}
}

func sendDirectKey(linuxCode uint16, holdMs int) bool {
	eventMu.Lock()
	defer eventMu.Unlock()

	targetFd := keyboardFd
	if targetFd == nil {
		targetFd = eventFd
	}
	if targetFd == nil {
		var err error
		eventFd, err = os.OpenFile("/dev/input/event0", os.O_WRONLY, 0666)
		if err == nil {
			targetFd = eventFd
		} else {
			return false
		}
	}

	buf := new(bytes.Buffer)
	now := time.Now()

	// Key Down (Value: 1)
	writeKernelInputEvent(buf, now, 1, linuxCode, 1)
	writeKernelInputEvent(buf, now, 0, 0, 0)

	if _, err := targetFd.Write(buf.Bytes()); err != nil {
		if targetFd == eventFd {
			eventFd.Close()
			eventFd = nil
		}
		return false
	}

	if holdMs <= 0 {
		holdMs = 12
	}

	if holdMs > 100 {
		// Long press: emit repeat events (Value: 2) every 100ms
		steps := holdMs / 100
		for i := 0; i < steps; i++ {
			time.Sleep(100 * time.Millisecond)
			buf.Reset()
			now = time.Now()
			writeKernelInputEvent(buf, now, 1, linuxCode, 2)
			writeKernelInputEvent(buf, now, 0, 0, 0)
			targetFd.Write(buf.Bytes())
		}
	} else {
		time.Sleep(time.Duration(holdMs) * time.Millisecond)
	}

	// Key Up (Value: 0)
	buf.Reset()
	now = time.Now()

	writeKernelInputEvent(buf, now, 1, linuxCode, 0)
	writeKernelInputEvent(buf, now, 0, 0, 0)

	if _, err := targetFd.Write(buf.Bytes()); err != nil {
		if targetFd == eventFd {
			eventFd.Close()
			eventFd = nil
		}
		return false
	}
	return true
}

func sendRelMouse(dx, dy int) {
	eventMu.Lock()
	defer eventMu.Unlock()
	targetFd := mouseFd
	if targetFd == nil {
		targetFd = eventFd
		if targetFd == nil {
			return
		}
	}

	buf := new(bytes.Buffer)
	now := time.Now()

	if dx != 0 {
		writeKernelInputEvent(buf, now, 2, 0, int32(dx)) // REL_X
	}
	if dy != 0 {
		writeKernelInputEvent(buf, now, 2, 1, int32(dy)) // REL_Y
	}
	writeKernelInputEvent(buf, now, 0, 0, 0) // SYN
	targetFd.Write(buf.Bytes())
}

func sendMouseButton(btn uint16) {
	eventMu.Lock()
	defer eventMu.Unlock()
	targetFd := mouseFd
	if targetFd == nil {
		targetFd = eventFd
		if targetFd == nil {
			return
		}
	}

	buf := new(bytes.Buffer)
	now := time.Now()

	// Down
	writeKernelInputEvent(buf, now, 1, btn, 1)
	writeKernelInputEvent(buf, now, 0, 0, 0)
	targetFd.Write(buf.Bytes())

	time.Sleep(20 * time.Millisecond)

	// Up
	buf.Reset()
	now = time.Now()
	writeKernelInputEvent(buf, now, 1, btn, 0)
	writeKernelInputEvent(buf, now, 0, 0, 0)
	targetFd.Write(buf.Bytes())
}

func sendMouseWheel(val int) {
	eventMu.Lock()
	defer eventMu.Unlock()
	targetFd := mouseFd
	if targetFd == nil {
		targetFd = eventFd
		if targetFd == nil {
			return
		}
	}

	buf := new(bytes.Buffer)
	now := time.Now()

	writeKernelInputEvent(buf, now, 2, 8, int32(val)) // REL_WHEEL
	writeKernelInputEvent(buf, now, 0, 0, 0)
	targetFd.Write(buf.Bytes())
}

func sendDirectTouchTap(px, py float64, tvConfirm bool) {
	px, py = remapTouchToScreen(px, py)
	if px < 0 {
		px = 0
	} else if px > 1 {
		px = 1
	}
	if py < 0 {
		py = 0
	} else if py > 1 {
		py = 1
	}

	if touchFd != nil {
		eventMu.Lock()
		absX := int32(px * 4095.0)
		absY := int32(py * 4095.0)

		buf := new(bytes.Buffer)
		now := time.Now()
		sec := int32(now.Unix())
		usec := int32(now.UnixNano()%1e9) / 1000

		// Touch Down (with BTN_TOOL_FINGER so Android TouchInputMapper always sets TOOL_TYPE_FINGER)
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 3, 0, absX})  // EV_ABS, ABS_X
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 3, 1, absY})  // EV_ABS, ABS_Y
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x14a, 1}) // EV_KEY, BTN_TOUCH, 1
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x145, 1}) // EV_KEY, BTN_TOOL_FINGER, 1
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 0, 0, 0})     // EV_SYN
		touchFd.Write(buf.Bytes())

		time.Sleep(28 * time.Millisecond)

		// Touch Up
		buf.Reset()
		now = time.Now()
		sec = int32(now.Unix())
		usec = int32(now.UnixNano()%1e9) / 1000
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x14a, 0}) // EV_KEY, BTN_TOUCH, 0
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x145, 0}) // EV_KEY, BTN_TOOL_FINGER, 0
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 0, 0, 0})     // EV_SYN
		touchFd.Write(buf.Bytes())
		eventMu.Unlock()

		invalidateScreenCache()
		return
	}

	screenW, screenH := getScreenDimensions()
	x := int(px * float64(screenW))
	y := int(py * float64(screenH))
	runSh(fmt.Sprintf("input tap %d %d", x, y))
	invalidateScreenCache()
}

func sendDirectTouchLongPress(px, py float64) {
	px, py = remapTouchToScreen(px, py)
	if px < 0 {
		px = 0
	} else if px > 1 {
		px = 1
	}
	if py < 0 {
		py = 0
	} else if py > 1 {
		py = 1
	}

	if touchFd != nil {
		eventMu.Lock()
		absX := int32(px * 4095.0)
		absY := int32(py * 4095.0)

		buf := new(bytes.Buffer)
		now := time.Now()
		sec := int32(now.Unix())
		usec := int32(now.UnixNano()%1e9) / 1000

		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 3, 0, absX})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 3, 1, absY})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x14a, 1})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x145, 1})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 0, 0, 0})
		touchFd.Write(buf.Bytes())
		eventMu.Unlock()

		time.Sleep(650 * time.Millisecond)

		eventMu.Lock()
		buf.Reset()
		now = time.Now()
		sec = int32(now.Unix())
		usec = int32(now.UnixNano()%1e9) / 1000
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x14a, 0})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x145, 0})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 0, 0, 0})
		touchFd.Write(buf.Bytes())
		eventMu.Unlock()
		invalidateScreenCache()
		return
	}

	screenW, screenH := getScreenDimensions()
	x := int(px * float64(screenW))
	y := int(py * float64(screenH))
	runSh(fmt.Sprintf("input swipe %d %d %d %d 750", x, y, x, y))
	invalidateScreenCache()
}

func sendDirectTouchSwipe(px1, py1, px2, py2 float64, durMs int) {
	px1, py1 = remapTouchToScreen(px1, py1)
	px2, py2 = remapTouchToScreen(px2, py2)
	dx := px2 - px1
	dy := py2 - py1

	// On Android TV / Projector Leanback interfaces (TX3 Mini, Hyundai Projector, KAW Projector),
	// raw touch swipe often clicks dismiss backdrops (returning to Home) or fails to scroll TV rows.
	// D-Pad directional steps scroll every TV/Projector launcher row, settings list, YouTube, and TiviMate cleanly!
	if myDeviceType == "tx3" || myDeviceType == "projector" || myDeviceType == "kaw" {
		if math.Abs(dx) > math.Abs(dy) {
			steps := int(math.Abs(dx) / 0.16)
			if steps < 1 {
				steps = 1
			} else if steps > 4 {
				steps = 4
			}
			// Swipe left (dx < 0) moves focus right across the row; swipe right (dx > 0) moves focus left
			keyCode := 22 // DPAD_RIGHT
			if dx > 0 {
				keyCode = 21 // DPAD_LEFT
			}
			for i := 0; i < steps; i++ {
				triggerKey(keyCode, 12)
				if i+1 < steps {
					time.Sleep(35 * time.Millisecond)
				}
			}
		} else {
			steps := int(math.Abs(dy) / 0.16)
			if steps < 1 {
				steps = 1
			} else if steps > 4 {
				steps = 4
			}
			// Swipe up (dy < 0) scrolls down the list; swipe down (dy > 0) scrolls up the list
			keyCode := 20 // DPAD_DOWN
			if dy > 0 {
				keyCode = 19 // DPAD_UP
			}
			for i := 0; i < steps; i++ {
				triggerKey(keyCode, 12)
				if i+1 < steps {
					time.Sleep(35 * time.Millisecond)
				}
			}
		}
		invalidateScreenCache()
		return
	}

	if touchFd != nil {
		steps := 12
		stepSleep := time.Duration(durMs/steps) * time.Millisecond
		if stepSleep < 8*time.Millisecond {
			stepSleep = 8 * time.Millisecond
		}

		eventMu.Lock()
		buf := new(bytes.Buffer)
		now := time.Now()
		sec := int32(now.Unix())
		usec := int32(now.UnixNano()%1e9) / 1000

		absX1 := int32(px1 * 4095.0)
		absY1 := int32(py1 * 4095.0)
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 3, 0, absX1})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 3, 1, absY1})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x14a, 1})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 0, 0, 0})
		touchFd.Write(buf.Bytes())

		for i := 1; i <= steps; i++ {
			time.Sleep(stepSleep)
			t := float64(i) / float64(steps)
			cx := int32((px1 + (px2-px1)*t) * 4095.0)
			cy := int32((py1 + (py2-py1)*t) * 4095.0)
			buf.Reset()
			now = time.Now()
			sec = int32(now.Unix())
			usec = int32(now.UnixNano()%1e9) / 1000
			binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 3, 0, cx})
			binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 3, 1, cy})
			binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 0, 0, 0})
			touchFd.Write(buf.Bytes())
		}

		buf.Reset()
		now = time.Now()
		sec = int32(now.Unix())
		usec = int32(now.UnixNano()%1e9) / 1000
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 1, 0x14a, 0})
		binary.Write(buf, binary.LittleEndian, InputEvent{sec, usec, 0, 0, 0})
		touchFd.Write(buf.Bytes())
		eventMu.Unlock()
		invalidateScreenCache()
		return
	}

	screenW, screenH := getScreenDimensions()
	x1 := int(px1 * float64(screenW))
	y1 := int(py1 * float64(screenH))
	x2 := int(px2 * float64(screenW))
	y2 := int(py2 * float64(screenH))
	runSh(fmt.Sprintf("input swipe %d %d %d %d %d", x1, y1, x2, y2, durMs))
	invalidateScreenCache()
}

func triggerKey(androidCode int, holdMs int) {
	defer invalidateScreenCache()
	if !isAndroid() {
		sendLinuxPCKey(androidCode)
		return
	}
	var linuxCode uint16
	switch androidCode {
	case 19: // DPAD_UP
		linuxCode = 103
	case 20: // DPAD_DOWN
		linuxCode = 108
	case 21: // DPAD_LEFT
		linuxCode = 105
	case 22: // DPAD_RIGHT
		linuxCode = 106
	case 23: // DPAD_CENTER (KEY_SELECT in Android Generic.kl)
		linuxCode = 353
	case 66: // ENTER
		linuxCode = 28
	case 4: // BACK
		linuxCode = 158
	case 3: // HOME
		linuxCode = 102
	case 82: // MENU
		linuxCode = 139
	case 24: // VOLUME_UP
		linuxCode = 115
	case 25: // VOLUME_DOWN
		linuxCode = 114
	case 164: // VOLUME_MUTE
		linuxCode = 113
	case 26: // POWER
		linuxCode = 116
	case 85: // MEDIA_PLAY_PAUSE
		linuxCode = 119
	case 67: // DEL
		linuxCode = 14
	// Projector keys
	case 265: // FOCUS_UP
		linuxCode = 265
	case 266: // FOCUS_DOWN
		linuxCode = 266
	case 289: // AUTOFOCUS
		linuxCode = 289
	case 196: // AUTO_KEYSTONE
		linuxCode = 196
	case 372: // KEY_ZOOM
		linuxCode = 372
	case 270: // ACTION_WIFI
		linuxCode = 270
	case 271: // ACTION_BT
		linuxCode = 271
	default:
		if holdMs > 100 {
			runSh(fmt.Sprintf("input keyevent --longpress %d", androidCode))
		} else {
			runSh(fmt.Sprintf("input keyevent %d", androidCode))
		}
		return
	}

	if !sendDirectKey(linuxCode, holdMs) {
		if holdMs > 100 {
			runSh(fmt.Sprintf("input keyevent --longpress %d", androidCode))
		} else {
			runSh(fmt.Sprintf("input keyevent %d", androidCode))
		}
	}

	// Ensure HOME key (3) always brings the HOME launcher activity to front across TX3, Hyundai, and KAW
	if androidCode == 3 {
		go runSh("am start -a android.intent.action.MAIN -c android.intent.category.HOME >/dev/null 2>&1")
	}
}

func runSh(cmdStr string) {
	select {
	case shSem <- struct{}{}:
		defer func() { <-shSem }()
	default:
		// Drop if 2 shell commands are already in flight to prevent process pile-up
		return
	}
	fmt.Printf("[EXEC SH] %s\n", cmdStr)
	ctx, cancel := context.WithTimeout(context.Background(), 2000*time.Millisecond)
	defer cancel()
	shPath := "/system/bin/sh"
	if !isAndroid() {
		shPath = "/bin/sh"
	}
	out, err := exec.CommandContext(ctx, shPath, "-c", cmdStr).CombinedOutput()
	if err != nil {
		fmt.Printf("[EXEC ERR] %v: %s\n", err, string(out))
	}
}

var proxyTransport = &http.Transport{
	MaxIdleConns:          128,
	MaxIdleConnsPerHost:   32,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   5 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	DisableCompression:    true,
}

func forwardIfRemote(w http.ResponseWriter, r *http.Request) bool {
	dev := r.URL.Query().Get("dev")
	if r.URL.Path == "/api/upload_image" && isAndroid() {
		if dev == "" || dev == "local" || dev == myDeviceType || dev == "tx3" || dev == "projector" || dev == "kaw" || dev == "tv360" {
			if getDeviceHost("pc") != "" {
				dev = "pc"
			} else if getDeviceHost("win11") != "" {
				dev = "win11"
			}
		}
	}
	if dev == "" || dev == "local" || dev == myDeviceType || dev == myIP || isOwnLocalIP(dev) {
		return false
	}
	if (myDeviceType == "tx3" && (dev == "tx3" || dev == "192.168.1.88" || dev == "192.168.1.140" || dev == "192.168.1.67")) ||
		(myDeviceType == "projector" && (dev == "projector" || dev == "192.168.1.135")) ||
		(myDeviceType == "kaw" && (dev == "kaw" || dev == "192.168.1.138")) ||
		(myDeviceType == "pc" && (dev == "pc" || dev == "192.168.1.154" || dev == "192.168.1.161")) ||
		(myDeviceType == "win11" && (dev == "win11" || dev == "192.168.1.55")) {
		return false
	}

	if dev == "tv360" || dev == "192.168.1.11" {
		if r.URL.Path == "/api/screen" {
			client := http.Client{Timeout: 3500 * time.Millisecond, Transport: proxyTransport}
			resp, err := client.Get("http://192.168.1.11:8081/screen.jpg")
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				resp, err = client.Get("http://192.168.1.154:8089/screen")
				if err != nil || resp.StatusCode != 200 {
					if resp != nil {
						resp.Body.Close()
					}
					resp, err = client.Get("http://192.168.1.148:8089/screen")
				}
			}
			if err == nil && resp != nil && resp.StatusCode == 200 {
				defer resp.Body.Close()
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Content-Type", "image/jpeg")
				w.Header().Set("Cache-Control", "private, max-age=2")
				io.Copy(w, resp.Body)
				return true
			}
			if resp != nil {
				resp.Body.Close()
			}
			http.Error(w, "TV360 screen stream unavailable", http.StatusServiceUnavailable)
			return true
		}
		bridgeHost := "192.168.1.154:8089"
		if d, ok := deviceRegistry["tv360"]; ok && d.Host != "" {
			bridgeHost = d.Host
		}
		var targetURL string
		switch r.URL.Path {
		case "/api/key":
			targetURL = fmt.Sprintf("http://%s/key?code=%s", bridgeHost, url.QueryEscape(r.URL.Query().Get("code")))
		case "/api/cmd":
			targetURL = fmt.Sprintf("http://%s/cmd?action=%s&pin=%s", bridgeHost, url.QueryEscape(r.URL.Query().Get("action")), url.QueryEscape(r.URL.Query().Get("pin")))
		case "/api/text":
			targetURL = fmt.Sprintf("http://%s/text?q=%s", bridgeHost, url.QueryEscape(r.URL.Query().Get("q")))
		case "/api/app":
			targetURL = fmt.Sprintf("http://%s/app?pkg=%s", bridgeHost, url.QueryEscape(r.URL.Query().Get("pkg")))
		case "/api/touch":
			targetURL = fmt.Sprintf("http://%s/touch?%s", bridgeHost, r.URL.RawQuery)
		case "/api/status":
			targetURL = fmt.Sprintf("http://%s/status", bridgeHost)
		case "/api/tv360/pair_start":
			targetURL = fmt.Sprintf("http://%s/pair/start", bridgeHost)
		case "/api/tv360/pair_pin":
			targetURL = fmt.Sprintf("http://%s/pair/pin?pin=%s", bridgeHost, url.QueryEscape(r.URL.Query().Get("pin")))
		default:
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"unsupported_tv360_endpoint"}`))
			return true
		}
		client := http.Client{Timeout: 5 * time.Second, Transport: proxyTransport}
		resp, err := client.Get(targetURL)
		if err == nil {
			defer resp.Body.Close()
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			return true
		}
		fmt.Printf("[TV360 FORWARD ERR] %v\n", err)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGatewayTimeout)
		w.Write([]byte(`{"error":"tv360_unreachable"}`))
		return true
	}

	targetHost := getDeviceHost(dev)
	if targetHost == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(fmt.Sprintf(`{"error":"unknown_device","dev":%q}`, dev)))
		return true
	}

	rawURI := r.URL.RequestURI()
	re := regexp.MustCompile(`([?&])dev=[^&]*`)
	var forwardURI string
	if re.MatchString(rawURI) {
		forwardURI = re.ReplaceAllString(rawURI, "${1}dev=local")
	} else if strings.Contains(rawURI, "?") {
		forwardURI = rawURI + "&dev=local"
	} else {
		forwardURI = rawURI + "?dev=local"
	}

	targetURL := "http://" + targetHost + forwardURI
	timeout := 2500 * time.Millisecond
	if r.URL.Path == "/api/screen" {
		timeout = 4500 * time.Millisecond
	} else if r.URL.Path == "/api/upload_image" {
		timeout = 180 * time.Second
	} else if r.URL.Path == "/api/text" {
		timeout = 15 * time.Second
	}
	client := http.Client{Timeout: timeout, Transport: proxyTransport}

	var bodyBytes []byte
	var reqBody io.Reader = r.Body
	if r.Body != nil && r.URL.Path != "/api/upload_image" {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, reqErr := http.NewRequest(r.Method, targetURL, reqBody)
	if reqErr != nil {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(fmt.Sprintf(`{"error":"bad_proxy_request","dev":%q}`, dev)))
		return true
	}
	if r.URL.Path == "/api/upload_image" && r.ContentLength > 0 {
		req.ContentLength = r.ContentLength
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if ck := r.Header.Get("Cookie"); ck != "" {
		req.Header.Set("Cookie", ck)
	}
	resp, err := client.Do(req)
	if err != nil && dev == "pc" && targetHost != "192.168.1.154:8090" && r.URL.Path != "/api/upload_image" {
		fallbackHost := "192.168.1.154:8090"
		var retryBody io.Reader
		if len(bodyBytes) > 0 {
			retryBody = bytes.NewReader(bodyBytes)
		}
		if req2, err2 := http.NewRequest(r.Method, "http://"+fallbackHost+forwardURI, retryBody); err2 == nil {
			if ct := r.Header.Get("Content-Type"); ct != "" {
				req2.Header.Set("Content-Type", ct)
			}
			if ck := r.Header.Get("Cookie"); ck != "" {
				req2.Header.Set("Cookie", ck)
			}
			if resp2, errDo2 := client.Do(req2); errDo2 == nil {
				resp = resp2
				err = nil
				deviceRegistryMu.Lock()
				if d, ok := deviceRegistry["pc"]; ok && d != nil {
					d.Host = fallbackHost
				}
				deviceRegistryMu.Unlock()
			}
		}
	}
	if err == nil {
		defer resp.Body.Close()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if r.URL.Path == "/api/screen" {
			w.Header().Set("Cache-Control", "private, max-age=2")
		}
		if resp.StatusCode != http.StatusOK {
			w.WriteHeader(resp.StatusCode)
		}
		io.Copy(w, resp.Body)
		return true
	}

	fmt.Printf("[PROXY WARN] Forward to %s failed: %v\n", targetURL, err)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGatewayTimeout)
	w.Write([]byte(fmt.Sprintf(`{"error":"offline","dev":%q}`, dev)))
	return true
}

func handleZankCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "OK"
	}
	fmt.Printf("[Zank Command] %s\n", cmd)

	switch {
	case cmd == "getName":
		return "TX3 Mini TV"
	case cmd == "dpadUp" || cmd == "up" || cmd == "DPAD_UP" || cmd == "keyUp":
		if !sendDirectKey(103, 12) {
			runSh("input keyevent 19")
		}
	case cmd == "dpadDown" || cmd == "down" || cmd == "DPAD_DOWN" || cmd == "keyDown":
		if !sendDirectKey(108, 12) {
			runSh("input keyevent 20")
		}
	case cmd == "dpadLeft" || cmd == "left" || cmd == "DPAD_LEFT":
		if !sendDirectKey(105, 12) {
			runSh("input keyevent 21")
		}
	case cmd == "dpadRight" || cmd == "right" || cmd == "DPAD_RIGHT":
		if !sendDirectKey(106, 12) {
			runSh("input keyevent 22")
		}
	case cmd == "dpadCenter" || cmd == "ok" || cmd == "enter" || cmd == "select" || cmd == "center" || cmd == "DPAD_CENTER" || cmd == "click":
		if !sendDirectKey(97, 12) {
			runSh("input keyevent 23")
		}
	case cmd == "dpadCenterLong" || cmd == "longClick" || cmd == "longPress" || cmd == "centerLong" || cmd == "dpadLong":
		if !sendDirectKey(97, 700) {
			runSh("input keyevent --longpress 23")
		}
	case cmd == "back" || cmd == "BACK" || cmd == "goBack":
		if !sendDirectKey(1, 12) {
			runSh("input keyevent 4")
		}
	case cmd == "home" || cmd == "HOME" || cmd == "goHome":
		triggerKey(3, 12)
	case cmd == "menu" || cmd == "MENU":
		if !sendDirectKey(139, 12) {
			runSh("input keyevent 82")
		}
	case cmd == "recent" || cmd == "recents":
		runSh("input keyevent 187")
	case cmd == "volumeUp":
		if !sendDirectKey(115, 12) {
			runSh("input keyevent 24")
		}
	case cmd == "volumeDown":
		if !sendDirectKey(114, 12) {
			runSh("input keyevent 25")
		}
	case cmd == "volumeMute" || cmd == "mute":
		if !sendDirectKey(113, 12) {
			runSh("input keyevent 164")
		}
	case cmd == "power":
		if !sendDirectKey(116, 12) {
			runSh("input keyevent 26")
		}
	case cmd == "playPause":
		if !sendDirectKey(119, 12) {
			runSh("input keyevent 85")
		}
	case strings.HasPrefix(cmd, "setText ") || strings.HasPrefix(cmd, "setFinalText "):
		parts := strings.SplitN(cmd, " ", 2)
		if len(parts) == 2 {
			text := strings.ReplaceAll(parts[1], " ", "%s")
			runSh("input text " + text)
		}
	case strings.HasPrefix(cmd, "openApp ") || strings.HasPrefix(cmd, "launchApp ") || strings.HasPrefix(cmd, "launch "):
		parts := strings.SplitN(cmd, " ", 2)
		if len(parts) == 2 {
			runSh("monkey -p " + parts[1] + " -c android.intent.category.LAUNCHER 1")
		}
	case strings.HasPrefix(cmd, "keycode "):
		parts := strings.SplitN(cmd, " ", 2)
		if len(parts) == 2 {
			code, err := strconv.Atoi(parts[1])
			if err == nil {
				triggerKey(code, 12)
			} else {
				runSh("input keyevent " + parts[1])
			}
		}
	case cmd == "getApps":
		return `[{"name":"TiviMate IPTV","pkg":"ar.tvplayer.tv"},{"name":"OTT Navigator","pkg":"studio.scillarium.ottnavigator"},{"name":"SmartTube","pkg":"org.smarttube.stable"},{"name":"Stremio 4K","pkg":"com.stremio.one"}]`
	}
	return "OK"
}

func startZankUDPServer() {
	addr, err := net.ResolveUDPAddr("udp4", ":1028")
	if err != nil {
		fmt.Printf("Zank UDP Resolve error: %v\n", err)
		return
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		fmt.Printf("Zank UDP Listen error: %v\n", err)
		return
	}
	defer conn.Close()
	fmt.Println("Zank Remote UDP Host listening on :1028 (Auto-Discovery ready)")

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		msg := string(buf[:n])
		resp := handleZankCommand(msg)
		if resp != "OK" || strings.HasPrefix(msg, "getName") {
			conn.WriteTo([]byte(resp), remoteAddr)
		}
	}
}

func startZankTCPServer() {
	l, err := net.Listen("tcp4", ":1029")
	if err != nil {
		fmt.Printf("Zank TCP Listen error: %v\n", err)
		return
	}
	defer l.Close()
	fmt.Println("Zank Remote TCP Host listening on :1029")

	frameRe := regexp.MustCompile(`^!(\d+)!`)

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			reader := bufio.NewReader(c)
			for {
				c.SetReadDeadline(time.Now().Add(5 * time.Minute))
				line, err := reader.ReadString('\n')
				if err != nil {
					peek, pErr := reader.Peek(reader.Buffered())
					if pErr == nil && len(peek) > 0 {
						line = string(peek)
						reader.Discard(len(peek))
					} else {
						break
					}
				}
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				m := frameRe.FindStringSubmatch(line)
				if len(m) > 0 {
					payloadLen, _ := strconv.Atoi(m[1])
					start := len(m[0])
					if len(line) >= start+payloadLen {
						line = line[start : start+payloadLen]
					}
				}
				resp := handleZankCommand(line)
				if resp != "OK" {
					c.Write([]byte(resp + "\n"))
				}
			}
		}(conn)
	}
}

const pinLockHTML = `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>VuiRemote - Xác thực bảo mật</title>
<style>
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  body {
    margin: 0; padding: 0; width: 100%; height: 100vh; height: 100dvh;
    background: radial-gradient(circle at top, #1e293b, #07090e);
    color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    user-select: none; -webkit-user-select: none;
  }
  .pin-card {
    background: rgba(22, 27, 38, 0.88); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(59, 130, 246, 0.35); border-radius: 20px;
    padding: 24px 20px 20px; width: 90%; max-width: 320px;
    display: flex; flex-direction: column; align-items: center; text-align: center;
    box-shadow: 0 10px 30px rgba(0,0,0,0.7);
  }
  .lock-icon {
    font-size: 38px; margin-bottom: 8px; filter: drop-shadow(0 0 12px rgba(59, 130, 246, 0.6));
  }
  .title { font-size: 17px; font-weight: 700; color: #f1f5f9; margin-bottom: 4px; }
  .desc { font-size: 11.5px; color: #94a3b8; margin-bottom: 18px; line-height: 1.4; }
  .dots { display: flex; gap: 14px; margin-bottom: 22px; }
  .dot {
    width: 14px; height: 14px; border-radius: 50%; border: 2px solid #475569;
    background: transparent; transition: all 0.15s ease;
  }
  .dot.filled { background: #3b82f6; border-color: #60a5fa; box-shadow: 0 0 10px #3b82f6; transform: scale(1.15); }
  .dot.error { background: #ef4444; border-color: #f87171; box-shadow: 0 0 10px #ef4444; }
  .numpad { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; width: 100%; max-width: 250px; }
  .num-btn {
    height: 50px; background: rgba(30, 41, 59, 0.65); border: 1px solid rgba(255,255,255,0.08);
    border-radius: 14px; color: #f8fafc; font-size: 20px; font-weight: 700;
    display: flex; align-items: center; justify-content: center; cursor: pointer;
    transition: all 0.1s ease; touch-action: manipulation;
  }
  .num-btn:active { background: #2563eb; transform: scale(0.92); color: #fff; }
  .btn-action { font-size: 14px; color: #94a3b8; font-weight: 600; }
  .msg-toast {
    margin-top: 14px; font-size: 11.5px; color: #f87171; min-height: 16px; font-weight: 600;
    transition: all 0.2s;
  }
  @keyframes shake {
    0%, 100% { transform: translateX(0); }
    20%, 60% { transform: translateX(-8px); }
    40%, 80% { transform: translateX(8px); }
  }
  .shake { animation: shake 0.35s ease; }
</style>
</head>
<body>
<div class="pin-card" id="pin-card" style="position:relative;">
  <button id="pin-lang-btn" onclick="togglePinLang()" style="position:absolute; top:12px; right:12px; background:rgba(30,41,59,0.85); border:1px solid rgba(148,163,184,0.3); color:#cbd5e1; border-radius:999px; padding:3px 9px; font-size:11px; font-weight:700; cursor:pointer;">🌐 VI</button>
  <div class="lock-icon">🔒</div>
  <div class="title" id="pin-title">VuiRemote Bảo Mật</div>
  <div class="desc" id="pin-desc">Kết nối từ xa qua Internet an toàn.<br>Nhập mã PIN để mở khóa điều khiển.</div>
  
  <div class="dots" id="dots">
    <div class="dot" id="dot-0"></div>
    <div class="dot" id="dot-1"></div>
    <div class="dot" id="dot-2"></div>
    <div class="dot" id="dot-3"></div>
  </div>

  <div class="numpad">
    <button class="num-btn" onclick="pressNum('1')">1</button>
    <button class="num-btn" onclick="pressNum('2')">2</button>
    <button class="num-btn" onclick="pressNum('3')">3</button>
    <button class="num-btn" onclick="pressNum('4')">4</button>
    <button class="num-btn" onclick="pressNum('5')">5</button>
    <button class="num-btn" onclick="pressNum('6')">6</button>
    <button class="num-btn" onclick="pressNum('7')">7</button>
    <button class="num-btn" onclick="pressNum('8')">8</button>
    <button class="num-btn" onclick="pressNum('9')">9</button>
    <button class="num-btn btn-action" onclick="clearPin()">C</button>
    <button class="num-btn" onclick="pressNum('0')">0</button>
    <button class="num-btn btn-action" onclick="backspacePin()">⌫</button>
  </div>
  <div class="msg-toast" id="msg-toast"></div>
</div>

<script>
var currentPin = "";
var inFlight = false;
var pinLang = localStorage.getItem('vui_lang') || (((navigator.language || '').toLowerCase().indexOf('vi') === 0) ? 'vi' : 'en');

function applyPinLang() {
  var isEn = (pinLang === 'en');
  var btn = document.getElementById('pin-lang-btn');
  var title = document.getElementById('pin-title');
  var desc = document.getElementById('pin-desc');
  if (btn) btn.innerText = isEn ? '🌐 EN' : '🌐 VI';
  if (title) title.innerText = isEn ? 'VuiRemote Security' : 'VuiRemote Bảo Mật';
  if (desc) desc.innerHTML = isEn
    ? 'Zero-Trust Remote Internet Access.<br>Enter your 4-digit PIN to unlock.'
    : 'Kết nối từ xa qua Internet an toàn.<br>Nhập mã PIN để mở khóa điều khiển.';
}
function togglePinLang() {
  pinLang = (pinLang === 'en') ? 'vi' : 'en';
  try { localStorage.setItem('vui_lang', pinLang); } catch(e){}
  applyPinLang();
}
applyPinLang();

function updateDots() {
  for (var i = 0; i < 4; i++) {
    var d = document.getElementById('dot-' + i);
    if (d) {
      d.className = 'dot' + (i < currentPin.length ? ' filled' : '');
    }
  }
}

function pressNum(num) {
  if (inFlight || currentPin.length >= 4) return;
  currentPin += num;
  updateDots();
  if (navigator.vibrate) navigator.vibrate(10);
  if (currentPin.length === 4) {
    submitPin();
  }
}

function backspacePin() {
  if (inFlight) return;
  if (currentPin.length > 0) {
    currentPin = currentPin.slice(0, -1);
    updateDots();
  }
}

function clearPin() {
  if (inFlight) return;
  currentPin = "";
  updateDots();
  var t = document.getElementById('msg-toast');
  if (t) t.innerText = "";
}

function submitPin() {
  inFlight = true;
  var isEn = (pinLang === 'en');
  var card = document.getElementById('pin-card');
  var toast = document.getElementById('msg-toast');
  if (toast) {
    toast.style.color = "#93c5fd";
    toast.innerText = isEn ? "Verifying PIN..." : "Đang xác thực...";
  }
  
  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/auth?pin=' + encodeURIComponent(currentPin) + '&t=' + Date.now(), true);
  xhr.timeout = 5000;
  xhr.onload = function() {
    inFlight = false;
    if (xhr.status === 200) {
      try {
        var res = JSON.parse(xhr.responseText);
        if (res.token) {
          document.cookie = "vui_session=" + res.token + "; path=/; max-age=2592000; SameSite=Lax";
        }
      } catch(e){}
      if (toast) {
        toast.style.color = "#4ade80";
        toast.innerText = isEn ? "Unlocked successfully!" : "Mở khóa thành công!";
      }
      setTimeout(function() { window.location.reload(); }, 350);
    } else {
      currentPin = "";
      updateDots();
      if (card) {
        card.classList.add('shake');
        setTimeout(function() { card.classList.remove('shake'); }, 400);
      }
      for (var i = 0; i < 4; i++) {
        var d = document.getElementById('dot-' + i);
        if (d) d.className = 'dot error';
      }
      setTimeout(updateDots, 600);
      if (toast) {
        toast.style.color = "#f87171";
        var errMsg = isEn ? "Incorrect PIN, please try again!" : "Mã PIN không đúng, vui lòng thử lại!";
        try {
          var errRes = JSON.parse(xhr.responseText);
          if (xhr.status === 429 || errRes.error === "locked") {
            var mins = Math.ceil((errRes.retry_after_sec || 900) / 60);
            errMsg = isEn
              ? ("🛡️ Temporarily locked for " + mins + " min after 5 failed attempts!")
              : ("🛡️ Đã khóa tạm thời " + mins + " phút do nhập sai quá 5 lần!");
          } else if (typeof errRes.remaining_attempts === "number") {
            errMsg = isEn
              ? ("Incorrect PIN! (" + errRes.remaining_attempts + " attempts left)")
              : ("Mã PIN không đúng! (Còn " + errRes.remaining_attempts + " lần thử)");
          }
        } catch(e){}
        toast.innerText = errMsg;
      }
      if (navigator.vibrate) navigator.vibrate([40, 60, 40]);
    }
  };
  xhr.onerror = xhr.ontimeout = function() {
    inFlight = false;
    if (toast) {
      toast.style.color = "#f87171";
      toast.innerText = isEn ? "Server connection error!" : "Lỗi kết nối máy chủ!";
    }
  };
  xhr.send();
}

document.addEventListener('keydown', function(e) {
  if (e.key >= '0' && e.key <= '9') {
    pressNum(e.key);
  } else if (e.key === 'Backspace') {
    backspacePin();
  } else if (e.key === 'Escape' || e.key === 'Delete') {
    clearPin();
  }
});
</script>
</body>
</html>`

const htmlPage = `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="apple-mobile-web-app-title" content="VuiRemote">
<title>VuiRemote Hub</title>
<style>
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body {
    margin: 0; padding: 0; width: 100%; height: 100vh; height: 100dvh; overflow: hidden;
    background: #07090e; color: #fff;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    display: flex; flex-direction: column; align-items: center; justify-content: flex-start;
    user-select: none; -webkit-user-select: none;
  }
  .header { display: flex; justify-content: space-between; width: 100%; max-width: 380px; align-items: center; margin-bottom: 8px; }
  .title { font-size: 17px; font-weight: 700; color: #e2e8f0; display: flex; align-items: center; gap: 6px; }
  .badge { background: #22c55e22; color: #22c55e; border: 1px solid #22c55e55; padding: 4px 10px; border-radius: 12px; font-size: 11.5px; font-weight: 600; transition: all 0.2s; }
  
  /* Device Switcher */
  .device-bar { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; width: 100%; max-width: 380px; margin-bottom: 12px; }
  .dev-tab {
    background: #181b24; border: 1px solid #262a38; border-radius: 10px; padding: 6px 2px;
    font-size: 11px; font-weight: 600; color: #94a3b8; text-align: center; cursor: pointer; transition: all 0.15s;
    display: flex; flex-direction: column; align-items: center; gap: 2px;
  }
  .dev-tab.active { background: #1e293b; border-color: #3b82f6; color: #60a5fa; box-shadow: 0 0 10px #3b82f633; }
  .dev-tab .icon { font-size: 14px; }
  
  /* Mode Switcher */
  .mode-bar { display: flex; background: #181b24; border-radius: 10px; padding: 3px; width: 100%; max-width: 380px; margin-bottom: 12px; border: 1px solid #262a38; }
  .mode-tab { flex: 1; text-align: center; padding: 7px; font-size: 13px; font-weight: 600; color: #94a3b8; cursor: pointer; border-radius: 8px; transition: all 0.15s; }
  .mode-tab.active { background: #2563eb; color: #fff; }

  .btn {
    background: #1a1d27; border: 1px solid #282d3d; color: #f1f5f9; border-radius: 12px;
    font-size: 15px; font-weight: 600; display: flex; align-items: center; justify-content: center;
    cursor: pointer; transition: all 0.08s ease; outline: none; touch-action: manipulation;
  }
  .btn:active { background: #3b82f6; transform: scale(0.95); }
  .btn-power { color: #ef4444; border-color: #ef444433; }
  .btn-quick { background: #1e1b4b; border-color: #6366f166; color: #a5b4fc; }
  .btn-quick:active { background: #4f46e5; color: #fff; }
  .btn-home { background: #1d4ed8; border-color: #60a5fa; color: #fff; font-weight: 700; box-shadow: 0 0 12px #3b82f644; }
  .btn-home:active { background: #2563eb; transform: scale(0.94); }

  .top-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; width: 100%; max-width: 380px; margin-bottom: 12px; }
  .top-row .btn { height: 46px; }
  
  /* Projector Focus Bar (Visible only when Projector is active) */
  .proj-panel {
    display: none; width: 100%; max-width: 380px; background: #161a29; border: 1px solid #3b82f655;
    border-radius: 12px; padding: 10px; margin-bottom: 12px;
  }
  .proj-title { font-size: 12px; font-weight: 700; color: #93c5fd; margin-bottom: 8px; display: flex; justify-content: space-between; }
  .proj-grid { display: grid; grid-template-columns: 1fr 1.2fr 1fr; gap: 6px; margin-bottom: 6px; }
  .proj-btn { height: 40px; font-size: 13px; border-radius: 8px; }
  .btn-focus { background: #1e293b; color: #e2e8f0; border-color: #3b82f666; }
  .btn-autofocus { background: #2563eb; color: #fff; border: none; font-weight: 700; }
  .proj-subgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }

  /* D-Pad */
  .dpad-container {
    display: grid;
    grid-template-columns: 78px 88px 78px;
    grid-template-rows: 78px 88px 78px;
    gap: 8px;
    margin: 4px 0 16px;
    align-items: center;
    justify-content: center;
  }
  .dpad-cell {
    background: #161822; border: 2px solid #262a3a; border-radius: 16px;
    color: #cbd5e1; font-size: 24px; display: flex; flex-direction: column; align-items: center; justify-content: center;
    cursor: pointer; height: 100%; width: 100%; touch-action: manipulation; transition: all 0.08s;
  }
  .dpad-cell:active { background: #2563eb; color: #fff; transform: scale(0.92); }
  .dpad-center {
    background: #232738; border-color: #3b82f699; border-radius: 50%;
    color: #fff; font-size: 19px; font-weight: 700;
  }
  .dpad-center .sub { font-size: 8.5px; color: #93c5fd; font-weight: 500; margin-top: 1px; }
  .dpad-center.holding {
    background: #e11d48 !important; border-color: #fda4af !important; color: #fff !important;
    transform: scale(0.92); box-shadow: 0 0 18px #e11d48cc;
  }

  .nav-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; width: 100%; max-width: 380px; margin-bottom: 12px; }
  .nav-row .btn { height: 46px; font-size: 14.5px; }
  
  .vol-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; width: 100%; max-width: 380px; margin-bottom: 12px; }
  .vol-row .btn { height: 42px; font-size: 14px; }
  
  .app-shortcuts { width: 100%; max-width: 380px; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px; }
  .app-btn { height: 42px; font-size: 13.5px; border-radius: 10px; }
  .app-tivimate { border-color: #3b82f655; background: #152238; color: #93c5fd; }
  .app-ott { border-color: #10b98155; background: #13241b; color: #6ee7b7; }
  .app-youtube { border-color: #f59e0b55; background: #271f13; color: #fde68a; }
  .app-stremio { border-color: #8b5cf655; background: #20172e; color: #ddd6fe; }
  
  /* Input + Voice */
  .input-box { width: 100%; max-width: 380px; display: flex; gap: 8px; margin-bottom: 8px; }
  .input-field {
    flex: 1; height: 44px; background: #161822; border: 1px solid #282d3d; border-radius: 10px;
    padding: 0 12px; color: #fff; font-size: 14px; outline: none;
  }
  .input-field:focus { border-color: #3b82f6; }
  .voice-btn {
    width: 46px; height: 44px; background: #10b98122; border: 1px solid #10b98155;
    color: #10b981; border-radius: 10px; font-size: 20px; display: flex; align-items: center; justify-content: center; cursor: pointer;
  }
  .voice-btn.listening { background: #ef4444; color: #fff; border-color: #ef4444; animation: pulse 1s infinite; }
  .send-btn { width: 65px; height: 44px; background: #2563eb; border: none; color: #fff; font-weight: 600; border-radius: 10px; cursor: pointer; }

  /* Touchpad Section */
  .touchpad-section { display: none; width: 100%; max-width: 380px; flex-direction: column; align-items: center; }
  .touchpad-area {
    width: 100%; height: 260px; background: #161822; border: 2px dashed #2d3348; border-radius: 16px;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    color: #64748b; font-size: 14px; touch-action: none; position: relative; margin-bottom: 12px;
  }
  .touchpad-buttons { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; width: 100%; margin-bottom: 10px; }
  .touchpad-buttons .btn { height: 48px; }
  .airmouse-toggle { width: 100%; height: 42px; background: #1e293b; border-color: #3b82f655; color: #93c5fd; font-size: 13.5px; }
  .airmouse-toggle.active { background: #2563eb; color: #fff; }

  /* Full-App Rotation Container: Xoay đồng bộ màn hình, thanh công cụ nổi, cụm phím điều khiển và hộp thoại theo cùng chiều màn hình */
  .app-root {
    position: fixed; display: flex; flex-direction: column;
    background: #07090e; overflow: hidden; z-index: 1;
  }
  .app-root.rot-90 {
    top: 50%; left: 50%;
    width: 100vh; width: 100dvh;
    height: 100vw;
    transform: translate(-50%, -50%) rotate(90deg);
    transform-origin: center center;
  }
  .app-root.rot-270 {
    top: 50%; left: 50%;
    width: 100vh; width: 100dvh;
    height: 100vw;
    transform: translate(-50%, -50%) rotate(270deg);
    transform-origin: center center;
  }
  .app-root.rot-0 {
    inset: 0;
    width: 100vw;
    height: 100vh; height: 100dvh;
    transform: none;
  }

  /* Quick Drawer / Modal (Nằm trong .app-root nên luôn cùng chiều với màn hình) */
  .modal-backdrop {
    display: none; position: absolute; inset: 0; background: rgba(0,0,0,0.68); backdrop-filter: blur(4px);
    z-index: 100; align-items: center; justify-content: center; padding: 8px;
  }
  .modal-backdrop.show { display: flex; }
  .drawer {
    width: 100%; max-width: 480px; background: #161824; border: 1px solid #2e344a; border-radius: 16px;
    padding: 12px 14px; max-height: 92%; overflow-y: auto; animation: slideUp 0.2s ease-out;
  }
  .drawer-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid #282d3e; padding-bottom: 8px; }
  .drawer-title { font-size: 15px; font-weight: 700; color: #e2e8f0; display: flex; align-items: center; gap: 8px; }
  .drawer-close { background: #232738; border: none; color: #94a3b8; font-size: 18px; width: 30px; height: 30px; border-radius: 50%; cursor: pointer; }
  .drawer-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px; }
  .drawer-btn {
    height: 44px; background: #1c2030; border: 1px solid #2b3248; border-radius: 10px;
    color: #f1f5f9; font-size: 12.5px; font-weight: 600; display: flex; align-items: center; gap: 8px; padding: 0 10px; cursor: pointer;
  }
  .drawer-btn .d-icon { font-size: 16px; }
  .drawer-btn:active { background: #3b82f6; }
  .drawer-section-title { font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin: 8px 0 5px; letter-spacing: 0.5px; }

  /* Screen Section: 100% Edge-to-Edge Full-Screen Display (Không mất 1 pixel nào cho thanh công cụ tĩnh) */
  .screen-section {
    display: flex; width: 100%; height: 100%; max-width: none; margin: 0; padding: 0;
    flex-direction: column; align-items: stretch; justify-content: stretch; overflow: hidden;
  }
  .screen-box {
    width: 100%; height: 100%; background: #000; border: none; border-radius: 0;
    padding: 0; margin: 0; position: relative;
    display: flex; flex-direction: column; overflow: hidden;
  }
  .stage-container {
    flex: 1; min-height: 0; width: 100%; height: 100%; display: flex; flex-direction: column; position: relative;
  }

  /* Universal Drag Handle (Modern Web Guidance compliant: touch-action: none, -webkit-user-select before user-select) */
  .drag-handle {
    cursor: grab;
    touch-action: none;
    -webkit-user-select: none;
    user-select: none;
  }
  .drag-handle.dragging, .dragging .drag-handle, .drag-handle:active {
    cursor: grabbing;
  }

  /* Floating Watermark Top Pill (Kéo di chuyển tự do mọi vị trí & Thu gọn 1 chạm để không bao giờ che Title Bar cửa sổ) */
  .wm-top-bar {
    position: absolute; top: 6px; left: 6px; max-width: calc(100% - 12px); z-index: 25;
    display: flex; align-items: center; flex-wrap: wrap; gap: 4px;
    background: rgba(10, 15, 28, 0.58); backdrop-filter: blur(5px); -webkit-backdrop-filter: blur(5px);
    border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 14px;
    padding: 3px 5px; opacity: 0.9; transition: opacity 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    box-shadow: 0 2px 10px rgba(0,0,0,0.45);
    -webkit-user-select: none; user-select: none; touch-action: none;
  }
  .wm-top-bar:hover, .wm-top-bar:active { opacity: 0.99; }
  .wm-top-bar.dragging, .screen-watermark-source.dragging, .screen-watermark-pill.dragging, .vui-landscape-kbd.dragging {
    opacity: 0.98 !important;
    border-color: rgba(96, 165, 250, 0.85) !important;
    box-shadow: 0 8px 26px rgba(0, 0, 0, 0.72), 0 0 12px rgba(59, 130, 246, 0.35) !important;
    transition: none !important;
  }
  .wm-bar-grip {
    display: inline-flex; align-items: center; justify-content: center;
    height: 24px; padding: 0 6px; border-radius: 999px;
    background: rgba(30, 41, 59, 0.65); border: 1px solid rgba(148, 163, 184, 0.32);
    color: #93c5fd; font-size: 11.5px; font-weight: 800; line-height: 1;
    text-shadow: 0 1px 2px rgba(0,0,0,0.9);
  }
  .wm-bar-grip:focus-visible, .drag-handle:focus-visible {
    outline: 2px solid #60a5fa; outline-offset: 1px;
  }
  .wm-top-collapse-btn {
    width: 24px; height: 24px; padding: 0; font-size: 12px; font-weight: 900;
    background: rgba(30, 41, 59, 0.65); border-color: rgba(148, 163, 184, 0.35); color: #e2e8f0;
  }
  .wm-top-bar.collapsed > *:not(.wm-bar-grip):not(.wm-keep-collapsed):not(.wm-top-collapse-btn) {
    display: none !important;
  }

  .wm-source-badge {
    display: inline-flex; align-items: center; background: #f59e0b; color: #0f172a;
    font-size: 9px; font-weight: 800; padding: 1px 5px; border-radius: 999px; margin-left: 4px;
    letter-spacing: 0.3px; box-shadow: 0 1px 3px rgba(0,0,0,0.5);
    animation: pulseAmber 2.2s infinite ease-in-out;
  }
  @keyframes pulseAmber {
    0%, 100% { opacity: 0.92; transform: scale(1); }
    50% { opacity: 1; transform: scale(1.06); }
  }

  .screen-watermark-source {
    position: absolute; top: 6px; right: 6px; z-index: 23;
    display: flex; flex-direction: column; gap: 3px;
    background: rgba(15, 23, 42, 0.82); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
    border: 1px solid rgba(245, 158, 11, 0.5); border-radius: 10px;
    padding: 4px 8px 5px 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.55);
    -webkit-user-select: none; user-select: none; touch-action: none; font-size: 11px; color: #f1f5f9;
    text-shadow: 0 1px 2px rgba(0,0,0,0.9);
    max-width: 260px;
    transition: opacity 0.2s ease, border-color 0.2s ease;
  }
  .screen-watermark-source .src-header-row {
    display: flex; align-items: center; gap: 5px; font-weight: 700; color: #fbbf24; font-size: 11px;
  }
  .screen-watermark-source .src-dot {
    width: 7px; height: 7px; border-radius: 50%; background: #f59e0b; box-shadow: 0 0 8px #f59e0b;
    animation: pulseAmber 1.8s infinite;
  }
  .screen-watermark-source .src-ctrl-row {
    display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 9.5px;
    border-top: 1px solid rgba(255, 255, 255, 0.12); padding-top: 3px; margin-top: 1px;
  }
  .screen-watermark-source .src-ctrl-hint {
    color: #94a3b8; white-space: nowrap; font-size: 9.5px;
  }
  .screen-watermark-source .src-switch-btn {
    background: linear-gradient(135deg, #2563eb, #1d4ed8); border: 1px solid rgba(147, 197, 253, 0.4); border-radius: 999px;
    padding: 2px 7px; font-size: 9.5px; font-weight: 700; color: #fff; cursor: pointer;
    box-shadow: 0 1px 4px rgba(0,0,0,0.4); transition: all 0.12s ease; white-space: nowrap;
  }
  .screen-watermark-source .src-switch-btn:active {
    transform: scale(0.93); background: #1e40af;
  }

  .screen-dev-picker-btn {
    background: rgba(20, 26, 42, 0.55); border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 999px;
    padding: 0 8px; height: 24px; color: #f8fafc; font-size: 11px; font-weight: 700;
    display: flex; align-items: center; gap: 5px; cursor: pointer; transition: all 0.1s;
    user-select: none; -webkit-user-select: none; white-space: nowrap;
    text-shadow: 0 1px 2px rgba(0,0,0,0.9);
  }
  .screen-dev-picker-btn:active { background: rgba(37, 99, 235, 0.85); color: #fff; border-color: #60a5fa; }

  .btn-wm-icon {
    background: rgba(20, 26, 42, 0.48); border: 1px solid rgba(255, 255, 255, 0.18); color: #f1f5f9;
    border-radius: 999px; height: 24px; padding: 0 7px; font-size: 11px; font-weight: 700;
    cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 3px;
    user-select: none; -webkit-user-select: none; white-space: nowrap;
    text-shadow: 0 1px 2px rgba(0,0,0,0.9);
  }
  .btn-wm-icon:active, .btn-wm-icon.active-btn {
    background: rgba(37, 99, 235, 0.85); color: #fff; border-color: #60a5fa; transform: scale(0.92);
  }

  /* Floating Status Toast (Cùng chiều với màn hình TV, tự ẩn sau 1.2s) */
  .toast {
    position: absolute; top: 36px; left: 50%; transform: translateX(-50%) translateY(-16px);
    background: rgba(15, 23, 42, 0.92); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
    border: 1px solid rgba(59, 130, 246, 0.55); color: #f1f5f9; padding: 4px 13px;
    border-radius: 20px; font-size: 11.5px; font-weight: 700; z-index: 99999; pointer-events: none;
    opacity: 0; transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1); box-shadow: 0 4px 18px rgba(0,0,0,0.7);
    white-space: nowrap; max-width: 90%; overflow: hidden; text-overflow: ellipsis;
  }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

  #dev-modal .drawer {
    width: 95%; max-width: 680px; max-height: 92%; padding: 12px 14px;
  }
  .dev-modal-grid {
    display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; padding: 4px 0;
  }
  .app-root.rot-0 .dev-modal-grid {
    grid-template-columns: 1fr;
  }
  @media (max-width: 560px) {
    .app-root.rot-0 .dev-modal-grid { grid-template-columns: 1fr; }
  }
  .dev-modal-card {
    display: flex; align-items: center; gap: 10px; background: #131722; border: 1px solid #283348;
    border-radius: 12px; padding: 10px 12px; min-height: 54px; cursor: pointer; transition: background 0.15s, border-color 0.15s;
    user-select: none; -webkit-user-select: none;
  }
  .dev-modal-card:active { transform: scale(0.98); }
  .dev-modal-card.active {
    background: #1e3a8a33; border-color: #3b82f6; box-shadow: 0 0 12px rgba(59,130,246,0.3);
  }
  .dev-card-icon { font-size: 22px; flex-shrink: 0; }
  .dev-card-info { flex: 1; display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .dev-card-name {
    font-size: 13.5px; font-weight: 700; color: #f1f5f9;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; line-height: 1.3;
  }
  .dev-card-sub {
    font-size: 11px; color: #94a3b8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .dev-card-check { font-size: 14px; color: #3b82f6; font-weight: 800; opacity: 0; flex-shrink: 0; margin-left: 2px; }
  .dev-modal-card.active .dev-card-check { opacity: 1; }
  .dev-wol-wrap { display: inline-flex; align-items: center; flex-shrink: 0; }
  .dev-wol-btn {
    background: #15803d; border: 1px solid #22c55e88; color: #fff;
    border-radius: 7px; padding: 5px 9px; font-size: 11px; font-weight: 700;
    cursor: pointer; margin-right: 2px; transition: transform 0.1s;
    user-select: none; -webkit-user-select: none; white-space: nowrap;
  }
  .dev-wol-btn:active { transform: scale(0.92); background: #16a34a; }
  .live-dot {
    width: 7px; height: 7px; background: #22c55e; border-radius: 50%;
    box-shadow: 0 0 8px #22c55e; animation: blink 1.2s infinite; flex-shrink: 0;
  }
  .stream-settings-group {
    display: flex; gap: 8px; margin: 4px 0 10px;
  }
  .stream-opt-card {
    flex: 1; background: #1a2030; border: 1px solid #2d374d; border-radius: 10px;
    padding: 8px 4px; text-align: center; cursor: pointer; transition: all 0.15s;
    display: flex; flex-direction: column; align-items: center; gap: 3px;
    user-select: none; -webkit-user-select: none;
  }
  .stream-opt-card:active { transform: scale(0.96); }
  .stream-opt-card.active {
    background: #1e3a8a44; border-color: #3b82f6; box-shadow: 0 0 12px rgba(59,130,246,0.35);
  }
  .stream-opt-icon { font-size: 18px; }
  .stream-opt-title { font-size: 12px; font-weight: 700; color: #f1f5f9; }
  .stream-opt-desc { font-size: 9.5px; color: #94a3b8; line-height: 1.25; }

  /* Main Screen Stage: 100% Full Screen Viewport */
  .screen-stage-wrapper {
    flex: 1; min-height: 0; width: 100%; height: 100%; position: relative;
    display: flex; align-items: center; justify-content: center; overflow: hidden;
  }
  .screen-viewport {
    width: 100%; height: 100%; background: #000; border-radius: 0; overflow: hidden;
    position: relative; display: flex; align-items: center; justify-content: center;
    border: none; touch-action: none; user-select: none; -webkit-user-select: none;
    cursor: crosshair;
  }
  .screen-viewport img {
    width: 100%; height: 100%; object-fit: contain; display: block;
  }
  .app-root.rot-0 .screen-viewport img {
    object-fit: contain;
  }

  /* Screen Watermark Controls (Frosted Glass Pills in Corners - Cùng chiều với màn hình TV) */
  .screen-watermark-pill {
    position: absolute; display: flex; align-items: center; gap: 4px;
    background: rgba(10, 15, 28, 0.42); backdrop-filter: blur(4px); -webkit-backdrop-filter: blur(4px);
    border: 1px solid rgba(255, 255, 255, 0.18); border-radius: 999px; padding: 3px 8px;
    color: #e2e8f0; font-size: 10.5px; font-weight: 700; cursor: pointer; z-index: 18;
    transition: opacity 0.15s ease, border-color 0.15s ease, background 0.15s ease; -webkit-user-select: none; user-select: none; touch-action: none;
    box-shadow: 0 2px 8px rgba(0,0,0,0.45); opacity: 0.72;
    text-shadow: 0 1px 2px rgba(0,0,0,0.9);
  }
  .screen-watermark-pill:active {
    background: rgba(37, 99, 235, 0.9); border-color: #60a5fa; color: #fff; opacity: 1; transform: scale(0.92);
  }
  .screen-watermark-pill.wm-left { bottom: 6px; left: 6px; }
  .screen-watermark-pill.wm-right { bottom: 6px; left: 96px; }
  .screen-watermark-pill.wm-right.zoomed {
    background: rgba(30, 58, 138, 0.85); border-color: #3b82f6; color: #93c5fd; opacity: 0.95;
  }
  .wm-reset-badge {
    background: rgba(239, 68, 68, 0.45); border: 1px solid rgba(239, 68, 68, 0.65);
    color: #fca5a5; border-radius: 4px; padding: 1px 5px; font-size: 10px; margin-left: 2px;
  }
  .wm-reset-badge:active { background: #ef4444; color: #fff; }

  /* DRAGGABLE WATERMARK NAVIGATION CLUSTER (Hiện luôn trên màn hình như Watermark, thu nhỏ gọn gàng góc phải dưới & Kéo di chuyển tự do) */
  .wm-nav-cluster {
    position: absolute; right: 8px; bottom: 8px; z-index: 26;
    width: 136px; display: flex; flex-direction: column; gap: 3px;
    background: rgba(8, 12, 22, 0.26);
    backdrop-filter: blur(2.5px); -webkit-backdrop-filter: blur(2.5px);
    border: 1px solid rgba(255, 255, 255, 0.22);
    border-radius: 14px; padding: 4px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
    opacity: 0.76; transition: opacity 0.2s ease, border-color 0.2s ease;
    user-select: none; -webkit-user-select: none; touch-action: none;
  }
  .wm-nav-cluster.dragging, .wm-nav-cluster:active {
    opacity: 0.96;
    border-color: rgba(96, 165, 250, 0.65);
    box-shadow: 0 6px 24px rgba(0, 0, 0, 0.6);
  }
  .wm-nav-cluster.collapsed {
    width: auto; border-radius: 999px; padding: 4px 10px;
    background: rgba(10, 15, 28, 0.48);
  }
  .wm-nav-cluster.collapsed .wm-cluster-body {
    display: none;
  }
  .wm-drag-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 3px 1px; cursor: grab; color: rgba(226, 232, 240, 0.9);
    font-size: 9.5px; font-weight: 700; letter-spacing: 0.2px;
    text-shadow: 0 1px 3px rgba(0,0,0,0.95);
  }
  .wm-drag-header:active { cursor: grabbing; }
  .wm-drag-grip {
    display: flex; align-items: center; gap: 4px; flex: 1;
  }
  .wm-collapse-btn {
    background: rgba(255, 255, 255, 0.14); border: 1px solid rgba(255, 255, 255, 0.24);
    color: #fff; border-radius: 5px; width: 18px; height: 16px;
    font-size: 10px; font-weight: 800; line-height: 1;
    display: flex; align-items: center; justify-content: center; cursor: pointer;
  }
  .wm-collapse-btn:active { background: rgba(59, 130, 246, 0.8); }

  .wm-cluster-body {
    display: flex; flex-direction: column; gap: 3px;
  }
  .wm-dpad-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    grid-template-rows: repeat(3, 30px);
    gap: 3px;
  }
  .wm-btn {
    background: rgba(15, 23, 42, 0.36);
    border: 1px solid rgba(255, 255, 255, 0.24);
    color: rgba(255, 255, 255, 0.96);
    border-radius: 8px; font-size: 12.5px; font-weight: 800;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    cursor: pointer; user-select: none; -webkit-user-select: none;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.95);
    transition: transform 0.08s ease, background 0.08s ease;
    padding: 0;
  }
  .wm-btn:active, .wm-btn.holding, .wm-sub-btn:active, .wm-sub-btn.holding {
    background: rgba(37, 99, 235, 0.88) !important;
    border-color: #93c5fd !important;
    color: #fff !important;
    transform: scale(0.91);
  }
  .wm-nav-cluster, .wm-btn, .wm-sub-btn {
    -webkit-touch-callout: none;
    -webkit-user-select: none;
    user-select: none;
  }
  .wm-btn.wm-corner {
    font-size: 9px; font-weight: 700; background: rgba(15, 23, 42, 0.28);
    border-color: rgba(255, 255, 255, 0.18); color: rgba(226, 232, 240, 0.95);
    line-height: 1.05;
  }
  .wm-btn.wm-corner .c-ico { font-size: 10px; }
  .wm-btn.wm-corner.wm-home {
    border-color: rgba(56, 189, 248, 0.45); color: #7dd3fc;
  }
  .wm-btn.wm-ok {
    background: rgba(37, 99, 235, 0.44);
    border: 1.5px solid rgba(96, 165, 250, 0.65);
    color: #fff; font-size: 11px; font-weight: 900; border-radius: 50%;
    box-shadow: 0 0 10px rgba(37, 99, 235, 0.35);
  }
  .wm-nav-bottom-row {
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 3px; margin-top: 1px;
  }
  .wm-btn-nav {
    height: 30px; font-size: 9.5px; font-weight: 700; border-radius: 7px;
    background: rgba(15, 23, 42, 0.45); border: 1px solid rgba(255, 255, 255, 0.22);
    color: rgba(241, 245, 249, 0.95); display: flex; flex-direction: column;
    align-items: center; justify-content: center; cursor: pointer; line-height: 1.1;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.95);
    transition: transform 0.08s ease, background 0.08s ease;
    user-select: none; -webkit-user-select: none; -webkit-touch-callout: none;
  }
  .wm-btn-nav:active, .wm-btn-nav.holding {
    background: rgba(37, 99, 235, 0.88) !important;
    border-color: #93c5fd !important;
    color: #fff !important;
    transform: scale(0.91);
  }
  .wm-btn-nav.wm-home {
    border-color: rgba(56, 189, 248, 0.45); color: #7dd3fc;
  }
  .wm-btn-nav.wm-menu {
    border-color: rgba(168, 85, 247, 0.45); color: #e9d5ff;
  }
  .wm-btn-nav.active-recent {
    background: rgba(168, 85, 247, 0.95) !important;
    border-color: #f3e8ff !important;
    color: #fff !important;
    transform: scale(1.05) !important;
    box-shadow: 0 0 14px rgba(168, 85, 247, 0.8) !important;
  }
  .wm-sub-row {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 3px;
  }
  .wm-sub-btn {
    height: 22px; font-size: 9.5px; font-weight: 700; border-radius: 6px;
    background: rgba(15, 23, 42, 0.32); border: 1px solid rgba(255, 255, 255, 0.2);
    color: rgba(241, 245, 249, 0.95); display: flex; align-items: center; justify-content: center;
    cursor: pointer; text-shadow: 0 1px 3px rgba(0,0,0,0.95);
  }
  .wm-sub-btn:active {
    background: rgba(37, 99, 235, 0.78); border-color: #93c5fd; transform: scale(0.91);
  }
  .wm-proj-row {
    display: none; grid-template-columns: repeat(3, 1fr); gap: 3px;
  }

  .touch-indicator {
    position: absolute; width: 42px; height: 42px; border-radius: 50%;
    background: rgba(59, 130, 246, 0.35); border: 2px solid #60a5fa;
    transform: translate(-50%, -50%) scale(0);
    pointer-events: none; transition: transform 0.1s ease-out, opacity 0.15s ease-out;
    opacity: 0; z-index: 10;
  }
  .touch-indicator.active {
    opacity: 1; transform: translate(-50%, -50%) scale(1);
  }
  .touch-indicator.holding {
    background: rgba(225, 29, 72, 0.5) !important; border-color: #fda4af !important;
    transform: translate(-50%, -50%) scale(1.3) !important;
    box-shadow: 0 0 18px rgba(225, 29, 72, 0.9);
  }
  .screen-spinner {
    position: absolute; color: #93c5fd; font-size: 12px; font-weight: 600;
    background: rgba(15, 23, 42, 0.85); border: 1px solid #3b82f655; padding: 6px 12px; border-radius: 8px;
    display: none; pointer-events: none; z-index: 12;
  }

  /* Invisible IME Input Bridge (Ô nhập text hoàn toàn vô hình chỉ dùng để kích hoạt bàn phím hệ thống và nhận bộ gõ IME mà không bao giờ hiện khung đè lên màn hình) */
  .smart-input-bar, .smart-input-bar.show {
    position: fixed !important; left: 0 !important; top: 0 !important; bottom: auto !important;
    width: 32px !important; height: 24px !important; max-width: 32px !important;
    margin: 0 !important; padding: 0 !important; border: none !important;
    background: transparent !important; box-shadow: none !important;
    opacity: 0.01 !important; overflow: hidden !important; pointer-events: none !important;
    z-index: 2 !important; display: block !important; transform: none !important;
  }
  .smart-input-inner, .smart-input-actions {
    width: 32px !important; height: 24px !important; min-height: 0 !important;
    margin: 0 !important; padding: 0 !important; border: none !important;
    background: transparent !important; box-shadow: none !important;
    overflow: hidden !important; pointer-events: none !important;
  }
  .quick-txt-input {
    width: 32px !important; height: 24px !important; min-height: 0 !important; max-height: 24px !important;
    padding: 0 !important; margin: 0 !important; border: none !important; outline: none !important;
    background: transparent !important; color: transparent !important; caret-color: transparent !important;
    font-size: 16px !important; resize: none !important; overflow: hidden !important;
    opacity: 0.01 !important; pointer-events: none !important;
  }
  .attach-stage-chip, .btn-inline-send, .btn-clear-txt, .btn-send-txt, .btn-close-txt {
    display: none !important;
  }

  /* BÀN PHÍM CẢM ỨNG NGANG TÍCH HỢP (Luôn xuất hiện đúng chiều ngang của màn hình máy bị điều khiển, có thanh nắm kéo di chuyển tự do để không bao giờ che cửa sổ) */
  .vui-landscape-kbd {
    position: absolute; left: 0; right: 0; bottom: 0; z-index: 9998;
    background: rgba(15, 23, 42, 0.96); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
    border-top: 1.5px solid rgba(59, 130, 246, 0.65);
    padding: 4px 6px 6px; box-sizing: border-box;
    display: none; flex-direction: column; gap: 4px;
    box-shadow: 0 -8px 28px rgba(0, 0, 0, 0.85);
    -webkit-user-select: none; user-select: none; touch-action: manipulation;
  }
  .vui-landscape-kbd.show {
    display: flex;
  }
  .vkbd-drag-header {
    display: flex; align-items: center; justify-content: space-between;
    width: 100%; max-width: 680px; margin: 0 auto 1px; padding: 1px 6px;
    box-sizing: border-box; border-radius: 6px;
    background: rgba(30, 41, 59, 0.65); border: 1px solid rgba(148, 163, 184, 0.25);
    color: #93c5fd; font-size: 10px; font-weight: 700;
  }
  .vkbd-dock-btn {
    background: rgba(59, 130, 246, 0.22); border: 1px solid rgba(96, 165, 250, 0.45);
    color: #dbeafe; border-radius: 999px; padding: 1px 7px; font-size: 9.5px; font-weight: 700;
    cursor: pointer; line-height: 1.2;
  }
  .vkbd-dock-btn:active { background: #2563eb; color: #fff; }
  .vkbd-row {
    display: flex; align-items: center; justify-content: center; gap: 4px; width: 100%; max-width: 680px; margin: 0 auto;
  }
  .vkbd-key {
    flex: 1; height: 33px; min-width: 0; border-radius: 7px;
    background: #1e293b; border: 1px solid #334155; color: #f8fafc;
    font-size: 14px; font-weight: 600; font-family: inherit;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; padding: 0 2px; box-shadow: 0 1px 2px rgba(0,0,0,0.45);
    user-select: none; -webkit-user-select: none; touch-action: manipulation;
  }
  .vkbd-key:active {
    background: #3b82f6; border-color: #60a5fa; color: #fff; transform: scale(0.95);
  }
  .vkbd-key.vkbd-fn {
    background: #0f172a; border-color: #334155; color: #cbd5e1; font-size: 11.5px; font-weight: 700; flex: 1.35;
  }
  .vkbd-key.vkbd-fn.active {
    background: #1d4ed8; border-color: #60a5fa; color: #fff;
  }
  .vkbd-key.vkbd-space {
    flex: 4.2; font-size: 12px; color: #cbd5e1; font-weight: 600;
  }
  .vkbd-key.vkbd-enter {
    flex: 1.65; background: #2563eb; border-color: #3b82f6; color: #fff; font-size: 12px; font-weight: 700;
  }

  .tool-btn {
    flex: 1; height: 33px; background: #1a2030; border: 1px solid #2b354c; border-radius: 8px;
    color: #cbd5e1; font-size: 11px; font-weight: 700; cursor: pointer;
    display: flex; align-items: center; justify-content: center; gap: 3px;
    transition: all 0.1s; user-select: none; -webkit-user-select: none; touch-action: manipulation;
  }
  .tool-btn:active { background: #3b82f6; color: #fff; border-color: #60a5fa; transform: scale(0.92); }
  .tool-btn.btn-mic { color: #34d399; border-color: #05966955; }
  .dpad-btn {
    background: #1c2232; border: 1px solid #334155; color: #f1f5f9;
    border-radius: 8px; font-size: 15px; font-weight: 800; cursor: pointer;
    display: flex; align-items: center; justify-content: center; transition: all 0.1s;
    user-select: none; -webkit-user-select: none; touch-action: manipulation;
  }
  .dpad-btn:active { background: #3b82f6; color: #fff; transform: scale(0.92); }
  .dpad-ok {
    background: #2563eb; border-color: #60a5fa; color: #fff;
  }

  .help-modal-content {
    max-width: 480px; max-height: 90%; overflow-y: auto; background: #131722;
    border: 1px solid #334155; border-radius: 16px; padding: 14px; color: #cbd5e1; width: 94%;
    box-shadow: 0 10px 30px rgba(0,0,0,0.85);
  }
  .help-header {
    display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #283348;
    padding-bottom: 8px; margin-bottom: 10px;
  }
  .help-title { font-size: 14.5px; font-weight: 800; color: #38bdf8; display: flex; align-items: center; gap: 6px; }
  .help-section { margin-bottom: 10px; }
  .help-sec-title { font-size: 12px; font-weight: 700; color: #f1f5f9; margin-bottom: 3px; display: flex; align-items: center; gap: 6px; }
  .help-item { font-size: 11px; line-height: 1.45; color: #94a3b8; margin-bottom: 2px; padding-left: 4px; }
  .help-item b { color: #e2e8f0; }

  @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
  @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.08); } 100% { transform: scale(1); } }
  @keyframes slideUp { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

  /* Auto-Sleep Lock Screen Overlay (Tự ngắt truyền hình khi không dùng, bấm để mở khóa như ĐT) */
  .sleep-lock-overlay {
    position: absolute; inset: 0; z-index: 28;
    background: rgba(7, 9, 14, 0.84); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
    display: none; flex-direction: column; align-items: center; justify-content: center;
    padding: 16px; text-align: center; gap: 8px; cursor: pointer;
    user-select: none; -webkit-user-select: none;
  }
  .sleep-lock-overlay.show {
    display: flex;
  }
  .sleep-lock-icon {
    font-size: 34px; margin-bottom: 2px; filter: drop-shadow(0 4px 12px rgba(59,130,246,0.5));
  }
  .sleep-lock-title {
    font-size: 14.5px; font-weight: 800; color: #f1f5f9;
  }
  .sleep-lock-desc {
    font-size: 11.5px; color: #94a3b8; max-width: 340px; line-height: 1.4;
  }
  .sleep-unlock-btn {
    margin-top: 4px; background: linear-gradient(135deg, #2563eb, #1d4ed8);
    border: 1px solid #60a5fa; color: #fff; font-size: 12.5px; font-weight: 800;
    padding: 9px 18px; border-radius: 999px; cursor: pointer;
    box-shadow: 0 4px 20px rgba(37, 99, 235, 0.6);
    display: inline-flex; align-items: center; gap: 6px; transition: all 0.15s;
  }
  .sleep-unlock-btn:active {
    transform: scale(0.94); background: #1e40af;
  }
</style>
</head>
<body>
<input type="file" id="vui-img-upload" multiple style="position:fixed; left:-9999px; top:-9999px; width:1px; height:1px; opacity:0; pointer-events:none;" onchange="handleImageUploadFiles(this.files)">

<!-- Ô nhập cầu nối IME hoàn toàn vô hình đặt ngoài khung xoay .rot-90 để mọi trình duyệt di động luôn cho phép bật bàn phím hệ thống mà không bao giờ hiện khung che màn hình -->
<div class="smart-input-bar" id="smart-input-bar">
  <div class="smart-input-inner" id="smart-input-inner">
    <textarea id="quick-txt-input" class="quick-txt-input" rows="1" inputmode="none" onfocus="onQuickInputFocus(event)" onblur="onQuickInputBlur(event)" oninput="onQuickInputChanged()" onkeydown="onQuickInputKeyDown(event)" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea>
  </div>
</div>

<div class="app-root rot-90" id="app-root">
<div id="status-toast" class="toast"></div>

<!-- SCREEN VIEW: 100% DIỆN TÍCH MÀN HÌNH ĐIỆN THOẠI DÀNH TRỌN CHO HÌNH MÀN HÌNH THIẾT BỊ -->
<div class="screen-section rot-90" id="view-screen">
  <div class="screen-box rot-90" id="screen-box">
    <div class="stage-container" id="stage-container">
      <div class="screen-stage-wrapper" id="screen-stage-wrapper">
        <div class="screen-viewport" id="screen-viewport">
          <img id="screen-img" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" alt="Đang chụp màn hình..." draggable="false" />
          <div id="screen-spinner" class="screen-spinner">Đang chụp...</div>
          <div id="touch-indicator" class="touch-indicator"></div>

          <!-- Bàn phím cảm ứng Ngang tích hợp (Xuất hiện đúng chiều ngang màn hình khi bấm nút ⌨️ Bàn phím) -->
          <div class="vui-landscape-kbd" id="vui-landscape-kbd"></div>

          <!-- Watermark Pill Góc Trái Trên: Chọn thiết bị & Công cụ nhanh (Kéo di chuyển tự do & Thu gọn 1 chạm để không bao giờ che Title Bar cửa sổ) -->
          <div class="wm-top-bar" id="wm-top-bar">
            <span class="wm-bar-grip drag-handle" id="wm-top-drag-handle" tabindex="0" aria-label="Giữ kéo hoặc dùng phím mũi tên để di chuyển thanh công cụ" title="Giữ và kéo để di chuyển thanh công cụ tới vị trí bất kỳ (Nhấp đúp để về góc mặc định)">✥</span>
            <button class="screen-dev-picker-btn wm-keep-collapsed" onclick="openDevModal()" title="Đổi thiết bị điều khiển">
              <span class="live-dot" id="stream-status-dot"></span>
              <span id="screen-dev-name">📺 Tanix TX3</span>
              <span id="wm-source-badge" class="wm-source-badge" style="display:none;">HDMI 2</span>
              <span style="font-size:8px; opacity:0.7;">▼</span>
            </button>
            <button class="screen-dev-picker-btn" id="btn-pc-touch-mode" style="display:none; background:rgba(16,185,129,0.24); border-color:rgba(52,211,153,0.55); color:#a7f3d0; padding:0 8px; font-size:10.5px;" onclick="cyclePCTouchMode()" title="Đổi chế độ vuốt 1 ngón trên PC (Kéo thả / Cuộn / Bàn rê)">
              <span id="pc-touch-mode-label">🖱️ 1Ngón: Kéo thả</span>
            </button>
            <button class="screen-dev-picker-btn" id="btn-pc-win-picker" style="display:none; background:rgba(59,130,246,0.25); border-color:rgba(96,165,250,0.55); color:#bfdbfe; padding:0 8px; font-size:10.5px;" onclick="openWindowModal()" title="Làm việc riêng với từng cửa sổ chương trình (Antigravity, Chrome, Terminal...) hoặc Toàn màn hình">
              <span id="pc-win-picker-label">🪟 Cửa sổ</span>
            </button>
            <button class="screen-dev-picker-btn" id="btn-top-kbd" style="background:rgba(37,99,235,0.34); border-color:rgba(96,165,250,0.7); color:#dbeafe; padding:0 10px; font-size:11px;" onclick="toggleQuickInputBar()" title="Bật / Tắt bàn phím ảo trên màn hình (Bàn phím vật lý luôn gõ trực tiếp không cần hiện ô nhập)">
              <span id="top-kbd-label">⌨️ Bàn phím</span>
            </button>
            <label for="vui-img-upload" class="screen-dev-picker-btn" id="btn-top-attach" style="background:rgba(15,118,110,0.34); border-color:rgba(20,184,166,0.7); color:#ccfbf1; padding:0 8px; font-size:10.5px; cursor:pointer;" onclick="recordActivity()" title="Gửi trực tiếp File (Hình ảnh, Video, Âm thanh, Tài liệu) sang máy được điều khiển">
              <span id="top-attach-label">📎 Tệp</span>
            </label>
            <button class="screen-dev-picker-btn" id="btn-top-stream-mode" style="background:rgba(14,165,233,0.22); border-color:rgba(56,189,248,0.55); color:#bae6fd; padding:0 7px; font-size:10.5px;" onclick="cycleStreamMode()" title="Đổi kiểu truyền: Mặc định (35s tự dừng) ↔ Liên tục khi đang xem">
              <span id="top-stream-mode-label">⏱ 35s</span>
            </button>
            <button class="screen-dev-picker-btn" id="btn-top-stream-toggle" style="background:rgba(239,68,68,0.28); border-color:rgba(248,113,113,0.6); color:#fecaca; padding:0 8px; font-size:10.5px;" onclick="toggleStreamActive()" title="Đang truyền hình — Bấm để dừng truyền">
              <span id="top-stream-toggle-label">⏹ Dừng</span>
            </button>
            <button class="btn-wm-icon" id="btn-top-lang" onclick="toggleUILanguage()" style="width:auto; padding:0 6px; font-size:10px; font-weight:800; color:#bae6fd; border-color:rgba(56,189,248,0.5);" title="Switch Language (Tiếng Việt / English)">🌐 VI</button>
            <button class="btn-wm-icon" onclick="openDrawer()" title="Settings & Utilities / Thiết lập & Tiện ích">⚙️</button>
            <button class="btn-wm-icon" onclick="openHelpModal()" title="Guide / Hướng dẫn">❓</button>
            <button type="button" class="btn-wm-icon wm-top-collapse-btn" id="wm-top-collapse-btn" onclick="event.stopPropagation(); toggleTopBarCollapse();" title="Thu gọn / Mở rộng thanh công cụ">−</button>
          </div>

          <!-- Floating External Source Watermark Pill Góc Phải Trên (Kéo di chuyển tự do) -->
          <div id="screen-watermark-source" class="screen-watermark-source" style="display:none;" onclick="event.stopPropagation();">
            <div class="src-header-row drag-handle" id="wm-src-drag-handle" tabindex="0" aria-label="Giữ kéo hoặc dùng phím mũi tên để di chuyển bảng nguồn phát" title="Giữ và kéo để di chuyển bảng nguồn phát">
              <span>✥</span>
              <span class="src-dot"></span>
              <span>🔌</span>
              <span id="src-watermark-label">Đang xem: <b>HDMI 2 (TV360)</b></span>
            </div>
            <div class="src-ctrl-row">
              <span class="src-ctrl-hint" id="src-ctrl-hint">🎮 Nút bấm đang ĐK Máy chiếu</span>
              <button id="src-switch-btn" class="src-switch-btn" onclick="selectDevAndClose('tv360')" title="Chuyển sang điều khiển thiết bị phát">Đổi sang ĐK TV360 ➔</button>
            </div>
          </div>

          <!-- Watermark Pills Góc Trái Dưới: Xoay màn hình nhanh trên iPhone/Android & Phóng to (Kéo di chuyển tự do) -->
          <div class="screen-watermark-pill wm-left drag-handle" id="screen-watermark-rotate" tabindex="0" aria-label="Giữ kéo hoặc dùng phím mũi tên để di chuyển nút xoay màn hình" onclick="event.stopPropagation(); cycleScreenRotation();" title="Bấm để xoay màn hình • Giữ kéo để di chuyển vị trí">
            <span>🔁</span>
            <span id="wm-rot-text">Xoay 90°</span>
          </div>

          <div class="screen-watermark-pill wm-right drag-handle" id="screen-watermark-zoom" tabindex="0" aria-label="Giữ kéo hoặc dùng phím mũi tên để di chuyển nút thu phóng" onclick="event.stopPropagation(); cycleZoomDock();" title="Bấm để phóng to / thu nhỏ • Giữ kéo để di chuyển vị trí">
            <span>🔍</span>
            <span id="wm-zoom-text">1.0x</span>
            <span id="wm-zoom-reset" class="wm-reset-badge" style="display:none;" onclick="event.stopPropagation(); resetZoom();" title="Về chuẩn 1x">↺</span>
          </div>

          <!-- CỤM PHÍM ĐIỀU HƯỚNG WATERMARK NỔI & DI CHUYỂN ĐƯỢC (Luôn hiển thị trong suốt trên màn hình, kéo đi bất kỳ đâu) -->
          <div class="wm-nav-cluster" id="wm-nav-cluster">
            <div class="wm-drag-header drag-handle" id="wm-drag-header" tabindex="0" aria-label="Giữ kéo hoặc dùng phím mũi tên để di chuyển cụm phím điều hướng" title="Giữ và kéo để di chuyển cụm phím tới bất kỳ vị trí nào">
              <div class="wm-drag-grip">
                <span>✥</span>
                <span id="wm-nav-title">Điều hướng</span>
              </div>
              <button class="wm-collapse-btn" id="wm-collapse-btn" onclick="event.stopPropagation(); toggleNavClusterCollapse();" title="Thu gọn / Mở rộng cụm phím">−</button>
            </div>

            <div class="wm-cluster-body" id="wm-cluster-body">
              <!-- Cụm 3x3: Bốn góc xung quanh điều hướng bố trí Âm lượng (-, +), Tắt tiếng (Mute) và Xóa (⌫) -->
              <div class="wm-dpad-grid" oncontextmenu="return false;">
                <button class="wm-btn wm-corner" id="nav-btn-voldown" data-act="voldown" title="Giảm âm lượng (Giữ để giảm liên tục)">
                  <span class="c-ico">🔉</span><span>-</span>
                </button>
                <button class="wm-btn" id="nav-btn-up" data-act="up" title="Lên (Giữ để cuộn lên)">▲</button>
                <button class="wm-btn wm-corner" id="nav-btn-volup" data-act="volup" title="Tăng âm lượng (Giữ để tăng liên tục)">
                  <span class="c-ico">🔊</span><span>+</span>
                </button>

                <button class="wm-btn" id="nav-btn-left" data-act="left" title="Trái (Giữ để tua trái)">◀</button>
                <button class="wm-btn wm-ok" id="nav-btn-ok" data-act="ok" title="OK / Chọn (Bấm để mở)">OK</button>
                <button class="wm-btn" id="nav-btn-right" data-act="right" title="Phải (Giữ để tua phải)">▶</button>

                <button class="wm-btn wm-corner" id="nav-btn-mute" data-act="mute" onclick="wmAct(event, function(){ key(164, 'Tắt tiếng'); })" title="Tắt tiếng">
                  <span class="c-ico">🔇</span><span>Tắt</span>
                </button>
                <button class="wm-btn" id="nav-btn-down" data-act="down" title="Xuống (Giữ để cuộn xuống)">▼</button>
                <button class="wm-btn wm-corner" id="nav-btn-del" data-act="del" title="Xóa ký tự (Giữ để xóa nhanh)">
                  <span class="c-ico">⌫</span><span>Xóa</span>
                </button>
              </div>

              <!-- HÀNG 3 NÚT ĐIỀU HƯỚNG CƠ BẢN NGAY DƯỚI CỤM ĐIỀU HƯỚNG: Lùi, Home, Menu (Bấm giữ là Đa nhiệm) -->
              <div class="wm-nav-bottom-row" oncontextmenu="return false;">
                <button class="wm-btn-nav" id="nav-btn-back" data-act="back" title="Quay lại (Lùi) - Giữ để lùi nhanh">
                  <span style="font-size:12px;">↩</span>
                  <span>Lùi</span>
                </button>
                <button class="wm-btn-nav wm-home" id="nav-btn-home" data-act="home" onclick="wmAct(event, function(){ androidKey(3, 'Home'); })" title="Trang chủ (Home)">
                  <span style="font-size:12px;">⌂</span>
                  <span>Home</span>
                </button>
                <button class="wm-btn-nav wm-menu" id="nav-btn-menu" data-act="menu" title="Bấm: Menu • Giữ: Đa nhiệm (Recent Apps)">
                  <span style="font-size:11px;">☰</span>
                  <span style="font-size:10px; font-weight:800;">Menu</span>
                  <span style="font-size:7.5px; opacity:0.85; font-weight:normal; letter-spacing:-0.2px;">Giữ: Đa nhiệm</span>
                </button>
              </div>

              <!-- Hàng Lấy nét Máy chiếu (Tự động hiện khi điều khiển Hyundai / KAW) -->
              <div class="wm-proj-row" id="deck-proj-row" oncontextmenu="return false;">
                <button class="wm-sub-btn" id="proj-btn-focusdown" title="Lấy nét - (Giữ để chỉnh liên tục)">🔍-</button>
                <button class="wm-sub-btn" onclick="wmAct(event, function(){ cmd('autofocus', 'Auto Nét'); })" title="Tự động lấy nét">⚡Nét</button>
                <button class="wm-sub-btn" id="proj-btn-focusup" title="Lấy nét + (Giữ để chỉnh liên tục)">🔍+</button>
              </div>

              <!-- Hàng Chuột & Phím Tắt Máy Tính (Tự động hiện khi điều khiển PC) -->
              <div class="wm-proj-row" id="deck-pc-row" style="display:none; grid-template-columns:repeat(3,1fr); gap:4px; margin-top:4px;" oncontextmenu="return false;">
                <button class="wm-sub-btn" onclick="wmAct(event, function(){ sendPCRightClickAtLast(); })" title="Click chuột phải tại vị trí con trỏ" style="background:rgba(245,158,11,0.28); border-color:rgba(251,191,36,0.55); color:#fde68a;">🖱️Phải</button>
                <button class="wm-sub-btn" onclick="wmAct(event, function(){ sendPCDoubleClickAtLast(); })" title="Nhấp đúp chuột trái (Mở file/thư mục)" style="background:rgba(59,130,246,0.28); border-color:rgba(96,165,250,0.55); color:#bfdbfe;">⚡Đúp</button>
                <button class="wm-sub-btn" id="btn-pc-draglock" onclick="wmAct(event, function(){ togglePCDragLock(); })" title="Khóa giữ chuột trái để kéo thả dài">✊GiữKéo</button>
                <button class="wm-sub-btn" onclick="wmAct(event, function(){ sendPCHotkey('ctrl+c', 'Copy (Ctrl+C)'); })" title="Sao chép (Ctrl+C)">📋Copy</button>
                <button class="wm-sub-btn" onclick="wmAct(event, function(){ sendPCHotkey('ctrl+v', 'Paste (Ctrl+V)'); })" title="Dán (Ctrl+V)">📥Paste</button>
                <button class="wm-sub-btn" onclick="wmAct(event, function(){ sendPCHotkey('Return', 'Enter'); })" title="Bấm phím Enter (Return)" style="background:rgba(16,185,129,0.25); border-color:rgba(52,211,153,0.55); color:#a7f3d0;">↵Enter</button>
              </div>
            </div>
          </div>

          <!-- Màn hình khóa tự ngắt truyền hình khi không dùng (Chạm để mở khóa) -->
          <div id="screen-sleep-overlay" class="sleep-lock-overlay" onclick="event.stopPropagation(); wakeFromSleep();">
            <div class="sleep-lock-icon">🔒</div>
            <div class="sleep-lock-title">Truyền hình đang tạm nghỉ</div>
            <div class="sleep-lock-desc">Đã tự động ngắt truyền hình khi không thao tác để tiết kiệm tài nguyên & chống đơ máy.</div>
            <button class="sleep-unlock-btn" onclick="event.stopPropagation(); wakeFromSleep();">🔓 Chạm để Mở khóa & Điều khiển</button>
          </div>
          
          <!-- TV360 Interactive Console Pad (Dự phòng nếu luồng chụp màn hình TV360 chưa bật) -->
          <div id="screen-tv360-notice" style="display:none; position:absolute; inset:0; background:radial-gradient(circle at center, #111827 0%, #07090e 100%); flex-direction:row; align-items:stretch; justify-content:space-between; padding:38px 14px 10px; gap:12px; z-index:5;">
            <!-- Cột Giữa: Bàn vuốt cảm ứng (Swipe/Tap) & Chuyển Kênh CH +/- -->
            <div style="flex:1; display:flex; flex-direction:column; justify-content:space-between; gap:8px;">
              <div style="display:flex; align-items:center; justify-content:space-between; background:rgba(15,23,42,0.8); border:1px solid rgba(34,197,94,0.35); border-radius:10px; padding:6px 12px; flex-wrap:wrap; gap:6px;" onmousedown="event.stopPropagation()" ontouchstart="event.stopPropagation()">
                <div style="display:flex; align-items:center; gap:6px;">
                  <span style="font-size:16px;">📦</span>
                  <span id="tv360-status-badge" style="font-weight:800; color:#4ade80; font-size:13px;">Viettel TV360 Box (Online)</span>
                </div>
                <div style="display:flex; gap:6px; flex-wrap:wrap;">
                  <button class="tool-btn" style="height:26px; padding:0 8px; font-size:11px; background:rgba(59,130,246,0.22); border-color:rgba(96,165,250,0.55); color:#bfdbfe;" onclick="startTv360Pairing()">🔗 Ghép nối PIN</button>
                  <button class="tool-btn" style="height:26px; padding:0 8px; font-size:11px; background:rgba(220,38,38,0.2); border-color:rgba(248,113,113,0.45); color:#fecaca;" onclick="app('studio.scillarium.ottnavigator', 'Truyền hình OTT')">📺 TV (246 Kênh)</button>
                  <button class="tool-btn" style="height:26px; padding:0 8px; font-size:11px; background:rgba(245,158,11,0.18); border-color:rgba(251,191,36,0.45); color:#fde68a;" onclick="app('org.smarttube.stable', 'SmartTube')">▶️ SmartTube</button>
                  <button class="tool-btn" style="height:26px; padding:0 8px; font-size:11px; background:rgba(16,185,129,0.18); border-color:rgba(52,211,153,0.45); color:#a7f3d0;" onclick="app('com.stremio.one', 'Stremio 4K')">🎬 Stremio</button>
                  <button class="tool-btn" style="height:26px; padding:0 8px; font-size:11px; background:rgba(147,51,234,0.25); border-color:rgba(192,132,252,0.5); color:#e9d5ff;" onclick="cmd('devsettings', 'Mở Tùy chọn Nhà Phát Triển')">⚡ Tùy chọn Dev</button>
                  <button class="tool-btn" style="height:26px; padding:0 8px; font-size:11px; background:rgba(239,68,68,0.18); border-color:rgba(239,68,68,0.45); color:#fca5a5;" onclick="key(26, 'Nguồn TV360')">⏻ Nguồn</button>
                </div>
              </div>

              <!-- Thanh nhập mã PIN 6 ký tự khi TV360 yêu cầu ghép nối lại Google TV Remote v2 -->
              <div id="tv360-pair-bar" onmousedown="event.stopPropagation()" ontouchstart="event.stopPropagation()" style="display:none; align-items:center; justify-content:space-between; gap:8px; background:rgba(30,41,59,0.92); border:1px solid rgba(251,191,36,0.6); border-radius:10px; padding:6px 10px;">
                <span id="tv360-pair-hint" style="font-size:11.5px; color:#fde68a; font-weight:600;">🔑 TV360 cần ghép nối lại: bấm <b>Gửi mã lên TV</b> rồi nhập 6 ký tự trên màn hình TV:</span>
                <div style="display:flex; align-items:center; gap:6px;">
                  <button class="tool-btn" style="height:28px; padding:0 10px; font-size:11px; background:#2563eb; color:#fff; border:none;" onclick="startTv360Pairing()">📲 Gửi mã lên TV</button>
                  <input id="tv360-pin-input" type="text" maxlength="6" placeholder="Mã 6 ký tự" style="width:96px; height:28px; border-radius:6px; border:1px solid #60a5fa; background:#0f172a; color:#f8fafc; font-weight:700; text-align:center; font-size:12px; text-transform:uppercase;" onkeydown="if(event.key==='Enter'){event.preventDefault();submitTv360Pin();}" />
                  <button class="tool-btn" style="height:28px; padding:0 10px; font-size:11px; background:#16a34a; color:#fff; border:none;" onclick="submitTv360Pin()">✅ Xác nhận</button>
                </div>
              </div>

              <!-- Vùng Bàn Vuốt Cảm Ứng Trực Tiếp cho TV360 -->
              <div id="tv360-touchpad" style="flex:1; background:rgba(15,23,42,0.55); border:1.5px dashed rgba(56,189,248,0.4); border-radius:14px; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:4px; color:#93c5fd; cursor:pointer; position:relative;">
                <div style="font-size:20px;">👆</div>
                <div style="font-size:12.5px; font-weight:700; color:#e0f2fe;">Bàn Cảm Ứng TV360 (Chạm & Vuốt) + Cụm Phím Nổi</div>
                <div style="font-size:10.5px; color:#94a3b8;">Chạm 1 lần = <b>OK</b> • Vuốt 4 hướng = <b>Di chuyển</b> • Cụm phím điều hướng bên phải kéo đi tự do</div>
              </div>

              <!-- Hàng nút Chuyển Kênh & Tìm Kiếm -->
              <div onmousedown="event.stopPropagation()" ontouchstart="event.stopPropagation()" style="display:grid; grid-template-columns:repeat(4, 1fr); gap:6px;">
                <button class="tool-btn" style="height:32px; font-size:11.5px; background:rgba(37,99,235,0.22); border-color:rgba(59,130,246,0.5); color:#bfdbfe;" onclick="key(166, 'Kênh + (CH+)')">🔼 Kênh +</button>
                <button class="tool-btn" style="height:32px; font-size:11.5px; background:rgba(37,99,235,0.22); border-color:rgba(59,130,246,0.5); color:#bfdbfe;" onclick="key(167, 'Kênh - (CH-)')">🔽 Kênh -</button>
                <button class="tool-btn" style="height:32px; font-size:11.5px;" onclick="cmd('apps', 'Kho Ứng Dụng')">📱 Kho App</button>
                <button class="tool-btn btn-mic" style="height:32px; font-size:11.5px;" onclick="key(231, 'Giọng nói TV360')">🎙️ Giọng nói</button>
              </div>
            </div>
          </div>

          <!-- Device Offline Notice -->
          <div id="screen-offline-notice" style="display:none; position:absolute; inset:0; background:#0b0f19; flex-direction:column; align-items:center; justify-content:center; padding:14px; text-align:center; gap:8px; z-index:5;">
            <div id="screen-offline-icon" style="font-size:36px;">💤</div>
            <div id="screen-offline-title" style="font-weight:700; color:#f87171; font-size:15px;">Thiết bị đang tắt nguồn (Offline)</div>
            <div id="screen-offline-desc" style="font-size:11.5px; color:#cbd5e1; line-height:1.4; max-width:300px;">
              Thiết bị hiện chưa phản hồi trên mạng LAN.<br>
              Vui lòng bật máy hoặc dùng Wake-on-LAN để đánh thức từ xa.
            </div>
            <div style="display:flex; gap:8px; margin-top:4px;">
              <button id="screen-offline-wol-btn" class="btn" onclick="sendWoL(currentDev)" style="background:#16a34a; color:#fff; border:none; padding:7px 14px; border-radius:8px; font-weight:700; font-size:12px; cursor:pointer;">⚡ BẬT NGUỒN (Wake-on-LAN)</button>
              <button class="btn" onclick="wakeAndRefresh()" style="background:#2563eb; color:#fff; border:none; padding:7px 14px; border-radius:8px; font-weight:700; font-size:12px; cursor:pointer;">🔄 Kiểm tra lại</button>
            </div>
          </div>
        </div>
      </div>
    </div> <!-- end #stage-container -->
  </div>
</div>

<!-- Smart Text & Voice Input Modal (Dự phòng) -->
<div class="modal-backdrop" id="text-modal" onclick="if(event.target===this)closeTextModal()">
  <div class="drawer" style="max-width: 440px;">
    <div class="drawer-header">
      <div class="drawer-title">⌨️ Nhập chữ & Giọng nói lên TV</div>
      <button class="drawer-close" onclick="closeTextModal()">&times;</button>
    </div>
    
    <div style="display:flex; flex-direction:column; gap:10px; padding: 4px 0 6px 0;">
      <!-- Input Field -->
      <div style="display:flex; gap:6px;">
        <input type="text" id="txt-modal-input" class="input-field" style="flex:1; height:42px; font-size:14px; border-radius:10px; background:#0f131d; border:1px solid #334155; padding:0 12px; color:#fff;" placeholder="Gõ chữ hoặc bấm Mic trên bàn phím..." onkeydown="if(event.key==='Enter')submitModalText()">
        <button class="send-btn" onclick="submitModalText()" style="height:42px; padding:0 16px; font-size:13.5px; font-weight:700; border-radius:10px; background:#2563eb; color:#fff; border:none; cursor:pointer;">Gửi</button>
      </div>

      <!-- Quick Action Chips -->
      <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:5px;">
        <button class="btn" onclick="pasteClipboardToInput()" style="background:#1e293b; color:#93c5fd; border:1px solid #334155; padding:7px 2px; border-radius:8px; font-size:11px; font-weight:600; cursor:pointer;">📋 Dán chữ</button>
        <button class="btn" onclick="clearModalInput()" style="background:#1e293b; color:#cbd5e1; border:1px solid #334155; padding:7px 2px; border-radius:8px; font-size:11px; font-weight:600; cursor:pointer;">✕ Xóa ô</button>
        <button class="btn" onclick="sendAndroidKeyFromModal(67, 'Xóa lùi')" style="background:#1e293b; color:#f87171; border:1px solid #334155; padding:7px 2px; border-radius:8px; font-size:11px; font-weight:600; cursor:pointer;">⌫ Xóa TV</button>
        <button class="btn" onclick="sendAndroidKeyFromModal(66, 'Enter')" style="background:#1e293b; color:#38bdf8; border:1px solid #334155; padding:7px 2px; border-radius:8px; font-size:11px; font-weight:700; cursor:pointer;">↵ Enter</button>
      </div>

      <label for="vui-img-upload" class="btn" onclick="recordActivity(); setTimeout(closeTextModal, 80);" style="background:#0f766e; color:#fff; border:1px solid #14b8a6; padding:9px 10px; border-radius:8px; font-weight:700; font-size:12px; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:6px;">
        <span>📎</span><span>Gửi File (Hình ảnh / Âm thanh / Video clip) từ ĐT</span>
      </label>

      <!-- TV Assistant & Close TV Keyboard -->
      <div style="display:flex; gap:6px;">
        <button class="btn" onclick="triggerTVVoiceAssistant()" style="flex:1.4; background:#1d4ed8; color:#fff; border:1px solid #3b82f6; padding:8px 10px; border-radius:8px; font-weight:700; font-size:12px; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:5px;">
          <span>🎙️</span><span>Trợ lý giọng nói TV</span>
        </button>
        <button class="btn" onclick="sendAndroidKeyFromModal(4, 'Đóng phím'); closeTextModal();" style="flex:1; background:#1e293b; color:#94a3b8; border:1px solid #334155; padding:8px 8px; border-radius:8px; font-weight:600; font-size:11.5px; cursor:pointer;">
          ✕ Đóng phím TV
        </button>
      </div>
    </div>
  </div>
</div>

<!-- Help Guide Modal (Hướng dẫn chi tiết trực quan) -->
<div class="modal-backdrop" id="help-modal" onclick="if(event.target===this)closeHelpModal()">
  <div class="help-modal-content">
    <div class="help-header">
      <div class="help-title">❓ Hướng Dẫn Cử Chỉ Đa Điểm & Điều Khiển</div>
      <button class="drawer-close" onclick="closeHelpModal()">&times;</button>
    </div>

    <div class="help-section">
      <div class="help-sec-title">🖱️ 1. Thao Tác 1 Ngón (Chuột, Bấm Giữ & Kéo Thả)</div>
      <div class="help-item">• <b>Chạm 1 lần (Tap)</b>: Click chuột trái / Chọn mở mục tại vị trí chạm.</div>
      <div class="help-item">• <b>Chạm đúp nhanh (Double-Tap)</b>: Nhấp đúp chuột trái (mở thư mục, file, phóng to cửa sổ trên PC).</div>
      <div class="help-item">• <b>Bấm giữ 0.4s rồi nhả (Long-Press)</b>: Click <b>Chuột phải</b> trên PC (hoặc mở Menu ngữ cảnh trên TV).</div>
      <div class="help-item">• <b>Bấm giữ 0.4s rồi kéo đi (Hold & Drag)</b>: <b>Kéo thả (Drag & Drop)</b> cửa sổ, bôi đen văn bản, di chuyển file theo thời gian thực!</div>
      <div class="help-item">• <b>Nút [🖱️ 1Ngón: Kéo thả / Cuộn / Bàn rê]</b>: Trên PC, bấm nút xanh trên thanh đầu để đổi nhanh chế độ rê 1 ngón.</div>
    </div>

    <div class="help-section">
      <div class="help-sec-title">✌️ 2. Cử Chỉ Đa Điểm 2 & 3 Ngón (Như Trackpad MacBook)</div>
      <div class="help-item">• <b>Vuốt 2 ngón song song (2-Finger Scroll)</b>: Cuộn trang mượt mà 4 chiều (Lên / Xuống / Trái / Phải) ngay tại vị trí con trỏ.</div>
      <div class="help-item">• <b>Chạm 2 ngón cùng lúc (2-Finger Tap)</b>: Click <b>Chuột phải</b> tức thì.</div>
      <div class="help-item">• <b>Chụm / Tách 2 ngón (Pinch Zoom)</b>: Phóng to / thu nhỏ màn hình từ 1.0x đến 4.0x.</div>
      <div class="help-item">• <b>Chạm 3 ngón (3-Finger Tap)</b>: Mở màn hình Đa nhiệm / Overview cửa sổ (Phím Super/Windows).</div>
    </div>

    <button class="btn" onclick="closeHelpModal()" style="width:100%; margin-top:6px; background:#2563eb; color:#fff; padding:9px; border-radius:8px; font-weight:700; border:none; cursor:pointer;">Đã hiểu & Bắt đầu dùng</button>
  </div>
</div>

<!-- Device Switcher Modal (Cùng chiều với màn hình TV, cố định vị trí thiết bị 100%) -->
<div class="modal-backdrop" id="dev-modal" onclick="if(event.target===this)closeDevModal()">
  <div class="drawer">
    <div class="drawer-header" style="margin-bottom:8px; padding-bottom:6px;">
      <div class="drawer-title">📱 Chọn Thiết Bị Điều Khiển</div>
      <button class="drawer-close" onclick="closeDevModal()">&times;</button>
    </div>
    <div class="dev-modal-grid" id="dev-modal-grid">
      <div class="dev-modal-card active" id="dev-card-tx3" onclick="selectDevAndClose('tx3')">
        <div class="dev-card-icon">📺</div>
        <div class="dev-card-info">
          <div class="dev-card-name">Tanix TX3 Mini</div>
          <div class="dev-card-sub"><span style="color:#22c55e; font-weight:700;">● Online</span> • 192.168.1.88:8080</div>
        </div>
        <div class="dev-wol-wrap" id="dev-wol-tx3"></div>
        <div class="dev-card-check">✓</div>
      </div>

      <div class="dev-modal-card" id="dev-card-pc" onclick="selectDevAndClose('pc')">
        <div class="dev-card-icon">💻</div>
        <div class="dev-card-info">
          <div class="dev-card-name">Máy tính (pop-os)</div>
          <div class="dev-card-sub"><span style="color:#22c55e; font-weight:700;">● Online</span> • 192.168.1.154:8090</div>
        </div>
        <div class="dev-wol-wrap" id="dev-wol-pc"></div>
        <div class="dev-card-check">✓</div>
      </div>

      <div class="dev-modal-card" id="dev-card-win11" onclick="selectDevAndClose('win11')">
        <div class="dev-card-icon">💻</div>
        <div class="dev-card-info">
          <div class="dev-card-name">Windows 11 (LAPTOP-2FDEKP1N)</div>
          <div class="dev-card-sub"><span style="color:#22c55e; font-weight:700;">● Online</span> • 192.168.1.55:8090</div>
        </div>
        <div class="dev-wol-wrap" id="dev-wol-win11"></div>
        <div class="dev-card-check">✓</div>
      </div>

      <div class="dev-modal-card" id="dev-card-projector" onclick="selectDevAndClose('projector')">
        <div class="dev-card-icon">📽</div>
        <div class="dev-card-info">
          <div class="dev-card-name">Máy chiếu Hyundai</div>
          <div class="dev-card-sub"><span style="color:#22c55e; font-weight:700;">● Online</span> • 192.168.1.135:8080</div>
        </div>
        <div class="dev-wol-wrap" id="dev-wol-projector"></div>
        <div class="dev-card-check">✓</div>
      </div>

      <div class="dev-modal-card" id="dev-card-kaw" onclick="selectDevAndClose('kaw')">
        <div class="dev-card-icon">📽</div>
        <div class="dev-card-info">
          <div class="dev-card-name">Máy chiếu KAW A70 Pro</div>
          <div class="dev-card-sub"><span style="color:#94a3b8;">○ Offline</span> • 192.168.1.138:8080</div>
        </div>
        <div class="dev-wol-wrap" id="dev-wol-kaw"></div>
        <div class="dev-card-check">✓</div>
      </div>

      <div class="dev-modal-card" id="dev-card-tv360" onclick="selectDevAndClose('tv360')">
        <div class="dev-card-icon">📦</div>
        <div class="dev-card-info">
          <div class="dev-card-name">Viettel TV360 Box</div>
          <div class="dev-card-sub"><span style="color:#22c55e; font-weight:700;">● Online</span> • 192.168.1.154:8089</div>
        </div>
        <div class="dev-wol-wrap" id="dev-wol-tv360"></div>
        <div class="dev-card-check">✓</div>
      </div>
    </div>
  </div>
</div>

<!-- PC Window Switcher / App Focus Modal -->
<div class="modal-backdrop" id="win-modal" onclick="if(event.target===this)closeWindowModal()">
  <div class="drawer" style="max-width:520px;">
    <div class="drawer-header">
      <div class="drawer-title">🪟 Chọn Cửa Sổ Làm Việc (PC / Windows 11)</div>
      <button class="drawer-close" onclick="closeWindowModal()">&times;</button>
    </div>
    <div style="display:grid; grid-template-columns: 1fr 1fr 0.7fr; gap:6px; margin-bottom:10px;">
      <button class="btn" onclick="selectPCWindow('full', 'Toàn màn hình', false)" style="background:#1e293b; color:#e2e8f0; border:1px solid #475569; padding:8px 6px; border-radius:8px; font-weight:700; font-size:11.5px; cursor:pointer;">🖥️ Xem Toàn Màn Hình</button>
      <button class="btn" onclick="quickFocusAntigravity()" style="background:#1d4ed8; color:#fff; border:1px solid #3b82f6; padding:8px 6px; border-radius:8px; font-weight:700; font-size:11.5px; cursor:pointer;">🚀 Gọi Antigravity</button>
      <button class="btn" onclick="closeWindowModal(); sendPCHotkey('alt+Tab', 'Alt+Tab');" style="background:#0f172a; color:#93c5fd; border:1px solid #334155; padding:8px 4px; border-radius:8px; font-weight:600; font-size:11px; cursor:pointer;">🔄 Alt+Tab</button>
    </div>
    <div class="dev-modal-grid" id="win-modal-grid" style="max-height:58vh; overflow-y:auto;">
      <div style="text-align:center; color:#94a3b8; padding:16px; font-size:12px;">Đang tải danh sách cửa sổ...</div>
    </div>
  </div>
</div>

<!-- Settings & Drawer Modal (⚙️ Thiết Lập & Tiện Ích - Cùng chiều với màn hình TV) -->
<div class="modal-backdrop" id="drawer-modal" onclick="if(event.target===this)closeDrawer()">
  <div class="drawer">
    <div class="drawer-header">
      <div class="drawer-title">⚙️ Thiết Lập & Tiện Ích</div>
      <button class="drawer-close" onclick="closeDrawer()">&times;</button>
    </div>

    <!-- Cụm Điều Khiển Thấu Kính & Nguồn Máy Chiếu (Tự động hiện khi chọn Hyundai / KAW) -->
    <div id="proj-controls" style="display:none; margin-bottom:10px;">
      <div class="drawer-section-title">📽 Thấu kính & Nguồn Máy Chiếu (Hyundai / KAW)</div>
      <div class="drawer-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom:6px;">
        <div class="drawer-btn" onclick="cmd('focus_down', 'Lấy nét -')" style="border-color:#3b82f666; background:#152238; color:#93c5fd;">
          <span class="d-icon">🔍</span>
          <span>Lấy nét -</span>
        </div>
        <div class="drawer-btn" onclick="cmd('autofocus', 'Tự động lấy nét')" style="border-color:#60a5fa; background:#1d4ed8; color:#fff;">
          <span class="d-icon">⚡</span>
          <span>Auto Lấy Nét</span>
        </div>
        <div class="drawer-btn" onclick="cmd('focus_up', 'Lấy nét +')" style="border-color:#3b82f666; background:#152238; color:#93c5fd;">
          <span class="d-icon">🔍</span>
          <span>Lấy nét +</span>
        </div>
      </div>
      <div class="drawer-grid">
        <div class="drawer-btn" onclick="drawerAction('keystone', 'Chỉnh vuông hình')">
          <span class="d-icon">📐</span>
          <span>Chỉnh vuông hình</span>
        </div>
        <div class="drawer-btn" onclick="drawerAction('zoom', 'Thu phóng màn chiếu')">
          <span class="d-icon">🔎</span>
          <span>Thu phóng (Zoom)</span>
        </div>
        <div class="drawer-btn" onclick="drawerAction('mutescreen', 'Tắt đèn hình nghe nhạc')">
          <span class="d-icon">🌙</span>
          <span>Tắt hình nghe nhạc</span>
        </div>
        <div class="drawer-btn" onclick="closeDrawer(); key(26, 'Nguồn Máy chiếu')" style="border-color:#f8717166; background:#2a1215; color:#fca5a5;">
          <span class="d-icon">⏻</span>
          <span>Nguồn Máy chiếu</span>
        </div>
      </div>
    </div>

    <!-- Cụm Điều Khiển Nguồn Máy Tính (Tự động hiện khi chọn PC / Windows 11) -->
    <div id="pc-controls" style="display:none; margin-bottom:10px;">
      <div class="drawer-section-title">💻 Điều Khiển Nguồn Máy Tính (PC / Windows 11)</div>
      <div class="drawer-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom:6px;">
        <div class="drawer-btn" onclick="pcAction('wake', 'Bật màn hình & Mở ô nhập mật khẩu')" style="border-color:#22c55e66; background:#0d2818; color:#86efac;">
          <span class="d-icon">🔓</span>
          <span>Bật màn hình</span>
        </div>
        <div class="drawer-btn" onclick="pcAction('suspend', 'Khóa & Tắt màn hình (Giữ mạng)')" style="border-color:#3b82f666; background:#152238; color:#93c5fd;">
          <span class="d-icon">💤</span>
          <span>Ngủ (Tắt hình)</span>
        </div>
        <div class="drawer-btn" onclick="pcAction('reboot', 'Khởi động lại máy tính')" style="border-color:#f59e0b66; background:#291e10; color:#fde68a;">
          <span class="d-icon">🔄</span>
          <span>Khởi động lại</span>
        </div>
        <div class="drawer-btn" onclick="pcAction('poweroff', 'Tắt nguồn máy tính')" style="border-color:#ef444466; background:#291417; color:#fca5a5;">
          <span class="d-icon">⚡</span>
          <span>Tắt nguồn</span>
        </div>
      </div>
    </div>

    <div class="drawer-section-title">📡 Truyền hình màn hình (1 nút đổi kiểu & 1 nút Dừng/Truyền)</div>
    <div class="stream-settings-group">
      <div class="stream-opt-card active" id="opt-stream-mode" onclick="cycleStreamMode()">
        <div class="stream-opt-icon" id="opt-stream-mode-icon">⏱</div>
        <div class="stream-opt-title" id="opt-stream-mode-title">Kiểu: Mặc định (35s)</div>
        <div class="stream-opt-desc" id="opt-stream-mode-desc">Không tương tác tự dừng<br>(Bấm để đổi sang Liên tục)</div>
      </div>
      <div class="stream-opt-card" id="opt-stream-toggle" onclick="toggleStreamActive()" style="border-color:rgba(248,113,113,0.6); background:rgba(239,68,68,0.18);">
        <div class="stream-opt-icon" id="opt-stream-toggle-icon">⏹</div>
        <div class="stream-opt-title" id="opt-stream-toggle-title" style="color:#fecaca;">Dừng truyền</div>
        <div class="stream-opt-desc" id="opt-stream-toggle-desc">Đang truyền — Bấm để dừng</div>
      </div>
    </div>

    <div class="drawer-section-title">🚀 Mở Nhanh Ứng Dụng</div>
    <div class="drawer-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom:12px;">
      <div class="drawer-btn" onclick="closeDrawer(); app('studio.scillarium.ottnavigator', 'Truyền hình OTT')">
        <span class="d-icon">📺</span>
        <span>TV (246 Kênh)</span>
      </div>
      <div class="drawer-btn" onclick="closeDrawer(); app('org.smarttube.stable', 'SmartTube')">
        <span class="d-icon">▶️</span>
        <span>SmartTube</span>
      </div>
      <div class="drawer-btn" onclick="closeDrawer(); app('com.stremio.one', 'Stremio 4K')">
        <span class="d-icon">🎬</span>
        <span>Stremio 4K</span>
      </div>
      <div class="drawer-btn" onclick="closeDrawer(); app('org.xbmc.kodi', 'Kodi Media')">
        <span class="d-icon">🍿</span>
        <span>Kodi TV</span>
      </div>
      <div class="drawer-btn" onclick="closeDrawer(); app('vn.vtv.vtvgo', 'VTV Go')">
        <span class="d-icon">📡</span>
        <span>VTV Go</span>
      </div>
      <div class="drawer-btn" onclick="closeDrawer(); app('com.ionitech.airscreen', 'AirScreen')">
        <span class="d-icon">📲</span>
        <span>AirScreen</span>
      </div>
      <div class="drawer-btn" onclick="closeDrawer(); app('com.alphainventor.filemanager', 'File Manager')">
        <span class="d-icon">📁</span>
        <span>File Manager</span>
      </div>
      <div class="drawer-btn" onclick="closeDrawer(); app('com.netflix.mediaclient', 'Netflix')">
        <span class="d-icon">🎬</span>
        <span>Netflix</span>
      </div>
    </div>

    <div class="drawer-section-title">Kết nối & Cài đặt TV</div>
    <div class="drawer-grid">
      <div class="drawer-btn" onclick="drawerAction('bluetooth', 'Loa Bluetooth')">
        <span class="d-icon">&#x1F50A;</span>
        <span>Loa Bluetooth</span>
      </div>
      <div class="drawer-btn" onclick="drawerAction('wifi', 'Cài đặt Wi-Fi')">
        <span class="d-icon">&#x1F4F6;</span>
        <span>Cài đặt Wi-Fi</span>
      </div>
      <div class="drawer-btn" onclick="drawerAction('display', 'Độ phân giải')">
        <span class="d-icon">&#x1F5A5;</span>
        <span>Màn hình & HDR</span>
      </div>
      <div class="drawer-btn" onclick="drawerAction('settings', 'Cài đặt Android')">
        <span class="d-icon">&#x2699;</span>
        <span>Cài đặt tổng</span>
      </div>
    </div>

    <div class="drawer-section-title">Hệ thống & Chống đơ (Không cần rút điện)</div>
    <div class="drawer-grid">
      <div class="drawer-btn" onclick="drawerAction('restart_launcher', 'Làm mới Giao diện')" style="border-color:#38bdf866; background:#0f172a; color:#7dd3fc;">
        <span class="d-icon">&#x26A1;</span>
        <span>Làm mới Giao diện</span>
      </div>
      <div class="drawer-btn" onclick="drawerAction('clean', 'Dọn dẹp RAM')">
        <span class="d-icon">&#x1F9F9;</span>
        <span>Dọn RAM tăng tốc</span>
      </div>
      <div class="drawer-btn" onclick="drawerAction('apps', 'Quản lý App')">
        <span class="d-icon">&#x1F4F1;</span>
        <span>Quản lý App</span>
      </div>
      <div class="drawer-btn" onclick="showTunnelInfo()" style="border-color:#10b98166; background:#064e3b33; color:#6ee7b7;">
        <span class="d-icon">🌐</span>
        <span>Link Internet (4G)</span>
      </div>
      <div class="drawer-btn" onclick="drawerAction('reboot', 'Khởi động lại Máy')" style="border-color:#f8717155; color:#fca5a5;">
        <span class="d-icon">&#x1F504;</span>
        <span>Khởi động lại Máy</span>
      </div>
    </div>
    <div style="margin-top:14px; padding-top:8px; border-top:1px solid rgba(148,163,184,0.1); text-align:center; font-size:10.5px; color:#64748b; line-height:1.5;">
      <strong>VuiRemote</strong> — Chia sẻ mã nguồn mở bởi mình (<strong>mrtrinhvn</strong>) • <a href="https://vuicahat.com" target="_blank" rel="noopener" style="color:#94a3b8; text-decoration:underline; text-underline-offset:2px;">VuiCaHat.com</a> &amp; <a href="https://dancaquanho.com" target="_blank" rel="noopener" style="color:#94a3b8; text-decoration:underline; text-underline-offset:2px;">DanCaQuanHo.com</a>
    </div>
  </div>
</div>
</div> <!-- end #app-root -->

<script>
var urlDev = (typeof URLSearchParams !== 'undefined') ? (new URLSearchParams(location.search).get('dev')) : null;
var hostDev = (location.hostname === '192.168.1.135') ? 'projector' :
              (location.hostname === '192.168.1.138') ? 'kaw' :
              (location.hostname === '192.168.1.154' || location.port === '8090') ? 'pc' : null;
var currentDev = urlDev || localStorage.getItem('vui_dev') || hostDev || 'tx3';
var currentMode = 'screen';
var recognition = null;

var knownDevices = {};
var nameMap = {
  'tx3': 'Tanix TX3',
  'pc': 'Máy tính PC',
  'win11': 'Windows 11',
  'kaw': 'KAW A70',
  'projector': 'Hyundai',
  'tv360': 'TV360'
};
var devIcons = {
  'tx3': '📺 ',
  'pc': '💻 ',
  'win11': '💻 ',
  'kaw': '📽 ',
  'projector': '📽 ',
  'tv360': '📦 '
};

function isCurrentDevPC() {
  return currentDev === 'pc' || currentDev === 'win11' || currentDev.indexOf('win') === 0 || (knownDevices[currentDev] && knownDevices[currentDev].type === 'pc');
}

// STREAM & AUTO-SLEEP LOCK ENGINE (2 kiểu truyền: 'auto' mặc định 35s tự dừng & 'continuous' liên tục khi đang xem)
var streamMode = localStorage.getItem('vui_stream_v3') || 'auto';
if (streamMode !== 'auto' && streamMode !== 'continuous') {
  streamMode = 'auto';
}
var autoRefreshTimer = null;
var interactiveTimers = [];
var isScreenLoading = false;
var loadWatchdogTimer = null;
var refreshIntervalMs = 180;
var emaFrameRttMs = 75;
var lastInteractiveBoostTime = 0;
var pendingPostInputRefresh = false;
var consecutiveScreenErrors = 0;

var isSleeping = false;
var sleepReason = ''; // 'idle' | 'manual' | 'hidden' | ''
var lastActivityTime = Date.now();
var IDLE_TIMEOUT_MS = 35000; // 35 giây không thao tác -> tự động dừng truyền (ở kiểu Mặc định)

function isAutoStreamingMode() {
  return streamMode === 'auto' || streamMode === 'continuous';
}

var uiLang = localStorage.getItem('vui_lang') || (((navigator.language || '').toLowerCase().indexOf('vi') === 0) ? 'vi' : 'en');
function isEN() { return uiLang === 'en'; }

function updateStreamButtonsUI() {
  var isActive = !isSleeping;
  var en = isEN();

  // 1. Nút chọn kiểu truyền trên Top Bar
  var modeBtn = document.getElementById('btn-top-stream-mode');
  var modeLbl = document.getElementById('top-stream-mode-label');
  if (modeBtn && modeLbl) {
    if (streamMode === 'continuous') {
      modeLbl.innerHTML = en ? '♾️ Live' : '♾️ Liên tục';
      modeBtn.style.background = 'rgba(56,189,248,0.18)';
      modeBtn.style.borderColor = 'rgba(56,189,248,0.45)';
      modeBtn.style.color = '#7dd3fc';
      modeBtn.title = en ? 'Stream Mode: Continuous Live (Click to switch to 35s Auto-Sleep)' : 'Kiểu truyền: Liên tục khi đang xem (Bấm để đổi sang Mặc định 35s)';
    } else {
      modeLbl.innerHTML = '⏱ 35s';
      modeBtn.style.background = 'rgba(255,255,255,0.08)';
      modeBtn.style.borderColor = 'rgba(255,255,255,0.18)';
      modeBtn.style.color = '#e2e8f0';
      modeBtn.title = en ? 'Stream Mode: 35s Smart Auto-Sleep (Click to switch to Continuous Live)' : 'Kiểu truyền: Mặc định 35s không tương tác tự dừng (Bấm để đổi sang Liên tục)';
    }
  }

  // 2. Nút Truyền / Dừng truyền trên Top Bar
  var toggleBtn = document.getElementById('btn-top-stream-toggle');
  var toggleLbl = document.getElementById('top-stream-toggle-label');
  if (toggleBtn && toggleLbl) {
    if (isActive) {
      toggleLbl.innerHTML = en ? '⏹ Stop' : '⏹ Dừng';
      toggleBtn.style.background = 'rgba(239,68,68,0.28)';
      toggleBtn.style.borderColor = 'rgba(248,113,113,0.65)';
      toggleBtn.style.color = '#fecaca';
      toggleBtn.title = en ? 'Streaming active — Click to pause' : 'Đang truyền hình — Bấm để dừng truyền';
    } else {
      toggleLbl.innerHTML = en ? '▶️ Live' : '▶️ Truyền';
      toggleBtn.style.background = 'rgba(22,163,74,0.38)';
      toggleBtn.style.borderColor = 'rgba(74,222,128,0.75)';
      toggleBtn.style.color = '#dcfce7';
      toggleBtn.title = en ? 'Stream paused — Click to resume' : 'Đã dừng truyền — Bấm để bắt đầu truyền lại';
    }
  }

  // 3. Nút Chuyển đổi Kiểu truyền & Nút Dừng/Truyền trong bảng Thiết lập (⚙️)
  var drawerModeCard = document.getElementById('opt-stream-mode');
  var drawerModeIcon = document.getElementById('opt-stream-mode-icon');
  var drawerModeTitle = document.getElementById('opt-stream-mode-title');
  var drawerModeDesc = document.getElementById('opt-stream-mode-desc');
  if (drawerModeCard && drawerModeIcon && drawerModeTitle && drawerModeDesc) {
    if (streamMode === 'continuous') {
      drawerModeIcon.innerText = '♾️';
      drawerModeTitle.innerText = en ? 'Mode: Continuous Live' : 'Kiểu: Truyền liên tục';
      drawerModeDesc.innerHTML = en ? 'Always stream while open<br>(Tap to switch to 35s Auto-Sleep)' : 'Truyền liên tục khi đang xem<br>(Bấm để đổi sang Mặc định 35s)';
      drawerModeCard.style.borderColor = 'rgba(56,189,248,0.6)';
      drawerModeCard.style.background = 'rgba(14,165,233,0.18)';
      drawerModeTitle.style.color = '#bae6fd';
    } else {
      drawerModeIcon.innerText = '⏱';
      drawerModeTitle.innerText = en ? 'Mode: Smart 35s Auto-Sleep' : 'Kiểu: Mặc định (35s)';
      drawerModeDesc.innerHTML = en ? 'Auto-pauses after 35s idle<br>(Tap to switch to Continuous)' : 'Không tương tác tự dừng<br>(Bấm để đổi sang Liên tục)';
      drawerModeCard.style.borderColor = '#3b82f6';
      drawerModeCard.style.background = '#1e3a8a44';
      drawerModeTitle.style.color = '#f1f5f9';
    }
  }

  var drawerToggle = document.getElementById('opt-stream-toggle');
  var drawerIcon = document.getElementById('opt-stream-toggle-icon') || document.getElementById('opt-toggle-icon');
  var drawerTitle = document.getElementById('opt-stream-toggle-title') || document.getElementById('opt-toggle-title');
  var drawerDesc = document.getElementById('opt-stream-toggle-desc') || document.getElementById('opt-toggle-desc');
  if (drawerToggle && drawerIcon && drawerTitle && drawerDesc) {
    if (isActive) {
      drawerIcon.innerText = '⏹';
      drawerTitle.innerText = en ? 'Pause Stream' : 'Dừng truyền';
      drawerDesc.innerText = en ? 'Streaming — Tap to pause' : 'Đang truyền — Bấm để dừng';
      drawerToggle.style.borderColor = 'rgba(248,113,113,0.6)';
      drawerToggle.style.background = 'rgba(239,68,68,0.18)';
      drawerTitle.style.color = '#fecaca';
    } else {
      drawerIcon.innerText = '▶️';
      drawerTitle.innerText = en ? 'Start Stream' : 'Bắt đầu truyền';
      drawerDesc.innerText = en ? 'Paused — Tap to resume' : 'Đã dừng — Bấm để truyền lại';
      drawerToggle.style.borderColor = 'rgba(74,222,128,0.65)';
      drawerToggle.style.background = 'rgba(22,163,74,0.22)';
      drawerTitle.style.color = '#dcfce7';
    }
  }

  // 4. Chấm trạng thái trên Top Bar
  var statusDot = document.getElementById('stream-status-dot');
  if (statusDot) {
    if (!isActive) {
      statusDot.style.background = (sleepReason === 'manual') ? '#ef4444' : '#f59e0b';
      statusDot.style.boxShadow = 'none';
      statusDot.style.animation = 'none';
      statusDot.title = (sleepReason === 'manual')
        ? (en ? 'Stream paused manually (Tap ▶️ Live to resume)' : 'Đã dừng truyền thủ công (Bấm ▶️ Truyền để tiếp tục)')
        : (en ? 'Auto-paused after 35s idle (Touch screen or tap ▶️ Live to wake)' : 'Đã tự dừng sau 35s không tương tác (Chạm màn hình hoặc bấm ▶️ Truyền để tiếp tục)');
    } else {
      var dotColor = (streamMode === 'continuous') ? '#38bdf8' : '#22c55e';
      statusDot.style.background = dotColor;
      statusDot.style.boxShadow = '0 0 8px ' + dotColor;
      statusDot.style.animation = 'blink 1.2s infinite';
      statusDot.title = (streamMode === 'continuous')
        ? (en ? 'Continuous Live Stream active' : 'Đang truyền liên tục khi còn đang xem')
        : (en ? 'Smart Stream active (Auto-pauses after 35s idle)' : 'Đang truyền mặc định (Tự dừng sau 35s không tương tác)');
    }
  }
}

function recordActivity() {
  lastActivityTime = Date.now();
  if (isSleeping && sleepReason !== 'manual') {
    wakeFromSleep();
  }
}

function enterSleepLock(reason) {
  isSleeping = true;
  sleepReason = reason || 'idle';
  stopAutoRefresh();
  clearInteractiveTimers();
  if (loadWatchdogTimer) {
    clearTimeout(loadWatchdogTimer);
    loadWatchdogTimer = null;
  }
  isScreenLoading = false;
  var spinner = document.getElementById('screen-spinner');
  if (spinner) spinner.style.display = 'none';

  // Giữ nguyên khung hình cuối trên màn hình để người dùng vẫn xem được nội dung và thấy rõ nút đã đổi sang "▶️ Truyền"
  var overlay = document.getElementById('screen-sleep-overlay');
  if (overlay) {
    overlay.classList.remove('show');
  }

  updateStreamButtonsUI();

  if (sleepReason === 'idle') {
    flashStatus('⏸ Đã tự dừng truyền sau 35s (Bấm ▶️ Truyền hoặc chạm để tiếp tục)', true);
  }
}

function wakeFromSleep() {
  lastActivityTime = Date.now();
  var wasSleeping = isSleeping;
  var prevReason = sleepReason;
  isSleeping = false;
  sleepReason = '';

  var overlay = document.getElementById('screen-sleep-overlay');
  if (overlay) overlay.classList.remove('show');

  updateStreamButtonsUI();

  if (wasSleeping && prevReason !== 'hidden') {
    flashStatus(prevReason === 'manual' ? '▶️ Đã bắt đầu truyền hình lại' : '▶️ Đã tiếp tục truyền hình', true);
    if (navigator.vibrate) navigator.vibrate(15);
  }

  refreshScreen(true);
  if (isAutoStreamingMode()) {
    scheduleNextAutoFrame();
  }
}

function toggleStreamActive() {
  if (isSleeping) {
    wakeFromSleep();
  } else {
    enterSleepLock('manual');
    flashStatus('⏹ Đã dừng truyền hình (Bấm ▶️ Truyền để bật lại)', true);
    if (navigator.vibrate) navigator.vibrate(15);
  }
}

function cycleStreamMode() {
  var nextMode = (streamMode === 'auto') ? 'continuous' : 'auto';
  setStreamMode(nextMode);
}

function wakeAndRefresh() {
  consecutiveScreenErrors = 0;
  if (isSleeping) {
    wakeFromSleep();
  } else {
    recordActivity();
    refreshScreen(true);
  }
}

// Kiểm tra định kỳ mỗi 2 giây: ở chế độ 'auto' (Mặc định), nếu quá 35s không tương tác thì tự dừng truyền
setInterval(function() {
  if (!isSleeping && streamMode === 'auto') {
    if (Date.now() - lastActivityTime > IDLE_TIMEOUT_MS) {
      enterSleepLock('idle');
    }
  }
}, 2000);

function setStreamMode(mode) {
  if (mode !== 'auto' && mode !== 'continuous') {
    mode = 'auto';
  }
  streamMode = mode;
  localStorage.setItem('vui_stream_v3', mode);
  lastActivityTime = Date.now();

  if (isSleeping) {
    isSleeping = false;
    sleepReason = '';
    var overlay = document.getElementById('screen-sleep-overlay');
    if (overlay) overlay.classList.remove('show');
  }

  stopAutoRefresh();
  clearInteractiveTimers();
  updateStreamButtonsUI();

  if (mode === 'continuous') {
    flashStatus('♾️ Truyền liên tục khi còn đang xem', true);
  } else {
    flashStatus('⏱ Mặc định: Truyền 35s, không tương tác tự dừng', true);
  }
  refreshScreen(false);
  scheduleNextAutoFrame();
}

function clearInteractiveTimers() {
  interactiveTimers.forEach(function(t) { clearTimeout(t); });
  interactiveTimers = [];
}

function getAdaptiveFrameDelayMs() {
  var now = Date.now();
  var isActive = (now - lastActivityTime < 15000) ||
                 (now - lastInteractiveBoostTime < 8000) ||
                 (typeof lastDirectTypeTime === 'number' && (now - lastDirectTypeTime < 8000));

  if (isCurrentDevPC()) {
    return isActive ? 4 : 30;
  }
  if (currentDev === 'tx3') {
    return isActive ? 10 : 65;
  }
  // Máy chiếu KAW / Hyundai hoặc thiết bị khác
  return isActive ? 35 : 120;
}

function scheduleNextAutoFrame() {
  stopAutoRefresh();
  if (isSleeping || !isAutoStreamingMode() || document.hidden) return;
  var delayMs = getAdaptiveFrameDelayMs();
  autoRefreshTimer = setTimeout(function() {
    autoRefreshTimer = null;
    if (!isSleeping && isAutoStreamingMode() && !document.hidden) {
      refreshScreen(false);
    }
  }, delayMs);
}

function stopAutoRefresh() {
  if (autoRefreshTimer) {
    clearTimeout(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}

function triggerInteractiveCapture() {
  lastInteractiveBoostTime = Date.now();
  recordActivity();

  if (isSleeping) return;
  // Luồng truyền hình chạy độc lập hoàn toàn với luồng phím/chuột:
  // Không bao giờ hủy (stopAutoRefresh) chu kỳ đang chạy; chỉ đánh thức nếu luồng hình đang rảnh.
  if (!isScreenLoading && !autoRefreshTimer) {
    refreshScreen(false);
  }
}

function refreshScreen(showSpin) {
  if (isSleeping && !showSpin) return;

  var img = document.getElementById('screen-img');
  var notice = document.getElementById('screen-tv360-notice');
  var offlineNotice = document.getElementById('screen-offline-notice');
  var spinner = document.getElementById('screen-spinner');

  if (isScreenLoading) return;
  isScreenLoading = true;
  pendingPostInputRefresh = false;

  if (showSpin && spinner) spinner.style.display = 'block';

  // Watchdog chống kẹt isScreenLoading vĩnh viễn nếu mạng lag
  if (loadWatchdogTimer) clearTimeout(loadWatchdogTimer);
  loadWatchdogTimer = setTimeout(function() {
    if (isScreenLoading) {
      isScreenLoading = false;
      if (spinner) spinner.style.display = 'none';
      if (isAutoStreamingMode() && !isSleeping) scheduleNextAutoFrame();
    }
  }, 3500);

  var reqDev = currentDev;
  // Luôn truyền độ phân giải gốc 2K (2560x1440) sắc nét tuyệt đối 1:1
  var targetW = 2560;
  var frameStartMs = Date.now();
  var src = '/api/screen?dev=' + reqDev + '&w=' + targetW + '&t=' + frameStartMs;

  if (!img) {
    isScreenLoading = false;
    return;
  }

  img.onload = function() {
    if (reqDev !== currentDev) {
      isScreenLoading = false;
      return;
    }
    if (loadWatchdogTimer) { clearTimeout(loadWatchdogTimer); loadWatchdogTimer = null; }
    var rtt = Math.max(4, Date.now() - frameStartMs);
    emaFrameRttMs = emaFrameRttMs ? Math.round(emaFrameRttMs * 0.65 + rtt * 0.35) : rtt;
    isScreenLoading = false;
    if (spinner) spinner.style.display = 'none';
    if (isSleeping && !showSpin) return;
    consecutiveScreenErrors = 0;
    if (img.style.display !== 'block') {
      img.style.display = 'block';
      applyImageTransform();
    }
    if (notice && notice.style.display !== 'none') notice.style.display = 'none';
    if (offlineNotice && offlineNotice.style.display !== 'none') offlineNotice.style.display = 'none';
    if (isAutoStreamingMode() && !isSleeping) {
      scheduleNextAutoFrame();
    }
  };
  img.onerror = function() {
    if (reqDev !== currentDev) {
      isScreenLoading = false;
      return;
    }
    if (loadWatchdogTimer) { clearTimeout(loadWatchdogTimer); loadWatchdogTimer = null; }
    isScreenLoading = false;
    if (spinner) spinner.style.display = 'none';
    if (isSleeping && !showSpin) return;
    consecutiveScreenErrors++;
    if (currentDev === 'tv360') {
      if (consecutiveScreenErrors >= 2) {
        if (img) img.style.display = 'none';
        if (notice) notice.style.display = 'flex';
        if (offlineNotice) offlineNotice.style.display = 'none';
      }
    } else {
      if (consecutiveScreenErrors >= 3) {
        if (img) img.style.display = 'none';
        if (offlineNotice) {
          offlineNotice.style.display = 'flex';
          var offTitle = document.getElementById('screen-offline-title');
          var offIcon = document.getElementById('screen-offline-icon');
          var offDesc = document.getElementById('screen-offline-desc');
          var offWolBtn = document.getElementById('screen-offline-wol-btn');
          var name = (nameMap[currentDev] || currentDev);
          if (offTitle) offTitle.innerText = name + ' đang tắt nguồn (Offline)';
          if (offIcon) offIcon.innerText = (devIcons[currentDev] || '💤').trim();
          if (currentDev === 'pc') {
            if (offDesc) offDesc.innerHTML = 'Máy tính chưa khởi động hoặc đang ở chế độ ngủ (Standby).<br>Bấm nút <b>BẬT NGUỒN (Wake-on-LAN)</b> bên dưới để đánh thức máy từ xa!';
            if (offWolBtn) offWolBtn.style.display = 'inline-block';
          } else {
            if (offDesc) offDesc.innerHTML = 'Thiết bị hiện chưa phản hồi trên Wi-Fi.<br>Vui lòng bật bằng remote hoặc bấm nút nguồn trên máy.';
            if (offWolBtn) offWolBtn.style.display = 'none';
          }
        }
      }
    }
    if (isAutoStreamingMode() && !isSleeping) {
      scheduleNextAutoFrame();
    }
  };
  img.src = src;
}

// Tự động tạm dừng truyền khi ẩn tab / tắt màn hình điện thoại, và tự truyền lại khi mở xem lại
document.addEventListener('visibilitychange', function() {
  if (document.hidden) {
    if (!isSleeping) {
      enterSleepLock('hidden');
    }
  } else {
    if (isSleeping && sleepReason === 'hidden') {
      wakeFromSleep();
    }
  }
});

// SCREEN ROTATION ENGINE (Tự động xoay theo cảm biến điện thoại + Xoay đồng bộ màn hình, thanh công cụ nổi, cụm điều hướng và hộp thoại; riêng #smart-input-bar nằm ngoài để luôn ngang cùng chiều bàn phím điện thoại)
var rotMode = localStorage.getItem('vui_rot_mode') || 'auto'; // 'auto' | '90' | '270' | '0'
var screenRotation = parseInt(localStorage.getItem('vui_rot_v3') || '90'); // Mặc định 90°
var sensorListening = false;
var sensorPendingRot = null;
var sensorConfirmTimer = null;

var lastKnownOSLandscape = ((window.innerWidth || document.documentElement.clientWidth || 360) > (window.innerHeight || document.documentElement.clientHeight || 640) * 1.08);
function getEffectiveRotation() {
  if (!isMobileTouchOS()) {
    if (rotMode === '90' || rotMode === '270') return screenRotation;
    return 0;
  }
  if (typeof window.orientation === 'number' && Math.abs(window.orientation) === 90) {
    return 0;
  }
  if (window.screen && window.screen.orientation && typeof window.screen.orientation.angle === 'number') {
    var ang = window.screen.orientation.angle;
    if (ang === 90 || ang === 270) return 0;
  }
  var Ww = window.innerWidth || document.documentElement.clientWidth || 360;
  var Wh = window.innerHeight || document.documentElement.clientHeight || 640;
  var inp = document.getElementById('quick-txt-input');
  var kbdOpen = (isMobileTouchOS() && forceNativePhoneKbd && inp && document.activeElement === inp);
  if (!kbdOpen) {
    lastKnownOSLandscape = (Ww > Wh * 1.08);
  }
  // Nếu hệ điều hành điện thoại đã tự xoay trình duyệt sang khung ngang, giữ CSS ở 0° để không bị xoay chồng 2 lần
  if (lastKnownOSLandscape) {
    return 0;
  }
  return screenRotation;
}

function updateRotBadgeUI() {
  var wmRot = document.getElementById('wm-rot-text');
  if (!wmRot) return;
  var eff = getEffectiveRotation();
  var degStr = (eff === 0) ? '0°' : (eff + '°');
  wmRot.innerText = 'Xoay ' + degStr;
}

function syncViewportSize() {
  var root = document.getElementById('app-root');
  var sec = document.getElementById('view-screen');
  var box = document.getElementById('screen-box');
  if (!root) return;
  var vv = window.visualViewport;
  var Vw = (vv && vv.width > 0) ? vv.width : (window.innerWidth || document.documentElement.clientWidth || 360);
  var Vh = (vv && vv.height > 0) ? vv.height : (window.innerHeight || document.documentElement.clientHeight || 640);
  var offX = vv ? vv.offsetLeft : 0;
  var offY = vv ? vv.offsetTop : 0;

  var effRot = getEffectiveRotation();
  var cls = (effRot === 90) ? 'rot-90' : (effRot === 270 ? 'rot-270' : 'rot-0');
  [root, sec, box].forEach(function(el) {
    if (!el) return;
    el.classList.remove('rot-90', 'rot-270', 'rot-0');
    el.classList.add(cls);
  });

  if (effRot === 90 || effRot === 270) {
    root.style.width = Vh + 'px';
    root.style.height = Vw + 'px';
    root.style.left = (offX + Vw / 2) + 'px';
    root.style.top = (offY + Vh / 2) + 'px';
  } else {
    root.style.width = Vw + 'px';
    root.style.height = Vh + 'px';
    root.style.left = offX + 'px';
    root.style.top = offY + 'px';
  }
  root.style.transform = '';
  updateRotBadgeUI();
  if (typeof positionSmartInputBar === 'function') {
    positionSmartInputBar();
  }
}

function setScreenRotation(rot, fromSensor) {
  screenRotation = rot;
  localStorage.setItem('vui_rot_v3', rot);

  syncViewportSize();
  var bar = document.getElementById('smart-input-bar');
  if (bar && bar.classList.contains('show') && typeof activateSmartKeyboardForOrientation === 'function') {
    activateSmartKeyboardForOrientation();
  }
  panX = 0; panY = 0;
  applyImageTransform();
  setTimeout(clampNavClusterPosition, 60);
  if (fromSensor) {
    var label = (rot === 90) ? '90° (Ngang)' : (rot === 270 ? '270° (Ngang đảo)' : '0° (Dọc)');
    flashStatus('📲 Tự động xoay: ' + label, true);
  }
}

function handleDeviceOrientation(e) {
  if (rotMode !== 'auto') return;
  var beta = e.beta;   // [-180, 180]: nghiêng trước/sau (dọc ~ 90)
  var gamma = e.gamma; // [-90, 90]: nghiêng trái/phải
  if (beta === null || gamma === null || typeof beta === 'undefined' || typeof gamma === 'undefined') return;

  // Khi điện thoại đặt nằm phẳng trên mặt bàn (|beta| < 25 và |gamma| < 25), giữ nguyên hướng hiện tại
  if (Math.abs(beta) < 25 && Math.abs(gamma) < 25) return;

  var targetRot = null;
  if (gamma < -38 && Math.abs(beta) < 52) {
    targetRot = 90;
  } else if (gamma > 38 && Math.abs(beta) < 52) {
    targetRot = 270;
  } else if (beta > 48 && Math.abs(gamma) < 28) {
    targetRot = 0;
  }

  if (targetRot !== null && targetRot !== screenRotation) {
    if (sensorPendingRot !== targetRot) {
      sensorPendingRot = targetRot;
      if (sensorConfirmTimer) clearTimeout(sensorConfirmTimer);
      sensorConfirmTimer = setTimeout(function() {
        if (rotMode === 'auto' && sensorPendingRot !== null && sensorPendingRot !== screenRotation) {
          setScreenRotation(sensorPendingRot, true);
        }
      }, 350);
    }
  } else {
    sensorPendingRot = null;
    if (sensorConfirmTimer) {
      clearTimeout(sensorConfirmTimer);
      sensorConfirmTimer = null;
    }
  }
}

function enableSensorAutoRotate() {
  if (sensorListening) return;
  if (typeof DeviceOrientationEvent !== 'undefined' && typeof DeviceOrientationEvent.requestPermission === 'function') {
    DeviceOrientationEvent.requestPermission().then(function(state) {
      if (state === 'granted' && !sensorListening) {
        sensorListening = true;
        window.addEventListener('deviceorientation', handleDeviceOrientation, true);
      }
    }).catch(function() {});
  } else if (typeof window.DeviceOrientationEvent !== 'undefined') {
    sensorListening = true;
    window.addEventListener('deviceorientation', handleDeviceOrientation, true);
  }
}

// Tự động kích hoạt cảm biến xoay ngay ở lần chạm đầu tiên trên iOS Safari
window.addEventListener('touchend', function onFirstTouchSensor() {
  enableSensorAutoRotate();
}, { once: true, passive: true });
window.addEventListener('click', function onFirstClickSensor() {
  enableSensorAutoRotate();
}, { once: true, passive: true });

function cycleScreenRotation() {
  enableSensorAutoRotate();
  var nextRot = (screenRotation === 90) ? 270 : (screenRotation === 270 ? 0 : 90);
  rotMode = (nextRot === 90) ? 'auto' : String(nextRot);
  localStorage.setItem('vui_rot_mode', rotMode);
  setScreenRotation(nextRot, false);
  if (nextRot === 90) {
    flashStatus('🔁 Đã xoay ngang 90° (Hỗ trợ tự xoay)', true);
  } else if (nextRot === 270) {
    flashStatus('🔁 Đã xoay ngang đảo chiều 270°', true);
  } else {
    flashStatus('🔁 Đã xoay khung dọc 0°', true);
  }
  if (navigator.vibrate) navigator.vibrate(15);
}

// CONTEXTUAL OVERLAYS, LANDSCAPE VIETNAMESE TELEX KEYBOARD & DRAGGABLE WATERMARK NAVIGATION CLUSTER
var isInputMultiline = true;
var inputMode = 'direct'; // Gõ trực tiếp tức thì từ bàn phím vật lý & bàn phím ảo với ô nhập hoàn toàn vô hình
var DIRECT_SENTINEL = '\u200B';
var suppressQuickInputEvent = false;
var directSentText = '';
var directSentCaret = 0;
var directInputQueue = [];
var directQueueBusy = false;
var lastDirectTypeTime = 0;
var lastQuickInputBlurTime = 0;
var remoteClipboardActive = false;
var preKbdCameraSaved = false;
var preKbdZoom = 1.0, preKbdPanX = 0, preKbdPanY = 0;

var allowAutoOpenIME = false; // Không bao giờ tự ý bật bàn phím khi người dùng chỉ chạm/vuốt trên màn hình
var imeOpenedByUser = false;
var lastTapRatioY = null;
var inputAnchorRatioY = null;
var forceNativePhoneKbd = false;
var vkbdShift = false;
var vkbdSymbols = false;
var vkbdTelex = localStorage.getItem('vui_vkbd_telex') !== '0'; // Mặc định bật gõ Tiếng Việt Telex trên bàn phím ảo

var pendingUploadFiles = [];
var TELEGRAM_PLANE_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>';

var virtualQuickInputCaret = 0;

function isMobileTouchOS() {
  return /Android|iPhone|iPad|iPod/i.test(navigator.userAgent || '');
}

var directInputSeq = 0;
var directInFlightCount = 0;
// Gửi tuần tự từng gói lệnh bàn phím (MAX=1) để mọi thao tác xóa lùi + bù chữ có dấu (Telex/Unikey/IBus) tự động gộp chuẩn xác trong hàng đợi và không bao giờ đua nhau (race condition)
var MAX_CONCURRENT_DIRECT_XHRS = 1;
var deltaCoalesceTimer = null;
var lastRepeatSentMs = 0;
var activeRepeatDirectXhr = null;

function cancelPendingKeyRepeats() {
  var hadRepeat = false;
  if (directInputQueue.length > 0) {
    var kept = [];
    for (var i = 0; i < directInputQueue.length; i++) {
      if (directInputQueue[i].repeat) {
        hadRepeat = true;
      } else {
        kept.push(directInputQueue[i]);
      }
    }
    directInputQueue = kept;
  }
  if (activeRepeatDirectXhr) {
    hadRepeat = true;
    var oldRep = activeRepeatDirectXhr;
    activeRepeatDirectXhr = null;
    if (typeof oldRep._done === 'function') {
      oldRep._done();
    }
    try { oldRep.abort(); } catch (e) {}
  }
  if (hadRepeat || (Date.now() - lastRepeatSentMs < 650)) {
    lastRepeatSentMs = 0;
    var xhrC = new XMLHttpRequest();
    xhrC.timeout = 1200;
    xhrC.open('GET', '/api/key?cancel=1&dev=' + encodeURIComponent(currentDev) + '&t=' + Date.now(), true);
    xhrC.send();
  }
  if (directInputQueue.length > 0) {
    pumpDirectInputQueue();
  }
}

function enqueueDirectTextDelta(bksp, text, isRepeat) {
  bksp = Math.max(0, bksp | 0);
  text = text || '';
  if (bksp === 0 && text === '') return;
  lastDirectTypeTime = Date.now();
  recordActivity();

  if (isRepeat && directInputQueue.length > 0) {
    var lastRep = directInputQueue[directInputQueue.length - 1];
    if (lastRep.type === 'delta' && lastRep.repeat && lastRep.dev === currentDev) {
      if (text === '' && bksp > 0 && lastRep.text === '') {
        lastRep.bksp = Math.min(6, lastRep.bksp + bksp);
        pumpDirectInputQueue();
        return;
      }
      if (bksp === 0 && text !== '' && lastRep.bksp === 0) {
        if (Array.from(lastRep.text).length < 6) {
          lastRep.text += text;
        }
        pumpDirectInputQueue();
        return;
      }
    }
  }

  if (!isRepeat && directInputQueue.length > 0) {
    var last = directInputQueue[directInputQueue.length - 1];
    if (last.type === 'delta' && !last.repeat && last.dev === currentDev) {
      var lastChars = Array.from(last.text);
      if (bksp <= lastChars.length) {
        lastChars.splice(lastChars.length - bksp, bksp);
        last.text = lastChars.join('') + text;
      } else {
        var extraBksp = bksp - lastChars.length;
        last.bksp += extraBksp;
        last.text = text;
      }
      if (last.bksp === 0 && last.text === '') {
        directInputQueue.pop();
      }
      scheduleDeltaPump();
      return;
    }
  }
  directInputQueue.push({
    type: 'delta',
    dev: currentDev,
    bksp: bksp,
    text: text,
    repeat: !!isRepeat
  });
  if (isRepeat) {
    pumpDirectInputQueue(true);
  } else {
    scheduleDeltaPump();
  }
}

function scheduleDeltaPump() {
  if (deltaCoalesceTimer) return;
  deltaCoalesceTimer = setTimeout(function() {
    deltaCoalesceTimer = null;
    pumpDirectInputQueue(true);
  }, 14);
}

function enqueueDirectKey(code, label, isRepeat) {
  lastDirectTypeTime = Date.now();
  recordActivity();
  if (isRepeat && directInputQueue.length > 0) {
    var last = directInputQueue[directInputQueue.length - 1];
    if (last.type === 'key' && last.repeat && last.code === code && last.dev === currentDev) {
      last.count = Math.min(6, (last.count || 1) + 1);
      pumpDirectInputQueue(true);
      return;
    }
    if (last.repeat) {
      directInputQueue.pop();
    }
  }
  directInputQueue.push({
    type: 'key',
    dev: currentDev,
    code: code,
    count: 1,
    label: label || '',
    repeat: !!isRepeat
  });
  pumpDirectInputQueue(true);
}

function enqueueDirectHotkey(combo, label, isRepeat) {
  lastDirectTypeTime = Date.now();
  recordActivity();
  if (isRepeat && directInputQueue.length > 0 && directInputQueue[directInputQueue.length - 1].repeat) {
    return;
  }
  directInputQueue.push({
    type: 'hotkey',
    dev: currentDev,
    combo: combo,
    label: label || combo,
    repeat: !!isRepeat
  });
  pumpDirectInputQueue(true);
}

function dispatchDirectInputItem(item) {
  var reqDev = item.dev || currentDev;
  var seq = ++directInputSeq;
  directInFlightCount++;
  directQueueBusy = (directInFlightCount >= MAX_CONCURRENT_DIRECT_XHRS);
  if (item.repeat) {
    lastRepeatSentMs = Date.now();
  }

  var finished = false;
  function attachDoneHandler(xhrRef) {
    var doneFn = function() {
      if (finished) return;
      finished = true;
      if (activeRepeatDirectXhr === xhrRef) {
        activeRepeatDirectXhr = null;
      }
      directInFlightCount = Math.max(0, directInFlightCount - 1);
      directQueueBusy = (directInFlightCount >= MAX_CONCURRENT_DIRECT_XHRS);
      if (directInputQueue.length > 0) {
        pumpDirectInputQueue(true);
      }
    };
    xhrRef._done = doneFn;
    xhrRef.onload = xhrRef.onerror = xhrRef.ontimeout = xhrRef.onabort = doneFn;
  }

  if (item.type === 'delta') {
    var xhr = new XMLHttpRequest();
    xhr.timeout = 4000;
    if (item.repeat) activeRepeatDirectXhr = xhr;
    var url = '/api/text?direct=1&bksp=' + item.bksp + '&q=' + encodeURIComponent(item.text) + '&seq=' + seq + '&dev=' + encodeURIComponent(reqDev) + '&t=' + Date.now();
    xhr.open('POST', url, true);
    xhr.setRequestHeader('Content-Type', 'text/plain; charset=utf-8');
    attachDoneHandler(xhr);
    xhr.send(item.text);
  } else if (item.type === 'key') {
    var xhrK = new XMLHttpRequest();
    xhrK.timeout = 3500;
    if (item.repeat) activeRepeatDirectXhr = xhrK;
    var cnt = item.count || 1;
    var repParam = item.repeat ? '&rep=1' : '';
    xhrK.open('GET', '/api/key?code=' + item.code + '&count=' + cnt + repParam + '&seq=' + seq + '&dev=' + encodeURIComponent(reqDev) + '&t=' + Date.now(), true);
    attachDoneHandler(xhrK);
    xhrK.send();
  } else if (item.type === 'hotkey') {
    var xhrH = new XMLHttpRequest();
    xhrH.timeout = 3500;
    if (item.repeat) activeRepeatDirectXhr = xhrH;
    xhrH.open('GET', '/api/touch?type=hotkey&key=' + encodeURIComponent(item.combo) + '&seq=' + seq + '&dev=' + encodeURIComponent(reqDev) + '&t=' + Date.now(), true);
    attachDoneHandler(xhrH);
    xhrH.send();
  } else {
    directInFlightCount = Math.max(0, directInFlightCount - 1);
    directQueueBusy = (directInFlightCount >= MAX_CONCURRENT_DIRECT_XHRS);
  }
}

function pumpDirectInputQueue(flushImmediate) {
  if (flushImmediate && deltaCoalesceTimer) {
    clearTimeout(deltaCoalesceTimer);
    deltaCoalesceTimer = null;
  }
  while (directInputQueue.length > 0 && directInFlightCount < MAX_CONCURRENT_DIRECT_XHRS) {
    var nextItem = directInputQueue[0];
    if (nextItem.repeat && activeRepeatDirectXhr !== null) {
      break;
    }
    if (!flushImmediate && nextItem.type === 'delta' && !nextItem.repeat && directInputQueue.length === 1) {
      scheduleDeltaPump();
      break;
    }
    var item = directInputQueue.shift();
    dispatchDirectInputItem(item);
  }
}

function setQuickInputCaret(charIdx) {
  virtualQuickInputCaret = charIdx || 0;
}

function resetDirectBuffer() {
  directSentText = '';
  directSentCaret = 0;
  virtualQuickInputCaret = 0;
  var inp = document.getElementById('quick-txt-input');
  if (inp) {
    suppressQuickInputEvent = true;
    inp.value = DIRECT_SENTINEL;
    try { inp.setSelectionRange(1, 1); } catch(e) {}
    suppressQuickInputEvent = false;
  }
}

function getQuickInputNFCAndCaret() {
  var inp = document.getElementById('quick-txt-input');
  if (!inp) return { text: '', caret: 0, chars: [], val: '' };
  var raw = (inp.value || '').replace(/\u200B/g, '');
  var normFull = raw.normalize ? raw.normalize('NFC') : raw;
  var fullChars = Array.from(normFull);
  return { text: normFull, val: normFull, caret: fullChars.length, chars: fullChars };
}

function applyInputModeUI() {
  updateClearBtnVisibility();
  var kbd = document.getElementById('vui-landscape-kbd');
  if (kbd && kbd.classList.contains('show')) {
    renderLandscapeKeyboard();
  }
}

function moveRemoteCaret(dir) {
  recordActivity();
  if (navigator.vibrate) navigator.vibrate(8);
  resetDirectBuffer();
  if (dir < 0) {
    enqueueDirectKey(21, 'Sang trái ◀');
  } else {
    enqueueDirectKey(22, 'Sang phải ▶');
  }
}

function sendRemoteEnterKey() {
  recordActivity();
  if (navigator.vibrate) navigator.vibrate(14);
  resetDirectBuffer();
  enqueueDirectKey(66, 'Enter ↵');
}

function getKeyboardObscuredBottom() {
  var kbd = document.getElementById('vui-landscape-kbd');
  if (!kbd || !kbd.classList.contains('show')) return 0;
  return (kbd.offsetHeight || 150) + 6;
}

function focusCameraOnRemoteInput(targetPx, targetPy, showPulse) {
  if (zoomLevel <= 1.05 || !isMobileTouchOS()) return;
  var kbd = document.getElementById('vui-landscape-kbd');
  if (!kbd || !kbd.classList.contains('show')) return;
  var vp = document.getElementById('screen-viewport');
  var img = document.getElementById('screen-img');
  if (!vp || !img) return;

  var px = (typeof targetPx === 'number' && !isNaN(targetPx)) ? targetPx : lastKnownPx;
  var py = (typeof targetPy === 'number' && !isNaN(targetPy)) ? targetPy : lastKnownPy;

  var box = getRenderedImageBox(vp, img);
  var Wv = box.Wv;
  var Hv = box.Hv;

  var kbdH = (kbd && kbd.classList.contains('show')) ? (kbd.offsetHeight || 150) : 0;
  var desiredRemoteY = Math.max(36, Hv - kbdH - 28);

  var targetZ = preKbdCameraSaved ? (preKbdZoom || 1.0) : (zoomLevel || 1.0);
  var basePanX = preKbdCameraSaved ? (preKbdPanX || 0) : 0;
  var basePanY = preKbdCameraSaved ? (preKbdPanY || 0) : 0;

  var dx = (px - 0.5) * box.renderW;
  var dy = (py - 0.5) * box.renderH;
  var naturalY = (Hv / 2) + basePanY + dy * targetZ;

  var newPanX = basePanX;
  var newPanY = basePanY;

  if (naturalY > desiredRemoteY) {
    newPanY = desiredRemoteY - (Hv / 2) - dy * targetZ;
  }

  if (showPulse) {
    img.style.transition = 'transform 0.18s ease-out';
    setTimeout(function() { if (img) img.style.transition = 'none'; }, 200);
  }

  setZoomAndPan(targetZ, newPanX, newPanY);
  if (showPulse) {
    var localX = (Wv / 2) + panX + dx * zoomLevel;
    var localY = (Hv / 2) + panY + dy * zoomLevel;
    showTouchIndicatorAt(localX, localY, false);
    setTimeout(hideTouchIndicator, 600);
  }
}

var VN_VOWEL_TONES = {
  'a': ['a','á','à','ả','ã','ạ'], 'ă': ['ă','ắ','ằ','ẳ','ẵ','ặ'], 'â': ['â','ấ','ầ','ẩ','ẫ','ậ'],
  'e': ['e','é','è','ẻ','ẽ','ẹ'], 'ê': ['ê','ế','ề','ể','ễ','ệ'], 'i': ['i','í','ì','ỉ','ĩ','ị'],
  'o': ['o','ó','ò','ỏ','õ','ọ'], 'ô': ['ô','ố','ồ','ổ','ỗ','ộ'], 'ơ': ['ơ','ớ','ờ','ở','ỡ','ợ'],
  'u': ['u','ú','ù','ủ','ũ','ụ'], 'ư': ['ư','ứ','ừ','ử','ữ','ự'], 'y': ['y','ý','ỳ','ỷ','ỹ','ỵ'],
  'A': ['A','Á','À','Ả','Ã','Ạ'], 'Ă': ['Ă','Ắ','Ằ','Ẳ','Ẵ','Ặ'], 'Â': ['Â','Ấ','Ầ','Ẩ','Ẫ','Ậ'],
  'E': ['E','É','È','Ẻ','Ẽ','Ẹ'], 'Ê': ['Ê','Ế','Ề','Ể','Ễ','Ệ'], 'I': ['I','Í','Ì','Ỉ','Ĩ','Ị'],
  'O': ['O','Ó','Ò','Ỏ','Õ','Ọ'], 'Ô': ['Ô','Ố','Ồ','Ổ','Ỗ','Ộ'], 'Ơ': ['Ơ','Ớ','Ờ','Ở','Ỡ','Ợ'],
  'U': ['U','Ú','Ù','Ủ','Ũ','Ụ'], 'Ư': ['Ư','Ứ','Ừ','Ử','Ữ','Ự'], 'Y': ['Y','Ý','Ỳ','Ỷ','Ỹ','Ỵ']
};
var VN_CHAR_TO_BASE = {};
(function initVnLookup() {
  for (var base in VN_VOWEL_TONES) {
    var arr = VN_VOWEL_TONES[base];
    for (var t = 0; t < arr.length; t++) {
      VN_CHAR_TO_BASE[arr[t]] = { base: base, tone: t };
    }
  }
})();

function rebuildVnWordWithTone(chars, tone) {
  var vIndices = [];
  for (var i = 0; i < chars.length; i++) {
    var info = VN_CHAR_TO_BASE[chars[i]];
    if (info) {
      var lowPrev = (i > 0) ? chars[i - 1].toLowerCase() : '';
      var lowBase = info.base.toLowerCase();
      if (lowPrev === 'q' && lowBase === 'u' && i + 1 < chars.length && VN_CHAR_TO_BASE[chars[i + 1]]) continue;
      if (lowPrev === 'g' && lowBase === 'i' && i + 1 < chars.length && VN_CHAR_TO_BASE[chars[i + 1]]) continue;
      vIndices.push(i);
    }
  }
  if (vIndices.length === 0) {
    for (var j = 0; j < chars.length; j++) {
      if (VN_CHAR_TO_BASE[chars[j]]) vIndices.push(j);
    }
  }
  if (vIndices.length === 0) return chars.join('');

  var targetIdx = vIndices[0];
  if (vIndices.length >= 2) {
    var specialIdx = -1;
    for (var k = 0; k < vIndices.length; k++) {
      var b = VN_CHAR_TO_BASE[chars[vIndices[k]]].base.toLowerCase();
      if (b === 'ă' || b === 'â' || b === 'ê' || b === 'ô' || b === 'ơ') {
        specialIdx = vIndices[k];
        break;
      }
      if (b === 'ư' && specialIdx === -1) {
        specialIdx = vIndices[k];
      }
    }
    if (specialIdx !== -1) {
      targetIdx = specialIdx;
    } else if (vIndices.length === 3) {
      targetIdx = vIndices[1];
    } else {
      var lastV = vIndices[vIndices.length - 1];
      var hasTrailingConsonant = (lastV < chars.length - 1);
      var pair = (VN_CHAR_TO_BASE[chars[vIndices[0]]].base + VN_CHAR_TO_BASE[chars[vIndices[1]]].base).toLowerCase();
      if (hasTrailingConsonant || pair === 'oa' || pair === 'oe' || pair === 'uy') {
        targetIdx = vIndices[1];
      } else {
        targetIdx = vIndices[0];
      }
    }
  }

  for (var m = 0; m < chars.length; m++) {
    var inf = VN_CHAR_TO_BASE[chars[m]];
    if (inf) {
      chars[m] = VN_VOWEL_TONES[inf.base][m === targetIdx ? tone : 0];
    }
  }
  return chars.join('');
}

var remoteIsLocked = false;
var lastVkbdTouchTime = 0;
var vkbdBkspRepeatTimer = null;

function applyVietnameseTelex(fullText, key) {
  if (!vkbdTelex || remoteIsLocked || key.length !== 1) return fullText + key;
  var m = fullText.match(/^(.*?)([a-zA-ZàáảãạăắằẳẵặâấầẩẫậèéẻẽẹêếềểễệìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵđĐ]+)$/);
  if (!m) return fullText + key;
  var prefix = m[1];
  var word = m[2];
  var chars = word.split('');
  var lk = key.toLowerCase();

  var curTone = 0;
  for (var i = 0; i < chars.length; i++) {
    var inf = VN_CHAR_TO_BASE[chars[i]];
    if (inf && inf.tone > 0) {
      curTone = inf.tone;
      chars[i] = inf.base;
    }
  }

  var lastChar = chars[chars.length - 1];
  if (lk === 'd') {
    if (lastChar === 'd') { chars[chars.length - 1] = 'đ'; return prefix + rebuildVnWordWithTone(chars, curTone); }
    if (lastChar === 'D') { chars[chars.length - 1] = 'Đ'; return prefix + rebuildVnWordWithTone(chars, curTone); }
    if (lastChar === 'đ') { chars[chars.length - 1] = 'd'; return prefix + rebuildVnWordWithTone(chars, curTone) + key; }
    if (lastChar === 'Đ') { chars[chars.length - 1] = 'D'; return prefix + rebuildVnWordWithTone(chars, curTone) + key; }
  }

  if (lk === 'a' || lk === 'e' || lk === 'o') {
    for (var j = chars.length - 1; j >= 0; j--) {
      var b = chars[j];
      if (lk === 'a' && (b === 'a' || b === 'A')) { chars[j] = (b === 'A') ? 'Â' : 'â'; return prefix + rebuildVnWordWithTone(chars, curTone); }
      if (lk === 'e' && (b === 'e' || b === 'E')) { chars[j] = (b === 'E') ? 'Ê' : 'ê'; return prefix + rebuildVnWordWithTone(chars, curTone); }
      if (lk === 'o' && (b === 'o' || b === 'O')) { chars[j] = (b === 'O') ? 'Ô' : 'ô'; return prefix + rebuildVnWordWithTone(chars, curTone); }
    }
  }

  if (lk === 'w') {
    for (var u = 0; u < chars.length - 1; u++) {
      var c1 = chars[u].toLowerCase(), c2 = chars[u + 1].toLowerCase();
      if ((c1 === 'u' || c1 === 'ư') && (c2 === 'o' || c2 === 'ơ') && !(c1 === 'ư' && c2 === 'ơ')) {
        chars[u] = (chars[u] === 'U' || chars[u] === 'Ư') ? 'Ư' : 'ư';
        chars[u + 1] = (chars[u + 1] === 'O' || chars[u + 1] === 'Ơ') ? 'Ơ' : 'ơ';
        return prefix + rebuildVnWordWithTone(chars, curTone);
      }
    }
    for (var w = chars.length - 1; w >= 0; w--) {
      var cw = chars[w];
      if (cw === 'u' || cw === 'U') { chars[w] = (cw === 'U') ? 'Ư' : 'ư'; return prefix + rebuildVnWordWithTone(chars, curTone); }
      if (cw === 'o' || cw === 'O') { chars[w] = (cw === 'O') ? 'Ơ' : 'ơ'; return prefix + rebuildVnWordWithTone(chars, curTone); }
      if (cw === 'a' || cw === 'A') { chars[w] = (cw === 'A') ? 'Ă' : 'ă'; return prefix + rebuildVnWordWithTone(chars, curTone); }
    }
  }

  var toneMap = { 's': 1, 'f': 2, 'r': 3, 'x': 4, 'j': 5, 'z': 0 };
  if (typeof toneMap[lk] === 'number') {
    var hasVowel = false;
    for (var v = 0; v < chars.length; v++) {
      if (VN_CHAR_TO_BASE[chars[v]]) { hasVowel = true; break; }
    }
    if (hasVowel) {
      var newTone = toneMap[lk];
      if (lk === 'z') {
        if (curTone > 0) return prefix + rebuildVnWordWithTone(chars, 0);
      } else if (curTone === newTone) {
        return prefix + rebuildVnWordWithTone(chars, 0) + key;
      } else {
        return prefix + rebuildVnWordWithTone(chars, newTone);
      }
    }
  }

  return fullText + key;
}

function clearVkbdBkspRepeat() {
  if (vkbdBkspRepeatTimer) {
    clearInterval(vkbdBkspRepeatTimer);
    vkbdBkspRepeatTimer = null;
    cancelPendingKeyRepeats();
  }
}

function bindLandscapeKeyboardTouchEvents(kbd) {
  if (!kbd || kbd._touchBound) return;
  kbd._touchBound = true;
  kbd.addEventListener('touchstart', function(e) {
    var btn = e.target && e.target.closest ? e.target.closest('.vkbd-key') : null;
    if (!btn) return;
    var act = btn.getAttribute('data-vkbd-act');
    var ch = btn.getAttribute('data-vkbd-char');
    if (act === 'NATIVE') {
      // Không preventDefault trên nút NATIVE để trình duyệt di động (iOS Safari / Android Chrome) cho phép mở bàn phím gốc
      var inp = document.getElementById('quick-txt-input');
      if (inp) {
        inp.removeAttribute('readonly');
        inp.setAttribute('inputmode', 'text');
        try { inp.focus({ preventScroll: true }); } catch(err) { try { inp.focus(); } catch(err2) {} }
      }
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    lastVkbdTouchTime = Date.now();
    clearVkbdBkspRepeat();
    if (ch !== null && ch !== undefined) {
      onVkbdChar(ch, true);
    } else if (act === 'HIDE') {
      toggleQuickInputBar(false, false, true);
    } else if (act) {
      onVkbdAction(act, true, false);
      if (act === 'BKSP') {
        vkbdBkspRepeatTimer = setInterval(function() {
          lastVkbdTouchTime = Date.now();
          onVkbdAction('BKSP', true, true);
        }, 95);
      }
    }
  }, { passive: false });
  kbd.addEventListener('touchend', clearVkbdBkspRepeat, { passive: true });
  kbd.addEventListener('touchcancel', clearVkbdBkspRepeat, { passive: true });
}

function renderLandscapeKeyboard() {
  var kbd = document.getElementById('vui-landscape-kbd');
  if (!kbd) return;
  bindLandscapeKeyboardTouchEvents(kbd);
  var rows = vkbdSymbols ? [
    ['1','2','3','4','5','6','7','8','9','0'],
    ['@','#','$','%','&','-','+','(',')','/'],
    ['SYM','*','"',"'",':',';','!','?','BKSP'],
    ['ABC','TELEX','NATIVE','SPACE','.',',','ENTER','HIDE']
  ] : [
    ['q','w','e','r','t','y','u','i','o','p'],
    ['a','s','d','f','g','h','j','k','l'],
    ['SHIFT','z','x','c','v','b','n','m','BKSP'],
    ['123','TELEX','NATIVE','SPACE','.',',','ENTER','HIDE']
  ];

  var dragHdrTitle = isEN() ? '✥ Virtual Keyboard (Drag to move)' : '✥ Bàn phím ảo (Kéo để di chuyển)';
  var dockBtnText = isEN() ? '↺ Dock bottom' : '↺ Về đáy';
  var dragAria = isEN()
    ? 'Drag to move virtual keyboard, or use arrow keys'
    : 'Kéo để di chuyển bàn phím ảo, hoặc dùng phím mũi tên';
  var html = '<div class="vkbd-drag-header drag-handle" id="vkbd-drag-handle" tabindex="0" aria-label="' + dragAria + '">' +
    '<span>' + dragHdrTitle + '</span>' +
    '<button type="button" class="vkbd-dock-btn" onclick="event.stopPropagation(); resetVkbdPosition();">' + dockBtnText + '</button>' +
    '</div>';
  for (var r = 0; r < rows.length; r++) {
    html += '<div class="vkbd-row">';
    for (var c = 0; c < rows[r].length; c++) {
      var k = rows[r][c];
      if (k === 'SHIFT' || k === 'SYM') {
        var sAct = vkbdShift ? ' active' : '';
        html += '<button type="button" class="vkbd-key vkbd-fn' + sAct + '" data-vkbd-act="SHIFT" onclick="onVkbdAction(\'SHIFT\')">⇧</button>';
      } else if (k === 'BKSP') {
        html += '<button type="button" class="vkbd-key vkbd-fn" data-vkbd-act="BKSP" onclick="onVkbdAction(\'BKSP\')">⌫</button>';
      } else if (k === '123' || k === 'ABC') {
        html += '<button type="button" class="vkbd-key vkbd-fn" data-vkbd-act="MODE" onclick="onVkbdAction(\'MODE\')">' + (vkbdSymbols ? 'ABC' : '?123') + '</button>';
      } else if (k === 'TELEX') {
        var effTelex = vkbdTelex && !remoteIsLocked;
        var tAct = effTelex ? ' active' : '';
        var tLabel = remoteIsLocked ? '🔒 MẬT KHẨU' : (vkbdTelex ? '🇻🇳 TELEX' : '🇬🇧 ENG');
        html += '<button type="button" class="vkbd-key vkbd-fn' + tAct + '" data-vkbd-act="TELEX" onclick="onVkbdAction(\'TELEX\')" title="Đổi giữa gõ Tiếng Việt Telex và Tiếng Anh / Mật khẩu">' + tLabel + '</button>';
      } else if (k === 'NATIVE') {
        html += '<button type="button" class="vkbd-key vkbd-fn" style="flex:1.05;" data-vkbd-act="NATIVE" onclick="onVkbdAction(\'NATIVE\')" title="Mở bàn phím gốc của điện thoại / Giọng nói 🎙️">📱</button>';
      } else if (k === 'SPACE') {
        html += '<button type="button" class="vkbd-key vkbd-space" data-vkbd-char=" " onclick="onVkbdChar(\' \')">Dấu cách</button>';
      } else if (k === 'ENTER') {
        var entLbl = vkbdShift ? '⇧↵' : '↵';
        var entTitle = vkbdShift ? 'Xuống dòng (Shift+Enter)' : 'Bấm phím Enter ↵';
        html += '<button type="button" class="vkbd-key vkbd-enter" data-vkbd-act="ENTER" onclick="onVkbdAction(\'ENTER\')" title="' + entTitle + '">' + entLbl + '</button>';
      } else if (k === 'HIDE') {
        html += '<button type="button" class="vkbd-key vkbd-fn" style="flex:0.9;" data-vkbd-act="HIDE" onclick="toggleQuickInputBar(false, false, true)" title="Thu gọn bàn phím">▾</button>';
      } else {
        var disp = (!vkbdSymbols && vkbdShift) ? k.toUpperCase() : k;
        var safeCh = disp.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
        var attrCh = disp.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
        html += '<button type="button" class="vkbd-key" data-vkbd-char="' + attrCh + '" onclick="onVkbdChar(\'' + safeCh + '\')">' + disp + '</button>';
      }
    }
    html += '</div>';
  }
  kbd.innerHTML = html;
}

function onVkbdChar(ch, fromTouch) {
  if (!fromTouch && (Date.now() - lastVkbdTouchTime < 450)) return;
  recordActivity();
  if (navigator.vibrate) navigator.vibrate(8);
  var inp = document.getElementById('quick-txt-input');
  var rawVal = inp ? (inp.value || '').replace(/\u200B/g, '') : directSentText;
  var before = rawVal.normalize ? rawVal.normalize('NFC') : rawVal;
  var nextVal = applyVietnameseTelex(before, ch);
  if (nextVal.normalize) nextVal = nextVal.normalize('NFC');
  if (inp) {
    suppressQuickInputEvent = true;
    inp.value = DIRECT_SENTINEL + nextVal;
    suppressQuickInputEvent = false;
  }
  if (vkbdShift) {
    vkbdShift = false;
    renderLandscapeKeyboard();
  }
  onQuickInputChanged();
  if (ch === ' ' || ch === '.' || ch === ',' || ch === '/' || ch === ':' || ch === ';' || ch === '!' || ch === '?') {
    resetDirectBuffer();
  }
}

function onVkbdAction(act, fromTouch, isRepeat) {
  if (!fromTouch && act !== 'NATIVE' && (Date.now() - lastVkbdTouchTime < 450)) return;
  recordActivity();
  if (navigator.vibrate) navigator.vibrate(10);
  var inp = document.getElementById('quick-txt-input');
  if (act === 'SHIFT') {
    vkbdShift = !vkbdShift;
    renderLandscapeKeyboard();
  } else if (act === 'MODE') {
    vkbdSymbols = !vkbdSymbols;
    renderLandscapeKeyboard();
  } else if (act === 'TELEX') {
    if (remoteIsLocked) {
      flashStatus('🔒 Màn hình khóa đang tự động ở chế độ gõ Mật khẩu (ENG) nguyên bản', true);
      return;
    }
    vkbdTelex = !vkbdTelex;
    try { localStorage.setItem('vui_vkbd_telex', vkbdTelex ? '1' : '0'); } catch(e) {}
    renderLandscapeKeyboard();
    resetDirectBuffer();
    flashStatus(vkbdTelex ? '🇻🇳 Đã bật gõ Tiếng Việt Telex' : '🇬🇧 Đã chuyển sang gõ Tiếng Anh / Mật khẩu', true);
  } else if (act === 'NATIVE') {
    forceNativePhoneKbd = true;
    if (inp) {
      inp.removeAttribute('readonly');
      inp.setAttribute('inputmode', 'text');
      try { inp.focus({ preventScroll: true }); } catch(e) { try { inp.focus(); } catch(e2) {} }
    }
    hideLandscapeKeyboard();
    resetDirectBuffer();
    flashStatus('📱 Đã bật bàn phím gốc của thiết bị (Ô nhập ẩn)', true);
  } else if (act === 'BKSP') {
    var rawB = inp ? (inp.value || '').replace(/\u200B/g, '') : '';
    var charsB = Array.from(rawB.normalize ? rawB.normalize('NFC') : rawB);
    if (charsB.length > 0) {
      charsB.pop();
      var nextB = charsB.join('');
      if (inp) {
        suppressQuickInputEvent = true;
        inp.value = DIRECT_SENTINEL + nextB;
        suppressQuickInputEvent = false;
      }
      onQuickInputChanged();
    } else {
      resetDirectBuffer();
      enqueueDirectTextDelta(1, '', !!isRepeat);
    }
  } else if (act === 'ENTER') {
    resetDirectBuffer();
    if (vkbdShift) {
      vkbdShift = false;
      renderLandscapeKeyboard();
      enqueueDirectHotkey('shift+Return', 'Shift+Enter ↵');
      flashStatus('⌨️ Xuống dòng (Shift+Enter)', true);
    } else {
      enqueueDirectKey(66, 'Enter ↵');
    }
  }
}

function showLandscapeKeyboard() {
  var kbd = document.getElementById('vui-landscape-kbd');
  if (!kbd) return;
  renderLandscapeKeyboard();
  kbd.classList.add('show');
  setTimeout(clampNavClusterPosition, 20);
  positionSmartInputBar();
}

function hideLandscapeKeyboard() {
  var kbd = document.getElementById('vui-landscape-kbd');
  if (kbd) kbd.classList.remove('show');
  if (zoomLevel <= 1.05) {
    panX = 0;
    panY = 0;
    applyImageTransform();
  }
  positionSmartInputBar();
}

function positionSmartInputBar() {
  focusCameraOnRemoteInput(lastKnownPx, lastKnownPy, false);
}

function autoResizeQuickInput() {}
function applyInputMultilineUI() {}
function toggleInputMultiline() {}

function activateSmartKeyboardForOrientation() {
  var inp = document.getElementById('quick-txt-input');
  var effRot = getEffectiveRotation();
  var useBuiltinVkbd = (effRot !== 0 || !isMobileTouchOS()) && !forceNativePhoneKbd;
  if (useBuiltinVkbd) {
    if (inp) {
      inp.removeAttribute('readonly');
      inp.setAttribute('inputmode', 'none');
    }
    showLandscapeKeyboard();
  } else {
    hideLandscapeKeyboard();
    if (inp) {
      inp.removeAttribute('readonly');
      inp.setAttribute('inputmode', 'text');
      try { inp.focus({ preventScroll: true }); } catch(e) { try { inp.focus(); } catch(e2) {} }
    }
  }
}

function toggleQuickInputBar(forceState, fromIME, closedByUser) {
  var bar = document.getElementById('smart-input-bar');
  var btn = document.getElementById('btn-top-kbd');
  var inp = document.getElementById('quick-txt-input');
  if (!bar) return;

  var wasOpen = bar.classList.contains('show');
  var willShow;
  if (typeof forceState === 'boolean') {
    willShow = forceState;
  } else if (!wasOpen && (Date.now() - lastQuickInputBlurTime < 260)) {
    willShow = false;
  } else {
    willShow = !wasOpen;
  }

  if (willShow) {
    if (wasOpen) {
      updateClearBtnVisibility();
      return;
    }
    if (!preKbdCameraSaved) {
      preKbdCameraSaved = true;
      preKbdZoom = zoomLevel || 1.0;
      preKbdPanX = panX || 0;
      preKbdPanY = panY || 0;
    }
    forceNativePhoneKbd = false;
    imeOpenedByUser = true;
    resetDirectBuffer();
    bar.classList.add('show');
    if (btn) btn.classList.add('active-btn');
    checkCurrentSource();
    activateSmartKeyboardForOrientation();
    setTimeout(function() {
      focusCameraOnRemoteInput(lastKnownPx, lastKnownPy, true);
    }, 65);
  } else {
    imeOpenedByUser = false;
    forceNativePhoneKbd = false;
    hideLandscapeKeyboard();
    bar.classList.remove('show');
    if (btn) btn.classList.remove('active-btn');
    resetDirectBuffer();
    if (inp) {
      inp.setAttribute('inputmode', 'none');
      inp.blur();
    }
    if (preKbdCameraSaved) {
      preKbdCameraSaved = false;
      var img = document.getElementById('screen-img');
      if (img) {
        img.style.transition = 'transform 0.22s ease-out';
        setTimeout(function() { if (img) img.style.transition = 'none'; }, 240);
      }
      setZoomAndPan(preKbdZoom, preKbdPanX, preKbdPanY);
    }
  }
  updateClearBtnVisibility();
}

var navWasDragged = false;
var navLastDragEndTime = 0;
var topBarWasDragged = false;
var topBarLastDragEndTime = 0;

function wmAct(ev, fn) {
  if (ev) ev.stopPropagation();
  if (navWasDragged || (Date.now() - navLastDragEndTime < 180)) return;
  if (typeof fn === 'function') fn();
}

function toggleTopBarCollapse() {
  if (topBarWasDragged) return;
  var bar = document.getElementById('wm-top-bar');
  var btn = document.getElementById('wm-top-collapse-btn');
  if (!bar) return;
  var isCollapsed = bar.classList.toggle('collapsed');
  if (btn) btn.innerText = isCollapsed ? '+' : '−';
  try { localStorage.setItem('vui_wm_top_collapsed', isCollapsed ? '1' : '0'); } catch (e) {}
  setTimeout(clampNavClusterPosition, 30);
}

function toggleNavClusterCollapse() {
  if (navWasDragged) return;
  var cluster = document.getElementById('wm-nav-cluster');
  var btn = document.getElementById('wm-collapse-btn');
  var title = document.getElementById('wm-nav-title');
  if (!cluster) return;
  var isCollapsed = cluster.classList.toggle('collapsed');
  if (btn) btn.innerText = isCollapsed ? '+' : '−';
  if (title) title.innerText = isCollapsed ? (isEN() ? '🎮 Keys' : '🎮 Phím') : (isEN() ? 'Navigate' : 'Điều hướng');
  try { localStorage.setItem('vui_wm_collapsed', isCollapsed ? '1' : '0'); } catch (e) {}
  setTimeout(clampNavClusterPosition, 30);
}

function toggleConsoleDeck(forceState) {
  var cluster = document.getElementById('wm-nav-cluster');
  if (!cluster) return;
  if (cluster.classList.contains('collapsed')) {
    toggleNavClusterCollapse();
  }
}

function resetFloatingToolbarPos(elId, storageKey, toastMsg) {
  var el = document.getElementById(elId);
  if (!el) return;
  el.classList.remove('floating-pos');
  el.style.left = '';
  el.style.top = '';
  el.style.right = '';
  el.style.bottom = '';
  if (storageKey) {
    try { localStorage.removeItem(storageKey); } catch (e) {}
  }
  if (toastMsg) flashStatus(toastMsg, true);
}

function resetVkbdPosition() {
  resetFloatingToolbarPos(
    'vui-landscape-kbd',
    'vui_wm_kbd_pos_v1',
    isEN() ? '📌 Docked virtual keyboard to bottom' : '📌 Đã đưa bàn phím ảo về sát đáy màn hình'
  );
}

function applyClampedPos(el, vp, rawLeft, rawTop, storageKey) {
  if (!el || !vp) return;
  var Wv = vp.clientWidth || vp.offsetWidth || 360;
  var Hv = vp.clientHeight || vp.offsetHeight || 640;
  var ew = el.offsetWidth || 80;
  var eh = el.offsetHeight || 28;
  var maxL = Math.max(4, Wv - ew - 4);
  var maxT = Math.max(4, Hv - eh - 4);
  var clampedL = Math.max(4, Math.min(maxL, rawLeft));
  var clampedT = Math.max(4, Math.min(maxT, rawTop));
  el.style.left = clampedL.toFixed(1) + 'px';
  el.style.top = clampedT.toFixed(1) + 'px';
  el.style.right = 'auto';
  el.style.bottom = 'auto';
  if (storageKey && Wv > 0 && Hv > 0) {
    try {
      localStorage.setItem(storageKey, JSON.stringify({
        rx: clampedL / Wv,
        ry: clampedT / Hv
      }));
    } catch (e) {}
  }
}

function clampSingleFloatingElement(el, vp) {
  if (!el || !vp) return;
  if (!el.style.left || !el.style.top) return;
  var curL = parseFloat(el.style.left);
  var curT = parseFloat(el.style.top);
  if (isNaN(curL) || isNaN(curT)) return;
  var Wv = vp.clientWidth || vp.offsetWidth || 360;
  var Hv = vp.clientHeight || vp.offsetHeight || 640;
  var ew = el.offsetWidth || 80;
  var eh = el.offsetHeight || 28;
  if (ew <= 0 || eh <= 0) return;
  var clampedL = Math.max(4, Math.min(Math.max(4, Wv - ew - 4), curL));
  var clampedT = Math.max(4, Math.min(Math.max(4, Hv - eh - 4), curT));
  el.style.left = clampedL.toFixed(1) + 'px';
  el.style.top = clampedT.toFixed(1) + 'px';
  el.style.right = 'auto';
  el.style.bottom = 'auto';
}

function clampNavClusterPosition() {
  var vp = document.getElementById('screen-viewport');
  if (!vp) return;
  var ids = [
    'wm-top-bar',
    'wm-nav-cluster',
    'screen-watermark-source',
    'screen-watermark-rotate',
    'screen-watermark-zoom',
    'vui-landscape-kbd'
  ];
  for (var i = 0; i < ids.length; i++) {
    clampSingleFloatingElement(document.getElementById(ids[i]), vp);
  }
}

function bindFloatingDraggable(el, storageKey, opts) {
  var vp = document.getElementById('screen-viewport');
  if (!el || !vp || el._floatingDragBound) return;
  el._floatingDragBound = true;
  opts = opts || {};

  // Restore saved position (if any)
  if (storageKey) {
    try {
      var savedPos = JSON.parse(localStorage.getItem(storageKey) || 'null');
      if (savedPos && typeof savedPos.rx === 'number' && typeof savedPos.ry === 'number') {
        setTimeout(function() {
          if (opts.floatingClass) el.classList.add(opts.floatingClass);
          var Wv = vp.clientWidth || vp.offsetWidth || 360;
          var Hv = vp.clientHeight || vp.offsetHeight || 640;
          var ew = el.offsetWidth || 80;
          var eh = el.offsetHeight || 28;
          var l = Math.max(4, Math.min(Math.max(4, Wv - ew - 4), savedPos.rx * Wv));
          var t = Math.max(4, Math.min(Math.max(4, Hv - eh - 4), savedPos.ry * Hv));
          el.style.left = l.toFixed(1) + 'px';
          el.style.top = t.toFixed(1) + 'px';
          el.style.right = 'auto';
          el.style.bottom = 'auto';
        }, 80);
      }
    } catch (e) {}
  }

  var dragging = false;
  var wasDragged = false;
  var lastDragEndTime = 0;
  var startClientX = 0, startClientY = 0;
  var startLeft = 0, startTop = 0;
  var lastGripTapTime = 0;

  function clientDeltaToViewport(dx, dy) {
    var effRot = getEffectiveRotation();
    if (effRot === 90) return { x: dy, y: -dx };
    if (effRot === 270) return { x: -dy, y: dx };
    return { x: dx, y: dy };
  }

  function canStartFromTarget(target) {
    if (!target) return false;
    if (opts.ignoreSelector && target.closest && target.closest(opts.ignoreSelector)) return false;
    if (opts.handleSelector) {
      return !!(target.closest && target.closest(opts.handleSelector));
    }
    return true;
  }

  function onStart(e) {
    if (!canStartFromTarget(e.target)) return;
    e.stopPropagation();
    if (e.touches && e.touches.length > 1) return;
    var pt = e.touches ? e.touches[0] : e;
    dragging = true;
    wasDragged = false;
    if (opts.onDragStateChange) opts.onDragStateChange(false, lastDragEndTime);
    startClientX = pt.clientX;
    startClientY = pt.clientY;
    startLeft = el.offsetLeft;
    startTop = el.offsetTop;
  }

  function onMove(e) {
    if (!dragging) return;
    e.stopPropagation();
    var pt = e.touches ? e.touches[0] : e;
    var rawDx = pt.clientX - startClientX;
    var rawDy = pt.clientY - startClientY;
    if (!wasDragged && Math.hypot(rawDx, rawDy) > 6) {
      wasDragged = true;
      if (opts.floatingClass && !el.classList.contains(opts.floatingClass)) {
        var oldW = el.offsetWidth;
        var oldL = el.offsetLeft;
        var oldT = el.offsetTop;
        el.classList.add(opts.floatingClass);
        var newW = el.offsetWidth;
        startLeft = oldL + Math.max(0, (oldW - newW) / 2);
        startTop = oldT;
      }
      el.classList.add('dragging');
      if (opts.onDragStateChange) opts.onDragStateChange(true, lastDragEndTime);
      if (navigator.vibrate) navigator.vibrate(10);
    }
    if (wasDragged) {
      if (e.cancelable) e.preventDefault();
      var d = clientDeltaToViewport(rawDx, rawDy);
      applyClampedPos(el, vp, startLeft + d.x, startTop + d.y, null);
    }
  }

  function onEnd(e) {
    if (!dragging) return;
    if (e && e.stopPropagation) e.stopPropagation();
    dragging = false;
    el.classList.remove('dragging');
    if (wasDragged) {
      lastDragEndTime = Date.now();
      if (opts.onDragStateChange) opts.onDragStateChange(true, lastDragEndTime);
      applyClampedPos(el, vp, el.offsetLeft, el.offsetTop, storageKey);
      setTimeout(function() {
        wasDragged = false;
        if (opts.onDragStateChange) opts.onDragStateChange(false, lastDragEndTime);
      }, 0);
    } else if (opts.resetGripSelector && e && e.target && e.target.closest && e.target.closest(opts.resetGripSelector)) {
      var now = Date.now();
      if (now - lastGripTapTime < 320) {
        lastGripTapTime = 0;
        resetFloatingToolbarPos(
          el.id,
          storageKey,
          isEN() ? '📌 Reset toolbar to default position' : '📌 Đã đưa thanh công cụ về vị trí mặc định'
        );
      } else {
        lastGripTapTime = now;
      }
    }
  }

  // Capture-phase click listener suppresses accidental child button clicks right after a drag
  el.addEventListener('click', function(e) {
    if (wasDragged) {
      wasDragged = false;
      if (opts.onDragStateChange) opts.onDragStateChange(false, 0);
      e.preventDefault();
      e.stopPropagation();
      if (e.stopImmediatePropagation) e.stopImmediatePropagation();
    }
  }, true);

  // Bubble-phase click listener prevents clicks on toolbar buttons from bubbling to #screen-viewport
  el.addEventListener('click', function(e) {
    e.stopPropagation();
  }, false);

  el.addEventListener('touchstart', onStart, { passive: true });
  el.addEventListener('touchmove', onMove, { passive: false });
  el.addEventListener('touchend', onEnd, { passive: true });
  el.addEventListener('touchcancel', onEnd, { passive: true });

  el.addEventListener('mousedown', function(e) {
    if (e.button !== 0) return;
    if (!canStartFromTarget(e.target)) return;
    e.stopPropagation();
    if (Date.now() - lastRealTouchTime < 1000) return;
    onStart(e);
  });
  window.addEventListener('mousemove', function(e) {
    if (Date.now() - lastRealTouchTime < 1000 || !dragging) return;
    onMove(e);
  });
  window.addEventListener('mouseup', function(e) {
    if (Date.now() - lastRealTouchTime < 1000 || !dragging) return;
    onEnd(e);
  });

  // Accessible keyboard arrow-key movement (15px per step, clamped to viewport)
  var KEY_DELTAS = {
    ArrowLeft: [-15, 0],
    ArrowRight: [15, 0],
    ArrowUp: [0, -15],
    ArrowDown: [0, 15]
  };
  el.addEventListener('keydown', function(e) {
    var delta = KEY_DELTAS[e.key];
    if (!delta) return;
    var t = e.target;
    if (!t || (!t.classList.contains('drag-handle') && t !== el)) return;
    e.preventDefault();
    e.stopPropagation();
    if (opts.floatingClass && !el.classList.contains(opts.floatingClass)) {
      var oldW = el.offsetWidth;
      var oldL = el.offsetLeft;
      var oldT = el.offsetTop;
      el.classList.add(opts.floatingClass);
      var newW = el.offsetWidth;
      applyClampedPos(el, vp, oldL + Math.max(0, (oldW - newW) / 2) + delta[0], oldT + delta[1], storageKey);
      return;
    }
    applyClampedPos(el, vp, el.offsetLeft + delta[0], el.offsetTop + delta[1], storageKey);
  });
}

function initNavClusterDrag() {
  var topBar = document.getElementById('wm-top-bar');
  if (topBar && localStorage.getItem('vui_wm_top_collapsed') === '1') {
    topBar.classList.add('collapsed');
    var topColBtn = document.getElementById('wm-top-collapse-btn');
    if (topColBtn) topColBtn.innerText = '+';
  }

  var cluster = document.getElementById('wm-nav-cluster');
  if (cluster && localStorage.getItem('vui_wm_collapsed') === '1') {
    cluster.classList.add('collapsed');
    var btn = document.getElementById('wm-collapse-btn');
    var title = document.getElementById('wm-nav-title');
    if (btn) btn.innerText = '+';
    if (title) title.innerText = isEN() ? '🎮 Keys' : '🎮 Phím';
  }

  bindFloatingDraggable(topBar, 'vui_wm_top_pos_v1', {
    resetGripSelector: '#wm-top-drag-handle',
    onDragStateChange: function(dragged, endTime) {
      topBarWasDragged = dragged;
      topBarLastDragEndTime = endTime;
    }
  });

  bindFloatingDraggable(cluster, 'vui_wm_nav_pos_v2', {
    resetGripSelector: '#wm-drag-header',
    onDragStateChange: function(dragged, endTime) {
      navWasDragged = dragged;
      navLastDragEndTime = endTime;
    }
  });

  bindFloatingDraggable(document.getElementById('screen-watermark-source'), 'vui_wm_src_pos_v1', {});
  bindFloatingDraggable(document.getElementById('screen-watermark-rotate'), 'vui_wm_rot_pos_v1', {});
  bindFloatingDraggable(document.getElementById('screen-watermark-zoom'), 'vui_wm_zoom_pos_v1', {});
  bindFloatingDraggable(document.getElementById('vui-landscape-kbd'), 'vui_wm_kbd_pos_v1', {
    handleSelector: '#vkbd-drag-handle',
    ignoreSelector: '.vkbd-dock-btn',
    floatingClass: 'floating-pos',
    resetGripSelector: '#vkbd-drag-handle'
  });
}

function androidKey(code, name) {
  recordActivity();
  if (navigator.vibrate) navigator.vibrate(20);
  key(code, name);
}

function attachKeyRepeat(el, code, name, isCmd, customDelay, customInterval) {
  if (!el || el._repeatBound) return;
  el._repeatBound = true;
  var pressTimer = null;
  var repeatTimer = null;
  var isHolding = false;
  var wasRepeating = false;
  var lastTriggerMs = 0;
  // Chuẩn bàn phím thông thường: giữ đủ 550ms mới bắt đầu lặp, chu kỳ lặp 200ms
  var initialDelay = customDelay || 550;
  var repeatInterval = customInterval || 200;

  var stopAll = function(ev) {
    if (ev) {
      if (ev.type && ev.type.indexOf('touch') === 0) {
        lastRealTouchTime = Date.now();
        if (ev.cancelable) ev.preventDefault();
      }
      ev.stopPropagation();
    }
    var needCancel = isHolding && wasRepeating;
    isHolding = false;
    wasRepeating = false;
    if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; }
    if (repeatTimer) { clearInterval(repeatTimer); repeatTimer = null; }
    el.classList.remove('holding');
    if (needCancel) {
      cancelPendingKeyRepeats();
    }
  };

  var onDown = function(ev) {
    var now = Date.now();
    if (ev && ev.type === 'mousedown') {
      if (now - lastRealTouchTime < 1000) return;
      if (ev.button !== undefined && ev.button !== 0) return;
    }
    if (ev && ev.type === 'touchstart') {
      lastRealTouchTime = now;
    }
    if (navWasDragged || (now - navLastDragEndTime < 180)) return;
    if (now - lastTriggerMs < 110) return;
    lastTriggerMs = now;

    if (ev) {
      if (ev.cancelable) ev.preventDefault();
      ev.stopPropagation();
    }
    stopAll();
    isHolding = true;
    wasRepeating = false;
    el.classList.add('holding');

    if (isCmd) {
      cmd(code, name);
    } else {
      androidKey(code, name);
    }

    // Chỉ khi nhấn giữ liên tục quá 550ms mới bắt đầu lặp lại
    pressTimer = setTimeout(function() {
      if (!isHolding) return;
      wasRepeating = true;
      repeatTimer = setInterval(function() {
        if (!isHolding) {
          stopAll();
          return;
        }
        if (isCmd) {
          cmd(code, name);
        } else {
          enqueueDirectKey(code, name, true);
        }
        if (navigator.vibrate) navigator.vibrate(8);
      }, repeatInterval);
    }, initialDelay);
  };

  el.addEventListener('touchstart', onDown, { passive: false });
  el.addEventListener('touchend', stopAll, { passive: false });
  el.addEventListener('touchcancel', stopAll, { passive: false });
  el.addEventListener('mousedown', onDown);
  el.addEventListener('mouseup', stopAll);
  el.addEventListener('mouseleave', stopAll);
  el.addEventListener('click', function(ev) {
    if (ev.cancelable) ev.preventDefault();
    ev.stopPropagation();
    return false;
  }, { passive: false });
  el.addEventListener('contextmenu', function(ev) { if (ev.cancelable) ev.preventDefault(); return false; });
}

function attachMenuRecent(el) {
  if (!el || el._repeatBound) return;
  el._repeatBound = true;
  var holdTimer = null;
  var isTriggeredRecent = false;
  var isHolding = false;
  var lastDownMs = 0;

  var stopMenu = function(ev) {
    if (ev && ev.type === 'mouseup' && (Date.now() - lastRealTouchTime < 1000)) {
      return;
    }
    if (ev) {
      if (ev.type && ev.type.indexOf('touch') === 0) {
        lastRealTouchTime = Date.now();
      }
      if (ev.cancelable) ev.preventDefault();
      ev.stopPropagation();
    }
    if (holdTimer) {
      clearTimeout(holdTimer);
      holdTimer = null;
    }
    el.classList.remove('holding');
    // Nếu nhả tay TRƯỚC KHI đạt 480ms -> coi như là bấm Menu (keycode 82)
    if (isHolding && !isTriggeredRecent) {
      androidKey(82, 'Menu');
    }
    isHolding = false;
    isTriggeredRecent = false;
  };

  var onDown = function(ev) {
    var now = Date.now();
    if (ev && ev.type === 'mousedown') {
      if (now - lastRealTouchTime < 1000) return;
      if (ev.button !== undefined && ev.button !== 0) return;
    }
    if (ev && ev.type === 'touchstart') {
      lastRealTouchTime = now;
    }
    if (navWasDragged || (now - navLastDragEndTime < 180)) return;
    if (now - lastDownMs < 110) return;
    lastDownMs = now;

    if (ev) {
      if (ev.cancelable) ev.preventDefault();
      ev.stopPropagation();
    }
    if (holdTimer) { clearTimeout(holdTimer); holdTimer = null; }
    isHolding = true;
    isTriggeredRecent = false;
    el.classList.add('holding');

    // Bấm giữ >= 480ms -> kích hoạt Đa nhiệm (Recent Apps, keycode 187)
    holdTimer = setTimeout(function() {
      if (!isHolding) return;
      isTriggeredRecent = true;
      if (navigator.vibrate) navigator.vibrate([40, 50, 40]);
      androidKey(187, 'Đa nhiệm (Recent)');
      flashStatus('❐ Đã mở Đa nhiệm', true);
      el.classList.add('active-recent');
      setTimeout(function() { el.classList.remove('active-recent'); }, 300);
    }, 480);
  };

  el.addEventListener('touchstart', onDown, { passive: false });
  el.addEventListener('touchend', stopMenu, { passive: false });
  el.addEventListener('touchcancel', stopMenu, { passive: false });
  el.addEventListener('mousedown', onDown);
  el.addEventListener('mouseup', stopMenu);
  el.addEventListener('mouseleave', stopMenu);
  el.addEventListener('click', function(ev) {
    if (ev.cancelable) ev.preventDefault();
    ev.stopPropagation();
    return false;
  }, { passive: false });
  el.addEventListener('contextmenu', function(ev) { if (ev.cancelable) ev.preventDefault(); return false; });
}

function initAllKeyRepeats() {
  // Cụm điều hướng 4 chiều: giữ 550ms mới bắt đầu lặp, chu kỳ lặp 200ms
  attachKeyRepeat(document.getElementById('nav-btn-up'), 19, 'Lên', false, 550, 200);
  attachKeyRepeat(document.getElementById('nav-btn-down'), 20, 'Xuống', false, 550, 200);
  attachKeyRepeat(document.getElementById('nav-btn-left'), 21, 'Trái', false, 550, 200);
  attachKeyRepeat(document.getElementById('nav-btn-right'), 22, 'Phải', false, 550, 200);
  
  // Nút OK: bấm là chọn 1 lần, giữ 600ms lặp 260ms
  attachKeyRepeat(document.getElementById('nav-btn-ok'), 23, 'OK', false, 600, 260);

  // Xung quanh cụm điều hướng:
  // Âm lượng (+, -): giữ 500ms mới lặp, chu kỳ 160ms
  attachKeyRepeat(document.getElementById('nav-btn-volup'), 24, 'Tăng âm', false, 500, 160);
  attachKeyRepeat(document.getElementById('nav-btn-voldown'), 25, 'Giảm âm', false, 500, 160);
  // Xóa ký tự: giữ 500ms mới lặp, chu kỳ 140ms
  attachKeyRepeat(document.getElementById('nav-btn-del'), 67, 'Xóa ký tự', false, 500, 140);

  // Hàng 3 nút dưới cụm điều hướng:
  // Nút Lùi: giữ 600ms mới lặp, chu kỳ 260ms (tránh lùi quá nhanh thoát khỏi app)
  attachKeyRepeat(document.getElementById('nav-btn-back'), 4, 'Quay lại', false, 600, 260);
  // Nút Menu: bấm là Menu, giữ là Đa nhiệm
  attachMenuRecent(document.getElementById('nav-btn-menu'));

  // Lấy nét máy chiếu (nếu có):
  attachKeyRepeat(document.getElementById('proj-btn-focusdown'), 'focus_down', 'Lấy nét -', true, 480, 160);
  attachKeyRepeat(document.getElementById('proj-btn-focusup'), 'focus_up', 'Lấy nét +', true, 480, 160);
}

function promptQuickText() {
  toggleQuickInputBar(true);
}

// SMARTPHONE TOUCH, ZOOM, PAN & GESTURE ENGINE (WITH UNIFIED ROTATED COORDINATES)
var zoomLevel = 1.0;
var panX = 0;
var panY = 0;
var isPanMode = false;

// Pinch state (2-finger zoom & pan)
var isPinching = false;
var pinchStartDist = 0;
var pinchStartZoom = 1.0;
var pinchStartMidX = 0, pinchStartMidY = 0;
var pinchStartPanX = 0, pinchStartPanY = 0;

// Pan state for 1-finger pan mode
var panTouchStartX = 0, panTouchStartY = 0;
var panStartPanX = 0, panStartPanY = 0;

// Touch & tap tracking
var touchStartX = 0, touchStartY = 0;
var touchStartTime = 0;
var touchMoved = false;
var longPressTimer = null;
var isLongPressTriggered = false;
var touchActive = false;
var singleTapTimer = null;
var lastTapTimestamp = 0;
var lastTapCoords = null;

function clampPan(z, px, py, Wv, Hv) {
  if (z <= 1.0) return { panX: 0, panY: 0 };
  var obscured = (typeof getKeyboardObscuredBottom === 'function') ? getKeyboardObscuredBottom() : 0;
  var maxPanX = Math.max(0, (Wv * (z - 1.0)) / 2);
  var basePanY = Math.max(0, (Hv * (z - 1.0)) / 2);
  var minPanY = -basePanY - (obscured > 0 ? Math.max(obscured + 48, Hv * 0.85) : 0);
  var maxPanY = basePanY + (obscured > 0 ? 48 : 0);
  return {
    panX: Math.max(-maxPanX, Math.min(maxPanX, px)),
    panY: Math.max(minPanY, Math.min(maxPanY, py))
  };
}

function getRenderedImageBox(vp, img) {
  var Wv = vp.clientWidth || vp.offsetWidth || 360;
  var Hv = vp.clientHeight || vp.offsetHeight || 640;
  var natW = (img && img.naturalWidth > 16) ? img.naturalWidth : 2560;
  var natH = (img && img.naturalHeight > 16) ? img.naturalHeight : 1440;
  var imgAspect = natW / natH;
  var vpAspect = Wv / Hv;
  var renderW = Wv, renderH = Hv;
  if (vpAspect > imgAspect) {
    renderH = Hv;
    renderW = Hv * imgAspect;
  } else {
    renderW = Wv;
    renderH = Wv / imgAspect;
  }
  return { Wv: Wv, Hv: Hv, renderW: renderW, renderH: renderH };
}

function applyImageTransform() {
  var img = document.getElementById('screen-img');
  if (!img) return;
  img.style.position = '';
  img.style.left = '';
  img.style.top = '';
  img.style.width = '100%';
  img.style.height = '100%';
  img.style.transformOrigin = 'center center';
  img.style.objectFit = 'contain';

  if (zoomLevel <= 1.0 && Math.abs(panX) < 0.5 && Math.abs(panY) < 0.5) {
    img.style.transform = 'none';
    isPanMode = false;
  } else {
    img.style.transform = 'translate(' + panX.toFixed(1) + 'px, ' + panY.toFixed(1) + 'px) scale(' + zoomLevel.toFixed(2) + ')';
  }
}

window.addEventListener('resize', function() {
  syncViewportSize();
  applyImageTransform();
  positionSmartInputBar();
  setTimeout(clampNavClusterPosition, 40);
});
window.addEventListener('orientationchange', function() {
  setTimeout(function() {
    syncViewportSize();
    applyImageTransform();
    positionSmartInputBar();
    clampNavClusterPosition();
  }, 100);
});
if (window.visualViewport) {
  window.visualViewport.addEventListener('resize', function() {
    syncViewportSize();
    applyImageTransform();
    positionSmartInputBar();
    clampNavClusterPosition();
  });
  window.visualViewport.addEventListener('scroll', function() {
    syncViewportSize();
    positionSmartInputBar();
  });
}

var MAX_ZOOM_LEVEL = 10.0;
var zoomHiResRefreshTimer = null;

function setZoomAndPan(newZoom, newPanX, newPanY) {
  var vp = document.getElementById('screen-viewport');
  var img = document.getElementById('screen-img');
  if (!vp || !img) return;
  
  var prevZoom = zoomLevel;
  var box = getRenderedImageBox(vp, img);
  zoomLevel = Math.max(1.0, Math.min(MAX_ZOOM_LEVEL, Math.round(newZoom * 100) / 100));
  var clamped = clampPan(zoomLevel, newPanX, newPanY, box.renderW, box.renderH);
  panX = clamped.panX;
  panY = clamped.panY;
  
  applyImageTransform();
  updateZoomUI();

  if (zoomLevel > 1.05 && (prevZoom <= 1.05 || (img.naturalWidth > 0 && img.naturalWidth < 2200))) {
    if (zoomHiResRefreshTimer) clearTimeout(zoomHiResRefreshTimer);
    zoomHiResRefreshTimer = setTimeout(function() {
      zoomHiResRefreshTimer = null;
      if (!isSleeping) refreshScreen(false);
    }, 80);
  }
}

function updateZoomUI() {
  var wmText = document.getElementById('wm-zoom-text');
  var wmPill = document.getElementById('screen-watermark-zoom');
  var wmReset = document.getElementById('wm-zoom-reset');
  
  if (wmText && wmPill) {
    if (zoomLevel > 1.0) {
      wmPill.classList.add('zoomed');
      wmText.innerText = zoomLevel.toFixed(1) + 'x';
      if (wmReset) wmReset.style.display = 'inline-block';
    } else {
      wmPill.classList.remove('zoomed');
      wmText.innerText = '1.0x';
      if (wmReset) wmReset.style.display = 'none';
    }
  }
}

function zoomIn() {
  var nextZoom = zoomLevel < 1.6 ? 1.6 : (zoomLevel < 2.5 ? 2.5 : (zoomLevel < 4.0 ? 4.0 : (zoomLevel < 6.0 ? 6.0 : (zoomLevel < 8.0 ? 8.0 : MAX_ZOOM_LEVEL))));
  zoomToPoint(lastKnownPx, lastKnownPy, nextZoom);
  flashStatus('🔍 Phóng to ' + zoomLevel.toFixed(1) + 'x (Tối đa 10x • Độ phân giải 2K)', true);
}

function zoomOut() {
  var prevZoom = zoomLevel > 8.0 ? 8.0 : (zoomLevel > 6.0 ? 6.0 : (zoomLevel > 4.0 ? 4.0 : (zoomLevel > 2.5 ? 2.5 : (zoomLevel > 1.6 ? 1.6 : 1.0))));
  var img = document.getElementById('screen-img');
  if (img) {
    img.style.transition = 'transform 0.2s ease-out';
    setTimeout(function() { img.style.transition = 'none'; }, 220);
  }
  setZoomAndPan(prevZoom, panX, panY);
  flashStatus('🔍 Thu nhỏ ' + zoomLevel.toFixed(1) + 'x', true);
  if (zoomLevel <= 1.0 && !isSleeping) refreshScreen(false);
}

function resetZoom() {
  var img = document.getElementById('screen-img');
  if (img) {
    img.style.transition = 'transform 0.2s ease-out';
    setTimeout(function() { img.style.transition = 'none'; }, 220);
  }
  setZoomAndPan(1.0, 0, 0);
  isPanMode = false;
  flashStatus('🔍 Kích thước chuẩn 1x', true);
  if (!isSleeping) refreshScreen(false);
}

function cycleZoomDock() {
  if (zoomLevel <= 1.0) {
    zoomToPoint(lastKnownPx, lastKnownPy, 2.0);
    flashStatus('🔍 Phóng to 2.0x (Chạm 1 ngón đúng điểm, 2 ngón kéo khung hình)', true);
  } else if (zoomLevel < 3.2) {
    zoomToPoint(lastKnownPx, lastKnownPy, 3.8);
    flashStatus('🔍 Phóng to 3.8x (Độ phân giải gốc 2K)', true);
  } else if (zoomLevel < 5.5) {
    zoomToPoint(lastKnownPx, lastKnownPy, 6.5);
    flashStatus('🔍 Phóng to 6.5x (Siêu cận cảnh)', true);
  } else if (zoomLevel < 8.5) {
    zoomToPoint(lastKnownPx, lastKnownPy, 10.0);
    flashStatus('🔍 Phóng to cực đại 10.0x', true);
  } else {
    resetZoom();
  }
}

function zoomToPoint(targetPx, targetPy, targetScale) {
  var vp = document.getElementById('screen-viewport');
  var img = document.getElementById('screen-img');
  if (!vp) return;
  var box = getRenderedImageBox(vp, img);
  
  var newZoom = Math.max(1.0, Math.min(MAX_ZOOM_LEVEL, targetScale || 2.0));
  var dx = (targetPx - 0.5) * box.renderW;
  var dy = (targetPy - 0.5) * box.renderH;
  
  var newPanX = -dx * newZoom;
  var newPanY = -dy * newZoom;
  
  if (img) {
    img.style.transition = 'transform 0.22s ease-out';
    setTimeout(function() { img.style.transition = 'none'; }, 240);
  }
  
  setZoomAndPan(newZoom, newPanX, newPanY);
  if (newZoom > 1.05 && !isSleeping) refreshScreen(false);
}

function getActiveCssRotation() {
  var root = document.getElementById('app-root');
  if (root) {
    if (root.classList.contains('rot-90')) return 90;
    if (root.classList.contains('rot-270')) return 270;
    if (root.classList.contains('rot-0')) return 0;
  }
  return getEffectiveRotation();
}

function getNormalizedCoords(clientX, clientY) {
  var vp = document.getElementById('screen-viewport');
  var img = document.getElementById('screen-img');
  if (!vp || !img) return null;
  
  var rect = vp.getBoundingClientRect();
  if (!rect || rect.width <= 0 || rect.height <= 0) return null;
  
  var box = getRenderedImageBox(vp, img);
  var Wv = box.Wv;
  var Hv = box.Hv;
  var renderW = box.renderW;
  var renderH = box.renderH;

  var cx = rect.left + rect.width / 2;
  var cy = rect.top + rect.height / 2;
  var dx = clientX - cx;
  var dy = clientY - cy;

  var effRot = getActiveCssRotation();
  var u, v;
  if (effRot === 90) {
    var scaleU90 = (rect.height > 0) ? (Wv / rect.height) : 1;
    var scaleV90 = (rect.width > 0) ? (Hv / rect.width) : 1;
    u = dy * scaleU90;
    v = -dx * scaleV90;
  } else if (effRot === 270) {
    var scaleU270 = (rect.height > 0) ? (Wv / rect.height) : 1;
    var scaleV270 = (rect.width > 0) ? (Hv / rect.width) : 1;
    u = -dy * scaleU270;
    v = dx * scaleV270;
  } else if (effRot === 180) {
    var scaleU180 = (rect.width > 0) ? (Wv / rect.width) : 1;
    var scaleV180 = (rect.height > 0) ? (Hv / rect.height) : 1;
    u = -dx * scaleU180;
    v = -dy * scaleV180;
  } else {
    var scaleU0 = (rect.width > 0) ? (Wv / rect.width) : 1;
    var scaleV0 = (rect.height > 0) ? (Hv / rect.height) : 1;
    u = dx * scaleU0;
    v = dy * scaleV0;
  }

  // Tọa độ hiển thị vòng tròn chạm (#touch-indicator) trong không gian cục bộ của #screen-viewport (đã xoay cùng #app-root)
  var localX = Wv / 2 + u;
  var localY = Hv / 2 + v;

  var z = zoomLevel || 1.0;
  var pX = panX || 0;
  var pY = panY || 0;

  // Tọa độ điều khiển (px, py) được ánh xạ ngược chính xác qua cả góc xoay hình, phép dịch chuyển (panX, panY) và tỷ lệ phóng to (z)
  var px = 0.5 + (u - pX) / (z * renderW);
  var py = 0.5 + (v - pY) / (z * renderH);

  px = Math.max(0, Math.min(1, px));
  py = Math.max(0, Math.min(1, py));

  return {
    px: px,
    py: py,
    localX: localX,
    localY: localY,
    Wv: Wv,
    Hv: Hv,
    renderW: renderW,
    renderH: renderH
  };
}

function showTouchIndicatorAt(localX, localY, holding) {
  var ind = document.getElementById('touch-indicator');
  if (!ind) return;
  ind.style.left = localX.toFixed(1) + 'px';
  ind.style.top = localY.toFixed(1) + 'px';
  ind.classList.add('active');
  if (holding) {
    ind.classList.add('holding');
  } else {
    ind.classList.remove('holding');
  }
}

function hideTouchIndicator() {
  var ind = document.getElementById('touch-indicator');
  if (!ind) return;
  ind.classList.remove('active', 'holding');
}

// PC & Multi-Touch Gesture State
var pcTouchMode = localStorage.getItem('vui_pc_touch_mode') || 'scroll'; // 'scroll' (Cảm ứng chuẩn) | 'drag' | 'trackpad'
var pcDragLocked = false;
var lastKnownPx = 0.5, lastKnownPy = 0.5;
var lastMovePx = 0.5, lastMovePy = 0.5;
var isDragging = false;
var isMouseClickDrag = false;
var lastDragMoveSent = 0;

// 60Hz Coalesced Pointer Sender (prevents XHR pileup while delivering smooth 60fps mouse movement)
var pointerMoveInFlight = false;
var pendingPointerMove = null;
var pointerMoveLastSentMs = 0;
var pointerMoveTimer = null;

function flushCoalescedPointer() {
  if (pointerMoveTimer) {
    clearTimeout(pointerMoveTimer);
    pointerMoveTimer = null;
  }
  if (pointerMoveInFlight || !pendingPointerMove) return;
  var ev = pendingPointerMove;
  pendingPointerMove = null;
  pointerMoveInFlight = true;
  pointerMoveLastSentMs = Date.now();

  var xhr = new XMLHttpRequest();
  var url = '';
  if (ev.kind === 'rel') {
    url = '/api/mouse?dx=' + ev.dx + '&dy=' + ev.dy + getDevParam() + '&t=' + pointerMoveLastSentMs;
  } else {
    url = '/api/touch?type=' + ev.kind + '&px=' + ev.px.toFixed(4) + '&py=' + ev.py.toFixed(4) + getDevParam() + '&t=' + pointerMoveLastSentMs;
  }
  xhr.open('GET', url, true);
  xhr.timeout = 1200;
  var done = function() {
    pointerMoveInFlight = false;
    if (pendingPointerMove) {
      var elapsed = Date.now() - pointerMoveLastSentMs;
      if (elapsed >= 14) {
        flushCoalescedPointer();
      } else if (!pointerMoveTimer) {
        pointerMoveTimer = setTimeout(flushCoalescedPointer, 14 - elapsed);
      }
    }
  };
  xhr.onload = done;
  xhr.onerror = done;
  xhr.ontimeout = done;
  xhr.send();
  if (ev.kind !== 'hover' || (pointerMoveLastSentMs - lastInteractiveBoostTime > 90)) {
    triggerInteractiveCapture();
  }
}

function sendCoalescedPointer(kind, px, py, dx, dy) {
  if (kind === 'rel' && pendingPointerMove && pendingPointerMove.kind === 'rel') {
    pendingPointerMove.dx += dx;
    pendingPointerMove.dy += dy;
  } else {
    pendingPointerMove = { kind: kind, px: px, py: py, dx: dx || 0, dy: dy || 0 };
  }
  var now = Date.now();
  if (!pointerMoveInFlight) {
    var elapsed = now - pointerMoveLastSentMs;
    if (elapsed >= 14) {
      flushCoalescedPointer();
    } else if (!pointerMoveTimer) {
      pointerMoveTimer = setTimeout(flushCoalescedPointer, 14 - elapsed);
    }
  }
}

var twoFingerGestureMode = 'undecided'; // 'undecided' | 'scroll' | 'pinch'
var twoFingerStartTime = 0;
var twoFingerMoved = false;
var lastScrollMidX = 0, lastScrollMidY = 0;
var lastTwoFingerScrollSent = 0;
var pinchFocalImgX = 0, pinchFocalImgY = 0;

var threeFingerActive = false;
var threeFingerStartTime = 0;

function updatePCTouchModeUI() {
  var btn = document.getElementById('btn-pc-touch-mode');
  var lbl = document.getElementById('pc-touch-mode-label');
  if (!btn || !lbl) return;
  var en = isEN();
  btn.title = en
    ? 'Cycle 1-Finger PC Touch Mode (Drag & Select / Smooth Scroll / Virtual Trackpad)'
    : 'Đổi chế độ vuốt 1 ngón trên PC (Kéo thả / Cuộn / Bàn rê)';
  if (pcTouchMode === 'scroll') {
    lbl.innerText = en ? '👆 1F: Scroll' : '👆 Cảm ứng chuẩn';
    btn.style.background = 'rgba(37,99,235,0.28)';
    btn.style.borderColor = 'rgba(96,165,250,0.6)';
    btn.style.color = '#bfdbfe';
  } else if (pcTouchMode === 'drag') {
    lbl.innerText = en ? '🖱️ 1F: Drag' : '🖱️ 1Ngón: Kéo thả';
    btn.style.background = 'rgba(16,185,129,0.25)';
    btn.style.borderColor = 'rgba(52,211,153,0.6)';
    btn.style.color = '#a7f3d0';
  } else {
    lbl.innerText = en ? '🎯 1F: Trackpad' : '🎯 1Ngón: Bàn rê';
    btn.style.background = 'rgba(147,51,234,0.28)';
    btn.style.borderColor = 'rgba(192,132,252,0.6)';
    btn.style.color = '#e9d5ff';
  }
}

function cyclePCTouchMode() {
  recordActivity();
  var en = isEN();
  if (pcTouchMode === 'scroll') {
    pcTouchMode = 'drag';
    flashStatus(en ? '🖱️ 1-Finger Mode: Direct Drag & Select (2-Finger Swipe = Scroll)' : '🖱️ Chế độ 1 Ngón: Kéo thả trực tiếp (Vuốt 2 ngón = Cuộn trang)', true);
  } else if (pcTouchMode === 'drag') {
    pcTouchMode = 'trackpad';
    flashStatus(en ? '🎯 1-Finger Mode: Virtual Trackpad Cursor (2-Finger Swipe = Scroll)' : '🎯 Chế độ 1 Ngón: Bàn rê chuột Trackpad (Vuốt 2 ngón = Cuộn)', true);
  } else {
    pcTouchMode = 'scroll';
    flashStatus(en ? '👆 Standard Touch Mode: Tap=Click • Swipe=Scroll • Hold 0.4s=Right-Click • Hold+Drag=Move' : '👆 Chế độ Cảm ứng chuẩn: Chạm=Click • Vuốt=Cuộn • Giữ 0.4s=Chuột phải • Giữ+Kéo=Kéo thả', true);
  }
  localStorage.setItem('vui_pc_touch_mode', pcTouchMode);
  updatePCTouchModeUI();
}

function sendPCRightClickAtLast() {
  recordActivity();
  if (navigator.vibrate) navigator.vibrate(25);
  flashStatus('🖱️ Click Chuột Phải', true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/touch?type=rightclick&px=' + lastKnownPx.toFixed(4) + '&py=' + lastKnownPy.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
  xhr.send();
  triggerInteractiveCapture();
}

function sendPCDoubleClickAtLast() {
  recordActivity();
  if (navigator.vibrate) navigator.vibrate([15, 30, 20]);
  flashStatus('⚡ Nhấp Đúp Chuột Trái', true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/touch?type=doubletap&px=' + lastKnownPx.toFixed(4) + '&py=' + lastKnownPy.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
  xhr.send();
  triggerInteractiveCapture();
}

function togglePCDragLock() {
  recordActivity();
  var btn = document.getElementById('btn-pc-draglock');
  pcDragLocked = !pcDragLocked;
  if (pcDragLocked) {
    if (btn) {
      btn.style.background = 'rgba(245,158,11,0.45)';
      btn.style.borderColor = '#fbbf24';
      btn.style.color = '#fff';
      btn.innerText = '✊ĐangGiữ';
    }
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/touch?type=dragstart&px=' + lastKnownPx.toFixed(4) + '&py=' + lastKnownPy.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
    xhr.send();
    flashStatus('✊ Đã khóa giữ chuột trái! Chạm điểm đích để thả.', true);
  } else {
    if (btn) {
      btn.style.background = '';
      btn.style.borderColor = '';
      btn.style.color = '';
      btn.innerText = '✊GiữKéo';
    }
    var xhr2 = new XMLHttpRequest();
    xhr2.open('GET', '/api/touch?type=dragend&px=' + lastKnownPx.toFixed(4) + '&py=' + lastKnownPy.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
    xhr2.send();
    flashStatus('✓ Đã nhả giữ chuột trái', true);
    triggerInteractiveCapture();
  }
}

function sendPCHotkey(combo, label) {
  recordActivity();
  if (navigator.vibrate) navigator.vibrate(15);
  flashStatus('⌨️ ' + (label || combo), true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/touch?type=hotkey&key=' + encodeURIComponent(combo) + getDevParam() + '&t=' + Date.now(), true);
  xhr.send();
  triggerInteractiveCapture();
}

function rotateScreenDeltaToVp(deltaScreenX, deltaScreenY) {
  var effRot = getActiveCssRotation();
  if (effRot === 90) {
    return { x: deltaScreenY, y: -deltaScreenX };
  } else if (effRot === 270) {
    return { x: -deltaScreenY, y: deltaScreenX };
  } else if (effRot === 180) {
    return { x: -deltaScreenX, y: -deltaScreenY };
  }
  return { x: deltaScreenX, y: deltaScreenY };
}

function onTouchStart(e) {
  if (isSleeping && sleepReason !== 'manual') {
    wakeFromSleep();
    return;
  }
  recordActivity();

  if (pointerMoveTimer) {
    clearTimeout(pointerMoveTimer);
    pointerMoveTimer = null;
  }
  pendingPointerMove = null;

  var vp = document.getElementById('screen-viewport');
  if (!vp) return;

  // 3-Finger Multi-Touch (Overview / Multitasking)
  if (e.touches && e.touches.length === 3) {
    threeFingerActive = true;
    threeFingerStartTime = Date.now();
    isPinching = false;
    touchActive = false;
    if (longPressTimer) { clearTimeout(longPressTimer); longPressTimer = null; }
    hideTouchIndicator();
    return;
  }

  // 2-Finger Multi-Touch (Focal-Point Pinch Zoom, 2-Finger Pan when Zoomed, 2-Finger Scroll, 2-Finger Tap Right-Click)
  if (e.touches && e.touches.length === 2) {
    isPinching = true;
    touchActive = false;
    threeFingerActive = false;
    if (longPressTimer) { clearTimeout(longPressTimer); longPressTimer = null; }
    if (singleTapTimer) { clearTimeout(singleTapTimer); singleTapTimer = null; }
    hideTouchIndicator();

    var t0 = e.touches[0];
    var t1 = e.touches[1];
    twoFingerStartTime = Date.now();
    twoFingerMoved = false;
    twoFingerGestureMode = 'undecided';
    pinchStartDist = Math.hypot(t1.clientX - t0.clientX, t1.clientY - t0.clientY);
    pinchStartZoom = zoomLevel || 1.0;
    pinchStartMidX = (t0.clientX + t1.clientX) / 2;
    pinchStartMidY = (t0.clientY + t1.clientY) / 2;
    lastScrollMidX = pinchStartMidX;
    lastScrollMidY = pinchStartMidY;
    pinchStartPanX = panX || 0;
    pinchStartPanY = panY || 0;

    var rect = vp.getBoundingClientRect();
    if (rect && rect.width > 0 && rect.height > 0) {
      var cx = rect.left + rect.width / 2;
      var cy = rect.top + rect.height / 2;
      var startVp = rotateScreenDeltaToVp(pinchStartMidX - cx, pinchStartMidY - cy);
      pinchFocalImgX = (startVp.x - pinchStartPanX) / pinchStartZoom;
      pinchFocalImgY = (startVp.y - pinchStartPanY) / pinchStartZoom;
    }
    return;
  }

  if (e.touches && e.touches.length > 3) return;

  var point = e.touches ? e.touches[0] : e;

  // Right-click or Middle-click from physical mouse on browser
  if (!e.touches && typeof e.button === 'number') {
    if (e.button === 2) {
      var rcCoords = getNormalizedCoords(point.clientX, point.clientY);
      if (rcCoords) {
        lastKnownPx = rcCoords.px;
        lastKnownPy = rcCoords.py;
        sendPCRightClickAtLast();
      }
      return;
    }
    if (e.button === 1 && isCurrentDevPC()) {
      var mcCoords = getNormalizedCoords(point.clientX, point.clientY);
      if (mcCoords) {
        lastKnownPx = mcCoords.px;
        lastKnownPy = mcCoords.py;
        flashStatus('🖱️ Click Chuột Giữa', true);
        var xhrMc = new XMLHttpRequest();
        xhrMc.open('GET', '/api/touch?type=middleclick&px=' + mcCoords.px.toFixed(4) + '&py=' + mcCoords.py.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
        xhrMc.send();
        triggerInteractiveCapture();
      }
      return;
    }
  }

  if (isPanMode && zoomLevel > 1.0) {
    touchActive = true;
    panTouchStartX = point.clientX;
    panTouchStartY = point.clientY;
    panStartPanX = panX;
    panStartPanY = panY;
    return;
  }

  var coords = getNormalizedCoords(point.clientX, point.clientY);
  if (!coords) return;

  touchActive = true;
  isMouseClickDrag = (!e.touches && typeof e.button === 'number' && e.button === 0);
  touchStartX = coords.px;
  touchStartY = coords.py;
  lastMovePx = coords.px;
  lastMovePy = coords.py;
  lastKnownPx = coords.px;
  lastKnownPy = coords.py;
  touchStartTime = Date.now();
  touchMoved = false;
  isLongPressTriggered = false;
  isDragging = false;

  showTouchIndicatorAt(coords.localX, coords.localY, pcDragLocked);

  if (longPressTimer) clearTimeout(longPressTimer);
  var startLocalX = coords.localX;
  var startLocalY = coords.localY;
  longPressTimer = setTimeout(function() {
    longPressTimer = null;
    if (touchActive && !touchMoved && !isPinching && !threeFingerActive) {
      isLongPressTriggered = true;
      showTouchIndicatorAt(startLocalX, startLocalY, true);
      if (navigator.vibrate) navigator.vibrate(40);
      if (isCurrentDevPC()) {
        flashStatus('✊ Đã giữ! Nhả ra = Chuột phải | Kéo đi = Kéo thả (Drag & Drop)', true);
      } else {
        flashStatus('👆 Đã bấm giữ! Nhả ra = Menu | Kéo đi = Kéo thả', true);
      }
    }
  }, 380);
}

function onTouchMove(e) {
  if (threeFingerActive) return;

  if (isPinching && e.touches && e.touches.length === 2) {
    recordActivity();
    var vp = document.getElementById('screen-viewport');
    var t0 = e.touches[0];
    var t1 = e.touches[1];
    var dist = Math.hypot(t1.clientX - t0.clientX, t1.clientY - t0.clientY);
    var midX = (t0.clientX + t1.clientX) / 2;
    var midY = (t0.clientY + t1.clientY) / 2;

    var distDelta = Math.abs(dist - pinchStartDist);
    var midDelta = Math.hypot(midX - pinchStartMidX, midY - pinchStartMidY);

    if (distDelta > 6 || midDelta > 6) {
      twoFingerMoved = true;
    }

    if (twoFingerGestureMode === 'undecided') {
      if (zoomLevel > 1.05) {
        // Khi đang phóng to (>1x): 2 ngón luôn dùng để dịch chuyển vùng nhìn (Pan) & phóng to/thu nhỏ (Pinch) quanh tâm 2 ngón
        if (distDelta > 8 || midDelta > 8) {
          twoFingerGestureMode = 'pinch';
        }
      } else {
        // Khi ở 1x: Chụm/tách 2 ngón = Phóng to đúng tâm; Trượt song song 2 ngón = Cuộn trang
        if (distDelta > 20 && distDelta > midDelta * 0.55) {
          twoFingerGestureMode = 'pinch';
        } else if (midDelta > 12) {
          twoFingerGestureMode = 'scroll';
        }
      }
    }

    if (twoFingerGestureMode === 'pinch') {
      var ratio = dist / (pinchStartDist || 1);
      var newZoom = Math.max(1.0, Math.min(MAX_ZOOM_LEVEL, pinchStartZoom * ratio));
      if (vp) {
        var rect = vp.getBoundingClientRect();
        var cx = rect.left + rect.width / 2;
        var cy = rect.top + rect.height / 2;
        var curVp = rotateScreenDeltaToVp(midX - cx, midY - cy);
        var newPanX = curVp.x - pinchFocalImgX * newZoom;
        var newPanY = curVp.y - pinchFocalImgY * newZoom;
        setZoomAndPan(newZoom, newPanX, newPanY);
      }
      return;
    }

    if (twoFingerGestureMode === 'scroll') {
      var stepVp = rotateScreenDeltaToVp(midX - lastScrollMidX, midY - lastScrollMidY);
      var now = Date.now();
      if ((Math.abs(stepVp.x) >= 12 || Math.abs(stepVp.y) >= 12) && (now - lastTwoFingerScrollSent >= 35)) {
        lastTwoFingerScrollSent = now;
        lastScrollMidX = midX;
        lastScrollMidY = midY;
        var midCoords = getNormalizedCoords(midX, midY);
        var sPx = midCoords ? midCoords.px : lastKnownPx;
        var sPy = midCoords ? midCoords.py : lastKnownPy;
        var normDx = stepVp.x / (midCoords ? midCoords.renderW : 500);
        var normDy = stepVp.y / (midCoords ? midCoords.renderH : 300);
        var steps = Math.max(2, Math.min(6, Math.round(Math.hypot(stepVp.x, stepVp.y) / 14)));

        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/api/touch?type=scroll&px=' + sPx.toFixed(4) + '&py=' + sPy.toFixed(4) +
          '&dx=' + normDx.toFixed(4) + '&dy=' + normDy.toFixed(4) + '&steps=' + steps + getDevParam() + '&t=' + now, true);
        xhr.send();

        var dirTxt = Math.abs(normDy) >= Math.abs(normDx) ? (normDy < 0 ? 'Xuống ⬇' : 'Lên ⬆') : (normDx < 0 ? 'Phải ➔' : 'Trái ⬅');
        flashStatus('✌️ Cuộn 2 ngón: ' + dirTxt, true);
        triggerInteractiveCapture();
      }
      return;
    }
    return;
  }

  if (!touchActive) return;
  var point = e.touches ? e.touches[0] : e;

  if (isPanMode && zoomLevel > 1.0) {
    var dPan = rotateScreenDeltaToVp(point.clientX - panTouchStartX, point.clientY - panTouchStartY);
    setZoomAndPan(zoomLevel, panStartPanX + dPan.x, panStartPanY + dPan.y);
    return;
  }

  var coords = getNormalizedCoords(point.clientX, point.clientY);
  if (!coords) return;

  lastKnownPx = coords.px;
  lastKnownPy = coords.py;

  var dx = coords.px - touchStartX;
  var dy = coords.py - touchStartY;
  var dist = Math.hypot(dx, dy);
  var nowMove = Date.now();

  // Case 1: Long-Press was already triggered, and now finger moves -> Hold & Drag (Drag & Drop)
  if (isLongPressTriggered && dist > 0.008) {
    touchMoved = true;
    if (!isDragging) {
      isDragging = true;
      if (isCurrentDevPC()) {
        var xhrStart = new XMLHttpRequest();
        xhrStart.open('GET', '/api/touch?type=dragstart&px=' + touchStartX.toFixed(4) + '&py=' + touchStartY.toFixed(4) + getDevParam() + '&t=' + nowMove, true);
        xhrStart.send();
      }
      flashStatus('✊ Đang kéo thả (Drag & Drop)...', true);
    }
    if (isCurrentDevPC()) {
      sendCoalescedPointer('dragmove', coords.px, coords.py, 0, 0);
    }
  } else if (!isLongPressTriggered && dist > (isMouseClickDrag ? 0.012 : 0.015)) {
    // Case 2: Finger / Mouse moved before Long-Press timer fired
    touchMoved = true;
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }

    if (isCurrentDevPC()) {
      if (isMouseClickDrag || pcTouchMode === 'drag' || pcDragLocked) {
        if (!isDragging) {
          isDragging = true;
          if (!pcDragLocked) {
            var xhrDStart = new XMLHttpRequest();
            xhrDStart.open('GET', '/api/touch?type=dragstart&px=' + touchStartX.toFixed(4) + '&py=' + touchStartY.toFixed(4) + getDevParam() + '&t=' + nowMove, true);
            xhrDStart.send();
          }
          flashStatus('🖱️ Đang kéo thả (Drag & Drop)...', true);
        }
        sendCoalescedPointer('dragmove', coords.px, coords.py, 0, 0);
      } else if (pcTouchMode === 'trackpad') {
        var relDx = Math.round((coords.px - lastMovePx) * 2560 * 1.25);
        var relDy = Math.round((coords.py - lastMovePy) * 1440 * 1.25);
        if (Math.abs(relDx) >= 1 || Math.abs(relDy) >= 1) {
          lastDragMoveSent = nowMove;
          lastMovePx = coords.px;
          lastMovePy = coords.py;
          sendCoalescedPointer('rel', 0, 0, relDx, relDy);
        }
      }
    }
  }

  showTouchIndicatorAt(coords.localX, coords.localY, isLongPressTriggered || isDragging || pcDragLocked);
}

function onTouchEnd(e) {
  if (longPressTimer) {
    clearTimeout(longPressTimer);
    longPressTimer = null;
  }

  // 3-Finger Release
  if (threeFingerActive) {
    if (!e.touches || e.touches.length === 0) {
      threeFingerActive = false;
      if (Date.now() - threeFingerStartTime < 450) {
        if (navigator.vibrate) navigator.vibrate(30);
        if (isCurrentDevPC()) {
          sendPCHotkey('Super_L', 'Mở Đa nhiệm Cửa sổ (Super)');
        } else {
          key(187, 'Đa nhiệm (Recent Apps)');
        }
      }
    }
    return;
  }

  // 2-Finger Release
  if (isPinching) {
    if (!e.touches || e.touches.length === 0) {
      isPinching = false;
      if (twoFingerGestureMode === 'undecided' && !twoFingerMoved && (Date.now() - twoFingerStartTime < 350)) {
        var midCoords = getNormalizedCoords(pinchStartMidX, pinchStartMidY);
        var rPx = midCoords ? midCoords.px : lastKnownPx;
        var rPy = midCoords ? midCoords.py : lastKnownPy;
        lastKnownPx = rPx;
        lastKnownPy = rPy;
        if (navigator.vibrate) navigator.vibrate(25);
        flashStatus('✌️ Chạm 2 ngón: Click Chuột Phải', true);
        var xhrRc = new XMLHttpRequest();
        xhrRc.open('GET', '/api/touch?type=rightclick&px=' + rPx.toFixed(4) + '&py=' + rPy.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
        xhrRc.send();
        triggerInteractiveCapture();
      } else if (twoFingerGestureMode === 'pinch' && zoomLevel > 1.2) {
        refreshScreen(false);
      }
      twoFingerGestureMode = 'undecided';
    }
    return;
  }

  if (!touchActive) return;
  touchActive = false;
  var wasMouseClickDrag = isMouseClickDrag;
  isMouseClickDrag = false;

  if (pointerMoveTimer) {
    clearTimeout(pointerMoveTimer);
    pointerMoveTimer = null;
  }
  pendingPointerMove = null;

  if (isPanMode && zoomLevel > 1.0) {
    return;
  }

  hideTouchIndicator();

  var point = e.changedTouches ? e.changedTouches[0] : e;
  var coords = point ? getNormalizedCoords(point.clientX, point.clientY) : null;
  var endX = coords ? coords.px : lastKnownPx;
  var endY = coords ? coords.py : lastKnownPy;
  lastKnownPx = endX;
  lastKnownPy = endY;

  var dx = endX - touchStartX;
  var dy = endY - touchStartY;
  var dist = Math.hypot(dx, dy);
  var elapsed = Date.now() - touchStartTime;

  // 1. Complete Active Drag & Drop
  if (isDragging) {
    isDragging = false;
    isLongPressTriggered = false;
    pendingPointerMove = null;
    if (navigator.vibrate) navigator.vibrate(20);
    if (isCurrentDevPC()) {
      if (pcDragLocked && !wasMouseClickDrag) {
        togglePCDragLock();
      } else {
        var xhrDEnd = new XMLHttpRequest();
        xhrDEnd.open('GET', '/api/touch?type=dragend&px=' + endX.toFixed(4) + '&py=' + endY.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
        xhrDEnd.send();
        flashStatus('✓ Đã thả chuột (Hoàn tất Kéo thả)', true);
      }
    } else {
      var xhrADrag = new XMLHttpRequest();
      xhrADrag.open('GET', '/api/touch?type=drag&px1=' + touchStartX.toFixed(4) + '&py1=' + touchStartY.toFixed(4) +
        '&px2=' + endX.toFixed(4) + '&py2=' + endY.toFixed(4) + '&dur=750' + getDevParam() + '&t=' + Date.now(), true);
      xhrADrag.send();
      flashStatus('✓ Đã kéo thả', true);
    }
    triggerInteractiveCapture();
    return;
  }

  // 2. Stationary Long-Press Release -> Right-Click on PC / Long-Press on Android
  if (isLongPressTriggered && !touchMoved) {
    isLongPressTriggered = false;
    if (navigator.vibrate) navigator.vibrate(25);
    if (isCurrentDevPC()) {
      flashStatus('🖱️ Click Chuột Phải (Menu)', true);
      var xhrLP = new XMLHttpRequest();
      xhrLP.open('GET', '/api/touch?type=rightclick&px=' + touchStartX.toFixed(4) + '&py=' + touchStartY.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
      xhrLP.send();
    } else {
      flashStatus('👆 Đã bấm giữ (Long-Press)', true);
      var xhrALP = new XMLHttpRequest();
      xhrALP.open('GET', '/api/touch?type=longpress&px=' + touchStartX.toFixed(4) + '&py=' + touchStartY.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
      xhrALP.send();
    }
    triggerInteractiveCapture();
    return;
  }

  // 3. 1-Finger Movement (Scroll / Trackpad / Android Swipe)
  if (touchMoved && dist > 0.025) {
    if (isCurrentDevPC()) {
      if (pcTouchMode === 'trackpad') {
        triggerInteractiveCapture();
        return;
      }
      if (pcTouchMode === 'scroll') {
        var sDir = Math.abs(dy) >= Math.abs(dx) ? (dy < 0 ? 'Xuống ⬇' : 'Lên ⬆') : (dx < 0 ? 'Phải ➔' : 'Trái ⬅');
        flashStatus('👆 Cuộn: ' + sDir, true);
        var xhrSc = new XMLHttpRequest();
        xhrSc.open('GET', '/api/touch?type=scroll&px=' + touchStartX.toFixed(4) + '&py=' + touchStartY.toFixed(4) +
          '&dx=' + dx.toFixed(4) + '&dy=' + dy.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
        xhrSc.send();
        triggerInteractiveCapture();
        return;
      }
    }

    var swipeDir = "";
    if (Math.abs(dx) > Math.abs(dy)) {
      swipeDir = dx > 0 ? "Phải ➔" : "Trái ⬅";
    } else {
      swipeDir = dy > 0 ? "Xuống ⬇" : "Lên ⬆";
    }
    flashStatus('👆 Vuốt ' + swipeDir, true);
    if (navigator.vibrate) navigator.vibrate(20);

    var dur = Math.min(Math.max(elapsed, 120), 360);
    var xhrSw = new XMLHttpRequest();
    xhrSw.open('GET', '/api/touch?type=swipe&px1=' + touchStartX.toFixed(4) + '&py1=' + touchStartY.toFixed(4) +
      '&px2=' + endX.toFixed(4) + '&py2=' + endY.toFixed(4) + '&dur=' + dur + getDevParam() + '&t=' + Date.now(), true);
    xhrSw.send();
    triggerInteractiveCapture();
    return;
  }

  // 4. Single-Tap vs Double-Tap (Always click at the exact touchStartX, touchStartY point!)
  if (pcDragLocked && isCurrentDevPC()) {
    var xhrMoveEnd = new XMLHttpRequest();
    xhrMoveEnd.open('GET', '/api/touch?type=dragmove&px=' + touchStartX.toFixed(4) + '&py=' + touchStartY.toFixed(4) + getDevParam() + '&t=' + Date.now(), true);
    xhrMoveEnd.onload = function() { togglePCDragLock(); };
    xhrMoveEnd.send();
    return;
  }

  var nowTap = Date.now();
  var isDouble = (nowTap - lastTapTimestamp < 320) && lastTapCoords && (Math.hypot(touchStartX - lastTapCoords.px, touchStartY - lastTapCoords.py) < 0.045);

  // Khi người dùng chủ động chạm vào màn hình điều khiển, làm mới bộ đệm từ tại vị trí con trỏ mới (không tự động bật ô nhập/bàn phím)
  lastTapRatioY = (coords && coords.Hv > 0) ? (coords.localY / coords.Hv) : touchStartY;
  resetDirectBuffer();
  var kbdOpenNow = document.getElementById('vui-landscape-kbd');
  if (kbdOpenNow && kbdOpenNow.classList.contains('show')) {
    setTimeout(function() {
      focusCameraOnRemoteInput(lastKnownPx, lastKnownPy, false);
    }, 320);
  }

  if (isDouble) {
    lastTapTimestamp = 0;
    lastTapCoords = null;
    if (navigator.vibrate) navigator.vibrate([15, 30, 20]);
    flashStatus('⚡ Nhấp đúp: ' + Math.round(touchStartX*100) + '%, ' + Math.round(touchStartY*100) + '%', true);
    var dblUrl = '/api/touch?type=doubletap&px=' + touchStartX.toFixed(4) + '&py=' + touchStartY.toFixed(4);
    var xhrDbl = new XMLHttpRequest();
    xhrDbl.open('GET', dblUrl + getDevParam() + '&t=' + nowTap, true);
    xhrDbl.send();
    triggerInteractiveCapture(true);
  } else {
    lastTapTimestamp = nowTap;
    lastTapCoords = { px: touchStartX, py: touchStartY };
    if (navigator.vibrate) navigator.vibrate(15);
    flashStatus('👆 Chạm: ' + Math.round(touchStartX*100) + '%, ' + Math.round(touchStartY*100) + '%', true);
    var xhrTap = new XMLHttpRequest();
    xhrTap.open('GET', '/api/touch?type=tap&px=' + touchStartX.toFixed(4) + '&py=' + touchStartY.toFixed(4) + '&tv=1' + getDevParam() + '&t=' + nowTap, true);
    xhrTap.send();
    triggerInteractiveCapture(true);
  }
}

var lastRealTouchTime = 0;

function ensureDesktopImeBridgeFocus() {
  if (isMobileTouchOS() || isSleeping) return;
  if (isBlockingModalOrInputActive(document.activeElement)) return;
  var inp = document.getElementById('quick-txt-input');
  if (!inp) return;
  inp.removeAttribute('readonly');
  inp.setAttribute('inputmode', 'none');
  if (document.activeElement !== inp) {
    try { inp.focus({ preventScroll: true }); } catch (e) { try { inp.focus(); } catch (e2) {} }
    try {
      var len = (inp.value || '').length;
      inp.setSelectionRange(len, len);
    } catch (e3) {}
  }
}

function bindGestures() {
  initAllKeyRepeats();
  var qInp = document.getElementById('quick-txt-input');
  if (qInp && !qInp._compBound) {
    qInp._compBound = true;
    qInp.addEventListener('compositionstart', function() { qInp._isComposing = true; });
    qInp.addEventListener('compositionend', function() {
      qInp._isComposing = false;
      onQuickInputChanged();
    });
  }
  ensureDesktopImeBridgeFocus();
  if (!window._vuiPhysicalKbdBound) {
    window._vuiPhysicalKbdBound = true;
    window.addEventListener('focus', function() {
      ensureDesktopImeBridgeFocus();
    });
    window.addEventListener('blur', function() {
      remoteClipboardActive = false;
      cancelPendingKeyRepeats();
    });
    window.addEventListener('keyup', function() {
      cancelPendingKeyRepeats();
    }, true);
    window.addEventListener('keydown', handleGlobalPhysicalKeyDown, false);
    window.addEventListener('paste', handleGlobalPaste, false);
  }
  var vp = document.getElementById('screen-viewport');
  if (!vp || vp._gesturesBound) return;
  vp._gesturesBound = true;
  
  vp.addEventListener('touchstart', function(e) {
    lastRealTouchTime = Date.now();
    if (e.cancelable) e.preventDefault();
    onTouchStart(e);
  }, { passive: false });

  vp.addEventListener('touchmove', function(e) {
    lastRealTouchTime = Date.now();
    if (e.cancelable) e.preventDefault();
    onTouchMove(e);
  }, { passive: false });

  vp.addEventListener('touchend', function(e) {
    lastRealTouchTime = Date.now();
    if (e.cancelable) e.preventDefault();
    onTouchEnd(e);
  }, { passive: false });

  vp.addEventListener('touchcancel', function(e) {
    lastRealTouchTime = Date.now();
    onTouchEnd(e);
  }, { passive: true });

  vp.addEventListener('mousedown', function(e) {
    if (Date.now() - lastRealTouchTime < 1000) return;
    if (e.cancelable) e.preventDefault();
    ensureDesktopImeBridgeFocus();
    onTouchStart(e);
  });
  vp.addEventListener('mousemove', function(e) {
    if (Date.now() - lastRealTouchTime < 1000 || touchActive) return;
    if (isCurrentDevPC() && !isSleeping) {
      var hCoords = getNormalizedCoords(e.clientX, e.clientY);
      if (hCoords) {
        lastKnownPx = hCoords.px;
        lastKnownPy = hCoords.py;
        sendCoalescedPointer('hover', hCoords.px, hCoords.py, 0, 0);
      }
    }
  });
  window.addEventListener('mousemove', function(e) {
    if (Date.now() - lastRealTouchTime < 1000 || !touchActive) return;
    onTouchMove(e);
  });
  window.addEventListener('mouseup', function(e) {
    if (Date.now() - lastRealTouchTime < 1000 || !touchActive) return;
    onTouchEnd(e);
    ensureDesktopImeBridgeFocus();
  });
  vp.addEventListener('contextmenu', function(e) {
    e.preventDefault();
  });
  
  vp.addEventListener('wheel', function(e) {
    e.preventDefault();
    recordActivity();
    if (isCurrentDevPC() && !e.ctrlKey && zoomLevel <= 1.05) {
      var wCoords = getNormalizedCoords(e.clientX, e.clientY);
      var wPx = wCoords ? wCoords.px : lastKnownPx;
      var wPy = wCoords ? wCoords.py : lastKnownPy;
      var dy = e.deltaY > 0 ? -0.08 : 0.08;
      var dx = e.deltaX > 0 ? -0.08 : (e.deltaX < 0 ? 0.08 : 0);
      var xhrW = new XMLHttpRequest();
      xhrW.open('GET', '/api/touch?type=scroll&px=' + wPx.toFixed(4) + '&py=' + wPy.toFixed(4) + '&dx=' + dx + '&dy=' + dy + '&steps=3' + getDevParam() + '&t=' + Date.now(), true);
      xhrW.send();
      triggerInteractiveCapture();
      return;
    }
    var step = zoomLevel >= 3.0 ? 0.6 : 0.3;
    var delta = e.deltaY < 0 ? step : -step;
    var newZoom = Math.max(1.0, Math.min(MAX_ZOOM_LEVEL, zoomLevel + delta));
    var zCoords = getNormalizedCoords(e.clientX, e.clientY);
    if (zCoords && e.deltaY < 0) {
      zoomToPoint(zCoords.px, zCoords.py, newZoom);
    } else {
      setZoomAndPan(newZoom, panX, panY);
    }
  }, { passive: false });

  var overlays = ['screen-offline-notice', 'screen-watermark-zoom', 'screen-watermark-rotate', 'smart-input-bar', 'vui-landscape-kbd', 'wm-top-bar', 'screen-watermark-source', 'screen-sleep-overlay'];
  overlays.forEach(function(id) {
    var el = document.getElementById(id);
    if (el) {
      ['touchstart', 'touchmove', 'touchend', 'mousedown', 'mousemove', 'mouseup', 'click'].forEach(function(ev) {
        el.addEventListener(ev, function(e) { e.stopPropagation(); }, { passive: false });
      });
    }
  });
  initNavClusterDrag();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bindGestures);
} else {
  bindGestures();
}
setTimeout(bindGestures, 400);

var toastTimer = null;
function trToast(text) {
  if (!isEN() || !text) return text;
  return String(text)
    .replace('Đã gửi: ', 'Sent: ')
    .replace('Lệnh: ', 'Command: ')
    .replace('Mở: ', 'Launch: ')
    .replace('✈️ Đang truyền ', '✈️ Uploading ')
    .replace('✈️ Đang xử lý & truyền ảnh', '✈️ Processing & sending image')
    .replace('✓ Đã dán Hình ảnh vào máy từ xa (Ctrl+V)!', '✓ Image pasted into remote clipboard (Ctrl+V)!')
    .replace('✓ Đã truyền ', '✓ Transferred ')
    .replace(' & chèn vào máy từ xa!', ' & injected into remote!')
    .replace('🔑 Phiên kết nối cần mở khóa lại — Đang tải màn hình PIN...', '🔑 Session expired — Reloading PIN lock screen...')
    .replace('⚠️ Lỗi truyền file: ', '⚠️ File transfer error: ')
    .replace('⚠️ Lỗi kết nối khi truyền file', '⚠️ Connection error during file transfer')
    .replace('🖥️ Đang xem Toàn màn hình', '🖥️ Viewing Full Desktop')
    .replace('🎯 Đang làm việc riêng với: ', '🎯 Focused on window: ')
    .replace('🗖 Đã phóng to: ', '🗖 Maximized: ')
    .replace('🚀 Đang tìm & đưa cửa sổ Antigravity lên đầu...', '🚀 Finding & focusing Antigravity IDE...')
    .replace('🚀 Đã khóa khung hình riêng vào Antigravity!', '🚀 Stream locked to Antigravity window!')
    .replace('🖥️ Đã chuyển về Toàn màn hình', '🖥️ Switched to Full Desktop')
    .replace('Đang gửi chữ...', 'Sending text...')
    .replace('✓ Đã dán chữ chuẩn 100%', '✓ Text pasted 100%')
    .replace('Đã dán từ bộ nhớ tạm', 'Pasted from clipboard')
    .replace('Đang kiểm tra link Internet...', 'Checking Internet tunnel URL...');
}
function flashStatus(text, ok) {
  var toast = document.getElementById('status-toast');
  if (!toast) return;
  toast.innerText = trToast(text);
  toast.style.borderColor = ok ? 'rgba(34, 197, 94, 0.6)' : 'rgba(239, 68, 68, 0.6)';
  toast.style.color = ok ? '#86efac' : '#fca5a5';
  toast.classList.add('show');

  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(function() {
    toast.classList.remove('show');
  }, 1200);
}

function isBlockingModalOrInputActive(targetEl) {
  var inp = document.getElementById('quick-txt-input');
  if (targetEl && targetEl !== inp) {
    var tag = (targetEl.tagName || '').toUpperCase();
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || targetEl.isContentEditable) {
      return true;
    }
  }
  var txtModal = document.getElementById('text-modal');
  if (txtModal && txtModal.classList.contains('show')) return true;
  return false;
}

var PHYSICAL_SPECIAL_KEYS = {
  'Enter':      { code: 66,  hk: 'Return',    label: 'Enter ↵' },
  'Tab':        { code: 61,  hk: 'Tab',       label: 'Tab ⇥' },
  'Escape':     { code: 4,   hk: 'Escape',    label: 'Esc' },
  'Delete':     { code: 112, hk: 'Delete',    label: 'Delete' },
  'ArrowUp':    { code: 19,  hk: 'Up',        label: 'Lên ▲' },
  'ArrowDown':  { code: 20,  hk: 'Down',      label: 'Xuống ▼' },
  'ArrowLeft':  { code: 21,  hk: 'Left',      label: 'Trái ◀' },
  'ArrowRight': { code: 22,  hk: 'Right',     label: 'Phải ▶' },
  'Home':       { code: 122, hk: 'Home',      label: 'Home' },
  'End':        { code: 123, hk: 'End',       label: 'End' },
  'PageUp':     { code: 92,  hk: 'Page_Up',   label: 'PageUp' },
  'PageDown':   { code: 93,  hk: 'Page_Down', label: 'PageDown' }
};

var PHYSICAL_FUNC_KEYS = {
  'F1': 'F1', 'F2': 'F2', 'F3': 'F3', 'F4': 'F4',
  'F5': 'F5', 'F6': 'F6', 'F7': 'F7', 'F8': 'F8',
  'F9': 'F9', 'F10': 'F10', 'F11': 'F11', 'F12': 'F12'
};

function buildModifierPrefix(ev) {
  var mods = [];
  var labels = [];
  if (ev.ctrlKey || ev.metaKey) { mods.push('ctrl'); labels.push('Ctrl'); }
  if (ev.altKey) { mods.push('alt'); labels.push('Alt'); }
  if (ev.shiftKey) { mods.push('shift'); labels.push('Shift'); }
  return {
    prefix: mods.length > 0 ? (mods.join('+') + '+') : '',
    labelPrefix: labels.length > 0 ? (labels.join('+') + '+') : '',
    hasMod: mods.length > 0,
    hasCtrlOrAlt: !!(ev.ctrlKey || ev.metaKey || ev.altKey)
  };
}

function handlePhysicalSpecialOrShortcut(ev) {
  if (ev.isComposing || ev.keyCode === 229) return false;

  // Bỏ qua khi chỉ mới bấm giữ riêng phím bổ trợ (Shift, Ctrl, Alt, Meta)
  if (ev.key === 'Shift' || ev.key === 'Control' || ev.key === 'Alt' || ev.key === 'Meta' || ev.key === 'AltGraph' || ev.key === 'CapsLock') {
    return false;
  }

  var mod = buildModifierPrefix(ev);

  // 1. Các phím đặc biệt (Enter, Tab, Escape, Delete, Mũi tên, Home/End, PageUp/Down) KÈM hoặc KHÔNG KÈM tổ hợp Shift/Ctrl/Alt
  // Đặc biệt: Shift+Enter -> shift+Return (xuống dòng trong Antigravity/chat/code thay vì gửi luôn),
  // Ctrl+Enter -> ctrl+Return, Shift+Tab -> shift+Tab, Shift/Ctrl + Mũi tên -> bôi đen / nhảy từ.
  var spec = PHYSICAL_SPECIAL_KEYS[ev.key];
  if (spec) {
    ev.preventDefault();
    resetDirectBuffer();
    var isRep = !!ev.repeat;
    if (mod.hasMod) {
      var combo = mod.prefix + spec.hk;
      var comboLabel = mod.labelPrefix + spec.label;
      enqueueDirectHotkey(combo, comboLabel, isRep);
      if (!isRep) {
        if (ev.key === 'Enter' && ev.shiftKey && !ev.ctrlKey && !ev.altKey && !ev.metaKey) {
          flashStatus('⌨️ Xuống dòng (Shift+Enter)', true);
        } else {
          flashStatus('⌨️ ' + comboLabel, true);
        }
      }
    } else {
      enqueueDirectKey(spec.code, spec.label, isRep);
    }
    return true;
  }

  // 2. Các phím F1..F12 (có hoặc không có Ctrl/Alt/Shift, ví dụ F5, F11, F12, Alt+F4, Ctrl+F5)
  var fKey = PHYSICAL_FUNC_KEYS[ev.key];
  if (fKey) {
    ev.preventDefault();
    resetDirectBuffer();
    var fCombo = mod.prefix + fKey;
    var fLabel = mod.labelPrefix + fKey;
    enqueueDirectHotkey(fCombo, fLabel, !!ev.repeat);
    if (!ev.repeat) flashStatus('⌨️ ' + fLabel, true);
    return true;
  }

  // 3. Tổ hợp Ctrl/Alt + Backspace hoặc Ctrl/Alt + Space (xóa nguyên từ / mở gợi ý lệnh)
  if (ev.key === 'Backspace' && mod.hasCtrlOrAlt) {
    ev.preventDefault();
    resetDirectBuffer();
    enqueueDirectHotkey(mod.prefix + 'BackSpace', mod.labelPrefix + 'Backspace', !!ev.repeat);
    if (!ev.repeat) flashStatus('⌨️ ' + mod.labelPrefix + 'Backspace', true);
    return true;
  }
  if ((ev.key === ' ' || ev.code === 'Space') && mod.hasCtrlOrAlt) {
    ev.preventDefault();
    resetDirectBuffer();
    enqueueDirectHotkey(mod.prefix + 'space', mod.labelPrefix + 'Space', !!ev.repeat);
    if (!ev.repeat) flashStatus('⌨️ ' + mod.labelPrefix + 'Space', true);
    return true;
  }

  // 4. Tổ hợp phím tắt Ctrl / Alt + phím ký tự (Ctrl+C, Ctrl+V, Ctrl+Shift+C, Ctrl+Shift+V, Ctrl+A, Ctrl+Z, Ctrl+Y, Ctrl+S, Ctrl+F, Ctrl+/, Ctrl+B, v.v.)
  if (mod.hasCtrlOrAlt && ev.key && ev.key.length === 1) {
    var lk = ev.key.toLowerCase();
    if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && (lk === 'c' || lk === 'x')) {
      ev.preventDefault();
      resetDirectBuffer();
      remoteClipboardActive = true;
      var cxCombo = mod.prefix + lk;
      var cxLabel = mod.labelPrefix + lk.toUpperCase();
      enqueueDirectHotkey(cxCombo, cxLabel, !!ev.repeat);
      if (!ev.repeat) flashStatus('⌨️ Đã gửi ' + cxLabel, true);
      return true;
    }
    if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && lk === 'v') {
      if (ev.shiftKey || (remoteClipboardActive && isCurrentDevPC())) {
        ev.preventDefault();
        resetDirectBuffer();
        var vCombo = mod.prefix + 'v';
        var vLabel = mod.labelPrefix + 'V';
        enqueueDirectHotkey(vCombo, vLabel, !!ev.repeat);
        if (!ev.repeat) flashStatus('⌨️ Đã gửi ' + vLabel, true);
        return true;
      }
      // Khi bấm Ctrl+V thường và chưa copy trên máy đích: để sự kiện paste của trình duyệt dán văn bản / hình ảnh từ thiết bị điều khiển sang
      return false;
    }
    ev.preventDefault();
    resetDirectBuffer();
    var charToken = (lk === ' ') ? 'space' : lk;
    var hkCombo = mod.prefix + charToken;
    var hkLabel = mod.labelPrefix + lk.toUpperCase();
    enqueueDirectHotkey(hkCombo, hkLabel, !!ev.repeat);
    if (!ev.repeat) flashStatus('⌨️ Đã gửi ' + hkLabel, true);
    return true;
  }

  if (mod.hasCtrlOrAlt) return false;

  // 5. Phím Backspace thông thường
  if (ev.key === 'Backspace') {
    var inp = document.getElementById('quick-txt-input');
    var cleanVal = inp ? (inp.value || '').replace(/\u200B/g, '') : '';
    if (document.activeElement !== inp || cleanVal.length === 0) {
      ev.preventDefault();
      resetDirectBuffer();
      enqueueDirectTextDelta(1, '', !!ev.repeat);
      return true;
    }
    // Khi inp đang có chữ trong từ hiện tại, để trình duyệt tự xóa 1 ký tự trong inp và kích hoạt onQuickInputChanged (hỗ trợ hoàn hảo Unikey/IBus trên bàn phím vật lý)
    return false;
  }

  return false;
}

function handleGlobalPhysicalKeyDown(ev) {
  if (isSleeping) return;
  if (isBlockingModalOrInputActive(ev.target)) return;
  recordActivity();

  var inp = document.getElementById('quick-txt-input');
  if (ev.target === inp) {
    // Đã được xử lý bởi onQuickInputKeyDown
    return;
  }

  if (handlePhysicalSpecialOrShortcut(ev)) {
    return;
  }

  if (ev.isComposing || ev.keyCode === 229) {
    ensureDesktopImeBridgeFocus();
    return;
  }

  // Ký tự in được từ bàn phím vật lý khi #quick-txt-input chưa được focus:
  // Trên máy tính (!isMobileTouchOS), focus ngay vào #quick-txt-input và KHÔNG gọi preventDefault()
  // để bộ gõ Tiếng Việt hệ thống (Unikey, EVKey, IBus, Fcitx, macOS/Windows IME) tự xử lý ký tự nguyên bản trong textarea!
  if (ev.key && ev.key.length === 1 && !ev.ctrlKey && !ev.altKey && !ev.metaKey) {
    if (inp && !isMobileTouchOS()) {
      ensureDesktopImeBridgeFocus();
      return;
    }
    ev.preventDefault();
    if (inp) {
      inp.removeAttribute('readonly');
      var bar = document.getElementById('smart-input-bar');
      var isNativeOpen = bar && bar.classList.contains('show') && (forceNativePhoneKbd || (getEffectiveRotation() === 0 && isMobileTouchOS()));
      if (!isNativeOpen) {
        inp.setAttribute('inputmode', 'none');
      }
      try { inp.focus({ preventScroll: true }); } catch(e) { try { inp.focus(); } catch(e2) {} }
      var curClean = (inp.value || '').replace(/\u200B/g, '');
      suppressQuickInputEvent = true;
      inp.value = DIRECT_SENTINEL + curClean + ev.key;
      try { inp.setSelectionRange(inp.value.length, inp.value.length); } catch(e) {}
      suppressQuickInputEvent = false;
      onQuickInputChanged();
    } else {
      enqueueDirectTextDelta(0, ev.key);
    }
  }
}

function handleGlobalPaste(ev) {
  if (isSleeping) return;
  if (isBlockingModalOrInputActive(ev.target)) return;
  var cd = ev.clipboardData || window.clipboardData;
  if (!cd) return;
  if (cd.files && cd.files.length > 0) {
    ev.preventDefault();
    handleImageUploadFiles(cd.files);
    return;
  }
  var pastedText = cd.getData ? cd.getData('text/plain') : '';
  if (pastedText) {
    ev.preventDefault();
    resetDirectBuffer();
    enqueueDirectTextDelta(0, pastedText);
    flashStatus('📋 Đã dán văn bản sang ' + (nameMap[currentDev] || currentDev), true);
  }
}

function focusQuickInput() {
  recordActivity();
  activateSmartKeyboardForOrientation();
}

function onQuickInputFocus(ev) {
  recordActivity();
  var inp = document.getElementById('quick-txt-input');
  var bar = document.getElementById('smart-input-bar');
  var isKbdShown = bar && bar.classList.contains('show');
  if (!isKbdShown) {
    if (inp) inp.setAttribute('inputmode', 'none');
    return;
  }
  if ((getEffectiveRotation() !== 0 || !isMobileTouchOS()) && !forceNativePhoneKbd) {
    if (inp) inp.setAttribute('inputmode', 'none');
    showLandscapeKeyboard();
  }
}

function onQuickInputBlur(ev) {
  var barNow = document.getElementById('smart-input-bar');
  if (barNow && barNow.classList.contains('show')) {
    lastQuickInputBlurTime = Date.now();
  }
  if (!isMobileTouchOS()) {
    setTimeout(ensureDesktopImeBridgeFocus, 25);
  }
  setTimeout(function() {
    var inp = document.getElementById('quick-txt-input');
    var bar = document.getElementById('smart-input-bar');
    var kbd = document.getElementById('vui-landscape-kbd');
    var btn = document.getElementById('btn-top-kbd');
    if (inp && document.activeElement !== inp) {
      inp.setAttribute('inputmode', 'none');
      if (bar && bar.classList.contains('show') && (!kbd || !kbd.classList.contains('show'))) {
        bar.classList.remove('show');
        if (btn) btn.classList.remove('active-btn');
        forceNativePhoneKbd = false;
        imeOpenedByUser = false;
        updateClearBtnVisibility();
      }
    }
  }, 180);
}

function onQuickInputCursorChanged(ev) {}

function onQuickInputChanged() {
  if (suppressQuickInputEvent) return;
  recordActivity();
  var inp = document.getElementById('quick-txt-input');
  if (!inp) return;

  var rawVal = inp.value || '';
  var hadSentinel = (rawVal.indexOf(DIRECT_SENTINEL) !== -1);
  var cleanVal = rawVal.replace(/\u200B/g, '');

  // Khi người dùng bấm Backspace trên bàn phím ảo hệ thống lúc bộ đệm từ đang rỗng (xóa mất ký tự sentinel \u200B)
  if (!hadSentinel && cleanVal.length === 0 && directSentText.length === 0) {
    resetDirectBuffer();
    enqueueDirectTextDelta(1, '');
    return;
  }

  var hasNewline = (cleanVal.indexOf('\n') !== -1 || cleanVal.indexOf('\r') !== -1);
  if (hasNewline) {
    cleanVal = cleanVal.replace(/[\r\n]+/g, '');
  }

  var normNew = cleanVal.normalize ? cleanVal.normalize('NFC') : cleanVal;
  var normOld = directSentText.normalize ? directSentText.normalize('NFC') : directSentText;

  var oldChars = Array.from(normOld);
  var newChars = Array.from(normNew);

  var p = 0;
  var minLen = Math.min(oldChars.length, newChars.length);
  while (p < minLen && oldChars[p] === newChars[p]) {
    p++;
  }
  var bkspCount = oldChars.length - p;
  var appendStr = newChars.slice(p).join('');

  directSentText = normNew;

  if (bkspCount > 0 || appendStr.length > 0) {
    enqueueDirectTextDelta(bkspCount, appendStr);
  }

  if (hasNewline) {
    resetDirectBuffer();
    enqueueDirectKey(66, 'Enter ↵');
    return;
  }

  if (!hadSentinel && !inp._isComposing) {
    suppressQuickInputEvent = true;
    inp.value = DIRECT_SENTINEL + cleanVal;
    try { inp.setSelectionRange(inp.value.length, inp.value.length); } catch(e) {}
    suppressQuickInputEvent = false;
  } else if (!inp._isComposing && cleanVal.length > 120 && /\s$/.test(cleanVal)) {
    resetDirectBuffer();
  }
}

function onQuickInputKeyDown(ev) {
  if (isSleeping) return;
  recordActivity();
  handlePhysicalSpecialOrShortcut(ev);
}

function shouldShowSendPaperPlane() {
  return false;
}

function onInlineSendOrEnterClick() {
  sendRemoteEnterKey();
}

function clearPendingAttachments(ev) {
  if (ev) ev.stopPropagation();
  pendingUploadFiles = [];
}

function updateClearBtnVisibility() {
  var topBtn = document.getElementById('btn-top-kbd');
  var bar = document.getElementById('smart-input-bar');
  var kbd = document.getElementById('vui-landscape-kbd');
  if (topBtn) {
    var isBarOpen = (bar && bar.classList.contains('show')) || (kbd && kbd.classList.contains('show'));
    if (isBarOpen) {
      topBtn.innerHTML = '⌨️ Đóng phím';
      topBtn.style.borderColor = 'rgba(52, 211, 153, 0.85)';
      topBtn.style.background = 'rgba(16, 185, 129, 0.32)';
    } else {
      topBtn.innerHTML = '⌨️ Bàn phím';
      topBtn.style.borderColor = 'rgba(96, 165, 250, 0.7)';
      topBtn.style.background = 'rgba(37, 99, 235, 0.34)';
    }
  }
}

function clearQuickText() {
  recordActivity();
  resetDirectBuffer();
}

function submitQuickText(thenEnter) {
  recordActivity();
  if (thenEnter) {
    resetDirectBuffer();
    enqueueDirectKey(66, 'Enter ↵');
  }
}

function triggerImageUpload() {
  recordActivity();
  var fileInp = document.getElementById('vui-img-upload');
  if (!fileInp) return;
  fileInp.value = '';
  fileInp.click();
}

function convertFileToPngBlob(file, cb) {
  var url = URL.createObjectURL(file);
  var img = new Image();
  img.onload = function() {
    URL.revokeObjectURL(url);
    var w = img.naturalWidth || img.width;
    var h = img.naturalHeight || img.height;
    var maxDim = 2048;
    if (w > maxDim || h > maxDim) {
      if (w >= h) {
        h = Math.round(h * maxDim / w);
        w = maxDim;
      } else {
        w = Math.round(w * maxDim / h);
        h = maxDim;
      }
    }
    var canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    var ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0, w, h);
    if (canvas.toBlob) {
      canvas.toBlob(function(blob) {
        cb(blob || file);
      }, 'image/png');
    } else {
      cb(file);
    }
  };
  img.onerror = function() {
    URL.revokeObjectURL(url);
    cb(file);
  };
  img.src = url;
}

function handleImageUploadFiles(files) {
  recordActivity();
  if (!files || files.length === 0) return;
  var list = [];
  for (var i = 0; i < files.length; i++) {
    list.push(files[i]);
  }
  uploadQueuedFilesNow(list, function() {
    var fileInp = document.getElementById('vui-img-upload');
    if (fileInp) fileInp.value = '';
  });
}

function uploadQueuedFilesNow(list, onDone) {
  var idx = 0;
  var CHUNK_SIZE = 20 * 1024 * 1024; // 20MB/chunk để truyền mượt qua Cloudflare Tunnel (vượt giới hạn 100MB)

  function sendPayload(f, blobToSend, kind, fileName) {
    var totalBytes = blobToSend.size || 0;
    if (totalBytes > CHUNK_SIZE && typeof blobToSend.slice === 'function') {
      var totalChunks = Math.ceil(totalBytes / CHUNK_SIZE);
      var uploadId = Date.now() + '_' + Math.floor(Math.random() * 1000000);
      var chunkIdx = 0;

      function sendNextChunk() {
        var start = chunkIdx * CHUNK_SIZE;
        var end = Math.min(totalBytes, start + CHUNK_SIZE);
        var chunkBlob = blobToSend.slice(start, end);
        var xhr = new XMLHttpRequest();
        var qParams = '?paste=1&kind=' + encodeURIComponent(kind) +
          '&name=' + encodeURIComponent(fileName) +
          '&upload_id=' + encodeURIComponent(uploadId) +
          '&chunk_idx=' + chunkIdx +
          '&chunk_total=' + totalChunks +
          getDevParam() + '&t=' + Date.now();
        xhr.open('POST', '/api/upload_image' + qParams, true);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        if (xhr.upload) {
          xhr.upload.onprogress = function(ev) {
            if (ev.lengthComputable && ev.total > 0) {
              var overallLoaded = start + ev.loaded;
              var pct = Math.min(99, Math.round((overallLoaded * 100) / totalBytes));
              flashStatus('✈️ Đang truyền ' + fileName + ' (' + pct + '%)...', true);
            }
          };
        }
        xhr.onload = function() {
          if (xhr.status === 200) {
            chunkIdx++;
            if (chunkIdx < totalChunks) {
              sendNextChunk();
            } else {
              flashStatus('✓ Đã truyền ' + fileName + ' & chèn vào máy từ xa!', true);
              triggerInteractiveCapture();
              setTimeout(uploadNext, 280);
            }
          } else if (xhr.status === 401) {
            flashStatus('🔑 Phiên kết nối cần mở khóa lại — Đang tải màn hình PIN...', false);
            setTimeout(function() { window.location.reload(); }, 600);
          } else {
            flashStatus('⚠️ Lỗi truyền file: HTTP ' + xhr.status, false);
            setTimeout(uploadNext, 280);
          }
        };
        xhr.onerror = function() {
          flashStatus('⚠️ Lỗi kết nối khi truyền file', false);
          setTimeout(uploadNext, 280);
        };
        xhr.send(chunkBlob);
      }
      sendNextChunk();
      return;
    }

    var xhr = new XMLHttpRequest();
    var qParams = '?paste=1&kind=' + encodeURIComponent(kind) + '&name=' + encodeURIComponent(fileName) + getDevParam() + '&t=' + Date.now();
    xhr.open('POST', '/api/upload_image' + qParams, true);
    xhr.setRequestHeader('Content-Type', blobToSend.type || 'application/octet-stream');
    if (xhr.upload) {
      xhr.upload.onprogress = function(ev) {
        if (ev.lengthComputable && ev.total > 0) {
          var pct = Math.round((ev.loaded * 100) / ev.total);
          flashStatus('✈️ Đang truyền ' + fileName + ' (' + pct + '%)...', true);
        }
      };
    }
    xhr.onload = function() {
      if (xhr.status === 200) {
        if (kind === 'image') {
          flashStatus('✓ Đã dán Hình ảnh vào máy từ xa (Ctrl+V)!', true);
        } else {
          flashStatus('✓ Đã truyền ' + fileName + ' & chèn vào máy từ xa!', true);
        }
      } else if (xhr.status === 401) {
        flashStatus('🔑 Phiên kết nối cần mở khóa lại — Đang tải màn hình PIN...', false);
        setTimeout(function() { window.location.reload(); }, 600);
        return;
      } else {
        flashStatus('⚠️ Lỗi truyền file: HTTP ' + xhr.status, false);
      }
      triggerInteractiveCapture();
      setTimeout(uploadNext, 280);
    };
    xhr.onerror = function() {
      flashStatus('⚠️ Lỗi kết nối khi truyền file', false);
      setTimeout(uploadNext, 280);
    };
    xhr.send(blobToSend);
  }

  function uploadNext() {
    if (idx >= list.length) {
      triggerInteractiveCapture();
      if (typeof onDone === 'function') onDone();
      return;
    }
    var f = list[idx++];
    var rawName = f.name || ('file_' + idx);
    var isStillImage = (f.type && f.type.indexOf('image/') === 0 && f.type !== 'image/gif') || /\.(heic|heif|jpg|jpeg|png|webp|bmp)$/i.test(rawName);
    if (isStillImage) {
      flashStatus('✈️ Đang xử lý & truyền ảnh (' + idx + '/' + list.length + ')...', true);
      convertFileToPngBlob(f, function(blob) {
        var pngName = rawName.replace(/\.[^.]+$/, '') + '.png';
        sendPayload(f, blob, 'image', pngName);
      });
    } else {
      flashStatus('✈️ Đang truyền file ' + rawName + ' (' + idx + '/' + list.length + ')...', true);
      sendPayload(f, f, 'file', rawName);
    }
  }
  uploadNext();
}

function openDevModal() {
  recordActivity();
  loadDeviceList();
  var el = document.getElementById('dev-modal');
  if (el) el.classList.add('show');
  updateDevModalSelection(currentDev);
}
function closeDevModal() {
  var el = document.getElementById('dev-modal');
  if (el) el.classList.remove('show');
}
function selectDevAndClose(dev) {
  switchDev(dev);
  closeDevModal();
}
function updateDevModalSelection(dev) {
  document.querySelectorAll('.dev-modal-card').forEach(function(el) { el.classList.remove('active'); });
  var activeCard = document.getElementById('dev-card-' + dev);
  if (activeCard) activeCard.classList.add('active');
}

function loadDeviceList() {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/devices?t=' + Date.now(), true);
  xhr.timeout = 3000;
  xhr.onload = function() {
    if (xhr.status === 200) {
      try {
        var devs = JSON.parse(xhr.responseText);
        if (Array.isArray(devs) && devs.length > 0) {
          renderDeviceModalList(devs);
        }
      } catch(e) {}
    }
  };
  xhr.send();
}

var devOrderMap = { 'tx3': 1, 'pc': 2, 'win11': 3, 'projector': 4, 'kaw': 5, 'tv360': 6 };

function renderDeviceModalList(devList) {
  var grid = document.getElementById('dev-modal-grid');
  if (!grid || !Array.isArray(devList) || devList.length === 0) return;

  var sorted = devList.slice().sort(function(a, b) {
    var pa = devOrderMap[a.id] || 100;
    var pb = devOrderMap[b.id] || 100;
    if (pa !== pb) return pa - pb;
    return String(a.id || '').localeCompare(String(b.id || ''));
  });

  var validIds = {};
  sorted.forEach(function(d) {
    if (d && d.id) validIds[d.id] = true;
  });

  Array.prototype.slice.call(grid.querySelectorAll('.dev-modal-card')).forEach(function(cardEl) {
    var cid = (cardEl.id || '').replace(/^dev-card-/, '');
    if (cid && !validIds[cid]) {
      cardEl.parentNode.removeChild(cardEl);
      delete knownDevices[cid];
    }
  });

  sorted.forEach(function(d) {
    if (!d || !d.id) return;
    knownDevices[d.id] = d;
    if (d.name) nameMap[d.id] = d.name;
    if (d.icon) devIcons[d.id] = d.icon + ' ';

    var statusHtml = d.online
      ? '<span style="color:#22c55e; font-weight:700;">● Online</span>'
      : '<span style="color:#94a3b8;">○ Offline</span>';
    var subHtml = statusHtml + (d.host ? (' • ' + d.host) : '');
    var wolHtml = (!d.online && d.has_wol)
      ? '<button class="dev-wol-btn" onclick="event.stopPropagation(); sendWoL(\'' + d.id + '\')" title="Đánh thức qua mạng">⚡ Bật</button>'
      : '';

    var card = document.getElementById('dev-card-' + d.id);
    if (card) {
      var iconEl = card.querySelector('.dev-card-icon');
      if (iconEl && d.icon) iconEl.textContent = d.icon;
      var nameEl = card.querySelector('.dev-card-name');
      if (nameEl && d.name && nameEl.textContent !== d.name) nameEl.textContent = d.name;
      var subEl = card.querySelector('.dev-card-sub');
      if (subEl && subEl.innerHTML !== subHtml) subEl.innerHTML = subHtml;
      var wolWrap = document.getElementById('dev-wol-' + d.id) || card.querySelector('.dev-wol-wrap');
      if (wolWrap && wolWrap.innerHTML !== wolHtml) wolWrap.innerHTML = wolHtml;
    } else {
      var div = document.createElement('div');
      div.className = 'dev-modal-card' + (d.id === currentDev ? ' active' : '');
      div.id = 'dev-card-' + d.id;
      div.setAttribute('onclick', "selectDevAndClose('" + d.id + "')");
      div.innerHTML =
        '<div class="dev-card-icon">' + (d.icon || '📱') + '</div>' +
        '<div class="dev-card-info">' +
          '<div class="dev-card-name">' + (d.name || d.id) + '</div>' +
          '<div class="dev-card-sub">' + subHtml + '</div>' +
        '</div>' +
        '<div class="dev-wol-wrap" id="dev-wol-' + d.id + '">' + wolHtml + '</div>' +
        '<div class="dev-card-check">✓</div>';
      grid.appendChild(div);
    }
  });

  if (!validIds[currentDev] && sorted.length > 0 && sorted[0].id) {
    switchDev(sorted[0].id);
    return;
  }

  updateDevModalSelection(currentDev);
  var screenDevEl = document.getElementById('screen-dev-name');
  if (screenDevEl) {
    screenDevEl.innerText = (devIcons[currentDev] || '') + (nameMap[currentDev] || currentDev);
  }
}

function sendWoL(dev) {
  recordActivity();
  flashStatus('⚡ Đang gửi gói tin Wake-on-LAN đánh thức ' + dev.toUpperCase() + '...', true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/wol?dev=' + encodeURIComponent(dev) + '&t=' + Date.now(), true);
  xhr.onload = function() {
    try {
      var res = JSON.parse(xhr.responseText);
      if (res.ok || res.status === 'ok') {
        flashStatus('✓ ' + (res.message || 'Đã gửi gói tin đánh thức!'), true);
        setTimeout(function() { loadDeviceList(); refreshScreen(true); }, 2500);
      } else {
        flashStatus('⚠️ ' + (res.error || 'Lỗi gửi WoL'), true);
      }
    } catch(e) {
      flashStatus('✓ Đã phát lệnh WoL', true);
    }
  };
  xhr.onerror = function() {
    flashStatus('⚠️ Không kết nối được tới server', true);
  };
  xhr.send();
}

function pcAction(act, name) {
  closeDrawer();
  if (act === 'poweroff' || act === 'reboot') {
    var ok = confirm("⚠️ XÁC NHẬN " + name.toUpperCase() + ":\n\nBạn có chắc chắn muốn thực hiện hành động này không?");
    if (!ok) return;
  }
  cmd(act, name);
}

function switchDev(dev) {
  var prevDev = currentDev;
  currentDev = dev;
  localStorage.setItem('vui_dev', dev);
  lastActivityTime = Date.now();
  if (prevDev && prevDev !== dev) {
    directSentText = '';
    directSentCaret = 0;
  }
  if (isSleeping) {
    isSleeping = false;
    sleepReason = '';
    var overlay = document.getElementById('screen-sleep-overlay');
    if (overlay) overlay.classList.remove('show');
    updateStreamButtonsUI();
  }
  isScreenLoading = false;
  consecutiveScreenErrors = 0;

  var img = document.getElementById('screen-img');
  var notice = document.getElementById('screen-tv360-notice');
  var offlineNotice = document.getElementById('screen-offline-notice');
  if (dev === 'tv360') {
    if (img) img.style.display = 'none';
    if (notice) notice.style.display = 'flex';
    if (offlineNotice) offlineNotice.style.display = 'none';
    checkTv360Status();
  } else {
    if (notice) notice.style.display = 'none';
    if (offlineNotice) offlineNotice.style.display = 'none';
    if (img) img.style.display = 'block';
  }
  
  updateDevModalSelection(dev);

  var isProj = (dev === 'projector' || dev === 'kaw');
  var pCtrl = document.getElementById('proj-controls');
  if (pCtrl) pCtrl.style.display = isProj ? 'block' : 'none';
  var deckProjRow = document.getElementById('deck-proj-row');
  if (deckProjRow) deckProjRow.style.display = isProj ? 'grid' : 'none';

  var isPC = isCurrentDevPC();
  var pcCtrl = document.getElementById('pc-controls');
  if (pcCtrl) pcCtrl.style.display = isPC ? 'block' : 'none';
  var pcModeBtn = document.getElementById('btn-pc-touch-mode');
  if (pcModeBtn) pcModeBtn.style.display = isPC ? 'inline-flex' : 'none';
  var pcWinBtn = document.getElementById('btn-pc-win-picker');
  if (pcWinBtn) pcWinBtn.style.display = isPC ? 'inline-flex' : 'none';
  var deckPcRow = document.getElementById('deck-pc-row');
  if (deckPcRow) deckPcRow.style.display = isPC ? 'grid' : 'none';
  if (isPC) updatePCTouchModeUI();
  
  if (knownDevices[dev]) {
    nameMap[dev] = knownDevices[dev].name;
    devIcons[dev] = (knownDevices[dev].icon || '📱') + ' ';
  }

  flashStatus('Đã chọn: ' + (nameMap[dev] || dev), true);
  var screenDevEl = document.getElementById('screen-dev-name');
  if (screenDevEl) screenDevEl.innerText = (devIcons[dev] || '') + (nameMap[dev] || dev);
  if (typeof resetZoom === 'function') {
    setZoomAndPan(1.0, 0, 0);
  }
  setTimeout(clampNavClusterPosition, 40);
  refreshScreen(true);
  if (isAutoStreamingMode() && !isSleeping) {
    scheduleNextAutoFrame();
  }
  updateSourceIndicator(null);
  checkCurrentSource();
}

function checkTv360Status() {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/status?dev=tv360&_t=' + Date.now(), true);
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      try {
        var st = JSON.parse(xhr.responseText);
        var badge = document.getElementById('tv360-status-badge');
        var pairBar = document.getElementById('tv360-pair-bar');
        if (st.paired && st.is_on) {
          if (badge) {
            badge.style.color = '#4ade80';
            badge.innerText = 'Viettel TV360 Box (Đã kết nối • ' + (st.current_app || 'Sẵn sàng') + ')';
          }
          if (pairBar) pairBar.style.display = 'none';
        } else if (st.needs_pairing) {
          if (badge) {
            badge.style.color = '#fbbf24';
            badge.innerText = 'Viettel TV360 Box (Online • Cần ghép nối PIN 1 lần)';
          }
          if (pairBar) pairBar.style.display = 'flex';
        } else if (st.box_online) {
          if (badge) {
            badge.style.color = '#4ade80';
            badge.innerText = 'Viettel TV360 Box (Online)';
          }
        }
      } catch(e) {}
    }
  };
  xhr.send();
}

function startTv360Pairing() {
  var pairBar = document.getElementById('tv360-pair-bar');
  var hint = document.getElementById('tv360-pair-hint');
  var inp = document.getElementById('tv360-pin-input');
  if (pairBar) pairBar.style.display = 'flex';
  if (hint) hint.innerHTML = '⏳ Đang gửi yêu cầu ghép nối tới TV360 (192.168.1.11:6467)...';
  flashStatus('Đang gửi mã ghép nối lên màn hình TV360...', true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/tv360/pair_start?dev=tv360&_t=' + Date.now(), true);
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) {
      if (xhr.status === 200) {
        if (hint) hint.innerHTML = '📺 <b>Đã hiện mã 6 ký tự trên màn hình TV360!</b> Hãy nhập mã đó vào ô bên phải:';
        flashStatus('Đã hiện mã PIN trên TV360! Hãy nhập 6 ký tự', true);
        if (inp) { inp.value = ''; inp.focus(); }
      } else {
        if (hint) hint.innerHTML = '⚠️ Chưa gửi được mã PIN (' + xhr.status + '). Hãy thử bấm lại Gửi mã lên TV.';
        flashStatus('Lỗi gửi mã PIN TV360', false);
      }
    }
  };
  xhr.send();
}

function submitTv360Pin() {
  var inp = document.getElementById('tv360-pin-input');
  var hint = document.getElementById('tv360-pair-hint');
  var pin = inp ? inp.value.trim() : '';
  if (!pin) {
    flashStatus('Vui lòng nhập mã 6 ký tự trên màn hình TV!', false);
    if (inp) inp.focus();
    return;
  }
  if (hint) hint.innerHTML = '⏳ Đang xác thực mã PIN <b>' + pin + '</b>...';
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/tv360/pair_pin?dev=tv360&pin=' + encodeURIComponent(pin) + '&_t=' + Date.now(), true);
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) {
      if (xhr.status === 200) {
        flashStatus('🎉 Đã ghép nối thành công Viettel TV360 Box!', true);
        checkTv360Status();
      } else {
        if (hint) hint.innerHTML = '❌ Mã PIN chưa đúng hoặc đã hết hạn. Bấm <b>Gửi mã lên TV</b> để lấy mã mới.';
        flashStatus('Mã PIN TV360 không hợp lệ', false);
      }
    }
  };
  xhr.send();
}

function openWindowModal() {
  recordActivity();
  var el = document.getElementById('win-modal');
  if (el) el.classList.add('show');
  loadWindowList();
}

function closeWindowModal() {
  var el = document.getElementById('win-modal');
  if (el) el.classList.remove('show');
}

var lastActiveWinTitle = '';
function updateWinPickerBadge(activeTitle) {
  if (typeof activeTitle === 'string') lastActiveWinTitle = activeTitle;
  var lbl = document.getElementById('pc-win-picker-label');
  var btn = document.getElementById('btn-pc-win-picker');
  if (!lbl || !btn) return;
  var en = isEN();
  btn.title = en
    ? 'Isolate stream & touch to a single window (Antigravity, Chrome, Terminal...) or Full Desktop'
    : 'Làm việc riêng với từng cửa sổ chương trình (Antigravity, Chrome, Terminal...) hoặc Toàn màn hình';
  if (lastActiveWinTitle && lastActiveWinTitle !== 'Toàn màn hình' && lastActiveWinTitle !== 'Full Desktop') {
    var shortT = lastActiveWinTitle.length > 14 ? (lastActiveWinTitle.substring(0, 14) + '…') : lastActiveWinTitle;
    lbl.innerText = '🎯 ' + shortT;
    btn.style.background = 'rgba(245,158,11,0.32)';
    btn.style.borderColor = '#fbbf24';
    btn.style.color = '#fef08a';
  } else {
    lbl.innerText = en ? '🪟 Windows' : '🪟 Cửa sổ';
    btn.style.background = 'rgba(59,130,246,0.25)';
    btn.style.borderColor = 'rgba(96,165,250,0.55)';
    btn.style.color = '#bfdbfe';
  }
}

function loadWindowList() {
  var grid = document.getElementById('win-modal-grid');
  if (grid) grid.innerHTML = '<div style="text-align:center; color:#94a3b8; padding:14px; font-size:12px;">⏳ Đang quét các cửa sổ đang mở trên máy tính...</div>';
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/windows?t=' + Date.now() + getDevParam(), true);
  xhr.timeout = 4000;
  xhr.onload = function() {
    if (!grid) return;
    try {
      var res = JSON.parse(xhr.responseText);
      var wins = res.windows || [];
      var activeId = res.active_id || '';
      if (wins.length === 0) {
        grid.innerHTML = '<div style="text-align:center; color:#94a3b8; padding:14px; font-size:12px;">Không tìm thấy cửa sổ nào đang mở.</div>';
        return;
      }
      var html = '';
      var activeTitle = '';
      wins.forEach(function(w) {
        var isAct = (w.id === activeId);
        if (isAct) activeTitle = w.app + ': ' + w.title;
        var safeTitle = (w.title || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
        html += '<div class="dev-modal-card' + (isAct ? ' active' : '') + '" onclick="selectPCWindow(\'' + w.id + '\', \'' + safeTitle + '\', false)">' +
          '<div class="dev-card-icon">' + (w.icon || '🪟') + '</div>' +
          '<div class="dev-card-info" style="min-width:0; flex:1;">' +
            '<div class="dev-card-name" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">' + (w.app ? ('<b style="color:#60a5fa;">[' + w.app + ']</b> ') : '') + w.title + '</div>' +
            '<div class="dev-card-sub">' + w.w + '×' + w.h + ' • Tọa độ (' + w.x + ', ' + w.y + ')' + (isAct ? ' • <b style="color:#fbbf24;">🎯 Đang khóa riêng</b>' : '') + '</div>' +
          '</div>' +
          '<button class="dev-wol-btn" style="background:#1e293b; border:1px solid #475569; color:#93c5fd;" onclick="event.stopPropagation(); selectPCWindow(\'' + w.id + '\', \'' + safeTitle + '\', true)" title="Phóng to cửa sổ này ra toàn màn hình">🗖 To</button>' +
        '</div>';
      });
      grid.innerHTML = html;
      updateWinPickerBadge(activeTitle);
    } catch(e) {
      grid.innerHTML = '<div style="text-align:center; color:#f87171; padding:14px; font-size:12px;">Lỗi đọc danh sách cửa sổ.</div>';
    }
  };
  xhr.onerror = xhr.ontimeout = function() {
    if (grid) grid.innerHTML = '<div style="text-align:center; color:#f87171; padding:14px; font-size:12px;">Không kết nối được tới máy tính.</div>';
  };
  xhr.send();
}

function selectPCWindow(id, title, maximize) {
  closeWindowModal();
  recordActivity();
  var act = maximize ? 'maximize' : 'select';
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/windows?action=' + act + '&id=' + encodeURIComponent(id) + getDevParam() + '&t=' + Date.now(), true);
  xhr.onload = function() {
    if (id === 'full' || id === '' || maximize) {
      updateWinPickerBadge('');
      flashStatus(maximize ? ('🗖 Đã phóng to: ' + title) : '🖥️ Đang xem Toàn màn hình', true);
    } else {
      updateWinPickerBadge(title);
      flashStatus('🎯 Đang làm việc riêng với: ' + title, true);
    }
    if (typeof resetZoom === 'function') setZoomAndPan(1.0, 0, 0);
    setTimeout(function() { refreshScreen(true); }, 150);
  };
  xhr.send();
}

function quickFocusAntigravity() {
  closeWindowModal();
  recordActivity();
  flashStatus('🚀 Đang tìm & đưa cửa sổ Antigravity lên đầu...', true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/windows?action=antigravity' + getDevParam() + '&t=' + Date.now(), true);
  xhr.onload = function() {
    try {
      var res = JSON.parse(xhr.responseText);
      if (res.ok && res.active_id) {
        updateWinPickerBadge('Antigravity');
        flashStatus('🚀 Đã khóa khung hình riêng vào Antigravity!', true);
      } else {
        updateWinPickerBadge('');
        flashStatus('🖥️ Đã chuyển về Toàn màn hình', true);
      }
    } catch(e) {}
    if (typeof resetZoom === 'function') setZoomAndPan(1.0, 0, 0);
    setTimeout(function() { refreshScreen(true); }, 150);
  };
  xhr.send();
}

function checkCurrentSource() {
  if (isSleeping || document.hidden) return;
  if (currentDev !== 'kaw' && currentDev !== 'projector' && currentDev !== 'pc') {
    updateSourceIndicator({ is_external: false, is_locked: false });
    return;
  }
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/source?dev=' + currentDev + '&t=' + Date.now(), true);
  xhr.timeout = 2500;
  xhr.onload = function() {
    if (xhr.status === 200) {
      try {
        var data = JSON.parse(xhr.responseText);
        updateSourceIndicator(data);
      } catch(e) {}
    }
  };
  xhr.onerror = function() {};
  xhr.send();
}

function updateSourceIndicator(data) {
  var wasLocked = remoteIsLocked;
  remoteIsLocked = !!(data && data.is_locked);
  if (wasLocked !== remoteIsLocked) {
    resetDirectBuffer();
    var kbd = document.getElementById('vui-landscape-kbd');
    if (kbd && kbd.classList.contains('show')) {
      renderLandscapeKeyboard();
    }
  }

  var badge = document.getElementById('wm-source-badge');
  var wm = document.getElementById('screen-watermark-source');
  var label = document.getElementById('src-watermark-label');
  var ctrlHint = document.getElementById('src-ctrl-hint');
  var btn = document.getElementById('src-switch-btn');

  if (data && data.is_external) {
    if (badge) {
      badge.textContent = data.source || 'HDMI';
      badge.style.display = 'inline-flex';
    }
    if (wm) {
      wm.style.display = 'flex';
      if (label) label.innerHTML = 'Đang xem: <b>' + (data.source_label || data.source) + '</b>';
      if (ctrlHint) {
        var devName = (currentDev === 'kaw') ? 'Máy chiếu KAW' : ((currentDev === 'projector') ? 'Máy chiếu Hyundai' : 'Máy chiếu');
        ctrlHint.innerHTML = '🎮 Nút bấm đang ĐK ' + devName;
      }
      if (btn) {
        if (data.target_dev) {
          btn.style.display = 'inline-block';
          btn.textContent = 'Đổi sang ĐK ' + (data.target_name || 'TV360') + ' ➔';
          btn.onclick = function(e) {
            e.stopPropagation();
            selectDevAndClose(data.target_dev);
          };
        } else {
          btn.style.display = 'none';
        }
      }
    }
  } else {
    if (badge) badge.style.display = 'none';
    if (wm) wm.style.display = 'none';
  }
}

setInterval(checkCurrentSource, 3000);

function getDevParam() {
  return '&dev=' + currentDev;
}

function key(code, name, holdMs) {
  recordActivity();
  holdMs = holdMs || 12;
  flashStatus('Đã gửi: ' + name, true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/key?code=' + code + '&hold=' + holdMs + getDevParam() + '&t=' + Date.now(), true);
  xhr.send();
  triggerInteractiveCapture();
}

function cmd(action, name) {
  recordActivity();
  flashStatus('Lệnh: ' + name, true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/cmd?action=' + action + getDevParam() + '&t=' + Date.now(), true);
  xhr.send();
  triggerInteractiveCapture();
}

function app(pkg, name) {
  recordActivity();
  flashStatus('Mở: ' + name, true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/app?pkg=' + encodeURIComponent(pkg) + getDevParam() + '&t=' + Date.now(), true);
  xhr.send();
  triggerInteractiveCapture();
}

function sendText(textToSend) {
  recordActivity();
  var t = textToSend;
  if (typeof t === 'undefined') {
    var inp = document.getElementById('txt-modal-input');
    t = inp ? inp.value : '';
  }
  if (!t || !t.trim()) return;
  flashStatus('Đang gửi chữ...', true);
  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/text?q=' + encodeURIComponent(t) + getDevParam() + '&t=' + Date.now(), true);
  xhr.setRequestHeader('Content-Type', 'text/plain; charset=utf-8');
  xhr.onload = function() {
    var inp = document.getElementById('txt-modal-input');
    if (inp) inp.value = '';
    flashStatus('✓ Đã dán chữ chuẩn 100%', true);
    triggerInteractiveCapture();
  };
  xhr.send(t);
}

// Drawer Open / Close
function openDrawer() {
  updateStreamButtonsUI();
  document.getElementById('drawer-modal').classList.add('show');
}
function closeDrawer() {
  document.getElementById('drawer-modal').classList.remove('show');
}

// Help Modal Open / Close
function openHelpModal() {
  var el = document.getElementById('help-modal');
  if (el) el.classList.add('show');
}
function closeHelpModal() {
  var el = document.getElementById('help-modal');
  if (el) el.classList.remove('show');
}

// Smart Text & Voice Input Modal Open / Close
function openTextModal() {
  recordActivity();
  var el = document.getElementById('text-modal');
  if (el) el.classList.add('show');
  var inp = document.getElementById('txt-modal-input');
  if (inp) {
    setTimeout(function() { inp.focus(); }, 150);
  }
}
function closeTextModal() {
  var el = document.getElementById('text-modal');
  if (el) el.classList.remove('show');
}

function submitModalText() {
  var inp = document.getElementById('txt-modal-input');
  if (!inp || !inp.value.trim()) return;
  var txt = inp.value.trim();
  sendText(txt);
  inp.value = '';
  closeTextModal();
}

function clearModalInput() {
  var inp = document.getElementById('txt-modal-input');
  if (inp) {
    inp.value = '';
    inp.focus();
  }
}

function sendAndroidKeyFromModal(code, name) {
  androidKey(code, name);
  flashStatus('Đã gửi: ' + name, true);
}

function pasteClipboardToInput() {
  var inp = document.getElementById('txt-modal-input');
  if (navigator.clipboard && navigator.clipboard.readText) {
    navigator.clipboard.readText().then(function(txt) {
      if (txt && inp) {
        inp.value = (inp.value ? inp.value + ' ' : '') + txt;
        inp.focus();
        flashStatus('Đã dán từ bộ nhớ tạm', true);
      }
    }).catch(function() {
      var p = prompt("Dán nội dung vào đây:");
      if (p && inp) {
        inp.value = (inp.value ? inp.value + ' ' : '') + p;
        inp.focus();
      }
    });
  } else {
    var p = prompt("Dán nội dung vào đây:");
    if (p && inp) {
      inp.value = (inp.value ? inp.value + ' ' : '') + p;
      inp.focus();
    }
  }
}

function triggerTVVoiceAssistant() {
  closeTextModal();
  androidKey(231, 'Trợ lý ảo TV');
  flashStatus('🎙️ Đã kích hoạt Tìm kiếm giọng nói trên TV!', true);
}

function handleVoiceAction() {
  recordActivity();
  toggleQuickInputBar(true);
  flashStatus('🎙️ Bấm nút Micro trên bàn phím điện thoại để nói tiếng Việt', true);
}

var imeCheckInFlight = false;
function checkIMEStatus() {
  // Không tự động mở hoặc đóng bàn phím khi chạm/vuốt màn hình (chỉ mở khi người dùng chủ động bấm nút ⌨️ Bàn phím)
}

function drawerAction(act, name) {
  closeDrawer();
  if (act === 'reboot') {
    var ok = confirm("⚠️ KHỞI ĐỘNG LẠI ĐẦU BOX:\n\nBạn có chắc chắn muốn khởi động lại toàn bộ đầu Box (thay vì rút điện) không?\n\n💡 Mẹo: Nếu chỉ bị đơ màn hình / Projectivy Launcher, hãy bấm nút [⚡ Làm mới Giao diện] sẽ hết đơ ngay trong 1 giây mà không cần khởi động lại máy!");
    if (!ok) return;
  }
  cmd(act, name);
}
function sleepTimerPrompt() {
  closeDrawer();
  if (currentDev === 'tx3') {
    alert("🛡️ BẢO VỆ TX3 MINI:\n\nKhông hẹn giờ tắt máy vì TX3 Mini cần hoạt động liên tục 24/7 cho Proxy DNSE!");
    return;
  }
  var mins = prompt("Hẹn giờ tắt máy (nhập số phút):", "60");
  if (mins && !isNaN(mins)) {
    flashStatus('Đã hẹn giờ tắt: ' + mins + ' phút', true);
    setTimeout(function() {
      key(26, 'Tắt nguồn');
    }, parseInt(mins) * 60 * 1000);
  }
}

function showTunnelInfo() {
  closeDrawer();
  var en = isEN();
  flashStatus('Đang kiểm tra link Internet...', true);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/tunnel?t=' + Date.now(), true);
  xhr.onload = function() {
    try {
      var res = JSON.parse(xhr.responseText);
      var shortUrl = res.short_url || '';
      var directUrl = res.url || '';
      if (directUrl || shortUrl) {
        var copyUrl = shortUrl || directUrl;
        var msg = en
          ? "🌐 FREE INTERNET REMOTE ACCESS (4G/5G):\n\n"
          : "🌐 ĐIỀU KHIỂN TỪ XA QUA INTERNET (4G/5G MIỄN PHÍ):\n\n";
        if (shortUrl) {
          msg += (en ? "📌 Permanent URL (GitHub Pages):\n👉 " : "📌 Link Cố Định Vĩnh Viễn (GitHub Pages):\n👉 ") + shortUrl + "\n\n";
        }
        msg += (en ? "🔗 Direct Cloudflare Tunnel URL:\n👉 " : "🔗 Link Cloudflare Tunnel trực tiếp:\n👉 ") + (directUrl || "(Syncing...)") + "\n\n";
        msg += (en ? "🔑 Security PIN: " : "🔑 Mã PIN bảo mật của bạn: ") + (res.pin || "(Run: vuiremote pin)") + "\n\n";
        msg += en
          ? "💡 Tip: Add this URL to your Phone Home Screen to control your PC (Antigravity / Claude Code) & TV from anywhere!"
          : "💡 Mẹo: Lưu link này ra Màn hình chính điện thoại để điều khiển Máy tính (Antigravity / Claude Code) & TV từ bất kỳ đâu!";
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(copyUrl);
          alert(msg + (en ? "\n\n✅ URL copied to clipboard!" : "\n\n✅ Đã tự động sao chép Link vào bộ nhớ tạm!"));
        } else {
          prompt(en ? "Copy Internet remote URL:" : "Copy link điều khiển Internet tại đây:", copyUrl);
        }
      } else {
        alert(en
          ? "🌐 Internet Tunnel (Cloudflare) is not running yet.\n\n👉 Start it for free in 3 seconds:\n• Run: vuiremote tunnel start\n• Or ask your AI Agent (Antigravity / Claude Code): 'Start Cloudflare Tunnel for VuiRemote'"
          : "🌐 Chưa bật đường truyền Internet (Cloudflare Tunnel).\n\n👉 Cách bật miễn phí trong 3 giây:\n• Gõ lệnh: vuiremote tunnel start\n• Hoặc bảo AI Agent (Antigravity / Claude Code): 'Hãy bật Cloudflare Tunnel cho VuiRemote'");
      }
    } catch(e) {
      alert((en ? "⚠️ Failed to fetch tunnel info: " : "⚠️ Không lấy được thông tin tunnel: ") + e);
    }
  };
  xhr.send();
}

function applyUILanguage() {
  var en = isEN();
  document.documentElement.lang = en ? 'en' : 'vi';
  var langBtn = document.getElementById('btn-top-lang');
  if (langBtn) {
    langBtn.innerText = en ? '🌐 EN' : '🌐 VI';
    langBtn.title = en ? 'Switch Language to Tiếng Việt (VI)' : 'Chuyển ngôn ngữ sang Tiếng Anh (English)';
  }
  var kbdLbl = document.getElementById('top-kbd-label');
  var kbdBtn = document.getElementById('btn-top-kbd');
  if (kbdLbl) kbdLbl.innerText = en ? '⌨️ Keyboard' : '⌨️ Bàn phím';
  if (kbdBtn) kbdBtn.title = en
    ? 'Toggle On-Screen Keyboard (Physical keyboard always types directly with zero overlay)'
    : 'Bật / Tắt bàn phím ảo trên màn hình (Bàn phím vật lý luôn gõ trực tiếp không cần hiện ô nhập)';

  var attLbl = document.getElementById('top-attach-label');
  var attBtn = document.getElementById('btn-top-attach');
  if (attLbl) attLbl.innerText = en ? '📎 File' : '📎 Tệp';
  if (attBtn) attBtn.title = en
    ? 'Teleport Files (Photos, Screenshots, Video, Audio, Docs) directly to the remote device'
    : 'Gửi trực tiếp File (Hình ảnh, Video, Âm thanh, Tài liệu) sang máy được điều khiển';

  var topGrip = document.getElementById('wm-top-drag-handle');
  if (topGrip) {
    topGrip.title = en
      ? 'Drag to move toolbar anywhere (never blocks window Title Bars!) — Double-tap to reset'
      : 'Kéo để di chuyển thanh công cụ đi bất kỳ đâu (tránh che Title Bar cửa sổ) — Chạm đúp để về vị trí gốc';
    topGrip.setAttribute('aria-label', en
      ? 'Drag to move main toolbar, or use arrow keys'
      : 'Kéo để di chuyển thanh công cụ chính, hoặc dùng phím mũi tên');
  }
  var topColBtn = document.getElementById('wm-top-collapse-btn');
  if (topColBtn) {
    topColBtn.title = en
      ? 'Collapse / Expand main toolbar so it never covers window Title Bars'
      : 'Thu gọn / Mở rộng thanh công cụ để không che thanh tiêu đề cửa sổ';
  }
  var navCluster = document.getElementById('wm-nav-cluster');
  var navTitle = document.getElementById('wm-nav-title');
  if (navCluster && navTitle) {
    var isNavCol = navCluster.classList.contains('collapsed');
    navTitle.innerText = isNavCol ? (en ? '🎮 Keys' : '🎮 Phím') : (en ? 'Navigate' : 'Điều hướng');
  }
  var kbdEl = document.getElementById('vui-landscape-kbd');
  if (kbdEl && kbdEl.classList.contains('show')) {
    renderLandscapeKeyboard();
  }

  var sleepOverlay = document.getElementById('screen-sleep-overlay');
  if (sleepOverlay) {
    var st = sleepOverlay.querySelector('.sleep-lock-title');
    var sd = sleepOverlay.querySelector('.sleep-lock-desc');
    var sb = sleepOverlay.querySelector('.sleep-unlock-btn');
    if (st) st.innerText = en ? 'Stream Paused (Zero-CPU Sleep)' : 'Truyền hình đang tạm nghỉ';
    if (sd) sd.innerText = en
      ? 'Automatically paused after 35s of inactivity to save CPU & battery.'
      : 'Đã tự động ngắt truyền hình khi không thao tác để tiết kiệm tài nguyên & chống đơ máy.';
    if (sb) sb.innerText = en ? '🔓 Tap Anywhere to Wake & Control' : '🔓 Chạm để Mở khóa & Điều khiển';
  }

  var devModalTitle = document.querySelector('#dev-modal .drawer-title');
  if (devModalTitle) devModalTitle.innerText = en ? '📱 Select Target Device' : '📱 Chọn Thiết Bị Điều Khiển';

  var winModalTitle = document.querySelector('#win-modal .drawer-title');
  if (winModalTitle) winModalTitle.innerText = en ? '🪟 Isolate Window (PC / Windows 11)' : '🪟 Chọn Cửa Sổ Làm Việc (PC / Windows 11)';
  var winBtns = document.querySelectorAll('#win-modal .btn');
  if (winBtns && winBtns.length >= 3) {
    winBtns[0].innerText = en ? '🖥️ Full Desktop' : '🖥️ Xem Toàn Màn Hình';
    winBtns[1].innerText = en ? '🚀 Focus Antigravity' : '🚀 Gọi Antigravity';
  }

  var drawerTitle = document.querySelector('#drawer-modal .drawer-title');
  if (drawerTitle) drawerTitle.innerText = en ? '⚙️ Settings & Quick Utilities' : '⚙️ Thiết Lập & Tiện Ích';

  var helpTitle = document.querySelector('#help-modal .help-title');
  if (helpTitle) helpTitle.innerText = en ? '❓ Multi-Touch Gestures & Remote Control Guide' : '❓ Hướng Dẫn Cử Chỉ Đa Điểm & Điều Khiển';
  var helpSecs = document.querySelectorAll('#help-modal .help-section');
  if (helpSecs && helpSecs.length >= 2) {
    if (en) {
      helpSecs[0].innerHTML =
        '<div class="help-sec-title">🖱️ 1. Single-Finger Touch (Click, Right-Click & Drag)</div>' +
        '<div class="help-item">• <b>Single Tap</b>: Left-click / Select item at touch position.</div>' +
        '<div class="help-item">• <b>Double-Tap</b>: Double-click (open folders, files, maximize windows on PC).</div>' +
        '<div class="help-item">• <b>Long-Press (0.4s) & Release</b>: <b>Right-Click</b> on PC (or Context Menu on TV).</div>' +
        '<div class="help-item">• <b>Hold (0.4s) & Drag</b>: Real-time <b>Drag & Drop</b> windows, select text, or move files!</div>' +
        '<div class="help-item">• <b>[🖱️ 1F: Drag / Scroll / Trackpad]</b>: Tap the green pill on the top bar to switch 1-finger mode.</div>';
      helpSecs[1].innerHTML =
        '<div class="help-sec-title">✌️ 2. Multi-Touch 2 & 3-Finger Gestures (MacBook Trackpad Style)</div>' +
        '<div class="help-item">• <b>2-Finger Parallel Swipe</b>: Smooth 4-way scrolling (Up / Down / Left / Right) at cursor.</div>' +
        '<div class="help-item">• <b>2-Finger Tap</b>: Instant <b>Right-Click</b>.</div>' +
        '<div class="help-item">• <b>2-Finger Pinch / Spread</b>: Hardware-crisp 2K Zoom from 1.0x up to 10.0x.</div>' +
        '<div class="help-item">• <b>3-Finger Tap</b>: Open Mission Control / Window Overview (Super / Windows key).</div>';
    } else {
      helpSecs[0].innerHTML =
        '<div class="help-sec-title">🖱️ 1. Thao Tác 1 Ngón (Chuột, Bấm Giữ & Kéo Thả)</div>' +
        '<div class="help-item">• <b>Chạm 1 lần (Tap)</b>: Click chuột trái / Chọn mở mục tại vị trí chạm.</div>' +
        '<div class="help-item">• <b>Chạm đúp nhanh (Double-Tap)</b>: Nhấp đúp chuột trái (mở thư mục, file, phóng to cửa sổ trên PC).</div>' +
        '<div class="help-item">• <b>Bấm giữ 0.4s rồi nhả (Long-Press)</b>: Click <b>Chuột phải</b> trên PC (hoặc mở Menu ngữ cảnh trên TV).</div>' +
        '<div class="help-item">• <b>Bấm giữ 0.4s rồi kéo đi (Hold & Drag)</b>: <b>Kéo thả (Drag & Drop)</b> cửa sổ, bôi đen văn bản, di chuyển file theo thời gian thực!</div>' +
        '<div class="help-item">• <b>Nút [🖱️ 1Ngón: Kéo thả / Cuộn / Bàn rê]</b>: Trên PC, bấm nút xanh trên thanh đầu để đổi nhanh chế độ rê 1 ngón.</div>';
      helpSecs[1].innerHTML =
        '<div class="help-sec-title">✌️ 2. Cử Chỉ Đa Điểm 2 & 3 Ngón (Như Trackpad MacBook)</div>' +
        '<div class="help-item">• <b>Vuốt 2 ngón song song (2-Finger Scroll)</b>: Cuộn trang mượt mà 4 chiều (Lên / Xuống / Trái / Phải) ngay tại vị trí con trỏ.</div>' +
        '<div class="help-item">• <b>Chạm 2 ngón cùng lúc (2-Finger Tap)</b>: Click <b>Chuột phải</b> tức thì.</div>' +
        '<div class="help-item">• <b>Chụm / Tách 2 ngón (Pinch Zoom)</b>: Phóng to / thu nhỏ màn hình từ 1.0x đến 10.0x.</div>' +
        '<div class="help-item">• <b>Chạm 3 ngón (3-Finger Tap)</b>: Mở màn hình Đa nhiệm / Overview cửa sổ (Phím Super/Windows).</div>';
    }
  }
  var helpCloseBtn = document.querySelector('#help-modal .btn');
  if (helpCloseBtn) helpCloseBtn.innerText = en ? 'Got It — Start Controlling' : 'Đã hiểu & Bắt đầu dùng';

  updateStreamButtonsUI();
  updatePCTouchModeUI();
  updateWinPickerBadge(lastActiveWinTitle);
}

function toggleUILanguage() {
  recordActivity();
  uiLang = (uiLang === 'en') ? 'vi' : 'en';
  try { localStorage.setItem('vui_lang', uiLang); } catch(e) {}
  applyUILanguage();
  flashStatus(uiLang === 'en' ? '🌐 Language switched to English (EN)' : '🌐 Đã chuyển giao diện sang Tiếng Việt (VI)', true);
}

// Khởi tạo bộ đệm gõ trực tiếp với ô nhập hoàn toàn vô hình
(function initDraftAndMultiline() {
  try {
    localStorage.removeItem('vui_draft_text');
    localStorage.removeItem('vui_draft_caret');
  } catch(e) {}
  resetDirectBuffer();
  applyInputModeUI();
  updateClearBtnVisibility();
})();

// Initialize active device, auto/90° rotation, and 0.38s smart stream mode on load
if (rotMode === 'auto') enableSensorAutoRotate();
setScreenRotation(screenRotation, false);
switchDev(currentDev);
setStreamMode(streamMode);
applyUILanguage();
loadDeviceList();
setInterval(loadDeviceList, 15000);
setTimeout(applyImageTransform, 100);
setTimeout(initNavClusterDrag, 120);
</script>
</body>
</html>`

func handleCLICommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	cmd := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(args[0])), "--")
	cmd = strings.TrimPrefix(cmd, "-")

	switch cmd {
	case "help", "h":
		fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
		fmt.Println("║   🚀 VuiRemote CLI — AI-Agent Native Multi-Device Remote Hub     ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
		fmt.Println("Usage / Cách dùng:")
		fmt.Println("  vuiremote                      Start VuiRemote Hub server (default) / Chạy máy chủ")
		fmt.Println("  vuiremote status               Show LAN IP, 4G URL & PIN / Xem trạng thái & PIN")
		fmt.Println("  vuiremote devices              List configured devices (devices.json) / Danh sách thiết bị")
		fmt.Println("  vuiremote pin                  Show current Internet PIN / Xem mã PIN hiện tại")
		fmt.Println("  vuiremote pin <4_DIGITS>       Set a new custom PIN (e.g. vuiremote pin 6868)")
		fmt.Println("  vuiremote pin --regen          Generate a new random 4-digit PIN / Sinh PIN ngẫu nhiên")
		fmt.Println("  vuiremote tunnel               Show Internet (4G/5G) remote URL / Xem Link điều khiển 4G")
		fmt.Println("  vuiremote tunnel start [port]  Start free Cloudflare Quick Tunnel in background")
		fmt.Println("  vuiremote tunnel stop          Stop Cloudflare Tunnel / Dừng dịch vụ Tunnel")
		return true

	case "pin":
		if len(args) >= 2 {
			arg := strings.TrimSpace(args[1])
			if arg == "--regen" || arg == "regen" || arg == "random" {
				newPin := generateRandomPin()
				if err := saveActivePin(newPin); err != nil {
					fmt.Printf("❌ Failed to save PIN / Không thể lưu mã PIN: %v\n", err)
					return true
				}
				fmt.Printf("🔑 Generated new random PIN / Đã sinh mã PIN mới: %s\n", newPin)
				return true
			}
			if len(arg) < 4 {
				fmt.Println("⚠️ PIN must be at least 4 characters / Mã PIN phải có ít nhất 4 ký tự (e.g. vuiremote pin 6868)")
				return true
			}
			if err := saveActivePin(arg); err != nil {
				fmt.Printf("❌ Failed to save PIN / Không thể lưu mã PIN: %v\n", err)
				return true
			}
			fmt.Printf("✅ Updated Internet security PIN / Đã cập nhật mã PIN thành: %s\n", arg)
			return true
		}
		fmt.Printf("🔑 Current Internet Security PIN / Mã PIN hiện tại: %s\n", getActivePin())
		fmt.Println("   (Required over 4G/5G Internet; bypassed automatically on trusted home LAN Wi-Fi)")
		return true

	case "devices":
		initDefaultDevices()
		deviceRegistryMu.RLock()
		defer deviceRegistryMu.RUnlock()
		fmt.Printf("📱 Devices / Danh sách thiết bị (%s):\n", getDevicesFilePath())
		for _, d := range deviceRegistry {
			if d != nil {
				fmt.Printf("  • %-10s | %s %-18s | %-19s | MAC: %s\n", d.ID, d.Icon, d.Name, d.Host, d.MAC)
			}
		}
		return true

	case "tunnel":
		if len(args) >= 2 {
			sub := strings.ToLower(strings.TrimSpace(args[1]))
			if sub == "start" {
				port := "8090"
				if isAndroid() {
					port = "8080"
				}
				if len(args) >= 3 && strings.TrimSpace(args[2]) != "" {
					port = strings.TrimSpace(args[2])
				}
				logPaths := getTunnelLogPaths()
				logFile := logPaths[0]
				_ = os.MkdirAll(filepath.Dir(logFile), 0755)
				shCmd := fmt.Sprintf("nohup cloudflared tunnel --url http://127.0.0.1:%s --no-autoupdate >%s 2>&1 &", port, logFile)
				_ = exec.Command("sh", "-c", shCmd).Start()
				fmt.Printf("⏳ Starting free Cloudflare Quick Tunnel to port :%s / Đang khởi tạo đường truyền...\n", port)
				for i := 0; i < 12; i++ {
					time.Sleep(1 * time.Second)
					if u := readActiveTunnelURL(); u != "" {
						syncTunnelURLToGist()
						cfg := readGistSyncConfig()
						fmt.Printf("✅ Internet Remote Access Active / Đã bật điều khiển qua Internet thành công!\n")
						if cfg.ShortURL != "" {
							fmt.Printf("   📌 Permanent URL (GitHub Pages) : %s\n", cfg.ShortURL)
						}
						fmt.Printf("   🔗 Direct Cloudflare URL        : %s\n", u)
						fmt.Printf("   🔑 Unlock PIN                   : %s\n", getActivePin())
						return true
					}
				}
				fmt.Printf("⚠️ cloudflared started in background (log: %s). Run 'vuiremote tunnel' in a few seconds.\n", logFile)
				return true
			} else if sub == "stop" {
				_ = exec.Command("killall", "cloudflared").Run()
				fmt.Println("🛑 Stopped Cloudflare Tunnel / Đã dừng Cloudflare Tunnel.")
				return true
			}
		}
		u := readActiveTunnelURL()
		cfg := readGistSyncConfig()
		fmt.Println("🌐 Internet Remote Status (4G/5G) / Trạng thái Điều khiển qua Internet:")
		if cfg.ShortURL != "" {
			fmt.Printf("  📌 Permanent URL (GitHub Pages) : %s\n", cfg.ShortURL)
		}
		if u != "" {
			fmt.Printf("  🔗 Active Cloudflare URL        : %s\n", u)
		} else {
			fmt.Println("  🔗 Active Cloudflare URL        : (Stopped — run 'vuiremote tunnel start' to enable)")
		}
		fmt.Printf("  🔑 Security PIN                 : %s\n", getActivePin())
		return true

	case "status":
		initDefaultDevices()
		ip := getCurrentLocalIP()
		port := os.Getenv("PORT")
		if port == "" {
			if isAndroid() {
				port = "8080"
			} else {
				port = "8090"
			}
		}
		u := readActiveTunnelURL()
		cfg := readGistSyncConfig()
		fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
		fmt.Println("║           📡 VUIREMOTE SYSTEM STATUS / TRẠNG THÁI HỆ THỐNG       ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
		fmt.Printf("  🏠 Home LAN URL (Wi-Fi)        : http://%s:%s (PIN-free / Miễn hỏi PIN)\n", ip, port)
		if cfg.ShortURL != "" {
			fmt.Printf("  📌 Permanent 4G URL            : %s\n", cfg.ShortURL)
		}
		if u != "" {
			fmt.Printf("  🌐 Direct Cloudflare URL       : %s\n", u)
		} else {
			fmt.Println("  🌐 Direct Cloudflare URL       : (Stopped — run 'vuiremote tunnel start')")
		}
		fmt.Printf("  🔑 Internet Security PIN       : %s (Brute-force lock: 15m after 5 tries)\n", getActivePin())
		fmt.Printf("  📂 Device Registry File        : %s (%d devices)\n", getDevicesFilePath(), len(deviceRegistry))
		return true
	}
	return false
}

func main() {
	if len(os.Args) > 1 && handleCLICommand(os.Args[1:]) {
		return
	}

	if isAndroid() {
		sysSetsidAndIgnoreSignals()
		boostProcessPriority()
		go func() {
			for {
				time.Sleep(20 * time.Second)
				boostProcessPriority()
			}
		}()
	}

	// Initialize input devices
	initInputDevice()
	initDefaultDevices()
	startClientAutoAnnounce()

	// Start background continuous screen capture producer
	go startScreenCaptureLoop()

	// 1. Start Zank Remote Host (UDP 1028 + TCP 1029)
	go startZankUDPServer()
	go startZankTCPServer()

	// 2. Start Web Remote Server on :8080
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !isRequestAuthenticated(r) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Write([]byte(pinLockHTML))
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Write([]byte(htmlPage))
	})

	http.HandleFunc("/api/auth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		clientIP := getClientIP(r)
		if allowed, waitSec := checkAuthRateLimit(clientIP); !allowed {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":"locked","retry_after_sec":%d}`, waitSec)))
			return
		}
		pin := strings.TrimSpace(r.URL.Query().Get("pin"))
		if pin == "" {
			r.ParseForm()
			pin = strings.TrimSpace(r.FormValue("pin"))
		}
		expectedPin := getActivePin()
		if pin != "" && subtle.ConstantTimeCompare([]byte(pin), []byte(expectedPin)) == 1 {
			recordAuthResult(clientIP, true)
			token := computeAuthToken(expectedPin)
			http.SetCookie(w, &http.Cookie{
				Name:     "vui_session",
				Value:    token,
				Path:     "/",
				MaxAge:   30 * 86400,
				HttpOnly: false,
				SameSite: http.SameSiteLaxMode,
			})
			w.Write([]byte(fmt.Sprintf(`{"ok":true,"token":"%s"}`, token)))
			return
		}
		rem := recordAuthResult(clientIP, false)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":"invalid_pin","remaining_attempts":%d}`, rem)))
	})

	http.HandleFunc("/api/tunnel", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		if !requireAuth(w, r) {
			return
		}

		tunnelURL := readActiveTunnelURL()
		cfg := readGistSyncConfig()
		pin := getActivePin()
		respObj := map[string]string{
			"url":       tunnelURL,
			"short_url": cfg.ShortURL,
			"pin":       pin,
		}
		b, _ := json.Marshal(respObj)
		w.Write(b)
	})

	http.HandleFunc("/windows", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		paths := []string{
			"/home/tao/Projects/VuiRemote/bin/vuiremote_windows_amd64.exe",
			"/data/local/tmp/vuiremote_windows_amd64.exe",
			"bin/vuiremote_windows_amd64.exe",
		}
		for _, p := range paths {
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				w.Header().Set("Content-Disposition", `attachment; filename="VuiRemote_Windows11.exe"`)
				w.Header().Set("Content-Type", "application/octet-stream")
				http.ServeFile(w, r, p)
				return
			}
		}
		http.Error(w, "File VuiRemote_Windows11.exe not found on this node", http.StatusNotFound)
	})

	http.HandleFunc("/tv.m3u", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		http.ServeFile(w, r, "/sdcard/tv.m3u")
	})

	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		if forwardIfRemote(w, r) {
			return
		}
		w.Write([]byte(fmt.Sprintf(`{"status":"online","device":"%s","ip":"%s","mac":"%s","platform":"%s","is_android":%t}`,
			myDeviceType, getCurrentLocalIP(), getLocalMAC(), runtime.GOOS, isAndroid())))
	})

	http.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		if !requireAuth(w, r) {
			return
		}

		deviceRegistryMu.RLock()
		list := make([]*DeviceInfo, 0, len(deviceRegistry))
		for _, d := range deviceRegistry {
			dCopy := *d
			list = append(list, &dCopy)
		}
		deviceRegistryMu.RUnlock()

		devPriority := func(id string) int {
			switch id {
			case "tx3":
				return 1
			case "pc":
				return 2
			case "win11":
				return 3
			case "projector":
				return 4
			case "kaw":
				return 5
			case "tv360":
				return 6
			default:
				return 100
			}
		}
		for i := 0; i < len(list); i++ {
			for j := i + 1; j < len(list); j++ {
				pi, pj := devPriority(list[i].ID), devPriority(list[j].ID)
				if pj < pi || (pj == pi && list[j].ID < list[i].ID) {
					list[i], list[j] = list[j], list[i]
				}
			}
		}

		var wg sync.WaitGroup
		for _, d := range list {
			if myDeviceType == d.ID {
				d.Online = true
				continue
			}
			wg.Add(1)
			go func(dev *DeviceInfo) {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", dev.Host, 1200*time.Millisecond)
				if err == nil {
					conn.Close()
					dev.Online = true
				} else {
					dev.Online = false
				}
			}(d)
		}
		wg.Wait()

		json.NewEncoder(w).Encode(list)
	})

	http.HandleFunc("/api/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		var reg DeviceInfo
		if r.Method == http.MethodPost {
			json.NewDecoder(r.Body).Decode(&reg)
		} else {
			reg.ID = r.URL.Query().Get("id")
			reg.Name = r.URL.Query().Get("name")
			reg.Icon = r.URL.Query().Get("icon")
			reg.Host = r.URL.Query().Get("host")
			reg.MAC = r.URL.Query().Get("mac")
			reg.Type = r.URL.Query().Get("type")
			reg.Platform = r.URL.Query().Get("platform")
		}

		if reg.ID == "" {
			http.Error(w, `{"error":"id_required"}`, http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("delete") == "1" || r.URL.Query().Get("action") == "delete" {
			deviceRegistryMu.Lock()
			delete(deviceRegistry, reg.ID)
			deviceRegistryMu.Unlock()
			saveDevicesToFile()
			fmt.Printf("[DEVICE REGISTRY] Deleted device '%s'\n", reg.ID)
			w.Write([]byte(fmt.Sprintf(`{"ok":true,"deleted":"%s"}`, reg.ID)))
			return
		}
		if reg.Host == "" {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			reg.Host = host + ":8080"
		}
		if reg.Name == "" {
			reg.Name = strings.ToUpper(reg.ID)
		}
		if reg.Icon == "" {
			reg.Icon = "📱"
		}
		if reg.MAC != "" {
			reg.HasWOL = true
		}
		reg.Online = true
		reg.LastSeen = time.Now().Unix()

		deviceRegistryMu.Lock()
		deviceRegistry[reg.ID] = &reg
		deviceRegistryMu.Unlock()

		saveDevicesToFile()
		fmt.Printf("[DEVICE REGISTRY] Registered '%s' (%s) at %s [MAC: %s]\n", reg.ID, reg.Name, reg.Host, reg.MAC)

		w.Write([]byte(fmt.Sprintf(`{"ok":true,"id":"%s"}`, reg.ID)))
	})

	http.HandleFunc("/api/wol", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		if !requireAuth(w, r) {
			return
		}

		dev := r.URL.Query().Get("dev")
		mac := r.URL.Query().Get("mac")

		if mac == "" && dev != "" {
			deviceRegistryMu.RLock()
			if d, ok := deviceRegistry[dev]; ok && d.MAC != "" {
				mac = d.MAC
			}
			deviceRegistryMu.RUnlock()
		}

		if mac == "" {
			http.Error(w, `{"ok":false,"status":"error","error":"mac_not_found"}`, http.StatusBadRequest)
			return
		}

		err := sendWoL(mac)
		if err != nil {
			fmt.Printf("[WOL ERR] %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf(`{"ok":false,"status":"error","error":"%v"}`, err)))
			return
		}

		fmt.Printf("[WOL SENT] Wake-on-LAN magic packet broadcasted for MAC: %s\n", mac)
		w.Write([]byte(fmt.Sprintf(`{"ok":true,"status":"ok","mac":"%s","message":"Đã gửi lệnh đánh thức (Magic Packet) tới %s"}`, mac, strings.ToUpper(dev))))
	})

	var keyDebounceMu sync.Mutex
	var lastKeySig string
	var lastKeyAt time.Time

	http.HandleFunc("/api/key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !requireAuth(w, r) {
			return
		}
		codeStr := r.URL.Query().Get("code")
		holdStr := r.URL.Query().Get("hold")
		dev := r.URL.Query().Get("dev")
		seq, _ := strconv.ParseInt(r.URL.Query().Get("seq"), 10, 64)
		count, _ := strconv.Atoi(r.URL.Query().Get("count"))
		if count <= 0 {
			count = 1
		}
		if count > 8 {
			count = 8
		}
		isRep := r.URL.Query().Get("rep") == "1"

		if r.URL.Query().Get("cancel") == "1" {
			if forwardIfRemote(w, r) {
				return
			}
			clearPCOrderedInputQueue()
			w.Write([]byte("CANCELED"))
			return
		}

		if seq <= 0 && count <= 1 && !isRep {
			sig := dev + ":" + codeStr
			keyDebounceMu.Lock()
			now := time.Now()
			if sig == lastKeySig && now.Sub(lastKeyAt) < 8*time.Millisecond {
				keyDebounceMu.Unlock()
				w.Write([]byte("DEBOUNCED"))
				return
			}
			lastKeySig = sig
			lastKeyAt = now
			keyDebounceMu.Unlock()
		}

		if forwardIfRemote(w, r) {
			return
		}

		// SAFETY GUARD: NEVER shut down or sleep TX3 Mini!
		if (myDeviceType == "tx3" && (dev == "" || dev == "local" || dev == "tx3" || dev == "192.168.1.140")) || dev == "tx3" {
			if codeStr == "26" {
				fmt.Println("[SAFETY GUARD] Blocked power off key (26) for TX3 Mini - 24/7 DNSE proxy protected!")
				w.Write([]byte("TX3_POWER_PROTECTED"))
				return
			}
		}

		holdMs := 12
		if holdStr != "" {
			if h, err := strconv.Atoi(holdStr); err == nil {
				holdMs = h
			}
		}
		if codeStr != "" {
			code, err := strconv.Atoi(codeStr)
			if err == nil {
				for i := 0; i < count; i++ {
					applyRemoteSimKey(code)
				}
				if !isAndroid() {
					invalidateScreenCache()
					cCopy := code
					cntCopy := count
					repCopy := isRep
					enqueueSequencedPCInput(seq, func() {
						sendLinuxPCKeyCount(cCopy, cntCopy, repCopy)
					})
				} else {
					go func(c, cnt, h int) {
						for i := 0; i < cnt; i++ {
							triggerKey(c, h)
						}
					}(code, count, holdMs)
				}
			} else {
				if holdMs > 100 {
					go runSh(fmt.Sprintf("input keyevent --longpress %s", codeStr))
				} else {
					go runSh(fmt.Sprintf("input keyevent %s", codeStr))
				}
			}
		}
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/windows", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}

		action := r.URL.Query().Get("action")
		id := r.URL.Query().Get("id")

		if action == "select" || action == "maximize" {
			ok := focusPCWindow(id, action == "maximize")
			w.Write([]byte(fmt.Sprintf(`{"ok":%t,"active_id":%q}`, ok, getActivePCWindowID())))
			return
		}
		if action == "antigravity" {
			wins := listPCWindows()
			targetID := ""
			for _, win := range wins {
				if win.App == "Antigravity" || strings.Contains(strings.ToLower(win.Title), "antigravity") {
					targetID = win.ID
					break
				}
			}
			if targetID == "" && len(wins) > 0 {
				targetID = wins[0].ID
			}
			if targetID != "" && getActivePCWindowID() != targetID {
				focusPCWindow(targetID, false)
			} else {
				focusPCWindow("full", false)
			}
			w.Write([]byte(fmt.Sprintf(`{"ok":true,"active_id":%q}`, getActivePCWindowID())))
			return
		}

		wins := listPCWindows()
		resp := struct {
			ActiveID string         `json:"active_id"`
			Windows  []PCWindowInfo `json:"windows"`
		}{
			ActiveID: getActivePCWindowID(),
			Windows:  wins,
		}
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/api/cmd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}

		action := r.URL.Query().Get("action")
		fmt.Printf("[CMD] action=%s\n", action)
		go func(act string) {
			switch act {
			case "mutescreen":
				runSh("am start -a android.intent.action.VIEW -d 'data:text/html;charset=utf-8,%3Chtml%20style=%22background:black;%22%3E%3Cbody%20style=%22background:black;margin:0;%22%3E%3C/body%3E%3C/html%3E' 2>/dev/null")
			case "unmutescreen":
				triggerKey(3, 12)
			case "bluetooth":
				if myDeviceType == "projector" {
					triggerKey(271, 50)
				}
				runSh("am start -a android.settings.BLUETOOTH_SETTINGS 2>/dev/null || am start -n com.android.tv.settings/.MainSettings")
			case "wifi":
				if myDeviceType == "projector" {
					triggerKey(270, 50)
				}
				runSh("am start -a android.settings.WIFI_SETTINGS 2>/dev/null || am start -n com.android.tv.settings/.MainSettings")
			case "display":
				runSh("am start -a android.settings.DISPLAY_SETTINGS 2>/dev/null || am start -n com.android.tv.settings/.device.display.DisplayActivity")
			case "settings":
				runSh("am start -n com.android.tv.settings/.MainSettings 2>/dev/null || am start -a android.settings.SETTINGS")
			case "apps":
				runSh("am start -a android.settings.APPLICATION_SETTINGS 2>/dev/null || am start -n com.android.tv.settings/.device.apps.AppsActivity")
			case "restart_launcher":
				runSh("input keyevent 4; am force-stop com.spocky.projengmenu 2>/dev/null; am force-stop com.newlink.overseaslauncher 2>/dev/null; am force-stop io.freemytv 2>/dev/null; am kill-all; sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; am start -a android.intent.action.MAIN -c android.intent.category.HOME")
				invalidateScreenCache()
			case "clean":
				runSh("am kill-all; sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null")
				invalidateScreenCache()
			case "poweroff":
				if runtime.GOOS == "windows" {
					exec.Command("shutdown", "/s", "/t", "0").Start()
					return
				}
				if !isAndroid() {
					exec.Command("systemctl", "poweroff", "-i").Start()
					return
				}
				runSh("svc power shutdown || reboot -p")
			case "wake":
				if runtime.GOOS == "windows" {
					winWakeDisplay()
					sendLinuxPCKey(62) // Space to slide up Windows 11 Lock Screen cover
					return
				}
				if !isAndroid() {
					sendLinuxPCKey(62)
					return
				}
				triggerKey(224, 12)
			case "suspend":
				if runtime.GOOS == "windows" {
					winSmartSleep()
					return
				}
				if !isAndroid() {
					exec.Command("systemctl", "suspend").Start()
					return
				}
			case "reboot":
				if runtime.GOOS == "windows" {
					exec.Command("shutdown", "/r", "/t", "0").Start()
					return
				}
				if !isAndroid() {
					exec.Command("systemctl", "reboot").Start()
					return
				}
				runSh("svc power reboot || reboot")
			case "focus_up":
				triggerKey(265, 120)
			case "focus_down":
				triggerKey(266, 120)
			case "autofocus":
				triggerKey(289, 50)
				runSh("am start -a com.zhiying.AUTO_FOCUS 2>/dev/null; am startservice -a com.zhiying.AUTO_FOCUS_SERVICE 2>/dev/null; am start -a android.intent.action.VIEW -d alliance://start_auto_focus 2>/dev/null")
			case "keystone":
				if myDeviceType == "kaw" {
					runSh("am start -n com.example.trapezoid/.MainActivity 2>/dev/null || am start -a android.intent.tecon.trapezoid 2>/dev/null || monkey -p com.example.trapezoid -c android.intent.category.LAUNCHER 1")
				} else {
					triggerKey(196, 50)
					runSh("am start -a com.zhiying.ONE_AUTO_CORRECTION_KEYSTONE 2>/dev/null; am start -a android.intent.action.VIEW -d alliance://start_auto_keystone 2>/dev/null")
				}
			case "zoom":
				triggerKey(372, 100)
			}
		}(action)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/source", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}

		if myDeviceType == "kaw" {
			isExt, port, label, targetDev := detectKawSource()
			targetName := ""
			if targetDev == "tv360" {
				targetName = "TV360"
			}
			w.Write([]byte(fmt.Sprintf(`{"dev":"kaw","is_external":%t,"source":"%s","source_label":"%s","target_dev":"%s","target_name":"%s"}`,
				isExt, port, label, targetDev, targetName)))
			return
		}

		if myDeviceType == "projector" {
			isExt, port, label := detectProjectorSource()
			w.Write([]byte(fmt.Sprintf(`{"dev":"projector","is_external":%t,"source":"%s","source_label":"%s","target_dev":"","target_name":""}`,
				isExt, port, label)))
			return
		}

		isLocked := false
		if !isAndroid() {
			isLocked = !isLinuxX11SessionReady() || isLinuxLoginOrLockScreen()
		}
		w.Write([]byte(fmt.Sprintf(`{"dev":"%s","is_external":false,"source":"internal","source_label":"Nội bộ","is_locked":%t}`, myDeviceType, isLocked)))
	})

	http.HandleFunc("/api/screen", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}

		twStr := r.URL.Query().Get("w")
		tw := 1920
		if twStr != "" {
			if v, err := strconv.Atoi(twStr); err == nil && v > 0 {
				tw = v
			}
		}

		data, err := captureScreenJpeg(tw)
		if err != nil {
			http.Error(w, fmt.Sprintf("Screen capture error: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "private, max-age=2")
		w.Write(data)
	})

	http.HandleFunc("/api/touch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}

		touchType := r.URL.Query().Get("type")
		if touchType == "" {
			touchType = "tap"
		}

		parseCoord := func(key string, def float64) float64 {
			s := r.URL.Query().Get(key)
			if s == "" {
				return def
			}
			v, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return def
			}
			return v
		}

		switch touchType {
		case "tap":
			px := parseCoord("px", 0.5)
			py := parseCoord("py", 0.5)
			if !isAndroid() {
				enqueuePCMouseInput(func() {
					sendLinuxPCTouchTap(px, py)
				})
			} else {
				tvStr := r.URL.Query().Get("tv")
				tvConfirm := (tvStr == "1" || tvStr == "true" || isLauncherInForeground())
				go sendDirectTouchTap(px, py, tvConfirm)
			}

		case "doubletap":
			px := parseCoord("px", -1)
			py := parseCoord("py", -1)
			if !isAndroid() {
				enqueuePCMouseInput(func() {
					sendLinuxPCDoubleTap(px, py)
				})
			} else if px >= 0 && py >= 0 {
				go func(x, y float64) {
					sendDirectTouchTap(x, y, true)
					time.Sleep(75 * time.Millisecond)
					sendDirectTouchTap(x, y, true)
				}(px, py)
			}

		case "rightclick", "longpress":
			px := parseCoord("px", -1)
			py := parseCoord("py", -1)
			if !isAndroid() {
				enqueuePCMouseInput(func() {
					sendLinuxPCRightClick(px, py)
				})
			} else if px >= 0 && py >= 0 {
				go sendDirectTouchLongPress(px, py)
			}

		case "middleclick":
			px := parseCoord("px", -1)
			py := parseCoord("py", -1)
			if !isAndroid() {
				enqueuePCMouseInput(func() {
					sendLinuxPCMiddleClick(px, py)
				})
			}

		case "dragstart":
			px := parseCoord("px", 0.5)
			py := parseCoord("py", 0.5)
			if !isAndroid() {
				enqueuePCMouseInput(func() {
					sendLinuxPCDragStart(px, py)
				})
			}

		case "dragmove", "hover":
			px := parseCoord("px", 0.5)
			py := parseCoord("py", 0.5)
			if !isAndroid() {
				enqueuePCMouseInput(func() {
					sendLinuxPCDragMove(px, py)
				})
			}

		case "dragend":
			px := parseCoord("px", 0.5)
			py := parseCoord("py", 0.5)
			if !isAndroid() {
				enqueuePCMouseInput(func() {
					sendLinuxPCDragEnd(px, py)
				})
			}

		case "drag":
			px1 := parseCoord("px1", 0.5)
			py1 := parseCoord("py1", 0.5)
			px2 := parseCoord("px2", 0.5)
			py2 := parseCoord("py2", 0.5)
			durStr := r.URL.Query().Get("dur")
			if !isAndroid() {
				enqueuePCMouseInput(func() {
					sendLinuxPCDragAtomic(px1, py1, px2, py2)
				})
			} else {
				dur := 750
				if d, err := strconv.Atoi(durStr); err == nil && d > 100 {
					dur = d
				}
				go sendDirectTouchSwipe(px1, py1, px2, py2, dur)
			}

		case "scroll":
			px := parseCoord("px", -1)
			py := parseCoord("py", -1)
			dx := parseCoord("dx", 0)
			dy := parseCoord("dy", 0)
			steps, _ := strconv.Atoi(r.URL.Query().Get("steps"))
			if !isAndroid() {
				enqueuePCMouseInput(func() {
					sendLinuxPCScrollXY(px, py, dx, dy, steps)
				})
			} else {
				x1 := 0.5
				y1 := 0.5
				if px >= 0 && py >= 0 {
					x1 = px
					y1 = py
				}
				x2 := math.Max(0.05, math.Min(0.95, x1+dx))
				y2 := math.Max(0.05, math.Min(0.95, y1+dy))
				go sendDirectTouchSwipe(x1, y1, x2, y2, 220)
			}

		case "swipe":
			px1 := parseCoord("px1", 0.5)
			py1 := parseCoord("py1", 0.5)
			px2 := parseCoord("px2", 0.5)
			py2 := parseCoord("py2", 0.5)
			durStr := r.URL.Query().Get("dur")
			if !isAndroid() {
				dx := px2 - px1
				dy := py2 - py1
				enqueuePCMouseInput(func() {
					sendLinuxPCScrollXY(px1, py1, dx, dy, 0)
				})
			} else {
				dur := 220
				if d, err := strconv.Atoi(durStr); err == nil && d > 50 {
					dur = d
				}
				go sendDirectTouchSwipe(px1, py1, px2, py2, dur)
			}

		case "hotkey":
			combo := r.URL.Query().Get("key")
			seq, _ := strconv.ParseInt(r.URL.Query().Get("seq"), 10, 64)
			if combo != "" {
				if !isAndroid() {
					invalidateScreenCache()
					cCopy := combo
					enqueueSequencedPCInput(seq, func() {
						sendLinuxPCHotkey(cCopy)
					})
				} else {
					go func(c string) {
						sendUinputHotkeyCombo(c)
						invalidateScreenCache()
					}(combo)
				}
			}
		}

		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/mouse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}

		dxStr := r.URL.Query().Get("dx")
		dyStr := r.URL.Query().Get("dy")
		clickStr := r.URL.Query().Get("click")
		wheelStr := r.URL.Query().Get("wheel")

		if !isAndroid() {
			if dxStr != "" || dyStr != "" {
				dx, _ := strconv.Atoi(dxStr)
				dy, _ := strconv.Atoi(dyStr)
				enqueuePCMouseInput(func() {
					sendLinuxPCRelMouse(dx, dy)
				})
			}
			if clickStr == "left" {
				enqueuePCMouseInput(func() {
					sendLinuxPCMouseButton(272)
				})
			} else if clickStr == "right" {
				enqueuePCMouseInput(func() {
					sendLinuxPCMouseButton(273)
				})
			}
			if wheelStr != "" {
				wVal, _ := strconv.Atoi(wheelStr)
				enqueuePCMouseInput(func() {
					sendLinuxPCScroll(wVal > 0)
				})
			}
			w.Write([]byte("OK"))
			return
		}

		if dxStr != "" || dyStr != "" {
			dx, _ := strconv.Atoi(dxStr)
			dy, _ := strconv.Atoi(dyStr)
			sendRelMouse(dx, dy)
		}
		if clickStr == "left" {
			sendMouseButton(272) // BTN_LEFT
		} else if clickStr == "right" {
			sendMouseButton(273) // BTN_RIGHT
		}
		if wheelStr != "" {
			wVal, _ := strconv.Atoi(wheelStr)
			sendMouseWheel(wVal)
		}
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}
		pkg := strings.TrimSpace(r.URL.Query().Get("pkg"))
		if pkg != "" {
			if strings.HasPrefix(pkg, "http://") || strings.HasPrefix(pkg, "https://") {
				go func(targetURL string) {
					if isAndroid() {
						runSh("am start -a android.intent.action.VIEW -d '" + strings.ReplaceAll(targetURL, "'", "") + "'")
					} else if runtime.GOOS == "windows" {
						exec.Command("cmd", "/c", "start", "", targetURL).Start()
					} else {
						cmd := exec.Command("xdg-open", targetURL)
						cmd.Env = getLinuxX11Env()
						_ = cmd.Start()
					}
				}(pkg)
			} else {
				go runSh("monkey -p " + pkg + " -c android.intent.category.LAUNCHER 1")
			}
		}
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/text", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}
		var q string
		if r.Method == "POST" && r.Body != nil {
			bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
			if err == nil && len(bodyBytes) > 0 {
				q = string(bodyBytes)
			}
		}
		if q == "" {
			q = r.URL.Query().Get("q")
		}
		bksp, _ := strconv.Atoi(r.URL.Query().Get("bksp"))
		mb, _ := strconv.Atoi(r.URL.Query().Get("mb"))
		ma, _ := strconv.Atoi(r.URL.Query().Get("ma"))
		direct := r.URL.Query().Get("direct") == "1"
		seq, _ := strconv.ParseInt(r.URL.Query().Get("seq"), 10, 64)
		opsStr := r.URL.Query().Get("ops")

		if r.URL.Query().Get("reset") == "1" {
			resetRemoteSimState()
		}

		type textDiffStep struct {
			MB   int    `json:"mb"`
			Bksp int    `json:"bksp"`
			Text string `json:"text"`
		}
		var steps []textDiffStep
		if opsStr != "" {
			_ = json.Unmarshal([]byte(opsStr), &steps)
		}
		if len(steps) == 0 && (q != "" || bksp > 0 || mb != 0 || ma != 0) {
			steps = []textDiffStep{{MB: mb, Bksp: bksp, Text: q}}
		}

		if len(steps) > 0 {
			for idx, st := range steps {
				stepMA := 0
				if idx == len(steps)-1 {
					stepMA = ma
				}
				applyRemoteSimStep(st.MB, st.Bksp, st.Text, stepMA)
			}
			if !isAndroid() {
				invalidateScreenCache()
				opList := make([]textDiffStep, len(steps))
				copy(opList, steps)
				finalMA := ma
				isDir := direct
				enqueueSequencedPCInput(seq, func() {
					for idx, st := range opList {
						stepMA := 0
						if idx == len(opList)-1 {
							stepMA = finalMA
						}
						sendLinuxPCTextDelta(st.Text, st.Bksp, st.MB, stepMA, isDir)
					}
				})
			} else {
				go func(opList []textDiffStep, finalMA int) {
					for idx, st := range opList {
						stepMA := 0
						if idx == len(opList)-1 {
							stepMA = finalMA
						}
						if st.MB < 0 {
							for i := 0; i < -st.MB; i++ {
								if !sendDirectKey(105, 6) {
									runSh("input keyevent 21")
								}
							}
						} else if st.MB > 0 {
							for i := 0; i < st.MB; i++ {
								if !sendDirectKey(106, 6) {
									runSh("input keyevent 22")
								}
							}
						}
						for i := 0; i < st.Bksp; i++ {
							if !sendDirectKey(14, 6) {
								runSh("input keyevent 67")
							}
						}
						if st.Text != "" {
							b64 := base64.StdEncoding.EncodeToString([]byte(st.Text))
							escaped := strings.ReplaceAll(st.Text, " ", "%s")
							runSh(fmt.Sprintf("am broadcast -a ADB_INPUT_B64 --es msg '%s' 2>/dev/null || am broadcast -a ADB_INPUT_TEXT --es msg '%s' 2>/dev/null || input text '%s'", b64, st.Text, escaped))
						}
						if stepMA < 0 {
							for i := 0; i < -stepMA; i++ {
								if !sendDirectKey(105, 6) {
									runSh("input keyevent 21")
								}
							}
						} else if stepMA > 0 {
							for i := 0; i < stepMA; i++ {
								if !sendDirectKey(106, 6) {
									runSh("input keyevent 22")
								}
							}
						}
					}
					invalidateScreenCache()
				}(steps, ma)
			}
		}
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/upload_image", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}
		if r.Body == nil {
			http.Error(w, "empty body", http.StatusBadRequest)
			return
		}

		kind := r.URL.Query().Get("kind")
		rawName := filepath.Base(r.URL.Query().Get("name"))
		var safeNameBuilder strings.Builder
		for _, ch := range rawName {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
				safeNameBuilder.WriteRune(ch)
			} else if ch == ' ' {
				safeNameBuilder.WriteRune('_')
			}
		}
		safeName := safeNameBuilder.String()
		if safeName == "" || safeName == "." {
			if kind == "image" || kind == "" {
				safeName = "image.png"
			} else {
				safeName = "file.bin"
			}
		}

		homeDir, _ := os.UserHomeDir()
		if homeDir == "" {
			if isAndroid() {
				homeDir = "/sdcard"
			} else {
				homeDir = os.TempDir()
			}
		}
		dlDir := filepath.Join(homeDir, "Downloads", "VuiRemote")
		if isAndroid() {
			dlDir = "/sdcard/Download/VuiRemote"
		}
		_ = os.MkdirAll(dlDir, 0755)
		ts := time.Now().Format("20060102_150405")
		fileName := fmt.Sprintf("%s_%s", ts, safeName)
		savePath := filepath.Join(dlDir, fileName)

		chunkTotal, _ := strconv.Atoi(r.URL.Query().Get("chunk_total"))
		chunkIdx, _ := strconv.Atoi(r.URL.Query().Get("chunk_idx"))
		uploadID := filepath.Base(r.URL.Query().Get("upload_id"))

		if chunkTotal > 1 && uploadID != "" && uploadID != "." {
			partPath := filepath.Join(dlDir, fmt.Sprintf(".part_%s_%s", uploadID, safeName))
			flags := os.O_CREATE | os.O_WRONLY
			if chunkIdx == 0 {
				flags |= os.O_TRUNC
			} else {
				flags |= os.O_APPEND
			}
			partFile, pErr := os.OpenFile(partPath, flags, 0644)
			if pErr != nil {
				http.Error(w, "cannot open chunk file", http.StatusInternalServerError)
				return
			}
			cWritten, cCopyErr := io.Copy(partFile, io.LimitReader(r.Body, 50*1024*1024))
			partFile.Close()
			if cCopyErr != nil || cWritten == 0 {
				http.Error(w, "empty or invalid chunk", http.StatusBadRequest)
				return
			}
			if chunkIdx < chunkTotal-1 {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(fmt.Sprintf(`{"ok":true,"chunk":%d}`, chunkIdx)))
				return
			}
			if rErr := os.Rename(partPath, savePath); rErr != nil {
				savePath = partPath
			}
			fmt.Printf("[UPLOAD OK] Assembled %d chunks -> %s\n", chunkTotal, savePath)
		} else {
			outFile, err := os.Create(savePath)
			if err != nil {
				fallbackDir := os.TempDir()
				if isAndroid() {
					fallbackDir = "/data/local/tmp"
				}
				savePath = filepath.Join(fallbackDir, fileName)
				outFile, err = os.Create(savePath)
				if err != nil {
					http.Error(w, "cannot create file", http.StatusInternalServerError)
					return
				}
			}
			written, copyErr := io.Copy(outFile, io.LimitReader(r.Body, 500*1024*1024))
			outFile.Close()
			if copyErr != nil || written == 0 {
				_ = os.Remove(savePath)
				http.Error(w, "empty or invalid upload", http.StatusBadRequest)
				return
			}
			fmt.Printf("[UPLOAD OK] Saved %s (%d bytes)\n", savePath, written)
		}

		finalPath := savePath
		ext := strings.ToLower(filepath.Ext(savePath))
		isImg := kind == "image" || ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".webp" || ext == ".bmp"

		if isImg {
			picDir := filepath.Join(homeDir, "Pictures", "VuiRemote")
			_ = os.MkdirAll(picDir, 0755)
			if imgBytes, rErr := os.ReadFile(savePath); rErr == nil {
				_ = os.WriteFile(filepath.Join(picDir, fileName), imgBytes, 0644)
				if runtime.GOOS != "windows" {
					_ = os.WriteFile("/tmp/vuiremote_latest.png", imgBytes, 0644)
				}
			}
		} else if ext == ".mov" {
			// Automatically convert iPhone .MOV video clip to universal .MP4 (H.264 + AAC) so Antigravity & browsers open it natively
			mp4Path := strings.TrimSuffix(savePath, filepath.Ext(savePath)) + ".mp4"
			ctxConv, cancelConv := context.WithTimeout(context.Background(), 45*time.Second)
			cmdConv := exec.CommandContext(ctxConv, "ffmpeg", "-nostats", "-loglevel", "error", "-y",
				"-i", savePath,
				"-c:v", "libx264", "-preset", "ultrafast", "-crf", "23", "-pix_fmt", "yuv420p",
				"-c:a", "aac", "-b:a", "128k",
				mp4Path,
			)
			if errConv := cmdConv.Run(); errConv == nil {
				finalPath = mp4Path
			}
			cancelConv()
		}

		autoPaste := r.URL.Query().Get("paste") != "0"
		if !isAndroid() {
			if isImg {
				if err := sendLinuxPCImageClipboard(finalPath, autoPaste); err != nil {
					fmt.Printf("[UPLOAD IMAGE CLIPBOARD WARN] %v\n", err)
				}
			} else if autoPaste {
				sendLinuxPCText(finalPath + " ")
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"ok":true,"kind":%q,"path":%q}`, kind, finalPath)))
	})

	var imeChecking int32
	http.HandleFunc("/api/ime", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !requireAuth(w, r) {
			return
		}
		if forwardIfRemote(w, r) {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

		// Non-blocking guard: never pile up IME / cursor check calls
		if !atomic.CompareAndSwapInt32(&imeChecking, 0, 1) {
			w.Write([]byte(`{"shown":false}`))
			return
		}
		defer atomic.StoreInt32(&imeChecking, 0)

		if !isAndroid() {
			if shown, px, py := linuxGetTextInputState(); shown {
				resp := map[string]interface{}{
					"shown": true,
				}
				if px >= 0 && py >= 0 {
					resp["px"] = px
					resp["py"] = py
				}
				_ = json.NewEncoder(w).Encode(resp)
			} else {
				w.Write([]byte(`{"shown":false}`))
			}
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		out, err := exec.CommandContext(ctx, "/system/bin/sh", "-c", "dumpsys input_method 2>/dev/null | grep -E 'mInputShown=true|mShowRequested=true|inputType=0x[1-9a-fA-F]'").Output()
		isShown := (err == nil && len(bytes.TrimSpace(out)) > 0)

		if isShown {
			w.Write([]byte(`{"shown":true}`))
		} else {
			w.Write([]byte(`{"shown":false}`))
		}
	})

	listenPort := 8080
	if pStr := os.Getenv("PORT"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
			listenPort = p
		}
	} else if !isAndroid() {
		listenPort = 8090
	}

	addr := fmt.Sprintf(":%d", listenPort)
	fmt.Printf("VuiRemote Hub listening on %s (Device: %s, Android: %t)\n", addr, myDeviceType, isAndroid())
	http.ListenAndServe(addr, nil)
}

func linuxGetTextInputState() (bool, float64, float64) {
	if runtime.GOOS == "windows" {
		return winGetTextInputState()
	}
	if isLinuxLoginOrLockScreen() {
		return true, 0.5, 0.55
	}
	ctx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
	defer cancel()
	pyScript := `import ctypes, subprocess, sys
class XFixesCursorImage(ctypes.Structure):
    _fields_ = [('x', ctypes.c_short), ('y', ctypes.c_short), ('width', ctypes.c_ushort), ('height', ctypes.c_ushort), ('xhot', ctypes.c_ushort), ('yhot', ctypes.c_ushort), ('cursor_serial', ctypes.c_ulong), ('pixels', ctypes.POINTER(ctypes.c_ulong)), ('atom', ctypes.c_ulong), ('name', ctypes.c_char_p)]
cx, cy = -1, -1
try:
    libX11 = ctypes.cdll.LoadLibrary('libX11.so.6')
    libX11.XOpenDisplay.argtypes = [ctypes.c_char_p]
    libX11.XOpenDisplay.restype = ctypes.c_void_p
    libX11.XCloseDisplay.argtypes = [ctypes.c_void_p]
    libXfixes = ctypes.cdll.LoadLibrary('libXfixes.so.3')
    libXfixes.XFixesGetCursorImage.argtypes = [ctypes.c_void_p]
    libXfixes.XFixesGetCursorImage.restype = ctypes.POINTER(XFixesCursorImage)
    dpy = libX11.XOpenDisplay(None)
    if dpy:
        img_p = libXfixes.XFixesGetCursorImage(dpy)
        if img_p:
            img = img_p.contents
            cx, cy = int(img.x), int(img.y)
            name = (img.name.decode('utf-8', 'ignore').lower() if img.name else '')
            if any(k in name for k in ('xterm', 'ibeam', 'text')):
                libX11.XCloseDisplay(dpy)
                print(f'1 {cx} {cy}')
                sys.exit(0)
            w, h, xh, yh = img.width, img.height, img.xhot, img.yhot
            minx, maxx, miny, maxy = w, 0, h, 0
            for y in range(h):
                for x in range(w):
                    if (img.pixels[y*w + x] >> 24) & 0xff > 128:
                        if x < minx: minx = x
                        if x > maxx: maxx = x
                        if y < miny: miny = y
                        if y > maxy: maxy = y
            bw = maxx - minx + 1 if maxx >= minx else 0
            bh = maxy - miny + 1 if maxy >= miny else 0
            libX11.XCloseDisplay(dpy)
            if bh >= 13 and bw <= 10 and yh >= h // 3 and yh <= (h * 2) // 3:
                print(f'1 {cx} {cy}')
                sys.exit(0)
    wid = subprocess.run(['xdotool', 'getactivewindow'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=0.15).stdout.decode('utf-8', 'ignore').strip()
    if not wid:
        print(f'1 {cx} {cy}')
        sys.exit(0)
    out = subprocess.check_output(['xprop', '-id', wid, 'WM_CLASS'], stderr=subprocess.DEVNULL, timeout=0.15).decode('utf-8', 'ignore').lower()
    if any(t in out for t in ('gnome-terminal', 'xterm', 'alacritty', 'kitty', 'konsole', 'tilix')):
        print(f'1 {cx} {cy}')
        sys.exit(0)
except Exception:
    pass
print('0')
`
	cmd := exec.CommandContext(ctx, "python3", "-c", pyScript)
	cmd.Env = getLinuxX11Env()
	out, err := cmd.Output()
	if err != nil {
		return false, -1, -1
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 || fields[0] != "1" {
		return false, -1, -1
	}
	if len(fields) >= 3 {
		curX, errX := strconv.Atoi(fields[1])
		curY, errY := strconv.Atoi(fields[2])
		if errX == nil && errY == nil && curX >= 0 && curY >= 0 {
			px, py := linuxPixelToCoord(curX, curY)
			return true, px, py
		}
	}
	return true, -1, -1
}

