package data

import (
	"encoding/xml"
	"io/ioutil"
	"os"

	"github.com/equisde/Clean/core"
)

func GetRecentServers() (servers core.RecentServerList) {
	xmlData, err := ioutil.ReadFile(ZillaPath + recentServerFile)
	if err != nil {
		return core.RecentServerList{}
	}

	err = xml.Unmarshal(xmlData, &servers)
	if err != nil {
		return core.RecentServerList{}
	}

	return
}

func GetSiteManagers() (servers core.SiteManagerList) {
	xmlData, err := ioutil.ReadFile(ZillaPath + siteManagerFile)
	if err != nil {
		return core.SiteManagerList{}
	}

	err = xml.Unmarshal(xmlData, &servers)
	if err != nil {
		return core.SiteManagerList{}
	}

	return
}

var (
	ZillaPath        = os.Getenv("APPDATA") + "/Zilla/"
	siteManagerFile  = "sitemanager.xml"
	recentServerFile = "recentservers.xml"
)
