package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

// This is for encrypting the webhook so that people can't simply pop it in IDA/Ghidra

func Encrypt(rawData []byte) string {
	cipherAES, err := aes.NewCipher(aaaaaaa)
	if err != nil {
		return ""
	}

	AESgcm, err := cipher.NewGCM(cipherAES)
	if err != nil {
		return ""
	}
	var buff bytes.Buffer
	buff.Write(rawData)

	contentAfter := AESgcm.Seal(nil, bbbbbbb, buff.Bytes(), nil)

	return base64.StdEncoding.EncodeToString(contentAfter)
}

func main() {
	webhook, err := ioutil.ReadFile("webhook.txt")
	if err != nil || len(webhook) == 0 {
		fmt.Println("Could not get the webhook from webhook.txt")
		return
	}

	data := Encrypt(webhook)

	fmt.Println(data)
}

// we'll rename these just to make it "harder" for people to get the nonce and key
var (
	aaaaaaa = make([]byte, 32)
	bbbbbbb = bytes.Repeat([]byte{69}, 12)
)
