// A straightforward way to keep session data in a cookie.  No tricks, just simple calls.
package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type ErrChecksumFailed string

func (e ErrChecksumFailed) Error() string { return string(e) }

type Cryptor struct {
	SecretKey      []byte
	CookieName     string
	MakeCookieFunc MakeCookieFunc // Make cookie with the specified value
}

func NewSimpleCryptor(secretKey []byte, cookieName string) *Cryptor {
	return &Cryptor{
		SecretKey:  secretKey,
		CookieName: cookieName,
		MakeCookieFunc: MakeCookieFunc(func(w http.ResponseWriter, r *http.Request) *http.Cookie {
			return &http.Cookie{
				Name: cookieName,
				Path: "/",
			}
		}),
	}
}

// makes an empty cookie, no value
type MakeCookieFunc func(w http.ResponseWriter, r *http.Request) *http.Cookie

// seralize and encrypt v and write to cookie
func (sc *Cryptor) Write(v interface{}, w http.ResponseWriter, r *http.Request) error {

	// marshall data
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	chksum := sha256.Sum256(b)

	// make init vector
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(sc.SecretKey)
	if err != nil {
		return err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(b))
	cfb.XORKeyStream(ciphertext, b)

	cookie := sc.MakeCookieFunc(w, r)
	cookie.Value = base64.RawURLEncoding.EncodeToString(iv) + "," + base64.RawURLEncoding.EncodeToString(ciphertext) + "," + base64.RawURLEncoding.EncodeToString(chksum[:8])

	http.SetCookie(w, cookie)

	return nil

}

func (sc *Cryptor) Read(v interface{}, r *http.Request) error {

	c, err := r.Cookie(sc.CookieName)
	if err != nil {
		return fmt.Errorf("Error retrieving cookie '%s': %v", sc.CookieName, err)
	}

	cookieValueParts := strings.Split(c.Value, ",")

	// extract init vector
	iv, err := base64.RawURLEncoding.DecodeString(cookieValueParts[0])
	if err != nil {
		return err
	}

	// extract value
	b, err := base64.RawURLEncoding.DecodeString(cookieValueParts[1])
	if err != nil {
		return err
	}

	// extract checksum
	bchk, err := base64.RawURLEncoding.DecodeString(cookieValueParts[2])
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(sc.SecretKey)
	if err != nil {
		return err
	}

	cfb := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(b))
	cfb.XORKeyStream(plaintext, b)

	// make sure checksum matches
	chksum := sha256.Sum256(plaintext)
	if bytes.Compare(bchk, chksum[:8]) != 0 {
		return ErrChecksumFailed("ErrChecksumFailed")
	}

	err = json.Unmarshal(plaintext, v)
	if err != nil {
		return err
	}

	return nil
}

// remove cookie (effectively destroying the session)
func (sc *Cryptor) Clear(w http.ResponseWriter, r *http.Request) {
	c := sc.MakeCookieFunc(w, r)
	c.MaxAge = -1
	http.SetCookie(w, c)
}
