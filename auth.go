package goandroidauth

import (
	"crypto/rsa"
	"encoding/base64"
	"crypto/sha1"
	"crypto/rand"
	"math/big"
	"net/url"
	"net/http"
	"strings"
	"compress/gzip"
	"io/ioutil"
	"fmt"
)

var (
	androidKey      *rsa.PublicKey
	androidKeyBytes []byte
)

type AndroidAuth struct {
	service   string
	androidId string
	app       string
	clientSig string
}

func NewAndroidAuth(androidId, app, clientSig, service string) AndroidAuth {
	return AndroidAuth{androidId: androidId,
		app: app,
		clientSig: clientSig,
		service: service}
}

func init() {
	var err error
	androidKeyBytes, err = base64.StdEncoding.DecodeString("AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6pr" +
	"wgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QR" +
	"NVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==")
	if err != nil {
		panic(err)
	}
	i := bytesToLong(androidKeyBytes[:4]).Int64()
	j := bytesToLong(androidKeyBytes[i + 4 : i + 8]).Int64()
	androidKey = &rsa.PublicKey{
		N: bytesToLong(androidKeyBytes[4 : 4 + i]),
		E: int(bytesToLong(androidKeyBytes[i + 8 : i + 8 + j]).Int64()),
	}
}

func signature(email, password string) (string, error) {
	hash := sha1.Sum(androidKeyBytes)
	msg := append([]byte(email), 0)
	msg = append(msg, []byte(password)...)
	encryptedLogin, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, androidKey, msg, nil)
	if err != nil {
		return "", err
	}
	sig := append([]byte{0}, hash[:4]...)
	sig = append(sig, encryptedLogin...)
	return base64.URLEncoding.EncodeToString(sig), nil
}

func bytesToLong(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func (a AndroidAuth) Login(username, password string) (token string, err error) {
	sig, err := signature(username, password)
	if err != nil {
		return "", err
	}

	postBody := url.Values{}

	postBody.Add("device_country", "us")
	postBody.Add("operatorCountry", "us")
	postBody.Add("lang", "en_US")
	postBody.Add("sdk_version", "23")
	postBody.Add("google_play_services_version", "9256438")
	postBody.Add("accountType", "HOSTED_OR_GOOGLE")
	postBody.Add("Email", username)
	postBody.Add("service", a.service)
	postBody.Add("source", "android")
	postBody.Add("androidId", a.androidId)
	postBody.Add("app", a.app)
	postBody.Add("client_sig", a.clientSig)
	postBody.Add("callerPkg", a.app)
	postBody.Add("callerSig", a.clientSig)
	postBody.Add("EncryptedPasswd", sig)

	req, err := http.NewRequest("POST", "https://android.clients.google.com/auth", strings.NewReader(string(postBody.Encode())))
	req.Header.Set("User-Agent", "GoogleAuth/1.4 (mako JDQ39)")
	req.Header.Set("Device", a.androidId)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("App", a.app)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	gzBody, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", err
	}
	decompressedBody, err := ioutil.ReadAll(gzBody)
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(decompressedBody), "\n") {
		sp := strings.SplitN(line, "=", 2)
		if len(sp) != 2 {
			continue
		}
		if sp[0] == "Auth" {
			return sp[1], nil
		}
	}
	return "", fmt.Errorf("No Auth found")
}
