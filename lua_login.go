package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"github.com/go-resty/resty/v2"
	"golang.org/x/crypto/pbkdf2"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type SessionInfo struct {
	XMLName   xml.Name `xml:"SessionInfo"`
	Text      string   `xml:",chardata"`
	SID       string   `xml:"SID"`
	Challenge string   `xml:"Challenge"`
	BlockTime string   `xml:"BlockTime"`
	Rights    string   `xml:"Rights"`
	Users     struct {
		Text string `xml:",chardata"`
		User []struct {
			Text string `xml:",chardata"`
			Last string `xml:"last,attr"`
		} `xml:"User"`
	} `xml:"Users"`
}

const loginUri = "http://127.0.0.1/login_sid.lua?version=2"

func main() {

	username := os.Getenv("FB_USERNAME")
	password := os.Getenv("FB_PASSWORD")

	sessionInfo := SessionInfo{}
	client := resty.New()
	response, err := client.R().
		EnableTrace().
		SetResult(&sessionInfo).
		Get(loginUri)
	if err != nil || !response.IsSuccess() {
		log.Fatal("Can't get login challenge")
	}
	challenge := strings.Split(sessionInfo.Challenge, "$")
	ver, iter1, salt1, iter2, salt2 := challenge[0], challenge[1], challenge[2], challenge[3], challenge[4]
	log.Printf("FBox login use ver: %q", ver) // Old v1 isn't supported yet

	iIter1, e1 := strconv.Atoi(iter1)
	iIter2, e2 := strconv.Atoi(iter2)
	hSalt1, e3 := hex.DecodeString(salt1)
	hSalt2, e4 := hex.DecodeString(salt2)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		log.Fatal("Can't convert login challenge")
	}
	hash1 := pbkdf2.Key([]byte(password), hSalt1, iIter1, 32, sha256.New)
	challengeResponse := salt2 + "$" + hex.EncodeToString(pbkdf2.Key(hash1, hSalt2, iIter2, 32, sha256.New))
	log.Printf(challengeResponse)
	params := url.Values{}
	params.Set("username", username)
	params.Set("response", challengeResponse)

	response, err = client.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetResult(&sessionInfo).
		SetBody(params.Encode()).Post(loginUri)

	if err != nil || !response.IsSuccess() {
		log.Fatal("Can't get login")
	}

	sid := sessionInfo.SID
	log.Printf("Sid %v", sid)
}
