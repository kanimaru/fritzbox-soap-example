package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/go-resty/resty/v2"
	"io"
	"log"
	"os"
	"strings"
	"text/template"
)

type envelopeParameter struct {
	Action string
	Uri    string
}

type envelopeResponse struct {
	XMLName       xml.Name `xml:"Envelope"`
	Text          string   `xml:",chardata"`
	S             string   `xml:"s,attr"`
	EncodingStyle string   `xml:"encodingStyle,attr"`
	Body          struct {
		Text                       string `xml:",chardata"`
		XAVMDECreateUrlSIDResponse struct {
			Text            string `xml:",chardata"`
			U               string `xml:"u,attr"`
			NewXAVMDEUrlSID string `xml:"NewX_AVM-DE_UrlSID"`
		} `xml:"X_AVM-DE_CreateUrlSIDResponse"`
	} `xml:"Body"`
}

type digestAuthParameter struct {
	username  string
	password  string
	realm     string
	nonce     string
	uri       string
	algorithm string
	qop       string
	cnonce    string
	response  string
}

var soapRequestBody, soapRequestBodyError = template.New("soapEnvelope").Parse(`<?xml version='1.0' encoding='utf-8'?>
<s:Envelope s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'>
    <s:Body>
        <u:{{ .Action }} xmlns:u='{{ .Uri }}'></u:{{ .Action }}>
    </s:Body>
</s:Envelope>`)

func createEnvelope(action string, uri string) string {
	buf := new(bytes.Buffer)
	err := soapRequestBody.Execute(buf, envelopeParameter{
		Action: action,
		Uri:    uri,
	})
	if err != nil {
		log.Fatal("Can't parse SOAP Envelope Template with parameters: \n" + err.Error())
	}
	return buf.String()
}

func parseAuthParam(allParams string) map[string]string {
	params := strings.Split(allParams, ",")
	result := map[string]string{}
	for _, param := range params {
		paramPair := strings.Split(param, "=")
		result[paramPair[0]] = strings.Trim(paramPair[1], "\"")
	}
	return result
}

// createDigestAuth creates the auth header for digest authorization. It's not a feature complete implementation see https://en.wikipedia.org/wiki/Digest_access_authentication
func createDigestAuth(username string, password string, response *resty.Response) string {
	authHeader := response.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(authHeader, "Digest") {
		log.Fatal("Can handle digest auth only!")
	}
	authParams := parseAuthParam(strings.TrimPrefix(authHeader, "Digest "))
	d := digestAuthParameter{
		username:  username,
		password:  password,
		realm:     authParams["realm"],
		nonce:     authParams["nonce"],
		uri:       response.Request.URL,
		algorithm: authParams["algorithm"],
		qop:       authParams["qop"],
		cnonce:    getCnonce(),
		response:  "",
	}
	ha1 := getMD5(d.username + ":" + d.realm + ":" + d.password)
	ha2 := getMD5(response.Request.Method + ":" + response.Request.URL)
	nonceCount := 00000001
	d.response = getMD5(fmt.Sprintf("%s:%s:%v:%s:%s:%s", ha1, d.nonce, nonceCount, d.cnonce, d.qop, ha2))
	return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", Uri="%s", cnonce="%s", nc="%v", qop="%s", response="%s"`,
		d.username, d.realm, d.nonce, d.uri, d.cnonce, nonceCount, d.qop, d.response)
}

func getMD5(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getCnonce() string {
	b := make([]byte, 8)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		log.Fatal("Can't create Cnonce random bytes: \n" + err.Error())
	}
	return fmt.Sprintf("%x", b)[:16]
}

func main() {
	if soapRequestBodyError != nil {
		log.Fatal("Can't parse SOAP envelope template")
	}
	username := os.Getenv("FB_USERNAME")
	password := os.Getenv("FB_PASSWORD")

	client := resty.New()
	envelope := createEnvelope("X_AVM-DE_CreateUrlSID", "urn:dslforum-org:service:DeviceConfig:1")
	createSessionUrl := "http://192.168.178.1:49000/upnp/control/deviceconfig"

	response, err := client.R().
		SetHeader("SOAPACTION", "urn:dslforum-org:service:DeviceConfig:1#X_AVM-DE_CreateUrlSID").
		SetHeader("Content-Type", "text/xml").
		SetBody(envelope).
		Post(createSessionUrl)

	if err != nil {
		log.Fatal("Can't call 192.168.178.1:\n" + err.Error())
	}
	if response.StatusCode() != 401 {
		log.Fatal("Expect to be unauthorized. Did you have enabled security or is TR064 protocol disabled? \n" + response.String())
	}

	digistAuth := createDigestAuth(username, password, response)
	sessionResponse := envelopeResponse{}
	response, err = client.R().
		SetHeader("Authorization", digistAuth).
		SetHeader("Content-Type", "text/xml").
		SetHeader("SOAPACTION", "urn:dslforum-org:service:DeviceConfig:1#X_AVM-DE_CreateUrlSID").
		SetBody(envelope).
		SetResult(&sessionResponse).
		Post(createSessionUrl)
	if !response.IsSuccess() {
		log.Fatal("Session create didn't work. \n" + response.String())
	}
	sid := strings.TrimLeft(sessionResponse.Body.XAVMDECreateUrlSIDResponse.NewXAVMDEUrlSID, "sid=")
	log.Printf("SessionID: %s", sid)
}
