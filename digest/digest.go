package digest

// Digest-Authorization Methode
// inspired by http://stackoverflow.com/questions/39474284/how-do-you-do-a-http-post-with-digest-authentication-in-golang/39481441#39481441

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

// Client represent a digest-client to make digest-calls
type Client struct {
	header      http.Header
	username    string
	password    string
	digestParts map[string]string
	DPopaque    string
}

const (
	// some keywords for digestParts
	dURI      = "uri"
	dMethod   = "method"
	dUsername = "username"
	dPassword = "password"
	dOpaque   = "opaque"

	dNonce = "nonce"
	dRealm = "realm"
	dQop   = "qop"

	// Some headernames
	wwwHeader     = "Www-Authenticate"
	authorization = "Authorization"
	contentType   = ""

	// others
	nonceCount = "00000001"
)

// NewDigestClient creates a new instance of a "digest client"
func NewDigestClient(username string, password string) *Client {
	return &Client{
		username: username,
		password: password,
	}
}

// Request - request with digest client
func (digest *Client) Request(host string, uri string, method string, postBody []byte, header http.Header) (*http.Response, error) {
	// build url
	url := host + uri

	// block redirect
	client :=
		&http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

	// Should we find out some digestParts?
	if digest.digestParts[dNonce] == "" {
		req, err := http.NewRequest(method, url, bytes.NewBuffer(postBody))
		req.Header = header

		// do first a request to get the headers
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			return nil, errors.New("Test request returned not: " + string(http.StatusUnauthorized) + " instead: " + string(resp.StatusCode))
		}

		// build digestParts
		// generate, add all headers
		digest.digestParts = digestParts(resp)
		digest.digestParts[dUsername] = digest.username
		digest.digestParts[dPassword] = digest.password
		digest.digestParts[dOpaque] = digest.DPopaque
	}

	// dynamic digestParts
	digest.digestParts[dURI] = uri
	digest.digestParts[dMethod] = method

	req, err := http.NewRequest(method, url, bytes.NewBuffer(postBody))
	req.Header = header
	req.Header.Set(authorization, getDigestAuthrization(digest.digestParts))

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read Response Body
	respBody, _ := ioutil.ReadAll(resp.Body)

	// Display Results
	fmt.Println("response Status : ", resp.Status)
	fmt.Println("response Headers : ", resp.Header)
	fmt.Println("response Body : ", string(respBody))

	return resp, nil
}

// extract some headers
func digestParts(resp *http.Response) map[string]string {
	result := map[string]string{}
	if len(resp.Header[wwwHeader]) > 0 {
		wantedHeaders := []string{dNonce, dRealm, dQop}
		responseHeaders := strings.Split(resp.Header[wwwHeader][0], ",")
		for _, r := range responseHeaders {
			for _, w := range wantedHeaders {
				if strings.Contains(r, w) {
					result[w] = strings.Split(r, `"`)[1]
				}
			}
		}
	}
	return result
}

func getMD5(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getCnonce() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)[:16]
}

func getDigestAuthrization(digestParts map[string]string) string {
	d := digestParts
	ha1 := getMD5(d[dUsername] + ":" + d[dRealm] + ":" + d[dPassword])
	ha2 := getMD5(d[dMethod] + ":" + d[dURI])
	cnonce := getCnonce()
	response := getMD5(fmt.Sprintf("%s:%s:%v:%s:%s:%s", ha1, d[dNonce], nonceCount, cnonce, d[dQop], ha2))
	authorization := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", opaque="%s", algorithm=MD5, qop=%s, nc=00000001, cnonce="%s"`,
		d[dUsername], d[dRealm], d[dNonce], d[dURI], response, d[dOpaque], d[dQop], cnonce)
	log.Println(authorization)
	return authorization
}
