// Package yauth provides functionality for OAuth authorization for Yahoo. This
// package is best suited for CLIs.
package yauth

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/toqueteos/webbrowser"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yahoo"
)

var (
	redirectURL string = "oob"
)

// YAuth holds client credentials along with an access token from Yahoo.
type YAuth struct {
	ClientID     string        `json:"client_id"`
	ClientSecret string        `json:"client_secret"`
	Token        *oauth2.Token `json:"token"`
}

// Client returns a http.Client to be used for sending requests to Yahoo's API
// endpoints that require OAuth.
func (y *YAuth) Client() *http.Client {
	return y.config().Client(context.Background(), y.Token)
}

// WriteToFile writes the YAuth object to the given file in JSON format.
func (y *YAuth) WriteToFile(filePath string) error {
	file, err := json.MarshalIndent(y, "", "\t")
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filePath, file, 0644); err != nil {
		return err
	}

	return nil
}

// config returns an oauth2.Config populated with the client credentials, Yahoo
// endpoints, and redirect url.
func (y *YAuth) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     y.ClientID,
		ClientSecret: y.ClientSecret,
		Endpoint:     yahoo.Endpoint,
		RedirectURL:  redirectURL,
	}
}

// getToken attempts to get a token for the user and stores the token in the
// YAuth object.
func (y *YAuth) getToken() error {
	code, err := y.requestAuthorizationCodeFromUser()
	if err != nil {
		return err
	}

	token, err := y.convertCodeToToken(code)
	if err != nil {
		return err
	}

	y.Token = token
	return nil
}

// convertCodeToToken converts the given authorization code into an oauth.Token.
func (y *YAuth) convertCodeToToken(code string) (*oauth2.Token, error) {
	token, err := y.config().Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// requestAuthorizationCodeFromUser starts the authorization process and prompts
// the user for an authorization code. The code provided by the user will be
// returned.
//
// Yahoo Authorization Flow:
// 1) User's browser opens with a request to authorize the client for use
// 2) User logs in to Yahoo, if not already
// 3) User authorizes app and is given an authorization code to provide to the
// client.
func (y *YAuth) requestAuthorizationCodeFromUser() (string, error) {
	browserCallback := y.config().AuthCodeURL("")
	if err := webbrowser.Open(browserCallback); err != nil {
		return "", err
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter authorization code: ")
	code, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return code, nil
}

// CreateYAuthFromRawCredentials builds a YAuth object using the provided client id
// and client secret. This function will always request a token from Yahoo.
func CreateYAuthFromRawCredentials(clientID string, clientSecret string) (*YAuth, error) {
	auth := YAuth{ClientID: clientID, ClientSecret: clientSecret}

	if err := auth.getToken(); err != nil {
		return nil, err
	}

	return &auth, nil
}

// CreateYAuthFromJSON builds a YAuth object from the JSON file located at the
// provided path. If there is no token in the JSON, one will be retrieved and
// the file will be updated.
func CreateYAuthFromJSON(filePath string) (*YAuth, error) {
	jsonFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	auth := new(YAuth)
	if err := json.Unmarshal(byteValue, auth); err != nil {
		return nil, err
	}

	if auth.Token != nil {
		return auth, nil
	}

	if err := auth.getToken(); err != nil {
		return nil, err
	}

	auth.WriteToFile(filePath)
	return auth, nil
}
