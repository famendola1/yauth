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

type YAuth struct {
	ClientID     string        `json:"client_id"`
	ClientSecret string        `json:"client_secret"`
	Token        *oauth2.Token `json:"token"`
}

func (y YAuth) Client() *http.Client {
	return y.config().Client(context.Background(), y.Token)
}

func (y YAuth) WriteToFile(filePath string) error {
	file, err := json.MarshalIndent(y, "", "\t")
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filePath, file, 0644); err != nil {
		return err
	}

	return nil
}

func (y YAuth) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     y.ClientID,
		ClientSecret: y.ClientSecret,
		Endpoint:     yahoo.Endpoint,
		RedirectURL:  redirectURL,
	}
}

func (y *YAuth) fetchToken() error {
	browserCallback := y.config().AuthCodeURL("")
	if err := webbrowser.Open(browserCallback); err != nil {
		return err
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter verification code: ")
	code, _ := reader.ReadString('\n')

	token, err := y.config().Exchange(context.Background(), code)
	if err != nil {
		return err
	}

	y.Token = token
	return nil
}

func CreateYAuthFromCredentials(clientID string, clientSecret string) (*YAuth, error) {
	auth := YAuth{ClientID: clientID, ClientSecret: clientSecret}

	if err := auth.fetchToken(); err != nil {
		return nil, err
	}

	return &auth, nil
}

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

	if err := auth.fetchToken(); err != nil {
		return nil, err
	}

	auth.WriteToFile(filePath)
	return auth, nil
}
