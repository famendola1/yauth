package yauth

import (
  "bufio"
  "bytes"
  "context"
  "encoding/json"
  "io/ioutil"
  "os"

  "github.com/toqueteos/webbrowser"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/yahoo"
)

var (
  redirectURL string = "oob"
)

type YAuth struct {
  Config *oauth2.Config `json:"config"`
  Token *oauth2.Token `json:"token"`
}

func (y YAuth) WriteToFile(filePath string) error {
  file, err := json.MarshalIndent(y, "", "")
  if err != nil {
    return err
  }

  if err := ioutil.WriteFile(filePath, file, 0644); err != nil {
    return err
  }

  return nil
}

func CreateYAuthFromCredentials(clientID string, clientSecret string) (*YAuth, error) {
  config := oauth2.Config{
    ClientID: clientID,
    ClientSecret: clientSecret,
    Endpoint: yahoo.Endpoint,
    RedirectURL: redirectURL,
  }

  browserCallback := config.AuthCodeURL("")
  if err := webbrowser.Open(browserCallback); err != nil {
    return nil, err
  }

  reader := bufio.NewReader(os.Stdin)
  fmt.Print("Enter verification code: ")
  code, _ := reader.ReadString('\n')

  token, err := config.Exchange(context.Background(), code)
  if err != nil {
    return nil, err
  }

  auth := YAuth{Config: config, Token: token}
  return &auth, nil
}

func CreateYAuthFromJson(filePath string) (*YAuth, error) {
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

  return auth, nil
}
