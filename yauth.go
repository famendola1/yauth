package yauth

import (
  "bufio"
  "bytes"
  "context"

  "github.com/toqueteos/webbrowser"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/yahoo"
)

var (
  redirectURL string = "oob"
)

func CreateTokenFromCredentials(clientID string, clientSecret string) (*oauth2.Token, error) {
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

  return token, nil
}
