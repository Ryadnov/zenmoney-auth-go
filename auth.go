package zenmoneyauth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

type (
	Auth struct {
		Application *Application
		Endpoints   *Endpoints
		User        *User
	}

	Application struct {
		ConsumerKey    string
		ConsumerSecret string
	}

	Endpoints struct {
		Authorize string
		Redirect  string
		Token     string
	}

	User struct {
		Login    string
		Password string
	}

	TokenResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
)

var DefaultEndpoints = &Endpoints{
	Authorize: "https://api.zenmoney.ru/oauth2/authorize/",
	Token:     "https://api.zenmoney.ru/oauth2/token/",
	Redirect:  "http://example.com",
}

func NewAuth(app *Application, user *User) *Auth {
	return &Auth{
		Application: app,
		User:        user,
		Endpoints:   DefaultEndpoints,
	}
}

func (a *Auth) GenerateAuthorizeUrl() string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", a.Application.ConsumerKey)
	v.Set("redirect_uri", a.Endpoints.Redirect)

	return a.Endpoints.Authorize + "?" + v.Encode()
}

func (a *Auth) GetAuthorizeCode() (string, error) {
	cookieJar, _ := cookiejar.New(nil)

	client := &http.Client{
		Jar: cookieJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authorizeUrl := a.GenerateAuthorizeUrl()

	err := goToAuthorizeUrl(client, authorizeUrl)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("username", a.User.Login)
	form.Add("password", a.User.Password)
	form.Add("auth_type_password", "Sign in")

	resp, err := client.PostForm(authorizeUrl, form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", err
	}

	return u.Query().Get("code"), nil
}

func goToAuthorizeUrl(client *http.Client, uri string) error {
	resp, err := client.Get(uri)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (a *Auth) GetToken(code string) (*TokenResponse, error) {
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Add("client_id", a.Application.ConsumerKey)
	f.Add("client_secret", a.Application.ConsumerSecret)
	f.Add("code", code)
	f.Add("redirect_uri", a.Endpoints.Redirect)

	resp, err := http.DefaultClient.PostForm(a.Endpoints.Token, f)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	tokenResponse := &TokenResponse{}
	err = json.Unmarshal(body, tokenResponse)
	if err != nil {
		return nil, err
	}

	return tokenResponse, nil
}
