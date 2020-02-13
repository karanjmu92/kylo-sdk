package utility

import (
	"encoding/json"
	"fmt"
	"github.com/gemalto/requester"
	"github.com/gemalto/requester/httpclient"
	"io/ioutil"
)

type AuthParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JWT struct {
	Jwt        string `json:"jwt"`
	Duration   int    `json:"duration"`
	Token_type string `json:"token_type"`
}

func GetBaseURL(ip string) string {
	return fmt.Sprintf("%s%s%s", HttpURL, ip, BASEPrefix)
}

func GetJWT(kyloIP string, kyloUser string, kyloPassword string) (string, error) {

	jwtURL := GetBaseURL(kyloIP) + JwtURL
	authParams := AuthParams{kyloUser, kyloPassword}
	jwt := JWT{}
	resp, err := requester.Send(
		requester.Post(jwtURL),
		requester.Body(authParams),
		requester.Client(httpclient.SkipVerify(true)),
	)
	if err != nil {
		fmt.Println(err)
		return "", nil
	}
	body, err := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &jwt)
	return jwt.Jwt, nil
}
