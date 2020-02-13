package kylo_sdk

import (
	"github.com/gemalto/requester"
)

type Config struct {
	//ip address of the kylo server
	KyloIP string
	//user of the kylo server
	KyloUser string
	//password of the kylo server
	KyloPassword string
	//location of log file. If not provided default will be created in current directory.
	LogFilePath string
	//logger will be initialize with given log level.
	//log level can be INFO,WARN,MEDIUM and DEBUG.
	LogLevel string
	//when to verify ssl certificates in rest call to kylo server.
	SkipSSLVerify bool
}
type Client struct {
	*requester.Requester
	Config *Config
	Keys   *KeysEndPoint
}

//Return Client with provided config
func NewClient(config *Config) (*Client, error) {
	client := &Client{
		Requester: &requester.Requester{},
		Config: &Config{},
	}
	client.Keys = (*KeysEndPoint)(client)
	client.Config.KyloIP = config.KyloIP
	client.Config.KyloPassword = config.KyloPassword
	client.Config.KyloUser = config.KyloUser
	client.Config.SkipSSLVerify = config.SkipSSLVerify
	return client, nil
}
