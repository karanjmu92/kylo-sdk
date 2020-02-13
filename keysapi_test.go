package kylo_sdk

import (
	"fmt"
	"testing"
)

func TestKeysEndPoint_CreateKey(t *testing.T) {
	config := &Config{
		KyloIP:        "127.0.0.1",
		KyloUser:      "admin",
		KyloPassword:  "admin",
		LogFilePath:   "",
		LogLevel:      "",
		SkipSSLVerify: true,
	}
	listKeysParams := &ListKeysParams{
		Limit:-1 , Skip: 0,
	}
	client ,_ := NewClient(config)
	createKeyParams := &CreateKeyParams{Name:"TestKey2"}
	fmt.Println("<===========================Creating key==================>")
	key , err := client.Keys.CreateKey(createKeyParams)
	if err != nil{
		fmt.Println(err)
	}
	fmt.Println(*key)

	fmt.Println("<===========================listing keys==================>")

	keys, err := client.Keys.ListKeys(listKeysParams)
	if err!= nil{
		fmt.Println(err)
	}
	fmt.Println(keys.Keys)
}