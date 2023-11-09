package tools

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/metacubex/mihomo/component/mtproxy/common"
)

func Generate(secretTypeOrHostName string) {
	data := make([]byte, common.SimpleSecretLength)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}

	secret := hex.EncodeToString(data)

	switch secretTypeOrHostName {
	case "simple":
		fmt.Println(secret)
	case "secured":
		fmt.Println("dd" + secret)
	default:
		fmt.Println("ee" + secret + hex.EncodeToString([]byte(secretTypeOrHostName)))
	}
}
