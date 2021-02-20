package constant

import "net/http"

var ecHandler http.Handler

func SetECHandler(h http.Handler) {
	ecHandler = h
}

func GetECHandler() http.Handler {
	return ecHandler
}
