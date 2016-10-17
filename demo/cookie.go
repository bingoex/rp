package main

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
)

func main() {
	rawCookies := "cookie1=value1;cookie2=value2"
	rawRequest := fmt.Sprintf("GET / HTTP/1.0\r\nCookie: %s\r\n\r\n", rawCookies)

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))

	if err == nil {
		cookies := req.Cookies()
		fmt.Println(cookies)

		if c, er1 := req.Cookie("cookie1"); er1 == nil {
			fmt.Println(c.Value)
		}
	}
}
