// Tiny HTTP server for test

package main

import (
	"flag"
	"fmt"
	"net/http"
)

var laddr *string = flag.String("l", ":8988", "listen port")

func init() {
	flag.Parse()
	fmt.Println("Listening to ", *laddr)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r)
		for k, v := range r.Header {
			fmt.Printf("[%s] = [%v]\n", k, v)
		}
	})

	http.ListenAndServe(*laddr, nil)
}
