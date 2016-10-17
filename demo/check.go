package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("%s ip ticket\n", os.Args[0])
		return
	}

	c := exec.Command("./checkOaKey", os.Args[2], os.Args[1])
	d, err := c.CombinedOutput()
	if err != nil {
		fmt.Println("check ticket failed", err)
		os.Exit(-1)
	}

	fmt.Printf("%s", string(d))
}
