package main

import (
	"os"
	"github.com/hknutzen/go-Netspoc/pkg/pass1"
)

func main() {
	pass1.ImportFromPerl()
	pass1.CheckExpandedRules()
	os.Exit(pass1.ErrorCounter)
}
