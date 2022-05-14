package main

import (
	"fieldflat/fss-pir/src/pir"
	"fieldflat/fss-pir/src/secure_update"
	"flag"
)

func main() {
	flag.Parse()
	if flag.Args()[0] == "pir_genkey" {
		pir.GenKey()
	} else if flag.Args()[0] == "pir_eval" {
		pir.Eval()
	} else if flag.Args()[0] == "pir_restore" {
		pir.Restore()
	} else if flag.Args()[0] == "secure_update_genkey" {
		secure_update.GenKey()
	} else if flag.Args()[0] == "secure_update_eval" {
		secure_update.Eval()
	} else if flag.Args()[0] == "secure_update_restore" {
		secure_update.Restore()
	}
}
