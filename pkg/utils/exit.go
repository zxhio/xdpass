package utils

import (
	"fmt"
	"os"
)

func CheckErrorAndExit(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}
