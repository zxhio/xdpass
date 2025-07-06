package utils

import (
	"fmt"
	"os"
)

func CheckErrorAndExit(err error, format string, a ...any) {
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "%s: %s\n", fmt.Sprintf(format, a...), err)
	os.Exit(1)
}

func CheckEqualAndExit(b bool, format string, a ...any) {
	if b {
		return
	}

	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(1)
}
