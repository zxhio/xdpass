package utils

import "fmt"

var verbose bool

func SetVerbose(v bool) {
	verbose = v
}

func VerbosePrintln(format string, a ...any) {
	if !verbose {
		return
	}
	fmt.Printf(format, a...)
	fmt.Println()
}

func VerbosePrint(format string, a ...any) {
	if verbose {
		fmt.Printf(format, a...)
	}
}
