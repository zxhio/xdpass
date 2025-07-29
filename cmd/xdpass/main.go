package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/cmd/xdpass/bench"
	"github.com/zxhio/xdpass/cmd/xdpass/rule"
	"github.com/zxhio/xdpass/cmd/xdpass/xdp"
	"github.com/zxhio/xdpass/pkg/builder"
	"github.com/zxhio/xdpass/pkg/utils"
)

var (
	verbose bool
	version bool
)

const logoAscii = `    |             
 \ \| |\ //| // //
      |`

var rootCmd = &cobra.Command{
	Use:   "xdpass",
	Short: "xdpass command line tool\n\n" + color.HiBlueString(logoAscii),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		utils.SetVerbose(verbose)
	},
	Run: func(cmd *cobra.Command, args []string) {
		if version {
			fmt.Println(builder.BuildInfo())
			os.Exit(0)
		}
		cmd.Help()
	},
}

func main() {
	cobra.EnableTraverseRunHooks = true
	rule.Export(rootCmd)
	xdp.Export(rootCmd)
	bench.Export(rootCmd)
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVarP(&version, "version", "V", false, "Print version")
	rootCmd.Execute()
}
