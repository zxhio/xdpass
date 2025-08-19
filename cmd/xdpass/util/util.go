package util

import "github.com/spf13/cobra"

func DisableSortFlags(cmds ...*cobra.Command) {
	for _, cmd := range cmds {
		cmd.InheritedFlags().SortFlags = false
		cmd.PersistentFlags().SortFlags = false
		cmd.Flags().SortFlags = false
	}
}
