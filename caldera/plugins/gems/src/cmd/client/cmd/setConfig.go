package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/spf13/cobra"
)

var (
	stringParams []string
	concatParams string
)

func init() {
	rootCmd.AddCommand(setConfigCmd)

	setConfigCmd.Flags().StringArrayVarP(&stringParams, "param", "p", []string{}, "parameter to set, may be repeated for additional parameters")
	setConfigCmd.Flags().StringVar(&concatParams, "params", "", "string of parameters to pass as arguments to directive, concatenated with the pipe character ('|')")
}

var setConfigCmd = &cobra.Command{
	Use:   "set [psm (ascii|xml)] [address (host:port)]",
	Short: "Set the value of one or more parameters",
	Long: `Connects to a GEMS server and sends a SetConfigMessage.
The SetConfigMessage contains a list of parameters to set. New parameter
values may be passed using the -p/--param flag for individual parameters or by using the 
--params for a list of parameters separated by the pipe character ('|'). All
parameters must be formatted as defined by GEMS ASCII.`,
	Args: cobra.ExactArgs(2),
	Run:  setConfig,
}

func setConfig(cmd *cobra.Command, args []string) {
	connect(args)

	params := make([]string, len(stringParams))
	copy(params, stringParams)
	if len(concatParams) > 0 {
		splitParams := strings.Split(concatParams, "|")
		params = append(params, splitParams...)
	}

	resp, err := client.SetConfig(params)
	if err != nil {
		fatal(err)
	}
	log.Println(client.Format(resp))
	fmt.Println(stdOut.Format(resp))
	disconnect()
}
