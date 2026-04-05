package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(directiveCmd)

	directiveCmd.Flags().StringArrayVarP(&stringParams, "param", "p", []string{}, "parameter to pass as argument to directive, may be repeated for additional parameters")
	directiveCmd.Flags().StringVar(&concatParams, "params", "", "string of parameters to pass as arguments to directive, concatenated with the pipe character ('|')")
}

var directiveCmd = &cobra.Command{
	Use:   "directive [psm (ascii|xml)] [address (host:port)] [directive name]",
	Short: "Send a directive",
	Long: `Connects to a GEMS server and sends a DirectiveMessage.
The DirectiveMessage invokes an action on the GEMS device. The message may contain
contain a list of parameter arguments. Parameters may be passed using the -p/--param
flag for individual parameters or by using the --params for a list of parameters
separated by the pipe character ('|'). All parameters must be formatted as defined
by GEMS ASCII.`,
	Args: cobra.ExactArgs(3),
	Run:  directive,
}

func directive(cmd *cobra.Command, args []string) {
	connect(args)

	params := make([]string, len(stringParams))
	copy(params, stringParams)
	if len(concatParams) > 0 {
		splitParams := strings.Split(concatParams, "|")
		params = append(params, splitParams...)
	}

	directiveName := args[2]
	resp, err := client.Directive(directiveName, params)
	if err != nil {
		fatal(err)
	}
	log.Println(client.Format(resp))
	fmt.Println(stdOut.Format(resp))
	disconnect()
}
