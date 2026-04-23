package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var (
	paramNames []string
)

func init() {
	rootCmd.AddCommand(getConfigCmd)

	getConfigCmd.Flags().StringSliceVar(&paramNames, "names", []string{}, "comma separated list of desired parameter names")
}

var getConfigCmd = &cobra.Command{
	Use:   "get [psm (ascii|xml)] [address (host:port)]",
	Short: "Get the value of one or more parameters",
	Long: `Connects to a GEMS server and sends a GetConfigMessage.
The GetConfigMessage requests the current configuration from the GEMS 
device. The message can optionally contain a list of desired parameters.`,
	Args: cobra.ExactArgs(2),
	Run:  getConfig,
}

func getConfig(cmd *cobra.Command, args []string) {
	connect(args)
	resp, err := client.GetConfig(paramNames...)
	if err != nil {
		fatal(err)
	}
	log.Println(client.Format(resp))
	fmt.Println(stdOut.Format(resp))
	disconnect()
}
