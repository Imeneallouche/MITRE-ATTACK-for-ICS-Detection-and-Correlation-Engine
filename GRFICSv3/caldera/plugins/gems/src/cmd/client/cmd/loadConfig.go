package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(loadConfigCmd)
}

var loadConfigCmd = &cobra.Command{
	Use:   "load [psm (ascii|xml)] [address (host:port)] [configuration name]",
	Short: "Load a saved configuration",
	Long: `Connects to a GEMS server and sends a LoadConfigMessage.
The LoadConfigMessage loads the configuration with the provided name.
The configuration name is an alphanumeric string with no spaces.`,
	Args: cobra.ExactArgs(3),
	Run:  loadConfig,
}

func loadConfig(cmd *cobra.Command, args []string) {
	connect(args)
	name := args[2]
	resp, err := client.LoadConfig(name)
	if err != nil {
		fatal(err)
	}
	log.Println(client.Format(resp))
	fmt.Println(stdOut.Format(resp))
}
