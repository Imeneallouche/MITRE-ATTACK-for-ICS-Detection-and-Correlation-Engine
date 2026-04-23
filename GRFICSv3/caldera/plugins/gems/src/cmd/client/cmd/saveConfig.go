package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(saveConfigCmd)
}

var saveConfigCmd = &cobra.Command{
	Use:   "save [psm (ascii|xml)] [address (host:port)] [configuration name]",
	Short: "Save a device configuration",
	Long: `Connects to a GEMS server and sends a SaveConfigMessage.
The SaveConfigMessage saves the configuration as the provided name.
The configuration name is an alphanumeric string with no spaces.`,
	Args: cobra.ExactArgs(3),
	Run:  saveConfig,
}

func saveConfig(cmd *cobra.Command, args []string) {
	connect(args)
	name := args[2]
	resp, err := client.SaveConfig(name)
	if err != nil {
		fatal(err)
	}
	log.Println(client.Format(resp))
	fmt.Println(stdOut.Format(resp))
	disconnect()
}
