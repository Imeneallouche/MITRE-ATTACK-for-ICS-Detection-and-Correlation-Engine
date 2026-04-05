package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(getConfigListCmd)
}

var getConfigListCmd = &cobra.Command{
	Use:   "get-config-list [psm (ascii|xml)] [address (host:port)]",
	Short: "List available configurations on the device",
	Long: `Connects to a GEMS server and sends a GetConfigListMessage.
The GetConfigListMessage retrieves all configurations available on 
the GEMS device. It does not require any additional arguments.`,
	Args: cobra.ExactArgs(2),
	Run:  getConfigList,
}

func getConfigList(cmd *cobra.Command, args []string) {
	connect(args)
	resp, err := client.GetConfigList()
	if err != nil {
		fatal(err)
	}
	log.Println(client.Format(resp))
	fmt.Println(stdOut.Format(resp))

	disconnect()
}
