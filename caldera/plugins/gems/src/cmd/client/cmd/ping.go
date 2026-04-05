package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(pingCmd)
}

var pingCmd = &cobra.Command{
	Use:   "ping [psm (ascii|xml)] [address (host:port)]",
	Short: "Ping a device",
	Long: `Connects to a GEMS server and sends a PingMessage.
The PingMessage provides a method for determining if a GEMS device
is responding to messages.`,
	Args: cobra.ExactArgs(2),
	Run:  ping,
}

func ping(cmd *cobra.Command, args []string) {
	connect(args)
	resp, err := client.Ping()
	if err != nil {
		fatal(err)
	}
	log.Println(client.Format(resp))
	fmt.Println(stdOut.Format(resp))
	disconnect()
}
