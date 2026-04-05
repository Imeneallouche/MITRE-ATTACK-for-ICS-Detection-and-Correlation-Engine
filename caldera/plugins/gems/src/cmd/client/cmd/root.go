package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	gems "github.com/mitre/gems/src"
	"github.com/mitre/gems/src/gemsV14"
	"github.com/spf13/cobra"
)

var (
	token    string
	target   string
	version  string
	user     string
	password string
	tls      bool
	insecure bool
	client   *gems.Client
	stdOut   = gems.ResponseContentFormatter{}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "GEMS authentication token")
	rootCmd.PersistentFlags().StringVar(&target, "target", "", "name of the target device")
	rootCmd.PersistentFlags().StringVar(&version, "version", "", "set the GEMS version (default: 1.4)")
	rootCmd.PersistentFlags().BoolVar(&tls, "tls", false, "connect using TLS")
	rootCmd.PersistentFlags().BoolVar(&insecure, "insecure", false, "allow self-signed certificates when connecting using TLS")

	rootCmd.PersistentFlags().StringVar(&user, "user", "", "username for GEMS authentication")
	rootCmd.PersistentFlags().StringVar(&password, "pass", "", "password for GEMS authentication")
}

var rootCmd = &cobra.Command{
	Use:  "gems-client",
	Long: "A client for producing GEMS communications.",
}

func connect(args []string) {
	psm := args[0]

	var (
		v   gems.Version
		err error
	)

	switch version {
	case "1.4", "14", "":
		v = gemsV14.GemsV14{}
	default:
		fmt.Printf("version '%s' not implemented\n", version)
		os.Exit(1)
	}

	client, err = gems.NewClient(v, psm, gems.DefaultFormatter{})
	if err != nil {
		fmt.Printf("failed to initialize client: %s\n", err)
		os.Exit(1)
	}

	if (strings.ToLower(user) != "none") && (strings.ToLower(password) != "none") &&
		(strings.ToLower(user) != "") && (strings.ToLower(password) != "") {
		token = fmt.Sprintf("up:%s:%s", user, password)
	}

	addr := args[1]
	if tls {
		err = client.ConnectTLS(addr, gems.ConnectionTypeControlAndStatus, token, target, insecure)
	} else {
		err = client.Connect(addr, gems.ConnectionTypeControlAndStatus, token, target)
	}
	if err != nil {
		fmt.Printf("failed to connect to server: %s\n", err)
		os.Exit(1)
	}
	log.Printf("connected to %s", client.ServerAddr())
}

func disconnect() {
	log.Println("disconnecting from server")
	client.Disconnect(gems.DisconnectReasonNormalTermination)
}

func fatal(err error) {
	log.Println(err)
	disconnect()
	os.Exit(1)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
