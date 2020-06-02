//go:generate go-bindata -mode 444 -modtime 1 cert/cert.pem cert/key.pem openapi/openapi/fixtures3.json openapi/openapi/spec3.json

package main

import (
	"flag"
	"fmt"

	"github.com/stripe/stripe-mock/core"
)

// verbose tracks whether the program is operating in verbose mode
var verbose bool

// This is set to the actual version by GoReleaser (using `-ldflags "-X ..."`)
// as it's run. Versions built from source will always show master.
var version = "master"

// ---

func main() {
	options := core.Options{}
	// As you can probably tell, there are just too many HTTP/HTTPS binding
	// options, which is a result of me not thinking through the original
	// interface well enough.
	//
	// I've left them all in place for now for backwards compatibility, but we
	// should probably deprecate `-http-port`, `-https-port`, `-port`, and
	// `-unix` in favor of the remaining more expressive and more versatile
	// alternatives.
	//
	// Eventually, `-http` and `-https` could become shorthand synonyms for
	// `-http-addr` and `-https-addr`.
	flag.BoolVar(&options.Http, "http", false, "Run with HTTP")
	flag.StringVar(&options.HttpAddr, "http-addr", "", fmt.Sprintf("Host and port to listen on for HTTP as `<ip>:<port>`; empty <ip> to bind all system IPs, empty <port> to have system choose; e.g. ':%v', '127.0.0.1:%v'", core.DefaultPortHTTP, core.DefaultPortHTTP))
	flag.IntVar(&options.HttpPort, "http-port", -1, "Port to listen on for HTTP; same as '-http-addr :<port>'")
	flag.StringVar(&options.HttpUnixSocket, "http-unix", "", "Unix socket to listen on for HTTP")

	flag.BoolVar(&options.Https, "https", false, "Run with HTTPS; also enables HTTP/2")
	flag.StringVar(&options.HttpsAddr, "https-addr", "", fmt.Sprintf("Host and port to listen on for HTTPS as `<ip>:<port>`; empty <ip> to bind all system IPs, empty <port> to have system choose; e.g. ':%v', '127.0.0.1:%v'", core.DefaultPortHTTPS, core.DefaultPortHTTPS))
	flag.IntVar(&options.HttpsPort, "https-port", -1, "Port to listen on for HTTPS; same as '-https-addr :<port>'")
	flag.StringVar(&options.HttpsUnixSocket, "https-unix", "", "Unix socket to listen on for HTTPS")

	flag.IntVar(&options.Port, "port", -1, "Port to listen on; also respects PORT from environment")
	flag.StringVar(&options.FixturesPath, "fixtures", "", "Path to fixtures to use instead of bundled version (should be JSON)")
	flag.StringVar(&options.SpecPath, "spec", "", "Path to OpenAPI spec to use instead of bundled version (should be JSON)")
	flag.BoolVar(&options.StrictVersionCheck, "strict-version-check", false, "Errors if version sent in Stripe-Version doesn't match the one in OpenAPI")
	flag.StringVar(&options.UnixSocket, "unix", "", "Unix socket to listen on")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose mode")
	flag.BoolVar(&options.ShowVersion, "version", false, "Show version and exit")

	flag.Parse()

	fmt.Printf("stripe-mock %s\n", version)
	if options.ShowVersion || len(flag.Args()) == 1 && flag.Arg(0) == "version" {
		return
	}

	// err := options.CheckConflictingOptions()
	// if err != nil {
	// 	flag.Usage()
	// 	core.Abort(fmt.Sprintf("Invalid options: %v", err))
	// }

	fmt.Println(options)
	core.StartMockServer(options)

}
