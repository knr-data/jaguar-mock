//go:generate go-bindata -mode 444 -modtime 1 cert/cert.pem cert/key.pem openapi/openapi/fixtures3.json openapi/openapi/spec3.json

// TODO(bwang): consider renaming core to something more descriptive (perhaps 'server'?)
package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/stripe/stripe-mock/spec"
)

const DefaultPortHTTP = 12111
const DefaultPortHTTPS = 12112

// verbose tracks whether the program is operating in verbose mode
var verbose bool

// This is set to the actual version by GoReleaser (using `-ldflags "-X ..."`)
// as it's run. Versions built from source will always show master.
var version = "master"

// ---

//
// Public-facing structs
//

// TODO: add tests here (in setup_tests.go)
type stripeMock struct {
	serverOptions Options
	server        *http.Server
}

func NewStripeMock(serverOptions Options) (stripeMock, error) {
	err := serverOptions.checkConflictingOptions()

	// TODO(bwang):
	if err != nil {
		errorMsg := fmt.Sprintf("Invalid options: %v", err)
		return stripeMock{}, errors.New(errorMsg)
	}

	return stripeMock{serverOptions: serverOptions}, nil

}

func (mock *stripeMock) Start() (err error) {
	fmt.Println("Starting mock server.")

	server, err := startMockServer(mock.serverOptions)

	if err != nil {
		mock.server = server
		return nil
	} else {
		return err
	}

}

func (mock *stripeMock) Stop() {
	// TODO: wait on cleanup like in https://stackoverflow.com/questions/39320025/how-to-stop-http-listenandserve
	// 			by using a sync.WaitGroup?
	fmt.Println("Stopping mock server.")
	if err := mock.server.Shutdown(context.TODO()); err != nil {
		panic(err)
	}
}

// TODO(bwang): no longer a private type
// Options is a container for the command line options passed to stripe-mock.
type Options struct {
	FixturesPath string

	Http            bool
	HttpAddr        string
	HttpPortDefault int // For testability -- in practice always DefaultPortHTTP
	HttpPort        int
	HttpUnixSocket  string

	Https            bool
	HttpsAddr        string
	HttpsPortDefault int // For testability -- in practice always DefaultPortHTTPS
	HttpsPort        int
	HttpsUnixSocket  string

	Port               int
	ShowVersion        bool
	SpecPath           string
	StrictVersionCheck bool
	UnixSocket         string
}

func (o *Options) checkConflictingOptions() error {
	if o.UnixSocket != "" && o.Port != -1 {
		return fmt.Errorf("Please specify only one of -port or -unix")
	}

	//
	// HTTP
	//

	if o.Http && (o.HttpUnixSocket != "" || o.HttpAddr != "" || o.HttpPort != -1) {
		return fmt.Errorf("Please don't specify -http when using -http-addr, -http-port, or -http-unix")
	}

	if (o.UnixSocket != "" || o.Port != -1) && (o.HttpUnixSocket != "" || o.HttpAddr != "" || o.HttpPort != -1) {
		return fmt.Errorf("Please don't specify -port or -unix when using -http-addr, -http-port, or -http-unix")
	}

	var numHTTPOptions int

	if o.HttpUnixSocket != "" {
		numHTTPOptions++
	}
	if o.HttpAddr != "" {
		numHTTPOptions++
	}
	if o.HttpPort != -1 {
		numHTTPOptions++
	}

	if numHTTPOptions > 1 {
		return fmt.Errorf("Please specify only one of -http-addr, -http-port, or -http-unix")
	}

	//
	// HTTPS
	//

	if o.Https && (o.HttpsUnixSocket != "" || o.HttpsAddr != "" || o.HttpsPort != -1) {
		return fmt.Errorf("Please don't specify -https when using -https-addr, -https-port, or -https-unix")
	}

	if (o.UnixSocket != "" || o.Port != -1) && (o.HttpsUnixSocket != "" || o.HttpAddr != "" || o.HttpsPort != -1) {
		return fmt.Errorf("Please don't specify -port or -unix when using -https-addr, -https-port, or -https-unix")
	}

	var numHTTPSOptions int

	if o.HttpsUnixSocket != "" {
		numHTTPSOptions++
	}
	if o.HttpsAddr != "" {
		numHTTPSOptions++
	}
	if o.HttpsPort != -1 {
		numHTTPSOptions++
	}

	if numHTTPSOptions > 1 {
		return fmt.Errorf("Please specify only one of -https-addr, -https-port, or -https-unix")
	}

	return nil
}

// getHTTPListener gets a listener on a port or unix socket depending on the
// options provided. If HTTP should not be enabled, it returns nil.
func (o *Options) getHTTPListener() (net.Listener, error) {
	protocol := "HTTP"

	if o.HttpAddr != "" {
		return getPortListener(o.HttpAddr, protocol)
	}

	if o.HttpPort != -1 {
		return getPortListener(fmt.Sprintf(":%v", o.HttpPort), protocol)
	}

	if o.HttpUnixSocket != "" {
		return getUnixSocketListener(o.HttpUnixSocket, protocol)
	}

	// HTTPS is active by default, but only if HTTP has not been explicitly
	// activated.
	if o.Https || o.HttpsPort != -1 || o.HttpsUnixSocket != "" {
		return nil, nil
	}

	if o.Port != -1 {
		return getPortListener(fmt.Sprintf(":%v", o.Port), protocol)
	}

	if o.UnixSocket != "" {
		return getUnixSocketListener(o.UnixSocket, protocol)
	}

	return getPortListenerDefault(o.HttpPortDefault, protocol)
}

// getNonSecureHTTPSListener gets a basic listener on a port or unix socket
// depending on the options provided. Its return listener must still be wrapped
// in a TLSListener. If HTTPS should not be enabled, it returns nil.
func (o *Options) getNonSecureHTTPSListener() (net.Listener, error) {
	protocol := "HTTPS"

	if o.HttpsAddr != "" {
		return getPortListener(o.HttpsAddr, protocol)
	}

	if o.HttpsPort != -1 {
		return getPortListener(fmt.Sprintf(":%v", o.HttpsPort), protocol)
	}

	if o.HttpsUnixSocket != "" {
		return getUnixSocketListener(o.HttpsUnixSocket, protocol)
	}

	// HTTPS is active by default, but only if HTTP has not been explicitly
	// activated. HTTP may be activated with `-http`, `-http-port`, or
	// `-http-unix`, but also with the old backwards compatible basic `-port`
	// option.
	if o.Http || o.HttpPort != -1 || o.HttpUnixSocket != "" || o.Port != -1 {
		return nil, nil
	}

	if o.Port != -1 {
		return getPortListener(fmt.Sprintf(":%v", o.Port), protocol)
	}

	if o.UnixSocket != "" {
		return getUnixSocketListener(o.UnixSocket, protocol)
	}

	return getPortListenerDefault(o.HttpsPortDefault, protocol)
}

//
// Private functions
//

func abort(message string) {
	fmt.Fprintf(os.Stderr, message)
	os.Exit(1)
}

// getTLSCertificate reads a certificate and key from the assets built by
// go-bindata.
func getTLSCertificate() (tls.Certificate, error) {
	cert, err := Asset("cert/cert.pem")
	if err != nil {
		return tls.Certificate{}, err
	}

	key, err := Asset("cert/key.pem")
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(cert, key)
}

func getFixtures(fixturesPath string) (*spec.Fixtures, error) {
	var data []byte
	var err error

	if fixturesPath == "" {
		// And do the same for fixtures
		data, err = Asset("openapi/openapi/fixtures3.json")
	} else {
		if !isJSONFile(fixturesPath) {
			return nil, fmt.Errorf("Fixtures should come from a JSON file")
		}

		data, err = ioutil.ReadFile(fixturesPath)
	}

	if err != nil {
		return nil, fmt.Errorf("error loading fixtures: %v", err)
	}

	var fixtures spec.Fixtures
	err = json.Unmarshal(data, &fixtures)
	if err != nil {
		return nil, fmt.Errorf("error decoding spec: %v", err)
	}

	return &fixtures, nil
}

func getPortListener(addr string, protocol string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("error listening at address: %v", err)
	}

	fmt.Printf("Listening for %s at address: %v\n", protocol, listener.Addr())
	return listener, nil
}

// getPortListenerDefault gets a port listener based on the environment
// variable `PORT`, or falls back to a listener on the default port
// (`defaultPort`) if one was not present.
func getPortListenerDefault(defaultPort int, protocol string) (net.Listener, error) {
	if os.Getenv("PORT") != "" {
		envPort, err := strconv.Atoi(os.Getenv("PORT"))
		if err != nil {
			return nil, err
		}
		return getPortListener(fmt.Sprintf(":%v", envPort), protocol)
	}

	return getPortListener(fmt.Sprintf(":%v", defaultPort), protocol)
}

func getSpec(specPath string) (*spec.Spec, error) {
	var data []byte
	var err error

	if specPath == "" {
		// Load the spec information from go-bindata
		data, err = Asset("openapi/openapi/spec3.json")
	} else {
		if !isJSONFile(specPath) {
			return nil, fmt.Errorf("spec should come from a JSON file")
		}

		data, err = ioutil.ReadFile(specPath)
	}
	if err != nil {
		return nil, fmt.Errorf("error loading spec: %v", err)
	}

	var stripeSpec spec.Spec
	err = json.Unmarshal(data, &stripeSpec)
	if err != nil {
		return nil, fmt.Errorf("error decoding spec: %v", err)
	}

	return &stripeSpec, nil
}

func getUnixSocketListener(unixSocket, protocol string) (net.Listener, error) {
	listener, err := net.Listen("unix", unixSocket)
	if err != nil {
		return nil, fmt.Errorf("error listening on socket: %v", err)
	}

	fmt.Printf("Listening for %s on Unix socket: %s\n", protocol, unixSocket)
	return listener, nil
}

// isJSONFile judges based on a file's extension whether it's a JSON file. It's
// used to return a better error message if the user points to an unsupported
// file.
func isJSONFile(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".json"
}

func startMockServer(options Options) (server *http.Server, err error) {
	options.HttpPortDefault = DefaultPortHTTP
	options.HttpsPortDefault = DefaultPortHTTPS

	// TODO(bwang): how to reimplemt default ports
	// options := options{
	// 	httpPortDefault:  DefaultPortHTTP,
	// 	httpsPortDefault: DefaultPortHTTPS,
	// }

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

	// For both spec and fixtures stripe-mock will by default load data from
	// internal assets compiled into the binary, but either one can be
	// overridden with a -spec or -fixtures argument and a path to a file.
	stripeSpec, err := getSpec(options.SpecPath)
	if err != nil {
		return nil, err
	}

	fixtures, err := getFixtures(options.FixturesPath)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	stub := StubServer{
		fixtures:           fixtures,
		spec:               stripeSpec,
		strictVersionCheck: options.StrictVersionCheck,
	}
	err = stub.initializeRouter()
	if err != nil {
		fmt.Printf("Error initializing router: %v\n", err)
		return nil, err
	}

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", stub.HandleRequest)

	// Deduplicates doubled slashes in paths. e.g. `//v1/charges` becomes
	// `/v1/charges`.
	handler := &DoubleSlashFixHandler{httpMux}

	httpListener, err := options.getHTTPListener()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	// Only start HTTP if requested (it will activate by default with no arguments, but it won't start if
	// HTTPS is explicitly requested and HTTP is not).
	if httpListener != nil {
		server := http.Server{
			Handler: handler,
		}

		// Listen in a new Goroutine that so we can start a simultaneous HTTPS
		// listener if necessary.
		go func() {
			err := server.Serve(httpListener)
			if err != nil && err != http.ErrServerClosed {
				abort(err.Error())
			}
		}()

		return &server, nil
	}

	httpsListener, err := options.getNonSecureHTTPSListener()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	// Only start HTTPS if requested (it will activate by default with no
	// arguments, but it won't start if HTTP is explicitly requested and HTTPS
	// is not).
	if httpsListener != nil {
		// Our self-signed certificate is bundled up using go-bindata so that
		// it stays easy to distribute stripe-mock as a standalone binary with
		// no other dependencies.
		certificate, err := getTLSCertificate()
		if err != nil {
			fmt.Println(err)
			return nil, err
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{certificate},

			// h2 is HTTP/2. A server with a default config normally doesn't
			// need this hint, but Go is somewhat inflexible, and we need this
			// here because we're using `Serve` and reading a TLS certificate
			// from memory instead of using `ServeTLS` which would've read a
			// certificate from file.
			NextProtos: []string{"h2"},
		}

		server := http.Server{
			Handler:   handler,
			TLSConfig: tlsConfig,
		}
		tlsListener := tls.NewListener(httpsListener, tlsConfig)

		go func() {
			err := server.Serve(tlsListener)
			if err != nil && err != http.ErrServerClosed {
				abort(err.Error())
			}
		}()

		return &server, nil
	}

	return nil, errors.New("Error: reached unexpected state when starting stripe-mock server.")
}
