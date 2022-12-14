package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

var (
	caBundle       string
	listenAddr     string
	connectAddr    string
	serverCertPath string
	serverKeyPath  string
	clientCertPath string
	clientKeyPath  string
)

var rootCmd = &cobra.Command{
	Short: "Test (m)TLS still works despite an expired CA",
	Long: ` 

    tls-test

    A straightforward mTLS example app, meant to test whether Go's HTTPS client and server
    still go ahead with the mTLS handshake and verification even if a CA in the chain 
    has expired.

    `,
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start a test HTTPS server",
	Long: `
    Start a test HTTPS server with the provided bundle, and leaf certificates.
    The server will return '204' for all HTTP requests made to it.`,
	Run: func(cmd *cobra.Command, args []string) {
		srv, err := mkServer(listenAddr, caBundle)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Starting server on %s", listenAddr)

		err = srv.ListenAndServeTLS(serverCertPath, serverKeyPath)
		if err != nil {
			log.Fatal(err)
		}
	},
}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start a test HTTPS client",
	Long: `
    Start a test HTTPS client, with the provided bundle, and leaf certificates.
    The client will send a request to the server, print the status code and exit.`,
	Run: func(cmd *cobra.Command, args []string) {
		client, err := mkClient(clientCertPath, clientKeyPath, caBundle)
		if err != nil {
			log.Fatal(err)
		}

		r, err := client.Get("https://" + connectAddr)
		if err != nil {
			log.Fatal(err)
		}
		defer r.Body.Close()
		fmt.Printf("%v\n", r.Status)
	},
}

func init() {
	log.SetOutput(os.Stdout)
	rootCmd.PersistentFlags().StringVar(&caBundle, "ca-bundle", "bundle.crt", "Path to CA bundle that contains at least one CA certificate (default 'bundle.crt')")

	rootCmd.PersistentFlags().StringVar(&listenAddr, "listen-addr", ":4000", "Address to bind server listener on")
	rootCmd.PersistentFlags().StringVar(&serverCertPath, "server-cert-path", "server-leaf.crt", "Path to the server's leaf certificate file")
	rootCmd.PersistentFlags().StringVar(&serverKeyPath, "server-key-path", "server-leaf.key", "Path to the server's leaf private key file")

	rootCmd.PersistentFlags().StringVar(&connectAddr, "connect-addr", ":4000", "Address to connect to")
	rootCmd.PersistentFlags().StringVar(&clientCertPath, "client-cert-path", "client-leaf.crt", "Path to the client's leaf certificate file")
	rootCmd.PersistentFlags().StringVar(&clientKeyPath, "client-key-path", "client-leaf.key", "Path to the client's leaf private key file")

	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(clientCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Create an HTTP Server that will bind on the provided listen address. A CA
// certificate path is passed in ('bundlepath') that will be used to read in the
// CA certs used to authenticate the client.
func mkServer(listenAddr, bundlePath string) (*http.Server, error) {
	// Read bundle, add to a set of certificates that will be used to
	// authenticate the client.
	certPool, err := configureTrustChain(bundlePath)
	if err != nil {
		log.Fatalf("Failed to configure server with trust bundle: %v", err)
		return nil, err
	}

	// Create a new HTTP mux, handle only '/'.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}

		// Return 204 status code.
		w.WriteHeader(204)
	})

	// Create an http server
	return &http.Server{
		Addr:    listenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			// Min TLS is v1.2
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			RootCAs:                  certPool,
			// Set of CAs that the server will use if it has to authenticate the
			// client.
			ClientCAs: certPool,
		},
	}, nil
}

// Create an HTTP client, the function accepts three strings that will instantiate
// the certificate chain used to authenticate the server, as well as the
// certificate used by the client.
func mkClient(certPath, keyPath, bundlePath string) (*http.Client, error) {
	// Read bundle, add to a set of certificates that will be used to
	// authenticate the server.
	certPool, err := configureTrustChain(bundlePath)
	if err != nil {
		log.Fatalf("Failed to configure server with trust bundle: %v", err)
		return nil, err
	}

	// Load our client certificate and key.
	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("Failed to load client keypair: %v", err)
		return nil, err
	}

	// Create an http client
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Expected server name is hardcoded to the SAN of the server
				// leaf certificate
				ServerName: "leaf-server.linkerd.cluster.local",
				// RootCAs are the CA certificates the client will use when
				// authenticating the server.
				RootCAs: certPool,
				// Certificates that the client will use.
				Certificates: []tls.Certificate{clientCert},
			},
		},
	}, nil
}

// configureTrustChain takes the path to a CA (or a bundle) certificate, and
// creates a new cert-pool, a set of certificates.
func configureTrustChain(caPath string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)
	return certPool, nil
}
