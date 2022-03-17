// An ACME client that requests issuance of a certificate using a SHA-1 signed
// and a redirect to an HTTPS server that offers only TLS 1.0 and TLS 1.1.
//
// To run against a local Boulder, edit docker-compose.yml to change FAKEDNS to 172.17.0.1 (your host IP) and run:
//
// docker-compose up
// go run oddclient.go -dirurl http://boulder:4001/directory -domains ${RANDOM}-example.com -httpListen :5002 -httpsListen :5001
//
// To run against a public ACME server, set up a host with wildcard DNS pointed at it and run:
//
//  go run oddclient.go -dirurl https://acme-staging-v02.api.letsencrypt.org/directory -domains ${RANDOM}.example.com
//
// Adapted from https://github.com/eggsampler/acme/blob/7c62a72ecf03a1e7d81ab94d17b1fbac0259265d/examples/certbot/certbot.go
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/pem"

	"flag"

	"github.com/eggsampler/acme/v3"
)

var (
	domains      string
	baseDomain   string
	issuePath    string
	directoryUrl string
	httpListen   string
	httpsListen  string
)

type acmeAccountFile struct {
	PrivateKey string `json:"privateKey"`
	Url        string `json:"url"`
}

func main() {
	flag.StringVar(&directoryUrl, "dirurl", acme.LetsEncryptStaging,
		"acme directory url - defaults to lets encrypt v2 staging url if not provided")
	flag.StringVar(&domains, "domains", "",
		"a comma separated list of domains to issue a certificate for")
	flag.StringVar(&baseDomain, "baseDomain", "",
		"a domain name under which to issue for subdomains, e.g. 'example.com'")
	flag.StringVar(&issuePath, "issuePath", "",
		"POST to this path to trigger an issuance")
	flag.StringVar(&httpListen, "httpListen", ":80", "Port on which to listen for HTTP")
	flag.StringVar(&httpsListen, "httpsListen", ":443", "Port on which to listen for HTTPS")
	flag.Parse()

	go redirectServer(httpListen)
	go challengeServer(httpsListen)

	if domains != "" {
		if err := issue(os.Stdout, strings.Split(domains, ","), directoryUrl, SHA1TLS1); err != nil {
			log.Fatal(err)
		}
	} else {
		// Wait for issuance requests via HTTP; shut down on SIGTERM
		select {}
	}
}

// Challenge responses to serve
var servables = challengeResponder{challenges: make(map[string]string)}

type challengeResponder struct {
	sync.Mutex
	// Map from a challenge token path to its contents
	challenges map[string]string
}

const ACME_CHALLENGE_PREFIX = "/.well-known/acme-challenge/"

// Serve challenge responses via HTTPS with a self-signed certificate. Never returns.
func challengeServer(addr string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{
					cert,
				},
				PrivateKey: key,
			},
		},
		MaxVersion: tls.VersionTLS11,
	}

	mux := http.NewServeMux()
	mux.Handle(ACME_CHALLENGE_PREFIX,
		http.StripPrefix(ACME_CHALLENGE_PREFIX, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			servables.Lock()
			defer servables.Unlock()
			challengeResponse := servables.challenges[r.URL.Path]
			if challengeResponse == "" {
				w.WriteHeader(404)
				fmt.Fprintf(w, "No challenge found for %s", r.URL.Path)
			} else {
				_, _ = w.Write([]byte(challengeResponse))
			}
		})))

	srv := &http.Server{
		Addr:      addr,
		TLSConfig: &tlsConfig,
		Handler:   mux,
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// Redirect all ACME challenge requests to their HTTPS equivalent. Never returns.
func redirectServer(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/request-a-cert", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(401)
			fmt.Fprintf(w, "Use POST")
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Error reading body: %s\n", err)
			return
		}
		components := strings.Split(string(body), ";")
		if len(components) != 2 {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Invalid POST body. Expected '<profile>;<directory url>, got %q\n", body)
			return
		}
		directoryUrl = components[1]
		profile, ok := profiles[components[0]]
		if !ok {
			w.WriteHeader(401)
			fmt.Fprintf(w, "Unrecognized profile %q\n", components[0])
		}

		if baseDomain == "" {
			w.WriteHeader(500)
			fmt.Fprintf(w, "No base domain configured. Start server with -baseDomain\n")
			return
		}
		var subdomain [4]byte
		_, err = rand.Reader.Read(subdomain[:])
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Error getting randomness: %s\n", err)
			return
		}
		hostname := fmt.Sprintf("%x.%s", subdomain, baseDomain)

		var buf bytes.Buffer
		err = issue(&buf, []string{hostname}, directoryUrl, profile)
		if err != nil {
			var prob acme.Problem
			if errors.As(err, &prob) {
				w.WriteHeader(prob.Status)
			} else {
				w.WriteHeader(500)
			}
			_, _ = w.Write(buf.Bytes())
			fmt.Fprintf(w, "error: %s\n", err)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))

	mux.Handle(ACME_CHALLENGE_PREFIX, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		w.Header().Set("Location", fmt.Sprintf("https://%s%s", r.Host, r.URL.Path))
		w.WriteHeader(302)
	}))

	s := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	log.Fatal(s.ListenAndServe())
}

type Profile int

const (
	TLS1 Profile = iota
	SHA1TLS1
)

var profiles = map[string]Profile{
	"sha1tls1": SHA1TLS1,
	"tls1":     TLS1,
}

type timestampWriter struct {
	io.Writer
}

func (tw timestampWriter) Write(b []byte) (int, error) {
	return fmt.Fprintf(tw.Writer, "%s: %s\n", time.Now().UTC().Format("2006-01-02T15:04:05.999Z"), string(b))
}

func issue(w io.Writer, domains []string, directoryURL string, profile Profile) error {
	w = timestampWriter{w}
	if len(domains) == 0 {
		return fmt.Errorf("no domains provided")
	}

	// create a new acme client given a provided (or default) directory url
	fmt.Fprintf(w, "Connecting to acme directory url: %s", directoryURL)
	client, err := acme.NewClient(directoryURL)
	if err != nil {
		return fmt.Errorf("connecting to acme directory: %w", err)
	}

	accountFile := base64.RawURLEncoding.EncodeToString([]byte(directoryURL)) + ".account.json"

	// attempt to load an existing account from file
	fmt.Fprintf(w, "Loading account file %s", accountFile)
	account, err := loadAccount(client, accountFile)
	if err != nil {
		fmt.Fprintf(w, "loading existing account: %s", err)
		// if there was an error loading an account, just create a new one
		fmt.Fprintf(w, "Creating new account")
		account, err = createAccount(client, accountFile)
		if err != nil {
			return fmt.Errorf("creating new account: %w", err)
		}
	}
	fmt.Fprintf(w, "Account url: %s", account.URL)

	var ids []acme.Identifier
	for _, domain := range domains {
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}

	// create a new order with the acme service given the provided identifiers
	fmt.Fprintf(w, "Creating new order for domains: %s", domains)
	order, err := client.NewOrder(account, ids)
	if err != nil {
		return fmt.Errorf("creating new order: %s", err)
	}
	fmt.Fprintf(w, "Order created: %s", order.URL)

	// loop through each of the provided authorization urls
	for _, authUrl := range order.Authorizations {
		// fetch the authorization data from the acme service given the provided authorization url
		fmt.Fprintf(w, "Fetching authorization: %s", authUrl)
		auth, err := client.FetchAuthorization(account, authUrl)
		if err != nil {
			return fmt.Errorf("fetching authorization url %q: %w", authUrl, err)
		}
		fmt.Fprintf(w, "Fetched authorization: %s", auth.Identifier.Value)

		// grab a http-01 challenge from the authorization if it exists
		chal, ok := auth.ChallengeMap[acme.ChallengeTypeHTTP01]
		if !ok {
			return fmt.Errorf("unable to find http challenge for auth %s", auth.Identifier.Value)
		}

		// create the challenge token file with the key authorization from the challenge
		fmt.Fprintf(w, "Preparing to serve challenge: %s", chal.Token)
		servables.Lock()
		servables.challenges[chal.Token] = chal.KeyAuthorization
		servables.Unlock()

		/*
			If you wanted to use a DNS-01 challenge you would extract the challenge object,
			chal, ok: = auth.ChallengeMap[acme.ChallengeTypeDNS01]

			You then need to base64 encode the challenge key authorisation for which a helper function is included,
			txt := acme.EncodeDNS01KeyAuthorization(chal.KeyAuthorization)

			This txt value is what you then place in the DNS TXT record for "_acme-challenge.[YOURDOMAIN]" before
			continuing to update the challenge.
		*/

		// update the acme server that the challenge file is ready to be queried
		fmt.Fprintf(w, "Updating challenge for authorization %s: %s", auth.Identifier.Value, chal.URL)
		chal, err = client.UpdateChallenge(account, chal)
		if err != nil {
			return fmt.Errorf("updating authorization %s challenge: %w", auth.Identifier.Value, err)
		}
		fmt.Fprintf(w, "Challenge updated")
	}

	// all the challenges should now be completed

	// create a csr for the new certificate
	fmt.Fprintf(w, "Generating certificate private key")
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating certificate key: %w", err)
	}

	signatureAlgorithm := x509.SHA256WithRSA
	if profile == SHA1TLS1 {
		signatureAlgorithm = x509.SHA1WithRSA
	}
	// create the new csr template
	fmt.Fprintf(w, "Creating csr")
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: signatureAlgorithm,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domains[0]},
		DNSNames:           domains,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		return fmt.Errorf("creating certificate request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return fmt.Errorf("parsing certificate request: %w", err)
	}

	// finalize the order with the acme server given a csr
	fmt.Fprintf(w, "Finalising order: %s", order.URL)
	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		return fmt.Errorf("finalizing order: %w", err)
	}

	fmt.Fprintf(w, "Certificate issued: %s", order.Certificate)
	fmt.Fprintf(w, "Done.")
	return nil
}

func loadAccount(client acme.Client, accountFile string) (acme.Account, error) {
	raw, err := ioutil.ReadFile(accountFile)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error reading account file %q: %w", accountFile, err)
	}
	var aaf acmeAccountFile
	if err := json.Unmarshal(raw, &aaf); err != nil {
		return acme.Account{}, fmt.Errorf("error parsing account file %q: %w", accountFile, err)
	}
	account, err := client.UpdateAccount(acme.Account{PrivateKey: pem2key([]byte(aaf.PrivateKey)), URL: aaf.Url})
	if err != nil {
		return acme.Account{}, fmt.Errorf("error updating existing account: %w", err)
	}
	return account, nil
}

func createAccount(client acme.Client, accountFile string) (acme.Account, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating private key: %v", err)
	}
	account, err := client.NewAccount(privKey, false, true)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating new account: %v", err)
	}
	raw, err := json.Marshal(acmeAccountFile{PrivateKey: string(key2pem(privKey)), Url: account.URL})
	if err != nil {
		return acme.Account{}, fmt.Errorf("error parsing new account: %v", err)
	}
	if err := ioutil.WriteFile(accountFile, raw, 0600); err != nil {
		return acme.Account{}, fmt.Errorf("error creating account file: %v", err)
	}
	return account, nil
}

func key2pem(certKey *ecdsa.PrivateKey) []byte {
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		log.Fatalf("Error encoding key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	})
}

func pem2key(data []byte) *ecdsa.PrivateKey {
	b, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		log.Fatalf("Error decoding key: %v", err)
	}
	return key
}
