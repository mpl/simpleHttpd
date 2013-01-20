package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	uploadform = "upload.html"
	selfKey    = "key.pem"
	selfCert   = "cert.pem"
	idstring   = "http://golang.org/pkg/http/#ListenAndServe"
)

var (
	host     = flag.String("host", "0.0.0.0:8080", "listening port and hostname")
	help     = flag.Bool("h", false, "show this help")
	userpass = flag.String("userpass", "", "optional username:password protection")
	secure   = flag.Bool("ssl", false, "for https")
	upload   = flag.Bool("upload", false, "enable upload and automatically create upload.html")
)

var (
	rootdir, _        = os.Getwd()
	kBasicAuthPattern = regexp.MustCompile(`^Basic ([a-zA-Z0-9\+/=]+)`)
	username          string
	password          string
)

func usage() {
	fmt.Fprintf(os.Stderr, "\t simpleHttpd \n")
	flag.PrintDefaults()
	os.Exit(2)
}

func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if e, ok := recover().(error); ok {
				http.Error(w, e.Error(), http.StatusInternalServerError)
				return
			}
		}()
		title := r.URL.Path
		w.Header().Set("Server", idstring)
		if isAllowed(r) {
			fn(w, r, title)
		} else {
			sendUnauthorized(w, r)
		}
	}
}

func basicAuth(req *http.Request) (string, string, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return "", "", fmt.Errorf("Missing \"Authorization\" in header")
	}
	matches := kBasicAuthPattern.FindStringSubmatch(auth)
	if len(matches) != 2 {
		return "", "", fmt.Errorf("Bogus Authorization header")
	}
	encoded := matches[1]
	enc := base64.StdEncoding
	decBuf := make([]byte, enc.DecodedLen(len(encoded)))
	n, err := enc.Decode(decBuf, []byte(encoded))
	if err != nil {
		return "", "", err
	}
	pieces := strings.SplitN(string(decBuf[0:n]), ":", 2)
	if len(pieces) != 2 {
		return "", "", fmt.Errorf("didn't get two pieces")
	}
	return pieces[0], pieces[1], nil
}

func isAllowed(req *http.Request) bool {
	if *userpass == "" {
		return true
	}
	user, pass, err := basicAuth(req)
	if err != nil {
		return false
	}
	return user == username && pass == password
}

func sendUnauthorized(rw http.ResponseWriter, req *http.Request) {
	realm := "simpleHttpd"
	rw.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", realm))
	rw.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(rw, "<html><body><h1>Unauthorized</h1>")
}

// because getting a 404 when trying to use http.FileServer. beats me.
func myFileServer(w http.ResponseWriter, r *http.Request, url string) {
	http.ServeFile(w, r, path.Join(rootdir, url))
}

func uploadHandler(rw http.ResponseWriter, req *http.Request, url string) {
	mr, err := req.MultipartReader()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(rw, "reading body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		fileName := part.FileName()
		if fileName == "" {
			continue
		}
		buf := bytes.NewBuffer(make([]byte, 0))
		_, err = io.Copy(buf, part)
		if err != nil {
			http.Error(rw, "copying: "+err.Error(), http.StatusInternalServerError)
			return
		}
		f, err := os.Create(path.Join(rootdir, fileName))
		if err != nil {
			http.Error(rw, "opening file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		_, err = buf.WriteTo(f)
		if err != nil {
			http.Error(rw, "writing: "+err.Error(), http.StatusInternalServerError)
			return
		}
		println(fileName + " uploaded")
	}
	http.ServeFile(rw, req, path.Join(rootdir, uploadform))
}

func createUploadForm() {
	contents := `
<!DOCTYPE html>
<html>
<head>
  <title>Upload file</title>
</head>
<body>
  <h1>Upload file</h1>

  <form action="/upload" method="POST" id="uploadform" enctype="multipart/form-data">
    <input type="file" id="fileinput" multiple="true" name="file">
    <input type="submit" id="filesubmit" value="Upload">
  </form>

</body>
</html>
`
	f, err := os.Create(path.Join(rootdir, uploadform))
	if err != nil {
		println("err creating uploadform")
		os.Exit(2)
	}
	defer f.Close()
	_, err = f.Write([]byte(contents))
	if err != nil {
		println("err writing uploadform")
		os.Exit(2)
	}
}

func genSelfTLS() error {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %s", err)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   *host,
			Organization: []string{*host},
		},
		NotBefore: now.Add(-5 * time.Minute).UTC(),
		NotAfter:  now.AddDate(1, 0, 0).UTC(),

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create(selfCert)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", selfCert, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Printf("written %s\n", selfCert)

	keyOut, err := os.OpenFile(selfKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing:", selfKey, err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Printf("written %s\n", selfKey)
	return nil
}

func initUserPass() {
	if *userpass == "" {
		return
	}
	pieces := strings.Split(*userpass, ":")
	if len(pieces) < 2 {
		log.Fatalf("Wrong userpass auth string; needs to be \"username:password\"")
	}
	username = pieces[0]
	password = pieces[1]
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if *help {
		usage()
	}

	nargs := flag.NArg()
	if nargs > 0 {
		usage()
	}

	listener, err := net.Listen("tcp", *host)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *host, err)
	}

	initUserPass()

	if *secure {
		// always use self gen/signed creds
		err := genSelfTLS()
		if err != nil {
			log.Fatal(err)
		}
		config := &tls.Config{
			Rand:       rand.Reader,
			Time:       time.Now,
			NextProtos: []string{"http/1.1"},
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(selfCert, selfKey)
		if err != nil {
			log.Fatalf("Failed to load TLS cert: %v", err)
		}
		listener = tls.NewListener(listener, config)
		err = os.Remove(selfKey)
		if err != nil {
			log.Fatalf("Failed to remove TLS key: %v", err)
		}
		err = os.Remove(selfCert)
		if err != nil {
			log.Fatalf("Failed to remove TLS cert: %v", err)
		}
	}

	if *upload {
		createUploadForm()
		http.HandleFunc("/upload", makeHandler(uploadHandler))
	}
	http.Handle("/", makeHandler(myFileServer))
	// http.ListenAndServe(*host, nil)
	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatalf("Error in http server: %v\n", err)
	}
}
