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
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	uploadform = "upload.html"
	idstring   = "http://golang.org/pkg/http/#ListenAndServe"
)

var (
	host     = flag.String("host", "0.0.0.0:8080", "listening port and hostname")
	help     = flag.Bool("h", false, "show this help")
	userpass = flag.String("userpass", "", "optional username:password protection")
	secure   = flag.Bool("ssl", false, `For https. If "key.pem" or "cert.pem" are not found in $HOME/keys/, in-memory self-signed are generated and used instead.`)
	upload   = flag.Bool("upload", false, "enable upload and automatically create upload.html")
)

var (
	rootdir, _        = os.Getwd()
	kBasicAuthPattern = regexp.MustCompile(`^Basic ([a-zA-Z0-9\+/=]+)`)
	username          string
	password          string
	selfKey           = filepath.Join(os.Getenv("HOME"), "keys", "key.pem")
	selfCert          = filepath.Join(os.Getenv("HOME"), "keys", "cert.pem")
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

type sortedFiles []os.FileInfo

func (s sortedFiles) Len() int { return len(s) }

func (s sortedFiles) Less(i, j int) bool {
	return strings.ToLower(s[i].Name()) < strings.ToLower(s[j].Name())
}

func (s sortedFiles) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func sortedDirList(w http.ResponseWriter, f http.File) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<pre>\n")
	var sdirs sortedFiles
	for {
		dirs, err := f.Readdir(100)
		if err != nil || len(dirs) == 0 {
			break
		}
		sdirs = append(sdirs, dirs...)
	}
	sort.Sort(sdirs)
	for _, d := range sdirs {
		name := d.Name()
		if d.IsDir() {
			name += "/"
		}
		// TODO htmlescape
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", name, name)
	}
	fmt.Fprintf(w, "</pre>\n")
}

// modtime is the modification time of the resource to be served, or IsZero().
// return value is whether this request is now complete.
func checkLastModified(w http.ResponseWriter, r *http.Request, modtime time.Time) bool {
	if modtime.IsZero() {
		return false
	}

	// The Date-Modified header truncates sub-second precision, so
	// use mtime < t+1s instead of mtime <= t to check for unmodified.
	if t, err := time.Parse(http.TimeFormat, r.Header.Get("If-Modified-Since")); err == nil && modtime.Before(t.Add(1*time.Second)) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	w.Header().Set("Last-Modified", modtime.UTC().Format(http.TimeFormat))
	return false
}

// name is '/'-separated, not filepath.Separator.
func serveFile(w http.ResponseWriter, r *http.Request, fs http.FileSystem, name string) {
	const indexPage = "/index.html"

	f, err := fs.Open(name)
	if err != nil {
		// TODO expose actual error?
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	d, err1 := f.Stat()
	if err1 != nil {
		// TODO expose actual error?
		http.NotFound(w, r)
		return
	}

	// use contents of index.html for directory, if present
	if d.IsDir() {
		index := name + indexPage
		ff, err := fs.Open(index)
		if err == nil {
			defer ff.Close()
			dd, err := ff.Stat()
			if err == nil {
				name = index
				d = dd
				f = ff
			}
		}
	}

	// Still a directory? (we didn't find an index.html file)
	if d.IsDir() {
		if checkLastModified(w, r, d.ModTime()) {
			return
		}
		sortedDirList(w, f)
		return
	}

	// serverContent will check modification time
	http.ServeContent(w, r, d.Name(), d.ModTime(), f)
}

func myFileServer(w http.ResponseWriter, r *http.Request, url string) {
	//	http.ServeFile(w, r, path.Join(rootdir, url))
	dir, file := filepath.Split(filepath.Join(rootdir, url))
	serveFile(w, r, http.Dir(dir), file)
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
		f, err := os.Create(filepath.Join(rootdir, fileName))
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
	http.ServeFile(rw, req, filepath.Join(rootdir, uploadform))
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
	f, err := os.Create(filepath.Join(rootdir, uploadform))
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

func genSelfTLS(certOut, keyOut io.Writer) error {
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

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	log.Println("self-signed cert and key generated")
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
		_, statErr1 := os.Stat(selfCert)
		_, statErr2 := os.Stat(selfKey)
		var cert tls.Certificate
		if statErr1 == nil && statErr2 == nil {
			cert, err = tls.LoadX509KeyPair(selfCert, selfKey)
		} else {
			// generate in-memory certs
			var certMem, keyMem bytes.Buffer
			err = genSelfTLS(&certMem, &keyMem)
			if err != nil {
				log.Fatal(err)
			}
			cert, err = tls.X509KeyPair(certMem.Bytes(), keyMem.Bytes())
		}
		if err != nil {
			log.Fatalf("Failed to load TLS cert: %v", err)
		}

		config := &tls.Config{
			Rand:       rand.Reader,
			Time:       time.Now,
			NextProtos: []string{"http/1.1"},
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = cert
		listener = tls.NewListener(listener, config)
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
