// Copyright 2012 Mathieu Lonjaret

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mpl/basicauth"
	"golang.org/x/crypto/acme/autocert"
)

const (
	uploadform = "upload.html"
	idstring   = "http://golang.org/pkg/http/#ListenAndServe"
)

var (
	host         = flag.String("host", "0.0.0.0:8080", "listening port and hostname")
	help         = flag.Bool("h", false, "show this help")
	flagUserpass = flag.String("userpass", "", "optional username:password protection")
	flagTLS      = flag.Bool("tls", false, `For https. If "key.pem" or "cert.pem" are not found in $HOME/keys/, in-memory self-signed are generated and used instead.`)
	flagAutocert = flag.Bool("autocert", false, `Get https certificate from Let's Encrypt. Implies -tls=true. Obviously -host must contain a full qualified domain name. The cached certificate(s) will be in $HOME/keys/letsencrypt.cache.`)
	upload       = flag.Bool("upload", false, "enable uploading at /upload")
)

var (
	rootdir, _ = os.Getwd()
	up         *basicauth.UserPass
	tlsKey     = filepath.Join(os.Getenv("HOME"), "keys", "key.pem")
	tlsCert    = filepath.Join(os.Getenv("HOME"), "keys", "cert.pem")
	certCache  = filepath.Join(os.Getenv("HOME"), "keys", "letsencrypt.cache")
	uploadTmpl *template.Template
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
			basicauth.SendUnauthorized(w, r, "simpleHttpd")
		}
	}
}

func isAllowed(r *http.Request) bool {
	if *flagUserpass == "" {
		return true
	}
	return up.IsAllowed(r)
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

// copied from stdlib, and modified to server sorted listing
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
	dir, file := filepath.Split(filepath.Join(rootdir, url))
	serveFile(w, r, http.Dir(dir), file)
}

func uploadHandler(rw http.ResponseWriter, req *http.Request, url string) {
	if req.Method == "GET" {
		if err := uploadTmpl.Execute(rw, nil); err != nil {
			log.Printf("template error: %v", err)
		}
		return
	}

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
	if err := uploadTmpl.Execute(rw, nil); err != nil {
		log.Printf("template error: %v", err)
	}
}

var uploadHTML = `
<!DOCTYPE html>
<html>
<head>
  <title>Upload files</title>
</head>
<body>
  <h1>Upload files</h1>

  <form action="/upload" method="POST" id="uploadform" enctype="multipart/form-data">
    <input type="file" id="fileinput" multiple="true" name="file">
    <input type="submit" id="filesubmit" value="Upload">
  </form>

</body>
</html>
`

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
	if *flagUserpass == "" {
		return
	}
	var err error
	up, err = basicauth.New(*flagUserpass)
	if err != nil {
		log.Fatal(err)
	}
}

func setupTLS() (*tls.Config, error) {
	hostname := *host
	if strings.Contains(hostname, ":") {
		h, _, err := net.SplitHostPort(hostname)
		if err != nil {
			return nil, err
		}
		hostname = h
	}
	if *flagAutocert {
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostname),
			Cache:      autocert.DirCache(certCache),
		}
		return &tls.Config{
			GetCertificate: m.GetCertificate,
		}, nil
	}
	_, statErr1 := os.Stat(tlsCert)
	_, statErr2 := os.Stat(tlsKey)
	var cert tls.Certificate
	var err error
	if statErr1 == nil && statErr2 == nil {
		cert, err = tls.LoadX509KeyPair(tlsCert, tlsKey)
	} else {
		// generate in-memory certs
		var certMem, keyMem bytes.Buffer
		err = genSelfTLS(&certMem, &keyMem)
		if err != nil {
			return nil, err
		}
		cert, err = tls.X509KeyPair(certMem.Bytes(), keyMem.Bytes())
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to load TLS cert: %v", err)
	}
	return &tls.Config{
		Rand:         rand.Reader,
		Time:         time.Now,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{cert},
	}, nil

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

	if !*flagTLS && *flagAutocert {
		*flagTLS = true
	}

	if *flagTLS {
		config, err := setupTLS()
		if err != nil {
			log.Fatalf("could not configure TLS connection: %v", err)
		}
		listener = tls.NewListener(listener, config)
	}

	if *upload {
		uploadTmpl = template.Must(template.New("upload").Parse(uploadHTML))
		http.HandleFunc("/upload", makeHandler(uploadHandler))
	}
	http.Handle("/", makeHandler(myFileServer))
	if err = http.Serve(listener, nil); err != nil {
		log.Fatalf("Error in http server: %v\n", err)
	}
}
