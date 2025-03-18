package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/oauth2-proxy/mockoidc"
)

var (
	clientID     string
	clientSecret string
	endpoint     string
	email        string
	password     string
	port         int
)

func init() {
	flag.StringVar(&clientID, "client-id", "", "Client ID")
	flag.StringVar(&clientSecret, "client-secret", "", "Client Secret")
	flag.StringVar(&endpoint, "endpoint", "", "Server endpoint URL")
	flag.StringVar(&email, "email", "admin@admin.com", "Admin email")
	flag.StringVar(&password, "password", "password", "Admin Password")
	flag.IntVar(&port, "port", 8080, "Port to listen on")
}

func main() {

	flag.Parse()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create an unstarted MockOIDC server
	m, _ := mockoidc.NewServer(rsaKey)

	m.AccessTTL = 24 * time.Hour
	m.RefreshTTL = 7 * 24 * time.Hour

	if len(endpoint) > 0 {
		m.Endpoint = endpoint
	}
	if len(clientID) > 0 {
		m.ClientID = clientID
		m.ClientSecret = clientSecret
	}

	// Add the User to the queue, this will be returned by the next login
	m.QueueUser(&mockoidc.MockUser{
		Subject:           "100001",
		PreferredUsername: "admin",
		Password:          password,
		Email:             email,
		Groups:            []string{"group1", "group2"},
		Roles:             []string{"admin"},
	})

	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			start := time.Now() // record the start time

			// request body
			var requestBody bytes.Buffer
			if req.Body != nil {
				tee := io.TeeReader(req.Body, &requestBody)
				req.Body = io.NopCloser(tee)
			}

			lrw := NewLoggingResponseWriter(rw)

			next.ServeHTTP(lrw, req)
			log.Printf(
				"%s %s %s?%s %dms %d RequestBody: %s ResponseBody: %s",
				req.RemoteAddr,
				req.Method,
				req.URL.Path,
				req.URL.RawQuery,
				time.Since(start).Milliseconds(),
				lrw.statusCode,
				requestBody.String(),
				lrw.body.String(),
			)
		})
	}

	m.AddMiddleware(middleware)

	// Create the net.Listener on the exact IP:Port you want
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		log.Fatal(err)
	}
	// tlsConfig can be nil if you want HTTP
	err = m.Start(ln, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer m.Shutdown()

	config := m.Config()
	log.Println("MockOIDC server started")
	log.Println("Discovery:", m.DiscoveryEndpoint())
	log.Println("Config:", config)

	authorizeQuery := url.Values{}
	authorizeQuery.Set("client_id", config.ClientID)
	authorizeQuery.Set("scope", "openid email profile roles groups")
	authorizeQuery.Set("response_type", "code")
	authorizeQuery.Set("redirect_uri", "http://127.0.0.1/oauth2/callback")
	authorizeQuery.Set("state", "xxx")
	authorizeQuery.Set("nonce", "yyyy")

	log.Println("Query:", authorizeQuery.Encode())

	q := make(chan bool)
	<-q
}

type LoggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func NewLoggingResponseWriter(w http.ResponseWriter) *LoggingResponseWriter {
	return &LoggingResponseWriter{w, http.StatusOK, bytes.Buffer{}}
}

func (lrw *LoggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *LoggingResponseWriter) Write(b []byte) (int, error) {
	lrw.body.Write(b)
	return lrw.ResponseWriter.Write(b)
}
