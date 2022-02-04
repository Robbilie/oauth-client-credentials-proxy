package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/robbilie/oauth-client-credentials-proxy/logger"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of http requests handled",
	}, []string{"status"})
	validationTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "nginx_subrequest_auth_jwt_token_validation_time_seconds",
		Help:    "Number of seconds spent validating token",
		Buckets: prometheus.ExponentialBuckets(100*time.Nanosecond.Seconds(), 3, 6),
	})
)

func init() {
	requestsTotal.WithLabelValues("200")
	requestsTotal.WithLabelValues("401")
	requestsTotal.WithLabelValues("405")
	requestsTotal.WithLabelValues("500")

	prometheus.MustRegister(
		requestsTotal,
		validationTime,
	)
}

type server struct {
	Upstream    *url.URL
	TokenSource oauth2.TokenSource
	Logger      logger.Logger
}

func main() {
	loggerInstance := logger.NewLogger(getEnv("LOG_LEVEL", "info")) // "debug", "info", "warn", "error", "fatal"

	server, err := newServer(
		loggerInstance,
		os.Getenv("UPSTREAM"),
		os.Getenv("TOKEN_URL"),
		os.Getenv("CLIENT_ID"),
		getEnv("CLIENT_SECRET", ""),
		getEnv("SCOPE", ""),
		os.Getenv("CERT_PATH"),
		os.Getenv("KEY_PATH"),
		os.Getenv("CACERT_PATH"),
	)
	if err != nil {
		loggerInstance.Fatalw("Couldn't initialize server", "err", err)
		return
	}

	http.HandleFunc("/", server.handleRequest)

	loggerInstance.Infow("Starting server", "addr", getListenAddress())
	err = http.ListenAndServe(getListenAddress(), nil)

	if err != nil {
		loggerInstance.Fatalw("Error running server", "err", err)
	}
}

func newServer(logger logger.Logger, upstream string, tokenUrl string, clientId string, clientSecret string, scope string, certPath string, keyPath string, caCertPath string) (*server, error) {
	u, _ := url.Parse(upstream)

	ctx := context.Background()
	conf := &clientcredentials.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       strings.Split(scope, ","),
		TokenURL:     tokenUrl,
	}

	if len(certPath) > 0 && len(keyPath) > 0 {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		var config *tls.Config
		if len(caCertPath) > 0 {
			caCert, err := ioutil.ReadFile(certPath)
			if err != nil {
				return nil, err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			config = &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			}
		} else {
			config = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
		}
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: config,
			},
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	return &server{
		Upstream:    u,
		Logger:      logger,
		TokenSource: conf.TokenSource(ctx),
	}, nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getListenAddress() string {
	port := getEnv("PORT", "8080")
	return ":" + port
}

func (s *server) handleRequest(res http.ResponseWriter, req *http.Request) {
	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(s.Upstream)

	// Update the headers to allow for SSL redirection
	req.URL.Host = s.Upstream.Host
	req.URL.Scheme = s.Upstream.Scheme
	req.Host = s.Upstream.Host

	token, err := s.TokenSource.Token()
	if err != nil {
		s.Logger.Errorw("Error getting token", err)
		res.WriteHeader(500)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	// Note that ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(res, req)
}
