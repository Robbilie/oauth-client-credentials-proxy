package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/test"
	"github.com/google/uuid"
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

const AUTHMODE_CLIENT_CREDENTIALS = "CLIENT_CREDENTIALS"
const AUTHMODE_ACTOR_TOKEN = "ACTOR_TOKEN"
const AUTHMODE_SELF_SIGNED_TOKEN = "SELF_SIGNED_TOKEN"
const AUTHMODE_SAS = "SAS"

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
	Upstream     *url.URL
	TokenSource  oauth2.TokenSource
	Logger       logger.Logger
	AuthMode     string
	SubjectField string
	HttpContext  context.Context
	HttpClient   *http.Client
	TokenUrl     string
	Scope        string
	ClientID     string
	ClientSecret string
	KeyPath      string
	Audience     string
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
		getEnv("INSECURE_SKIP_VERIFY", "false"),
		getEnv("TOKEN_EXCHANGE_AUTH_MODE", AUTHMODE_CLIENT_CREDENTIALS),
		getEnv("TOKEN_EXCHANGE_SUBJECT_FIELD", "subject"),
		getEnv("AUDIENCE", ""),
		getEnv("GRANT_TYPE", "client_credentials"),
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

func newServer(logger logger.Logger, upstream string, tokenUrl string, clientId string, clientSecret string, scope string, certPath string, keyPath string, caCertPath string, insecureSkipVerify string, authMode string, subjectField string, audience string, grantType string) (*server, error) {
	u, _ := url.Parse(upstream)

	conf := &clientcredentials.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       strings.Split(scope, ","),
		TokenURL:     tokenUrl,
		EndpointParams: url.Values{
			"grant_type": {grantType},
		},
	}

	config := &tls.Config{}

	if insecureSkipVerify == "true" {
		config.InsecureSkipVerify = true
	}

	if len(certPath) > 0 && len(keyPath) > 0 {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}

	if len(caCertPath) > 0 {
		caCertPaths := strings.Split(caCertPath, ",")
		caCertPool := x509.NewCertPool()
		for _, path := range caCertPaths {
			caCert, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			caCertPool.AppendCertsFromPEM(caCert)
		}
		config.RootCAs = caCertPool
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

	return &server{
		Upstream:     u,
		Logger:       logger,
		TokenSource:  conf.TokenSource(ctx),
		AuthMode:     authMode,
		SubjectField: subjectField,
		HttpContext:  ctx,
		HttpClient:   httpClient,
		TokenUrl:     tokenUrl,
		Scope:        scope,
		ClientID:     clientId,
		ClientSecret: clientSecret,
		KeyPath:      keyPath,
		Audience:     audience,
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

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

type SasTokenRequest struct {
	ClientID string   `json:"clientId"`
	Scopes   []string `json:"scopes"`
}

type SasTokenResponse struct {
	AccessToken string `json:"accessToken"`
}

func (s *server) handleRequest(res http.ResponseWriter, req *http.Request) {
	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(s.Upstream)

	// Update the headers to allow for SSL redirection
	req.URL.Host = s.Upstream.Host
	req.URL.Scheme = s.Upstream.Scheme
	req.Host = s.Upstream.Host

	if req.Header.Get("x-"+s.SubjectField) != "" {
		subject := req.Header.Get("x-" + s.SubjectField)

		var personalizedTokenConf *clientcredentials.Config

		switch s.AuthMode {
		case AUTHMODE_CLIENT_CREDENTIALS:
			// no need to fetch system token first
			personalizedTokenConf = &clientcredentials.Config{
				ClientID:     s.ClientID,
				ClientSecret: s.ClientSecret,
				Scopes:       strings.Split(s.Scope, ","),
				TokenURL:     s.TokenUrl,
				EndpointParams: url.Values{
					"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
					"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
					s.SubjectField:         {subject},
				},
			}

		case AUTHMODE_ACTOR_TOKEN:
			// fetch system token first to perform exchange
			token, err := s.TokenSource.Token()
			if err != nil {
				s.Logger.Errorw("Error getting system token", err)
				res.WriteHeader(500)
				return
			}

			personalizedTokenConf = &clientcredentials.Config{
				ClientID:     "",
				ClientSecret: "",
				Scopes:       strings.Split(s.Scope, ","),
				TokenURL:     s.TokenUrl,
				EndpointParams: url.Values{
					"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
					"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
					"actor_token_type":     {"urn:ietf:params:oauth:token-type:access_token"},
					"actor_token":          {token.AccessToken},
					s.SubjectField:         {subject},
				},
			}
		}

		token, err := personalizedTokenConf.TokenSource(s.HttpContext).Token()
		if err != nil {
			s.Logger.Errorw("Error fetching the subject token", err)
			res.WriteHeader(500)
			return
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	} else {
		switch s.AuthMode {
		case AUTHMODE_SELF_SIGNED_TOKEN:
			accessToken, err := createJwt(s.KeyPath, s.ClientID, s.Audience)
			if err != nil {
				s.Logger.Errorw("Error fetching the subject token", err)
				res.WriteHeader(500)
				return
			}
			u, err := url.Parse(s.TokenUrl)
			if err != nil {
				s.Logger.Errorw("Error fetching the subject token", err)
				res.WriteHeader(500)
				return
			}
			if req.URL.Path == u.Path {
				req.Header.Set("Authorization", "Bearer "+accessToken)
			} else {
				request, err := http.NewRequest(http.MethodPost, s.TokenUrl+"?grant_type=client_credentials", nil)
				if err != nil {
					s.Logger.Errorw("Error getting client credential token", err)
					res.WriteHeader(500)
					return
				}
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.Header.Set("Authorization", "Bearer "+accessToken)

				response, err := http.DefaultClient.Do(request)
				if err != nil {
					s.Logger.Errorw("Error getting client credential token", err)
					res.WriteHeader(500)
					return
				}
				defer response.Body.Close()
				body, err := ioutil.ReadAll(response.Body)
				var result TokenResponse
				if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
					s.Logger.Errorw("Error getting client credential token", err)
					res.WriteHeader(500)
					return
				}
				req.Header.Set("Authorization", "Bearer "+result.AccessToken)
			}
		case AUTHMODE_SAS:
			values := SasTokenRequest{ClientID: s.ClientID, Scopes: strings.Split(s.Scope, ",")}
			jsonValue, _ := json.Marshal(values)
			request, err := http.NewRequest(http.MethodPost, s.TokenUrl, bytes.NewBuffer(jsonValue))
			if err != nil {
				s.Logger.Errorw("Error getting sas token", err)
				res.WriteHeader(500)
				return
			}
			request.Header.Set("Content-Type", "application/json")

			response, err := s.HttpClient.Do(request)
			if err != nil {
				s.Logger.Errorw("Error getting sas token", err)
				res.WriteHeader(500)
				return
			}
			defer response.Body.Close()
			body, err := ioutil.ReadAll(response.Body)
			var result SasTokenResponse
			if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
				s.Logger.Errorw("Error getting sas token", err)
				res.WriteHeader(500)
				return
			}
			req.Header.Set("Authorization", "Bearer "+result.AccessToken)
		default:
			// only fetch system token
			token, err := s.TokenSource.Token()
			if err != nil {
				s.Logger.Errorw("Error getting client credential token", err)
				res.WriteHeader(500)
				return
			}
			req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		}
	}
	// Note that ServeHttp is non-blocking and uses a go routine under the hood
	proxy.ServeHTTP(res, req)
}

func createJwt(keyPath string, clientId string, audience string) (string, error) {
	jwtTestRS256PrivateKey := test.LoadRSAPrivateKeyFromDisk(keyPath)

	// Create the Claims
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 60)),
		Issuer:    clientId,
		Subject:   clientId,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Audience:  []string{audience},
		ID:        uuid.New().String(),
	}

	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": jwt.SigningMethodRS256.Alg(),
			"kid": clientId,
		},
		Claims: claims,
		Method: jwt.SigningMethodRS256,
	}

	return token.SignedString(jwtTestRS256PrivateKey)
}
