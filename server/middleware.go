package server

import (
	"encoding/base64"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/kost/tty2web/utils"
)

func (server *Server) wrapLogger(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &logResponseWriter{w, 200}
		handler.ServeHTTP(rw, r)
		log.Printf("%s %d %s %s", r.RemoteAddr, rw.status, r.Method, r.URL.Path)
	})
}

func (server *Server) wrapHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// todo add version
		w.Header().Set("Server", "tty2web")
		handler.ServeHTTP(w, r)
	})
}

func (server *Server) wrapBasicAuth(handler http.Handler, credential string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		if len(token) != 2 || strings.ToLower(token[0]) != "basic" {
			w.Header().Set("WWW-Authenticate", `Basic realm="tty2web"`)
			http.Error(w, "Bad Request", http.StatusUnauthorized)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(token[1])
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if credential != string(payload) {
			w.Header().Set("WWW-Authenticate", `Basic realm="tty2web"`)
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		log.Printf("Basic Authentication Succeeded: %s", r.RemoteAddr)
		handler.ServeHTTP(w, r)
	})
}

// OAuth2 middleware
func (server *Server) wrapOauth2(handler http.Handler) http.Handler {
	noneAuthPaths := []string{
		".*/oauth/callback",
		".*/oauth/login",
		".*/oauth/logout",
		".*/static/.*",
		".*/favicon.ico",
		".*/favicon.png",
		".*/js/.*",
		".*/css/.*",
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the request path is in the list of paths that do not require authentication
		for _, path := range noneAuthPaths {
			if matched, _ := regexp.MatchString(path, r.URL.Path); matched {
				// If the path is in the list, skip authentication
				handler.ServeHTTP(w, r)
				return
			}
		}

		_, err := utils.OauthTokenCheck(w, r, OauthConf, oauthCookieName)
		if err == nil {
			log.Printf("OAuth2 Authentication Succeeded: %s access %s", r.RemoteAddr, r.URL.Path)
			handler.ServeHTTP(w, r)
			return
		}

		utils.OauthMissingResponse(w, r, OauthConf)
		log.Printf("OAuth2 Authentication Failed: %s access %s", r.RemoteAddr, r.URL.Path)
		return
	})
}
