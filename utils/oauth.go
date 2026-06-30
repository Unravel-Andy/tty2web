package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kost/tty2web/bindata"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// OAuth2Config holds the configuration for OAuth2 authentication
type OAuth2Config struct {
	config             oauth2.Config
	jwtSecret          string
	DefaultValidPeriod time.Duration
	LoginTemplate      *template.Template
}

func (c *OAuth2Config) GetClientID() string {
	return c.config.ClientID
}

func (c *OAuth2Config) GetClientSecret() string {
	return c.config.ClientSecret
}

func (c *OAuth2Config) GetRedirectURL() string {
	return c.config.RedirectURL
}

func (c *OAuth2Config) GetScopes() []string {
	return c.config.Scopes
}

func (c *OAuth2Config) GetLoginUrl() string {
	return c.config.AuthCodeURL("")
}

func (c *OAuth2Config) SetDefaultValidPeriod(dur time.Duration) {
	c.DefaultValidPeriod = dur
}

// Exchange exchanges the authorization code for an access token using the OAuth2 configuration.
func (c *OAuth2Config) Exchange(code string, opts ...oauth2.AuthCodeOption) *oauth2.Token {
	tok, err := c.config.Exchange(context.Background(), code, opts...)
	if err != nil {
		log.Println("error getting access token: ", err)
		return &oauth2.Token{}
	}
	return tok
}

// ValidateLocalToken validates a JWT token using the configured JWT secret.
func (c *OAuth2Config) ValidateLocalToken(token string) (*oauth2.Token, error) {
	// Parse the token using the JWT secret
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(c.jwtSecret), nil
	}, jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithIssuer("tty2web"))

	if err != nil {
		log.Println("error parsing JWT token: ", err)
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		username, ok := claims["username"].(string)
		if !ok || username == "" {
			return nil, errors.New("invalid token claims")
		}
		return &oauth2.Token{AccessToken: token}, nil
	}

	return nil, errors.New("invalid token")
}

func (c *OAuth2Config) GenerateLocalToken(fields map[string]interface{}) (localToken string, claims jwt.MapClaims) {
	if c.jwtSecret == "" {
		log.Println("JWT secret is not set, generate random secret")
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Println("Failed to generate random key for JWT signing:", err)
			return "", jwt.MapClaims{}
		}
		c.jwtSecret = string(key)
	}
	// Create a new JWT token with the secret
	token := jwt.New(jwt.SigningMethodHS256)
	// Set the claims for the token
	claims = token.Claims.(jwt.MapClaims)
	claims["iss"] = "tty2web"
	claims["exp"] = time.Now().Add(c.DefaultValidPeriod).Unix() // Set expiration
	claims["iat"] = time.Now().Unix()                           // Set issued at time to now
	claims["nbf"] = time.Now().Unix()                           // Set not before time to now
	for key, value := range fields {
		claims[key] = value // Add custom fields to the claims
	}
	// Sign the token with the secret
	localToken, err := token.SignedString([]byte(c.jwtSecret))
	if err != nil {
		log.Println("error signing JWT token: ", err)
		return "", claims
	}
	return localToken, claims
}

func (c *OAuth2Config) GetLocalTokenField(token, fieldName string) interface{} {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(c.jwtSecret), nil
	})
	if err != nil {
		log.Println("error parsing JWT token: ", err)
		return nil
	}
	if value, ok := claims[fieldName]; ok {
		return value
	}
	log.Printf("field %s not found in token claims", fieldName)
	return nil
}

func OauthTokenCheck(w http.ResponseWriter, r *http.Request, OauthConf *OAuth2Config, oauthCookieName string) (token *oauth2.Token, err error) {
	// check for Authorization header
	t := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(t) == 2 && strings.ToLower(t[0]) == "JWT" {
		// validate JWT token
		if token, err := OauthConf.ValidateLocalToken(t[1]); err == nil {
			return token, nil
		}
	}

	// check for authentication in cookie
	cookie, err := r.Cookie(oauthCookieName)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		log.Println("Error getting cookies:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, err
	} else if cookie != nil {
		token, err = OauthConf.ValidateLocalToken(cookie.Value)
		if err == nil {
			log.Printf("auth cookie value: %s", cookie.Value)
			return token, nil
		}
	}
	return nil, errors.New("no valid token found")
}

// OauthMissingResponse sends a response indicating that the OAuth2 token is missing or invalid.
func OauthMissingResponse(w http.ResponseWriter, r *http.Request, OauthConf *OAuth2Config) {
	w.Header().Set("WWW-Authenticate", `JWT realm="tty2web"`)
	w.WriteHeader(http.StatusUnauthorized)
	// set redirect URL to the OAuth2 login page
	loginUrl := OauthConf.GetLoginUrl()
	buf := new(bytes.Buffer)
	err := OauthConf.LoginTemplate.Execute(buf, map[string]interface{}{
		"loginUrl": loginUrl,
	})
	if err != nil {
		log.Println("Error executing login template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
	return
}

// DecodeOauthTokenUnsafe decodes a JWT token without validating its signature.
func DecodeOauthTokenUnsafe(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid access token")
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return []byte(""), nil
		}
		return []byte(kid), nil
	}, jwt.WithoutClaimsValidation())
	if err != nil && (!errors.Is(err, jwt.ErrTokenSignatureInvalid)) {
		return nil, err
	}
	return claims, nil
}

// NewOAuth2Config creates a new OAuth2Config with the provided parameters
func NewOAuth2Config(clientID, clientSecret, redirectURL, jwtSecret string, scopes []string, endpoint oauth2.Endpoint) *OAuth2Config {
	loginData, err := bindata.Fs.ReadFile("static/oauth_login.html")
	if err != nil {
		panic("oauth_login.html not found") // must be in bindata
	}
	loginTemplate, err := template.New("oauth_login").Parse(string(loginData))
	if err != nil {
		panic("oauth login template parse failed: " + err.Error())
	}

	if clientID == "" || clientSecret == "" || redirectURL == "" {
		log.Println("OAuth2 configuration is incomplete. Please provide clientID, clientSecret, and redirectURL.")
		return nil
	}
	if len(scopes) == 0 {
		log.Println("No scopes provided for OAuth2 configuration. Defaulting to empty scopes.")
		scopes = []string{}
	}
	if jwtSecret == "" {
		// generate a random secret for HMAC signing
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Println("Failed to generate random key for JWT signing:", err)
		}
	}

	return &OAuth2Config{
		LoginTemplate:      loginTemplate,
		DefaultValidPeriod: time.Hour * 8,
		jwtSecret:          jwtSecret,
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint:     endpoint,
		},
	}
}
