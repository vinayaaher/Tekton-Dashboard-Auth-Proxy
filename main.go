package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"github.com/joho/godotenv"
)

// Configuration values
type Config struct {
	// Server configuration
	Port               string
	TektonDashboardURL string
	CookieSecret       string
	
	// Azure AD configuration
	TenantID     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	
	// Authorization configuration
	AllowedGroups []string // Groups that have access to Tekton Dashboard
}

// Session store for cookies
var store *sessions.CookieStore

// OIDC provider and OAuth2 config
var provider *oidc.Provider
var oauth2Config oauth2.Config
var verifier *oidc.IDTokenVerifier

// Microsoft Graph API constants
const (
	MicrosoftGraphURL = "https://graph.microsoft.com/v1.0"
)

// Group represents a Microsoft Graph group
type Group struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// GroupResponse represents the Microsoft Graph API response for groups
type GroupResponse struct {
	Value []Group `json:"value"`
	OdataNextLink string `json:"@odata.nextLink"` // Holds the URL for the next page
}

func main() {
	// Load configuration
	config := loadConfig()
	
	// Initialize session store with secret key for cookies
	cookieSecret := []byte(config.CookieSecret)
	store = sessions.NewCookieStore(cookieSecret)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 8, // 8 hours
		HttpOnly: true,
		Secure:   true, // Set to false for development without HTTPS
		SameSite: http.SameSiteLaxMode,
	}
	
	// Initialize OIDC provider
	ctx := context.Background()
	var err error
	providerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", config.TenantID)
	provider, err = oidc.NewProvider(ctx, providerURL)
	if err != nil {
		log.Fatalf("Failed to initialize OIDC provider: %v", err)
	}
	
	// Configure OAuth2
	oauth2Config = oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		// Add Microsoft Graph API permissions for groups
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/GroupMember.Read.All"},
	}
	
	// Set up OIDC token verifier
	verifier = provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	
	// Proxy endpoint to Tekton Dashboard
	tektonURL, err := url.Parse(config.TektonDashboardURL)
	if err != nil {
		log.Fatalf("Invalid Tekton Dashboard URL: %v", err)
	}
	
	tektonProxy := httputil.NewSingleHostReverseProxy(tektonURL)
	
	// Modify the director function to check authentication and implement Kubernetes impersonation
	originalDirector := tektonProxy.Director
	tektonProxy.Director = func(req *http.Request) {
		// Continue with the existing director logic
		originalDirector(req)
		
		// Get session
		session, _ := store.Get(req, "auth-session")
		
		// If user is authenticated, set Kubernetes impersonation headers
		if authenticated, ok := session.Values["authenticated"].(bool); ok && authenticated {
			if email, ok := session.Values["email"].(string); ok && email != "" {
				// Set Kubernetes impersonation header for the user
				// This will make the Kubernetes API treat the request as coming from this user
				req.Header.Set("Impersonate-User", email)
				log.Printf("[K8s Impersonation] Setting user: %s", email)
			} else {
				log.Printf("[K8s Impersonation] ERROR: No valid email found in session, cannot set Impersonate-User header")
			}

			// Set Kubernetes impersonation headers for groups
			// This will give the user access based on their group memberships
			if groups, ok := session.Values["groups"].([]string); ok && len(groups) > 0 {
				// Clear any existing impersonation groups to prevent header duplication
				req.Header.Del("Impersonate-Group")
				
				// Add each group as a separate Impersonate-Group header
				for _, group := range groups {
					req.Header.Add("Impersonate-Group", group)
					log.Printf("[K8s Impersonation] Adding group: %s", group)
				}
			}
			
			log.Printf("[K8s Impersonation] Request will be impersonated as user: %s with groups: %v",
				session.Values["email"], session.Values["groups"])
		} else {
			log.Printf("No authentication found in session, skipping impersonation headers")
		}
	}
	
	// Set up routes
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		handleLogin(w, r, config)
	})
	
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		handleCallback(w, r, config)
	})
	
	http.HandleFunc("/logout", handleLogout)
	
	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	// Main proxy handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated
		session, _ := store.Get(r, "auth-session")
		
		if authenticated, ok := session.Values["authenticated"].(bool); ok && authenticated {
			// Check if the session has expired
			if expiry, ok := session.Values["expiry"].(int64); ok {
				if time.Now().Unix() > expiry {
					log.Printf("Session expired for user %s, redirecting to login", session.Values["email"])
					// Session has expired, redirect to login
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
			}
			
			// Log the request before forwarding
			log.Printf("Authenticated request from %s, proxying to: %s%s", 
				session.Values["email"], tektonURL.String(), r.URL.Path)
			
			// User is authenticated, proxy the request to Tekton Dashboard
			// Kubernetes impersonation headers will be set by the Director function
			tektonProxy.ServeHTTP(w, r)
		} else {
			// Not authenticated, redirect to login
			log.Printf("Unauthenticated request to %s, redirecting to login", r.URL.Path)
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	})
	
	// Start server
	log.Printf("Starting Tekton Dashboard Auth Proxy on port %s", config.Port)
	log.Printf("Proxying requests with Kubernetes impersonation to Tekton Dashboard at %s", config.TektonDashboardURL)
	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

// Generate a random state string for OAuth2 flow
func generateRandomState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Handle login request
func handleLogin(w http.ResponseWriter, r *http.Request, config Config) {
	log.Printf("Login request received from %s", r.RemoteAddr)
	
	// Generate and store a random state string
	state := generateRandomState()
	session, _ := store.Get(r, "auth-session")
	session.Values["state"] = state
	
	// Store the original URL that the user was trying to access
	if referer := r.Header.Get("Referer"); referer != "" {
		session.Values["original_url"] = referer
	} else {
		session.Values["original_url"] = "/"
	}
	
	err := session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Redirect to Azure AD login
	authURL := oauth2Config.AuthCodeURL(state)
	log.Printf("Redirecting to Azure AD authentication: %s", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GetUserGroups fetches a user's group memberships from Microsoft Graph API
func getUserGroups(ctx context.Context, accessToken string) ([]Group, error) {
	log.Printf("Fetching user groups from Microsoft Graph API")

	allGroups := []Group{}
	requestURL := MicrosoftGraphURL + "/me/memberOf?$top=999" // Initial request URL

	for {
			// Create a new request for each page
			req, err := http.NewRequest("GET", requestURL, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create Graph API request: %v", err)
			}

			// Set the Authorization header with the access token
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Content-Type", "application/json")

			// Execute the request
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("failed to execute Graph API request: %v", err)
			}
			defer resp.Body.Close()

			// Check response status
			if resp.StatusCode != http.StatusOK {
				bodyBytes, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("Graph API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
			}

			// Parse the response
			var groupResponse GroupResponse
			if err := json.NewDecoder(resp.Body).Decode(&groupResponse); err != nil {
				return nil, fmt.Errorf("failed to decode Graph API response: %v", err)
			}

			// Append the groups from the current page to the overall list
			allGroups = append(allGroups, groupResponse.Value...)

			log.Printf("Retrieved %d groups for current page, total: %d", len(groupResponse.Value), len(allGroups))

			// Check for @odata.nextLink and continue or break the loop
			if groupResponse.OdataNextLink != "" {
				requestURL = groupResponse.OdataNextLink // Update URL for the next page
			} else {
				break // No more pages, exit the loop
			}
}

	return allGroups, nil
}

// Handle OAuth2 callback
func handleCallback(w http.ResponseWriter, r *http.Request, config Config) {
	log.Printf("OAuth2 callback received")
	
	// Get the session
	session, err := store.Get(r, "auth-session")
	if err != nil {
		log.Printf("Failed to get session: %v", err)
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}
	
	// Verify state parameter
	if r.URL.Query().Get("state") != session.Values["state"] {
		log.Printf("Invalid state parameter")
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	
	ctx := context.Background()
	
	// Exchange code for token
	code := r.URL.Query().Get("code")
	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Extract and verify ID Token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Printf("No ID token found in OAuth response")
		http.Error(w, "No ID token found", http.StatusInternalServerError)
		return
	}
	
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("Failed to verify ID token: %v", err)
		http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Extract claims from token
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("Failed to parse claims: %v", err)
		http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	log.Printf("User authenticated: %s (%s)", claims.Name, claims.Email)
	
	// Get the access token to call Microsoft Graph API
	accessToken := oauth2Token.AccessToken
	
	// Get user's groups from Microsoft Graph API
	groups, err := getUserGroups(ctx, accessToken)
	if err != nil {
		log.Printf("Failed to get user groups: %v", err)
		http.Error(w, "Failed to get user groups: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Check if user has access to any allowed group
	authorized := false
	var userGroups []string
	
	// Extract user's group IDs and display names for Kubernetes impersonation
	userGroupIDs := make([]string, 0, len(groups))
	userGroupNames := make([]string, 0, len(groups))
	
	for _, group := range groups {
		userGroupIDs = append(userGroupIDs, group.ID)
		userGroupNames = append(userGroupNames, group.DisplayName)
		
		// Check if this group is in the allowed list
		for _, allowedGroup := range config.AllowedGroups {
			if group.ID == allowedGroup || group.DisplayName == allowedGroup {
				authorized = true
				// Add to the list of groups that will be used for K8s impersonation
				userGroups = append(userGroups, group.DisplayName)
			}
		}
	}
	
	// Log the user's groups for debugging
	log.Printf("User %s belongs to groups: %v", claims.Email, userGroupNames)
	log.Printf("User %s will be authorized with K8s groups: %v", claims.Email, userGroups)
	
	if !authorized {
		log.Printf("User %s is not authorized to access this resource", claims.Email)
		http.Error(w, "You are not authorized to access this resource", http.StatusForbidden)
		return
	}
	
	// Store user information in session for Kubernetes impersonation
	session.Values["authenticated"] = true
	session.Values["email"] = claims.Email // Will be used for Impersonate-User
	session.Values["name"] = claims.Name
	session.Values["groups"] = userGroups  // Will be used for Impersonate-Group headers
	session.Values["expiry"] = time.Now().Add(8 * time.Hour).Unix()
	
	// Save the session
	if err := session.Save(r, w); err != nil {
		log.Printf("Failed to save session: %v", err)
		http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	log.Printf("Authentication successful for %s, setting up Kubernetes impersonation", claims.Email)
	
	// Redirect back to the original URL
	originalURL, ok := session.Values["original_url"].(string)
	if !ok || originalURL == "" {
		originalURL = "/"
	}
	
	log.Printf("Redirecting to %s", originalURL)
	http.Redirect(w, r, originalURL, http.StatusFound)
}

// Handle logout request
func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	
	// Log the logout
	if email, ok := session.Values["email"].(string); ok {
		log.Printf("Logout for user: %s", email)
	}
	
	// Clear all session values
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1 // Expire the cookie immediately
	session.Save(r, w)
	
	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}

// Load configuration from environment variables
func loadConfig() Config {
	godotenv.Load(".env")
	
	config := Config{
		Port:               getEnv("PORT", "8080"),
		TektonDashboardURL: getEnv("TEKTON_DASHBOARD_URL", "http://localhost:9097"),
		CookieSecret:       getEnv("COOKIE_SECRET", "change-me-in-production"),
		TenantID:           getEnv("AZURE_TENANT_ID", ""),
		ClientID:           getEnv("AZURE_CLIENT_ID", ""),
		ClientSecret:       getEnv("AZURE_CLIENT_SECRET", ""),
		RedirectURL:        getEnv("REDIRECT_URL", "http://localhost:8080/callback"),
		AllowedGroups:      strings.Split(getEnv("ALLOWED_GROUPS", ""), ","),
	}
	
	// Validate required fields
	if config.TenantID == "" || config.ClientID == "" || config.ClientSecret == "" {
		log.Fatalf("Missing required Azure AD configuration. Please set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET")
	}
	
	// Log configuration (excluding secrets)
	log.Printf("Configuration loaded:")
	log.Printf("- Port: %s", config.Port)
	log.Printf("- Tekton Dashboard URL: %s", config.TektonDashboardURL)
	log.Printf("- Azure AD Tenant ID: %s", config.TenantID)
	log.Printf("- Azure AD Client ID: %s", config.ClientID)
	log.Printf("- Redirect URL: %s", config.RedirectURL)
	log.Printf("- Allowed Groups: %v", config.AllowedGroups)
	
	return config
}

// Helper to get environment variable with fallback
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
