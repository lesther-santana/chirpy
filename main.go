package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"golang.org/x/crypto/bcrypt"

	"github.com/joho/godotenv"

	"github.com/golang-jwt/jwt/v5"
)

type apiConfig struct {
	fileserverHits int
}

type badResponse struct {
	Error string `json:"error"`
}
type Chirp struct {
	Id       int    `json:"id"`
	AuthorID int    `json:"author_id"`
	Body     string `json:"body"`
}

type User struct {
	Id          int    `json:"id"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

type DB struct {
	path           string
	mux            *sync.RWMutex
	ChirpIdCounter int
	UserIdCounter  int
}

type UserOut struct {
	Email       string `json:"email"`
	Id          int    `json:"id"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string, authorId int) (Chirp, error) {
	chirpDB, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	newChirp := Chirp{
		Id:       db.ChirpIdCounter,
		Body:     body,
		AuthorID: authorId,
	}
	chirpDB.Chirps[db.ChirpIdCounter] = newChirp // Add the new chirp to the map
	db.ChirpIdCounter++                          // Increment the ID counter for the next chirp

	err = db.writeDB(chirpDB)
	return newChirp, err
}

func (db *DB) CreateUser(email string, password string) (User, error) {
	chirpDB, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	if user, ok := chirpDB.Users[db.UserIdCounter]; ok {
		return user, nil
	}
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	newUser := User{
		Id:       db.UserIdCounter,
		Email:    email,
		Password: string(hashed),
	}
	chirpDB.Users[newUser.Id] = newUser // Add the new chirp to the map
	db.UserIdCounter++                  // Increment the ID counter for the next chirp

	err = db.writeDB(chirpDB)
	return newUser, err
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	db.mux.Lock()
	defer db.mux.Unlock()

	// Always create a new empty DB structure
	emptyDB := DBStructure{Chirps: make(map[int]Chirp), Users: make(map[int]User)}
	data, err := json.Marshal(emptyDB)
	if err != nil {
		return err
	}
	// Use os.WriteFile to overwrite any existing file
	return os.WriteFile(db.path, data, 0644)
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	var chirpDB DBStructure

	fileData, err := os.ReadFile(db.path)
	if err != nil {
		return chirpDB, err // Return empty DBStructure and the error
	}

	err = json.Unmarshal(fileData, &chirpDB)
	return chirpDB, err
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	data, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, data, 0644)
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	chirpDB, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	chirpArr := make([]Chirp, 0, len(chirpDB.Chirps))
	for _, chirp := range chirpDB.Chirps {
		chirpArr = append(chirpArr, chirp)
	}
	return chirpArr, nil
}

func (db *DB) DeleteChirp(chirpID int, userId int) int {

	chirpDB, err := db.loadDB()
	if err != nil {
		return 2
	}
	if !(chirpDB.Chirps[chirpID].AuthorID == userId) {
		return 1
	}
	delete(chirpDB.Chirps, chirpID)

	_ = db.writeDB(chirpDB)
	return 0
}

// UpdateUserRed sets a user's IsChirpyRed status to true in the database
func (db *DB) UpdateUserRed(userId int) error {
	chirpDB, err := db.loadDB()
	if err != nil {
		return err // Error loading the database
	}

	user, exists := chirpDB.Users[userId]
	if !exists {
		return fmt.Errorf("user with ID %d does not exist", userId) // Error if user does not exist
	}

	user.IsChirpyRed = true
	chirpDB.Users[userId] = user // Update the user in the in-memory database

	err = db.writeDB(chirpDB) // Write the updated database back to the file
	if err != nil {
		return err // Error writing to the database
	}

	return nil // Success
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mux:  new(sync.RWMutex),
	}

	// Ensure the database file exists and is correctly initialized
	if err := db.ensureDB(); err != nil {
		return nil, fmt.Errorf("failed to ensure database: %w", err)
	}
	db.UserIdCounter++
	db.ChirpIdCounter++
	return db, nil
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) reset() {
	cfg.fileserverHits = 0
}

func createToken(userID int) (string, error) {
	// Set a default expiration time of 24 hours if not specified or if specified value is greater than 24 hours
	const expiresInSeconds = 24 * 60 * 60

	// Create the JWT claims including the issuer, issued at time, expiration time, and subject
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Second * time.Duration(expiresInSeconds))),
		Subject:   strconv.Itoa(userID),
	}

	// Create a new token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	// Replace `your-secret-key` with your actual secret key
	secretKey := os.Getenv("JWT_SECRET")
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

func createRefresh(userID int) (string, error) {
	// Set a default expiration time of 24 hours if not specified or if specified value is greater than 24 hours
	const maxExpiration = 60 * 24 * 60 * 60

	// Create the JWT claims including the issuer, issued at time, expiration time, and subject
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy-refresh",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Second * time.Duration(maxExpiration))),
		Subject:   strconv.Itoa(userID),
	}

	// Create a new token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	// Replace `your-secret-key` with your actual secret key
	secretKey := os.Getenv("JWT_SECRET")
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// parseAndValidateToken parses the token string, validates the token, and returns the user ID if the token is valid
func parseAndValidateToken(tokenString string, issuer string) (int, error) {
	// Define a custom claims structure to extract the subject (user ID)
	type CustomClaims struct {
		jwt.RegisteredClaims
	}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the token signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the secret key for validation
		secretKey := os.Getenv("JWT_SECRET")
		return []byte(secretKey), nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		// Validate the issuer and the expiration time
		if claims.Issuer != issuer {
			return 0, fmt.Errorf("invalid issuer")
		}

		if claims.ExpiresAt.Time.Before(time.Now().UTC()) {
			return 0, fmt.Errorf("token has expired")
		}

		// Parse the user ID from the subject
		userID, err := strconv.Atoi(claims.Subject)
		if err != nil {
			return 0, fmt.Errorf("invalid user ID: %w", err)
		}

		// Token is valid
		return userID, nil
	}

	// Default case, return an error
	return 0, fmt.Errorf("invalid token")
}

func main() {

	godotenv.Load()

	db, err := NewDB("database.json")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
		return
	}

	revoked := make(map[string]bool)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	filepathRoot := "."
	port := "8080"
	apiCfg := apiConfig{
		fileserverHits: 0,
	}

	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot))))
	r.Handle("/app", fsHandler)
	r.Handle("/app/*", fsHandler)

	apiRouter := chi.NewRouter()

	apiRouter.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	apiRouter.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		apiCfg.reset()
	})

	apiRouter.Get("/chirps", func(w http.ResponseWriter, r *http.Request) {

		query := r.URL.Query()

		authorIdStr := query.Get("author_id")
		log.Print(authorIdStr)
		chirps, err := db.GetChirps()
		var userChirps []Chirp
		if authorIdStr != "" {
			authorId, _ := strconv.Atoi(authorIdStr)
			for _, v := range chirps {
				if v.AuthorID == authorId {
					userChirps = append(userChirps, v)
				}
			}
			chirps = userChirps
		}

		if query.Has("sort") {
			mode := query.Get("sort")
			sort.SliceStable(chirps, func(i, j int) bool {
				if mode == "desc" {
					return chirps[i].Id > chirps[j].Id
				} else {
					return chirps[i].Id < chirps[j].Id
				}
			})

		}
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			log.Print(err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(chirps)

	})

	apiRouter.Get("/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		chirpIdStr := chi.URLParam(r, "chirpID")
		chirpId, _ := strconv.Atoi(chirpIdStr)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if err != nil {
			log.Print(err)
			w.WriteHeader(500)
			return
		}
		chirpDB, _ := db.loadDB()
		chirp, ok := chirpDB.Chirps[chirpId]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(chirp)

	})

	apiRouter.Delete("/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		chirpIdStr := chi.URLParam(r, "chirpID")
		chirpId, _ := strconv.Atoi(chirpIdStr)

		// Extracting the token from the request headers
		authHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(authHeader) != 2 || authHeader[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Extract user ID from JWT claims
		userID, err := parseAndValidateToken(authHeader[1], "chirpy-access")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if err != nil {
			log.Print(err)
			w.WriteHeader(500)
			return
		}
		ok := db.DeleteChirp(chirpId, userID)
		if ok == 1 {
			w.WriteHeader(403)
			return
		} else if ok == 2 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(http.StatusOK)

	})

	apiRouter.Post("/chirps", func(w http.ResponseWriter, r *http.Request) {

		type reqBody struct {
			Body string `json:"body"`
		}

		// Extracting the token from the request headers
		authHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(authHeader) != 2 || authHeader[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Extract user ID from JWT claims
		userID, err := parseAndValidateToken(authHeader[1], "chirpy-access")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		profane := [3]string{"kerfuffle", "sharbert", "fornax"}
		//replacement := [3]string{"*********", "*******", "******"}
		decoder := json.NewDecoder(r.Body)
		params := reqBody{}
		err = decoder.Decode(&params)
		if err != nil {
			errResp, _ := json.Marshal(badResponse{Error: "Something went wrong"})
			w.WriteHeader(500)
			w.Write(errResp)
			return
		}
		if len(params.Body) > 140 {
			errResp, _ := json.Marshal(badResponse{Error: "Chirp is too long"})
			w.WriteHeader(400)
			w.Write(errResp)
			return
		}
		words := strings.Split(params.Body, " ")
		// cleaned := false
		for i := range words {
			for j := range profane {
				lowered := strings.ToLower(words[i])
				if lowered == profane[j] {
					// cleaned = true
					words[i] = "****"
					break
				}
			}
		}
		newChirp, err := db.CreateChirp(strings.Join(words, " "), userID)
		if err != nil {
			errResp, _ := json.Marshal(badResponse{Error: "Something went wrong"})
			w.WriteHeader(500)
			w.Write(errResp)
			return
		}
		okResp, _ := json.Marshal(newChirp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201) // Set status before writing the body
		w.Write(okResp)
	})

	apiRouter.Post("/users", func(w http.ResponseWriter, r *http.Request) {

		type reqBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := reqBody{}
		err := decoder.Decode(&params)
		if err != nil {
			errResp, _ := json.Marshal(badResponse{Error: "Something went wrong"})
			w.WriteHeader(500)
			w.Write(errResp)
			return
		}

		newUser, err := db.CreateUser(params.Email, params.Password)
		if err != nil {
			errResp, _ := json.Marshal(badResponse{Error: "Something went wrong"})
			w.WriteHeader(500)
			w.Write(errResp)
			return
		}
		okResp, _ := json.Marshal(UserOut{Id: newUser.Id, Email: newUser.Email, IsChirpyRed: newUser.IsChirpyRed})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201) // Set status before writing the body
		w.Write(okResp)
	})

	apiRouter.Post("/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {

		type data struct {
			UserId int `json:"user_id"`
		}

		type reqBody struct {
			Event string `json:"event"`
			Data  data   `json:"data"`
		}

		// Extracting the token from the request headers
		authHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(authHeader) != 2 || authHeader[0] != "ApiKey" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		decoder := json.NewDecoder(r.Body)
		params := reqBody{}
		err := decoder.Decode(&params)
		if err != nil {
			errResp, _ := json.Marshal(badResponse{Error: "Something went wrong"})
			w.WriteHeader(500)
			w.Write(errResp)
			return
		}

		if params.Event != "user.upgraded" {
			w.WriteHeader(200)
			return
		}
		//log.Print(params.Data.UserId)
		err = db.UpdateUserRed(params.Data.UserId)
		if err != nil {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200) // Set status before writing the body
		//w.Write({})
	})

	apiRouter.Put("/users", func(w http.ResponseWriter, r *http.Request) {
		type reqBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		// Extracting the token from the request headers
		authHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(authHeader) != 2 || authHeader[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Extract user ID from JWT claims
		userID, err := parseAndValidateToken(authHeader[1], "chirpy-access")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Decode the request body
		var updateData reqBody
		if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Load current database state
		chirpDB, err := db.loadDB()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Find the user based on ID and update their email and password
		for email, user := range chirpDB.Users {
			if user.Id == userID {
				// Update user data
				user.Email = updateData.Email
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateData.Password), bcrypt.DefaultCost)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				user.Password = string(hashedPassword)

				// Reflect changes in database
				chirpDB.Users[email] = user
				if err := db.writeDB(chirpDB); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				// Return the updated user information (excluding password)
				json.NewEncoder(w).Encode(UserOut{
					Id:          user.Id,
					Email:       user.Email,
					IsChirpyRed: user.IsChirpyRed,
				})
				return
			}
		}

		// If we did not find the user, return a 404 Not Found
		w.WriteHeader(http.StatusNotFound)
	})

	apiRouter.Post("/revoke", func(w http.ResponseWriter, r *http.Request) {

		// Extracting the token from the request headers
		authHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(authHeader) != 2 || authHeader[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Extract user ID from JWT claims
		_, err := parseAndValidateToken(authHeader[1], "chirpy-refresh")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		revoked[authHeader[1]] = true
		// If we did not find the user, return a 404 Not Found
		w.WriteHeader(http.StatusOK)
	})

	apiRouter.Post("/refresh", func(w http.ResponseWriter, r *http.Request) {
		type refreshResponse struct {
			Token string `json:"token"`
		}
		// Extracting the token from the request headers
		authHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(authHeader) != 2 || authHeader[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Extract user ID from JWT claims
		userID, err := parseAndValidateToken(authHeader[1], "chirpy-refresh") // Make sure this function is updated to accept the issuer as a parameter
		_, ok := revoked[authHeader[1]]
		if err != nil || ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Create a new token for the user
		newToken, err := createToken(userID) // Handling error from createToken
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError) // Use a 500 Internal Server Error or other appropriate status
			return
		}

		// If we did not find the user, return a 404 Not Found
		// Assuming this part is handled elsewhere as it's not shown here.

		// Set content type as JSON for the response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // This should ideally come before encoding the response
		response := refreshResponse{Token: newToken}
		json.NewEncoder(w).Encode(response)
	})

	apiRouter.Post("/login", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		type reqBody struct {
			Email              string `json:"email"`
			Password           string `json:"password"`
			Expires_in_seconds int    `json:"expires_in_seconds"`
		}

		type response struct {
			UserOut
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}

		decoder := json.NewDecoder(r.Body)
		params := reqBody{}
		err := decoder.Decode(&params)
		if err != nil {
			errResp, _ := json.Marshal(badResponse{Error: "Something went wrong"})
			w.WriteHeader(500)
			w.Write(errResp)
			return
		}

		chirpDB, _ := db.loadDB()
		var user User
		for _, v := range chirpDB.Users {
			if v.Email == params.Email {
				user = v
				break
			}
		}
		if user.Email == "" {
			w.WriteHeader(404)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(params.Password))
		if err != nil {
			w.WriteHeader(401)
			return
		}
		token, _ := createToken(user.Id)
		refresh, _ := createRefresh(user.Id)

		resp := response{
			UserOut: UserOut{
				Email:       user.Email,
				Id:          user.Id,
				IsChirpyRed: user.IsChirpyRed,
			},
			Token:        token,
			RefreshToken: refresh,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	})

	adminRouter := chi.NewRouter()
	adminRouter.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		s := "<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>"
		w.Write([]byte(fmt.Sprintf(s, apiCfg.fileserverHits)))
	})

	r.Mount("/api", apiRouter)
	r.Mount("/admin", adminRouter)
	corsMux := middlewareCors(r)
	server := &http.Server{
		Addr:    ":" + port,
		Handler: corsMux,
	}
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(server.ListenAndServe())
}
