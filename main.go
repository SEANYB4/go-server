package main


import (
	"net/http"
	"fmt"
	"github.com/go-chi/chi/v5"
	// "github.com/go-chi/chi/v5/middleware"
	"html/template"
	"encoding/json"
	"strings"
	"github.com/SEANYB4/go-server/internal/database"
	"sort"
	"strconv"
	"golang.org/x/crypto/bcrypt"
	// "github.com/google/uuid"
	"github.com/joho/godotenv"
	"os"
	"github.com/golang-jwt/jwt/v5"
	"time"
	
	
)



type apiConfig struct {

	FileserverHits int
	Database database.DB
	ChirpID int
	UserID int
	DatabaseMap database.DBStructure
	JWT_SECRET string
	POLKA_KEY string

}

type ChirpResponse struct{
	id int
	body string
}


func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler{
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("file server hit")
		cfg.FileserverHits++
		next.ServeHTTP(w, r)
	})

}


func (cfg *apiConfig) numberRequests(w http.ResponseWriter, r *http.Request) {
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hits: " + fmt.Sprint(cfg.FileserverHits))))
	
}





func main() {

	godotenv.Load()


	apiCfg := &apiConfig{
		FileserverHits: 0,
		Database: *database.NewDB("database.json"),
		ChirpID: 1,
		UserID: 1,
		DatabaseMap : database.DBStructure{
			Chirps: map[int]database.Chirp{},
			Users: map[int]database.User{},
			RevokedRefreshTokens: map[string]database.RevokedToken{},
		},
		JWT_SECRET: os.Getenv("JWT_SECRET"),
		POLKA_KEY: os.Getenv("POLKA_KEY"),
	}
	r := chi.NewRouter()
	apiRouter := chi.NewRouter()
	adminRouter := chi.NewRouter()	
	dir := "."
	fileServer := http.FileServer(http.Dir(dir))
	
	r.Mount("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Method != "GET" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		apiCfg.middlewareMetricsInc(fileServer).ServeHTTP(w, r)
	}))

	r.Mount("/admin", adminRouter)
	r.Mount("/api", apiRouter)

	// mux is a http multiplexer??
	// mux := http.NewServeMux()
	corsMux := middlewareCors(r)
	server := &http.Server{
		Addr: ":8080",
		Handler: corsMux,
	}

	
	
	apiRouter.Get("/healthz", readinessCheck)
	apiRouter.Get("/metrics", apiCfg.numberRequests)
	apiRouter.Post("/validate_chirp", checkLengthOfChirp)
	apiRouter.Post("/chirps", apiCfg.createChirp)
	apiRouter.Get("/chirps", apiCfg.getChirps)
	apiRouter.Get("/chirps/{chirpID}", apiCfg.getChirpFromID)
	apiRouter.Post("/users", apiCfg.createUser)
	apiRouter.Post("/login", apiCfg.login)
	apiRouter.Put("/users", apiCfg.updateUser)
	apiRouter.Post("/refresh", apiCfg.refresh)
	apiRouter.Post("/revoke", apiCfg.revoke)
	apiRouter.Delete("/chirps/{chirpID}", apiCfg.deleteChirp)
	apiRouter.Post("/polka/webhooks", apiCfg.polka)

	adminRouter.Mount("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Method != "GET" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		
		tmpl := template.Must(template.ParseFiles("./admin/metrics/index.html"))
		err := tmpl.Execute(w, apiCfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	
	// mux.Handle("/", apiCfg.middlewareMetricsInc())
	
	// mux.HandleFunc("/healthz", readinessCheck)
	//mux.HandleFunc("/metrics", apiCfg.numberRequests)

	fmt.Println("Server running...")
	server.ListenAndServe()
	
}



func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) error {
	response, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(code)
	w.Write(response)
	return nil
}

func respondWithError(w http.ResponseWriter, code int, response map[string]string ) error {
	return respondWithJSON(w, code, response)
}


func checkLengthOfChirp(w http.ResponseWriter, r *http.Request) {

	type parameters struct {

		Body string `json:"body"`
	}

	type responseBody1 map[string]string
	type responseBody2 map[string]string

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {

		respondWithJSON(w, 500, responseBody1{
			"error": "Something went wrong",
		})
	}

	var msg string = params.Body
	

	if len(msg) > 140 {
		respondWithError(w, 400, responseBody1{
			"error": "Chirp is too long",
		})
	} else {

		words := strings.Split(msg, " ")
		for i, word := range words {
			word = strings.ToLower(word)
			fmt.Println(word)
			if word == "kerfuffle" || word == "sharbert" || word == "fornax" {
				words[i] = "****"
			}
		}
		cleaned := strings.Join(words, " ")
		// fmt.Println(cleaned)
		respondWithJSON(w, 200, responseBody2{
			"cleaned_body": cleaned,
		})
	}

}

func readinessCheck(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))

}

func middlewareCors(next http.Handler) http.Handler{

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

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email string
		Password string
	}

	type responseBody map[string]string
	type responseBody2 struct{
		ID int
		Email string
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, responseBody{
			"error": "Something went wrong",
		})
	}
	id := cfg.UserID
	cfg.UserID += 1
	var email string = params.Email
	var password string = params.Password

	for i := range cfg.DatabaseMap.Users {
		if cfg.DatabaseMap.Users[i].Email == email {
			respondWithError(w, 500, responseBody{
			"error": "User already registered",
		})
		}
	}


	hash, err := bcrypt.GenerateFromPassword([]byte(password), 5)
	if err != nil {
		respondWithError(w, 500, responseBody{
			"error": "Something went wrong",
		})
	}

	hashPass := string(hash)


	user := database.User{
		ID: id,
		Email: email,
		HashedPassword: hashPass,
		Is_Chirpy_Red: false,
	}


	cfg.DatabaseMap.Users[id] = user
	cfg.Database.WriteDB(cfg.DatabaseMap)
		
	respondWithJSON(w, 201, responseBody2{
		ID: user.ID,
		Email: user.Email,
	})

}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {

	type parameters struct {
		Body string `json:"body"`
	}

	type responseBody map[string]string


	authHeader := r.Header.Get("Authorization")

	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer") {
		
		respondWithError(w, http.StatusUnauthorized, responseBody{

			"error": "User unauthenticated",
		})
		return
	}

	tokenString := authHeader[len("Bearer "):]

	// Parse the token using the jwt.ParseWithClaims function
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWT_SECRET), nil
	}

	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc)
	
	// check if the token is valid

	if err != nil || !token.Valid {
		
		respondWithError(w, 401, responseBody{
			"error": "Token invalid",
		})
		return
	}

	// Extract the claims

	myClaims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		respondWithError(w, 500, responseBody{
			"error": "Something went wrong",
		})
		return
	}

	userID, err := strconv.Atoi(myClaims.Subject)
	
	
	if err != nil {
		respondWithError(w, 500, responseBody{
			"error": "Error parsing user ID",
		})
		return
	}


	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, responseBody{
			"error": "Something went wrong",
		})
		return
	} 

	var msg string = params.Body
	if len(msg) > 140 {
		respondWithError(w, 400, responseBody{
			"error": "Chirp is too long",
		})
		return
	} else {

		words := strings.Split(msg, " ")
		for i, word := range words {

			word = strings.ToLower(word)
			if word == "kerfuffle" || word == "sharbert" || word == "fornax" {
				words[i] = "****"
			}

		}
		idForInsert := cfg.ChirpID
		cfg.ChirpID += 1
		cleaned := strings.Join(words, " ")
		chirp, err := cfg.Database.CreateChirp(cleaned, idForInsert, userID)
		if err != nil {
			fmt.Println("Error: ", err)
			return
		}

		cfg.DatabaseMap.Chirps[idForInsert] = chirp
		cfg.Database.WriteDB(cfg.DatabaseMap)
		
		respondWithJSON(w, 201, chirp)
	}
}


func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {

	type responseBody map[string]string

	authorIDString := r.URL.Query().Get("author_id")
	
	authorIDInt, err := strconv.Atoi(authorIDString)
	if err != nil {
		fmt.Println("Error parsing authorID into int format")
	}

	sortOrder := r.URL.Query().Get("sort")



	returnArray := make([]database.Chirp, 0)

	if authorIDString == "" {
		for i := range cfg.DatabaseMap.Chirps {
			returnArray = append(returnArray, cfg.DatabaseMap.Chirps[i])
		}
	} else {
		for i := range cfg.DatabaseMap.Chirps {
			if cfg.DatabaseMap.Chirps[i].AuthorID == authorIDInt {
				returnArray = append(returnArray, cfg.DatabaseMap.Chirps[i])
			}
		}
	}
	
	if sortOrder == "asc" || sortOrder == "" {
		sort.Slice(returnArray, func(i, j int) bool { return returnArray[i].ID < returnArray[j].ID })
	} else {
		sort.Slice(returnArray, func(i, j int) bool { return returnArray[i].ID > returnArray[j].ID })
	}

	
	respondWithJSON(w, 200, returnArray)
}


func (cfg *apiConfig) getChirpFromID(w http.ResponseWriter, r *http.Request) {
	type responseBody map[string]string

	id := chi.URLParam(r, "chirpID")
	intId, err := strconv.Atoi(id)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	chirp := cfg.DatabaseMap.Chirps[intId]

	if chirp.ID == 0 {
		respondWithError(w, 404, responseBody{
			"error": "id not found",
		})
		return
	}
	respondWithJSON(w, 200, chirp)
}


func (cfg *apiConfig) login(w http.ResponseWriter, r *http.Request) {

	type parameters struct {
		
		Password string
		Email string
		Expires int `json:"expires_in_seconds"`
	}
	type responseBody map[string]string
	type responseBody2 struct{
		ID int `json:"id"`
		Email string `json:"email"`
		AccessToken string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		Is_Chirpy_Red bool `json:"is_chirpy_red"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, responseBody{
			"error": "Something went wrong",
		})
		return
	}

	expires := params.Expires
	if expires == 0 {
		expires = int(time.Hour * 24)
	} else if expires > (24*60*60) {
		expires = int(time.Hour * 24)
	}

	email := params.Email
	password := []byte(params.Password)

	for i := range cfg.DatabaseMap.Users {
		if cfg.DatabaseMap.Users[i].Email == email {
			err := bcrypt.CompareHashAndPassword([]byte(cfg.DatabaseMap.Users[i].HashedPassword), password)
			
			if err != nil {
				respondWithError(w, 401, responseBody{
					"error": "Password incorrect",
				})
				return
			} else {


				// Create an access JWT
				accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Issuer: "chirpy-access",
					IssuedAt: jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					Subject: fmt.Sprint(cfg.DatabaseMap.Users[i].ID),
				})

				// Create a refresh JWT
				refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Issuer: "chirpy-refresh",
					IssuedAt: jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration((time.Hour*24)*60))),
					Subject : fmt.Sprint(cfg.DatabaseMap.Users[i].ID),
				})
				


				// Sign the access token with a secret key
				secretKey := []byte(cfg.JWT_SECRET)
				signedAccessToken, err := accessToken.SignedString(secretKey)
				

				if err != nil {
					fmt.Println("Error signing access token: ", err)
					respondWithError(w, 500, responseBody{
						"error": "Internal Server Error",
					})
					return
				}

				// Sign the refresh token with a secret key
				signedRefreshToken, err := refreshToken.SignedString(secretKey)

				if err != nil {
					fmt.Println("Error signing refesh token: ", err)
					respondWithError(w, 500, responseBody{
						"error": "Internal Server Error",
					})
					return
				}

				

				respondWithJSON(w, 200, responseBody2{
					ID: cfg.DatabaseMap.Users[i].ID,
					Email: cfg.DatabaseMap.Users[i].Email,
					AccessToken: signedAccessToken,
					RefreshToken: signedRefreshToken,
					Is_Chirpy_Red: cfg.DatabaseMap.Users[i].Is_Chirpy_Red,

				})
				return
			}

		}
	}


	respondWithError(w, 404, responseBody{
		"error": "User not found",
	})

}



func (cfg *apiConfig) updateUser(w http.ResponseWriter, r *http.Request) {


	type responseBody map[string]string
	type responseBody2 struct{
		ID int `json:"id"`
		Email string `json:"email"`

	}
	

	type parameters struct {
		Email string `json:"email"`
		Password string `json:"password"`
	}
	authHeader := r.Header.Get("Authorization")
	


	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer") || len(authHeader)<=7{
		respondWithError(w, http.StatusUnauthorized, responseBody{
			"error": "Couldn't find JWT",
		})
		return
	}

	
	// Extract the token string from the Authorization header by stripping off the Bearer prefix
	tokenString := authHeader[len("Bearer "):]

	// Parse the token using the jwt.ParseWithClaims function
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWT_SECRET), nil
	}

	claims := jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc)

	// Check if the token is valid
	if err != nil || !token.Valid {

		respondWithError(w, 401, responseBody{
			"error": fmt.Sprint(err),
		})
		return
	}


	// Extract the claims
	myClaims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		respondWithError(w, 500, responseBody{
			"error": "Internal server error",
		})
		return
	}



	// ******************************************************
	// Check the expiration time
	expTime := myClaims.ExpiresAt
	
	if expTime.Before(time.Now()) {
        respondWithError(w, 401, responseBody{
			"error": "Token expired",
		})
		return
    }
	

	// Check if token is an access token

	issuer := myClaims.Issuer

	if issuer != "chirpy-access" {
		respondWithError(w, 401, responseBody{
			"error": "No access token provided",
		})
		return
	}


	id := myClaims.Subject
	idForCompare, err := strconv.Atoi(id)

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {

		respondWithError(w, 500, responseBody{
			"error": "Something went wrong",
		})
		return
	}

	

	hash, err := bcrypt.GenerateFromPassword([]byte(params.Password), 5)
	if err != nil {
		respondWithError(w, 500, responseBody{
			"error": "Something went wrong",
		})
	}

	hashPass := string(hash)

	user := database.User{
		ID: idForCompare,
		Email: params.Email,
		HashedPassword: hashPass,
	}


	
	for i := range cfg.DatabaseMap.Users { 
		if cfg.DatabaseMap.Users[i].ID == idForCompare {
			cfg.DatabaseMap.Users[i] = user
			cfg.Database.WriteDB(cfg.DatabaseMap)
			respondWithJSON(w, 200, responseBody2{
				ID: user.ID,
				Email: user.Email,
			})
			return
		}
	}

	

}



func (cfg *apiConfig) refresh(w http.ResponseWriter, r *http.Request) {

	type responseBody map[string]string
	type responseBody2 struct{
		Token string `json:"token"`
	}
	

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer") || len(authHeader)<=7{
		respondWithError(w, http.StatusUnauthorized, responseBody{
			"error": "Couldn't find JWT",
		})
		return
	}

	// Extract the token string from the Authorization header by stripping off the Bearer prefix
	tokenString := authHeader[len("Bearer "):]

	// Parse the token using the jwt.ParseWithClaims function
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWT_SECRET), nil
	}

	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc)

	// Check if the token is valid
	if err != nil || !token.Valid {

		respondWithError(w, 401, responseBody{
			"error": fmt.Sprint(err),
		})
		return
	}

	// Extract the claims
	myClaims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		respondWithError(w, 500, responseBody{
			"error": "Internal server error",
		})
		return
	}


	// get user id

	id := myClaims.Subject

	issuer := myClaims.Issuer
	if issuer != "chirpy-refresh" {

		respondWithError(w, 401, responseBody{
			"error": "no refresh token provided",
		})
	}

	for i := range cfg.DatabaseMap.RevokedRefreshTokens {

		if tokenString == cfg.DatabaseMap.RevokedRefreshTokens[i].ID {
			respondWithError(w, 401, responseBody{
				"error": "refrsh token has been revoked",
			})
			return
		}
	}

	// Create an access JWT
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer: "chirpy-access",
		IssuedAt: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject: fmt.Sprint(id),
	})

	// Sign the access token with a secret key
	secretKey := []byte(cfg.JWT_SECRET)
	signedAccessToken, err := accessToken.SignedString(secretKey)
	

	if err != nil {
		fmt.Println("Error signing access token: ", err)
		respondWithError(w, 500, responseBody{
			"error": "Internal Server Error",
		})
		return
	}



	respondWithJSON(w, 200, responseBody2{
		Token: signedAccessToken,
	})


}




func (cfg *apiConfig) revoke(w http.ResponseWriter, r *http.Request) {


	type responseBody map[string]string

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer") || len(authHeader)<=7{
		respondWithError(w, http.StatusUnauthorized, responseBody{
			"error": "Couldn't find JWT",
		})
		return
	}


	// Extract the token string from the Authorization header by stripping off the Bearer prefix
	tokenString := authHeader[len("Bearer "):]

	cfg.DatabaseMap.RevokedRefreshTokens[tokenString] = database.RevokedToken{
		ID: tokenString,
		Time: time.Now(),
	}
	cfg.Database.WriteDB(cfg.DatabaseMap)
	respondWithJSON(w, 200, responseBody{
		"error": "None",
	})

}


func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {

	
	

	type responseBody map[string]string

	

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer") {
		respondWithError(w, http.StatusUnauthorized, responseBody{
			"error": "Couldn't find JWT",
		})
		return
	}

	tokenString := authHeader[len("Bearer "):]

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWT_SECRET), nil
	}

	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc)

	if err != nil || !token.Valid {
		respondWithError(w, 401, responseBody{
			"error": fmt.Sprint(err),
		})
		return
	}

	myClaims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		respondWithError(w, 500, responseBody{
			"error": "Internal server error",
		})
		return
	}

	userID, err := strconv.Atoi(myClaims.Subject)
	if err != nil {
		respondWithError(w, 500, responseBody{
			"error": "Error while parsing user ID",
		})
		return
	}
	
	id := chi.URLParam(r, "chirpID")
	chirpId, err := strconv.Atoi(id)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}


	for i := range cfg.DatabaseMap.Chirps {

		if i == chirpId {

			if cfg.DatabaseMap.Chirps[i].AuthorID == userID {


				// DELETE THE CHIRP FROM THE DATABASE
				delete(cfg.DatabaseMap.Chirps, i)
				cfg.Database.WriteDB(cfg.DatabaseMap)
				respondWithJSON(w, 200, responseBody{
					"error": "None",
				})
				return

			} else {
				respondWithError(w, 403, responseBody{
					"error": "User ID does not match author ID of chirp",
				})
				return
			}

		}

	}

}


func (cfg *apiConfig) polka (w http.ResponseWriter, r *http.Request) {

	type responseBody map[string]string
	type Data struct{
		UserID int `json:"user_id"`
	}
	type parameters struct{
		Event string `json:"event"`
		Data Data `json:"data"`
	}



	apiKey := r.Header.Get("Authorization")

	if apiKey == "" || !strings.HasPrefix(apiKey, "ApiKey") {
		respondWithError(w, 401, responseBody{
			"error": "no api key found in request",
		})
		return
	}

	apiKeyString := apiKey[len("ApiKey "):]

	if cfg.POLKA_KEY != apiKeyString {
		respondWithError(w, 401, responseBody{
			"error": "incorrect api key",
		})
		return
	}


	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, responseBody{
			"error": "Something went wrong",
		})
		return
	}


	event := params.Event
	userID := params.Data.UserID
	if event != "user.upgraded" {
		
		respondWithJSON(w, 200, responseBody{
			"error": "Event type unrecognised",
		})
		return
	} else {

		for i := range cfg.DatabaseMap.Users {

			if userID == cfg.DatabaseMap.Users[i].ID {
				user := cfg.DatabaseMap.Users[i]
				user.Is_Chirpy_Red = true
				cfg.DatabaseMap.Users[i] = user
				cfg.Database.WriteDB(cfg.DatabaseMap)
				respondWithJSON(w, 200, nil)
				return

			}
		}

		respondWithError(w, 404, responseBody{
			"error": "User not found",
		})
	}
}