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
		},
		JWT_SECRET: os.Getenv("JWT_SECRET"),
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

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, responseBody{
			"error": "Something went wrong",
		})
	} 

	var msg string = params.Body
	if len(msg) > 140 {
		respondWithError(w, 400, responseBody{
			"error": "Chirp is too long",
		})
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
		chirp, err := cfg.Database.CreateChirp(cleaned, idForInsert)
		if err != nil {
			fmt.Println("Error: ", err)
		}

		cfg.DatabaseMap.Chirps[idForInsert] = chirp
		cfg.Database.WriteDB(cfg.DatabaseMap)
		
		respondWithJSON(w, 201, chirp)
	}
}


func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {

	returnArray := make([]database.Chirp, 0)

	for i := range cfg.DatabaseMap.Chirps {
		returnArray = append(returnArray, cfg.DatabaseMap.Chirps[i])
	}

	sort.Slice(returnArray, func(i, j int) bool { return returnArray[i].ID < returnArray[j].ID })
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
		Expires int
	}
	type responseBody map[string]string
	type responseBody2 struct{
		ID int
		Email string
		Token string
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


				// Create a JWT
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Issuer: "chirpy",
					IssuedAt: jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expires))),
					Subject: string(cfg.DatabaseMap.Users[i].ID),
				})
				fmt.Println(token)


				// Sign the token with a secret key
				signedToken, err := token.SignedString(os.Getenv("JWT_SECRET"))
				if err != nil {
					fmt.Println("Error signing token")
				}


				respondWithJSON(w, 200, responseBody2{
					ID: cfg.DatabaseMap.Users[i].ID,
					Email: cfg.DatabaseMap.Users[i].Email,
					Token: signedToken,
				})
				return
			}

		}
	}


	respondWithError(w, 404, responseBody{
		"error": "User not found",
	})

}