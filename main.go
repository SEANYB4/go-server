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
	
)



type apiConfig struct {

	FileserverHits int

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

	db := NewDB("database.json")
	apiCfg := &apiConfig{
		FileserverHits: 0,
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
	apiRouter.Post("/chirps", createChirp)

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

func createChirp(w http.ResponseWriter, r *http.Request) {

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
		cleaned = strings.Join(words)
		chirp := CreateChirp(cleaned)



	}

}


