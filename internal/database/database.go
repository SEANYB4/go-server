package database

import (

	"sync"
	"os"
	"encoding/json"
	"fmt"
	"io"
	"time"
	
)

type DB struct {

	path string
	mux *sync.RWMutex
}


type Chirp struct {
	ID int `json:"id"`
	Body string `json:"body"`
	AuthorID int `json:"author_id"`
}


type User struct {
	ID int
	Email string
	HashedPassword string
	Is_Chirpy_Red bool
}

type DBStructure struct {

	Chirps map[int]Chirp `json:"chirps"`
	Users map[int]User `json:"users"`
	RevokedRefreshTokens map[string]RevokedToken `json:"revokedTokens"`
}

type RevokedToken struct {
	ID string
	Time time.Time
}


// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB) {

	err := os.WriteFile(path, []byte(""), 0666)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	db := DB{
		path: path,
	}
	return &db
}


// // CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string, id int, userID int) (Chirp, error) {

	chirp := Chirp{
		ID: id,
		Body: body,
		AuthorID: userID,
	}

	file, _ := json.MarshalIndent(chirp, "", " ")
	err := os.WriteFile("database.json", file, 0644)
	return chirp, err
}



// // GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	data, err := os.ReadFile("database.json")
	if err != nil {
		return nil, err
	}
	var chirpsArray []Chirp
	err = json.Unmarshal(data, &chirpsArray)
	if err != nil {
		return nil, err
	}
	return chirpsArray, nil
}






// // ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {

	_, err := os.Open("database.json")
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("File does not exist")
			err := os.WriteFile("database.json", []byte{}, 0644)
			return err
		}
		return err
	} else {
		return err
	}
}


// // loadDB reads the database file into memory
func (db *DB) LoadDB() (DBStructure, error) {

	file, err := os.Open("database.json")
	if err != nil {
		fmt.Println("Error:", err)
	}
	defer file.Close()

	// Read the contents of the file into a byte slice
	data := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Println("Error: ", err)
		}
		// checks if the end of the file has been reached
		// When the end of the file is reached, the Read method will return n == 0
		// and an error value of io.EOF, which indicates that there is no more data
		// to be read.
		if n == 0 {
			break
		}
		data = append(data, buf[:n]...)
	}

	// Parse the JSON data into a Go data structure
	var databaseMap DBStructure
	err = json.Unmarshal(data, &databaseMap)
	if err != nil {
		fmt.Println("Error: ", err)
		return databaseMap, err
	}

	return databaseMap, err

}

// // writeDB writes the database file to disk
func (db *DB) WriteDB(dbStructure DBStructure) error {

	// Convert the slice to a JSON-encoded byte slice
	data, err := json.Marshal(dbStructure)
	if err != nil {
		fmt.Println("Error: ", err)
		return err
	}
	// Write the byte slice to a file
	err = os.WriteFile("database.json", data, 0644)
	if err != nil {
		fmt.Println("Error: ", err)
		return err
	}

	return nil

}
