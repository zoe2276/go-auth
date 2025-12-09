package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// User is a user in the system
type User struct {
	Id          int    `db:"id"`
	Username    string `db:"username"`
	Password    string `db:"password"`
	Email       string `db:"email"`
	CreatedTime string `db:"created_time"`
	LastLogin   string `db:"last_login"`
}

var db *sqlx.DB

func main() {
	// connect to pgs
	connectionString := "user=postgres password=$_jejune dbname=auth sslmode=disable port=9884"
	var err error
	db, err = sqlx.Connect("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// init router
	router := mux.NewRouter()
	router.HandleFunc("/register", RegisterHandler).Methods("POST")
	router.HandleFunc("/token", LoginHandler).Methods("POST")

	log.Fatal(http.ListenAndServe(":8099", router))
}

// RegisterHandler handles user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid Input", http.StatusBadRequest)
		return
	}

	// hash the pw
	hashedPw, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("insert into users (username, password, email) values ($1, $2, $3);", user.Username, string(hashedPw), user.Email)
	if err != nil {
		http.Error(w, "Username or email already exists", http.StatusConflict)
		log.Println(err)
		return
	}

	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// LoginHandler for user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// check db for user
	var user User
	err := db.Get(&user, "select * from users where username=$1", creds.Username)
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid credentials", http.StatusBadRequest)
		return
	} else if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		log.Println("error getting user from db:", err)
		return
	}

	// verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// jwt gen
	tokenExpiration := time.Now().Add(time.Hour * 8).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"exp":      tokenExpiration,
	})
	tokenString, err := token.SignedString([]byte("4jejune[EGJEidzZ"))
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// update last login timestamp
	var _ any
	_, err = db.Exec("update users set last_login=current_timestamp where id=$1", user.Id)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString, "expires": strconv.FormatInt(tokenExpiration, 10)})
}
