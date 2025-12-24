package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"

	// _ "github.com/lib/pq"
	_ "github.com/go-sql-driver/mysql"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

// User is a user in the system
type User struct {
	Id          int            `db:"id"`
	Username    string         `db:"username" json:"username"`
	Password    string         `db:"pwhash" json:"password"`
	Email       string         `db:"email" json:"email"`
	CreatedTime string         `db:"created_time"`
	LastLogin   sql.NullString `db:"last_login"`
	LastPwReset sql.NullString `db:"last_pw_update"`
	Roles       string         `db:"roles" json:"roles"`
}

type JWTClaims struct {
	Username   string      `json:"username"`
	Expiration json.Number `json:"exp"`
	jwt.StandardClaims
}

var db *sqlx.DB
var jwtKey = []byte(os.Getenv("jwtSigningKey"))

func returnJson(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"message": message})
}

func main() {
	var err error
	// err = godotenv.Load(".env")
	// if err != nil {
	// 	log.Println(err)

	if err = godotenv.Load("/opt/goapp/.env"); err != nil {
		log.Fatal(err)
	}
	// }

	// connect to mysql
	connectionString := os.Getenv("authDbDsn")
	db, err = sqlx.Connect("mysql", connectionString)
	if err != nil {
		log.Println("error connecting to sql server with connectionstr:")
		log.Println(connectionString)
		log.Fatal(err)
	}
	defer db.Close()

	// init router
	router := mux.NewRouter()
	api := "/api"

	// unauthorized routes

	router.HandleFunc(api+"/register", RegisterHandler).Methods("POST")
	router.HandleFunc(api+"/token", TokenHandler).Methods("POST")

	// authorized routes

	router.Handle(api+"/authorization", AuthMiddleware(http.HandlerFunc(AuthorizationHandler))).Methods("GET")

	// cors
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173", "https://zoe.rip"},
		AllowCredentials: true,
	})

	handler := c.Handler(router)
	log.Fatal(http.ListenAndServe(":1358", handler))
}

// Middleware

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			returnJson(w, "No token provided", http.StatusUnauthorized)
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			returnJson(w, "Invalid token", http.StatusUnauthorized)
			if err != nil {
				log.Println("invalid token", err)
			}
			return
		}

		claims := token.Claims.(*JWTClaims)
		ctx := context.WithValue(r.Context(), "jwtClaims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Endpoints
// Unsecured

// RegisterHandler handles user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		returnJson(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// hash the pw
	hashedPw, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.MinCost)
	if err != nil {
		returnJson(w, "Server error", http.StatusInternalServerError)
		return
	}

	rolesJson, _ := json.Marshal(user.Roles)
	_, err = db.Exec("insert into users (username, pwhash, email, roles) values (?, ?, ?, ?);", user.Username, string(hashedPw), user.Email, string(rolesJson))
	if err != nil {
		returnJson(w, "Username or email already exists", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// TokenHandler for user API login
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		returnJson(w, "Invalid input", http.StatusBadRequest)
		log.Println(err)
		return
	}

	// check db for user
	var user User
	err := db.Get(&user, "select * from users where username=?", creds.Username)
	if err == sql.ErrNoRows {
		returnJson(w, "Invalid credentials", http.StatusBadRequest)
		return
	} else if err != nil {
		returnJson(w, "Server error", http.StatusInternalServerError)
		log.Println("error getting user from db:", err)
		return
	}

	// verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		returnJson(w, "Invalid credentials", http.StatusBadRequest)
		return
	}

	// jwt gen
	tokenExpiration := time.Now().Add(time.Hour * 8).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"exp":      tokenExpiration,
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		returnJson(w, "Server error", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// update last login timestamp
	var _ any
	_, err = db.Exec("update users set last_login=current_timestamp where id=?", user.Id)
	if err != nil {
		returnJson(w, "Server error", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString, "expires": strconv.FormatInt(tokenExpiration, 10)})
}

// Secured

// AuthorizedHandler displays authorization information for the signed in user
func AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value("jwtClaims").(*JWTClaims)

	var user User
	err := db.Get(&user, "select * from users where username=?", c.Username)
	if err != nil {
		returnJson(w, "Server error", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"authorized": true,
		"user":       user.Username,
		"email":      user.Email,
		"roles":      user.Roles,
	})
}
