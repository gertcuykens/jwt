package main

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

var (
	privateKey []byte //openssl genrsa -out jwt.rsa 1024
	publicKey  []byte //openssl rsa -in jwt.rsa -pubout > jwt.rsa.pub
)

func init() {
	var e error
	if privateKey, e = ioutil.ReadFile("jwt.rsa"); e != nil {
		panic(e)
	}
	if publicKey, e = ioutil.ReadFile("jwt.rsa.pub"); e != nil {
		panic(e)
	}
}

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		log.Print("deleting database sdb")
		os.RemoveAll("sdb")
		defer os.RemoveAll("sdb")
		os.Exit(1)
	}()

	getJwtTest()
	index := http.FileServer(http.Dir("static"))
	http.Handle("/", index)
	http.HandleFunc("/getJwt", getJwt)
	http.HandleFunc("/secureDb", secureDb)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

/*****************************************************************************/

func getJwtTest() {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims["PERMISSION"] = "ADMIN"
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	var tokenString string
	var e error
	if tokenString, e = token.SignedString(privateKey); e != nil {
		panic(e)
	}
	log.Printf("{\"string\": %v}", token)
	secureDbTest(tokenString)
}

func secureDbTest(t string) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err == nil && token.Valid {
		log.Printf("%v", token)
		sdb(token)
	} else {
		log.Printf("%s", err)
	}
}

/*****************************************************************************/

func getJwt(w http.ResponseWriter, r *http.Request) {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims["PERMISSION"] = "ADMIN"
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	var tokenString string
	var e error
	if tokenString, e = token.SignedString(privateKey); e != nil {
		panic(e)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+tokenString)
	w.WriteHeader(http.StatusOK)
	//fmt.Fprintf(w, "{\"token\": \"%s\"}", tokenString)
	//log.Printf("%s", tokenString)
}

func secureDb(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	token, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err == nil && token.Valid {
		log.Printf("%v", token)
		sdb(token)
		//fmt.Fprintf(w, "{\"object\": %v}", token)

	} else {
		fmt.Fprintf(w, "{\"error\": \"%s %s\"}", "JWT not valid,", err)
		log.Printf("%v", err)
	}
}

/*****************************************************************************/

func addDefaultHeaders(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		//w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token")
		//w.Header().Set("Access-Control-Allow-Credentials", "true")
		fn(w, r)
	}
}
