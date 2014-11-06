package main

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
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
	getJwtTest()
	index := http.FileServer(http.Dir("static"))
	http.Handle("/", index)
	http.HandleFunc("/getJwt", getJwt)
	http.HandleFunc("/checkJwt", checkJwt)
	log.Fatal(http.ListenAndServe(":8081", nil))
}

/*****************************************************************************/

func getJwtTest() {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims["PERMISSION"] = "admin@tiedot"
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	if tokenString, e := token.SignedString(privateKey); e != nil {
		panic(e)
	} else {
		checkJwtTest(tokenString)
	}
}

func checkJwtTest(t string) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if token.Valid {
		log.Printf("%v", token)
	} else {
		log.Printf("%s", err)
	}
}

/*****************************************************************************/

func getJwt(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("email")
	password := r.FormValue("password")
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims[password] = name
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

func checkJwt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	token, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if token.Valid {
		log.Printf("%v", token)
		//fmt.Fprintf(w, "{\"object\": %v}", token)

	} else {
		log.Printf("%v", err)
		fmt.Fprintf(w, "{\"error\": \"%s %s\"}", "JWT not valid,", err)
	}
}
