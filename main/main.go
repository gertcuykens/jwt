package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gertcuykens/jwt"
)

func main() {
	fmt.Println(os.Getenv("ORIGIN"))
	s := jwt.NewServer(nil)
	http.HandleFunc("/subject", s.Subject)
	http.HandleFunc("/delete", s.Delete)
	http.HandleFunc("/sign/", s.Sign)
	http.HandleFunc("/verify", s.Verify)
	http.Handle("/", http.FileServer(http.Dir("./pub")))
	log.Fatal(http.ListenAndServe(":8082", nil))
}
