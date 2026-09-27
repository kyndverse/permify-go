package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type response struct {
	Message string `json:"message"`
	Path    string `json:"path"`
	Method  string `json:"method"`
	User    string `json:"user"`
	Role    string `json:"role"`
}

func handler(
	w http.ResponseWriter,
	r *http.Request,
) {
	user := r.Header.Get(
		"x-current-user",
	)

	role := r.Header.Get(
		"x-current-role",
	)

	log.Printf(
		"backend request method=%s path=%s user=%s role=%s",
		r.Method,
		r.URL.Path,
		user,
		role,
	)

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(
		response{
			Message: "request reached backend",
			Path:    r.URL.Path,
			Method:  r.Method,
			User:    user,
			Role:    role,
		},
	)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc(
		"/",
		handler,
	)

	log.Println(
		"Backend API running on :8081",
	)

	if err := http.ListenAndServe(
		":8081",
		mux,
	); err != nil {
		log.Fatal(err)
	}
}
