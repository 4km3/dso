package main

import (
	"embed"
	"log"
	"net/http"
)

//go:embed index.html style.css
var staticFiles embed.FS

func main() {
	// Create a file server handler using the embedded files
	http.Handle("/", http.FileServer(http.FS(staticFiles)))

	// Start the server
	log.Println("Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
