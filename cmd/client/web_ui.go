package main

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed webui/index.html
var webUIFS embed.FS

func (s *apiState) handleWebUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.URL.Path == "/ui" {
		http.Redirect(w, r, "/ui/", http.StatusFound)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/ui/") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.URL.Path != "/ui/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	data, err := webUIFS.ReadFile("webui/index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
