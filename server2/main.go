package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	jwtld "github.com/marques-ma/jwt-ld"
	sd "github.com/marques-ma/merkle-selective-disclosure"
)

const listenAddr = ":8082"

func main() {
	http.HandleFunc("/execute", executeHandler)
	log.Println("[Server2] Listening on", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("--------------------------------------------------")
	log.Println("[Server2] /execute called")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		Token         string                     `json:"token"`
		Presentations map[string]json.RawMessage `json:"presentations"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Convert presentations to map[int]*sd.Disclosure
	presMap := map[int]*sd.Disclosure{}
	for kStr, raw := range req.Presentations {
		var idx int
		if _, err := fmt.Sscanf(kStr, "%d", &idx); err != nil {
			log.Printf("[Server2] ❌ invalid presentation key: %s", kStr)
			continue
		}
		d, err := sd.FromJSON(raw)
		if err != nil {
			log.Printf("[Server2] ❌ failed to parse presentation %d: %v", idx, err)
			continue
		}
		presMap[idx] = d
	}

	// Validate token with all presentations
	ok, err := jwtld.ValidateJWSWithPresentations(req.Token, 1, presMap)
	if err != nil || !ok {
		http.Error(w, "token validation failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	log.Println("[Server2] ✔ Token and presentations cryptographically valid")

	// Log all claims for debugging
	for i, d := range presMap {
		claims, err := jwtld.ExtractSDClaimsFromDisclosure(d)
		if err != nil {
			log.Printf("[Server2] ℹ️ Could not extract claims from presentation %d: %v", i, err)
			continue
		}
		for _, c := range claims {
			log.Printf("[Server2] 🔑 Presentation %d revealed claim: %s = %v", i, c.ID, c.Value)
		}
	}

	// --- Authorization checks ---

	// Node 0 = AS/host: repo.write = true
	asPres, ok := presMap[0]
	if !ok {
		http.Error(w, "missing AS presentation", http.StatusBadRequest)
		return
	}
	claims, _ := jwtld.ExtractSDClaimsFromDisclosure(asPres)
	var allowRepoWrite bool
	for _, c := range claims {
		if c.ID == "repo.write" {
			if v, ok := c.Value.(bool); ok && v {
				allowRepoWrite = true
			}
		}
	}
	if !allowRepoWrite {
		log.Println("[Server2] ❌ repo.write claim missing or false in AS node")
		http.Error(w, "repo.write claim invalid", http.StatusForbidden)
		return
	}

	// Node 1 = Server1: execute = true
	server1Pres, ok := presMap[1]
	if !ok {
		http.Error(w, "missing Server1 presentation", http.StatusBadRequest)
		return
	}
	claims, _ = jwtld.ExtractSDClaimsFromDisclosure(server1Pres)
	var allowExecute bool
	for _, c := range claims {
		if c.ID == "execute" {
			if v, ok := c.Value.(bool); ok && v {
				allowExecute = true
			}
		}
	}
	if !allowExecute {
		log.Println("[Server2] ❌ execute claim missing or false in Server1 node")
		http.Error(w, "execute claim invalid", http.StatusForbidden)
		return
	}

	log.Println("[Server2] ✔ Authorization granted for both AS and Server1 claims")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
