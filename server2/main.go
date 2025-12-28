package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	jwtld "github.com/marques-ma/jwt-ld"
	sd "github.com/marques-ma/merkle-selective-disclosure"
)

func main() {
	http.HandleFunc("/execute", executeHandler)
	log.Println("[Server2] Listening on :8082")
	log.Fatal(http.ListenAndServe(":8082", nil))
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("--------------------------------------------------")
	log.Println("[Server2] /execute called")
	body, _ := ioutil.ReadAll(r.Body)

	var req struct {
		Token       string   `json:"token"`
		Disclosures []string `json:"disclosures"`
	}
	json.Unmarshal(body, &req)

	// 1️⃣ Reconstrói mapa de disclosures
	disclosureMap := map[int]*sd.Disclosure{}
	for i, dStr := range req.Disclosures {
		d, err := sd.FromJSON([]byte(dStr))
		if err != nil {
			log.Println("[Server2] ❌ Failed to parse disclosure:", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		disclosureMap[i] = d

		// Log claims reveladas
		claims, err := jwtld.ExtractSDClaimsFromDisclosure(d)
		if err != nil {
			log.Printf("[Server2] ❌ Failed to extract claims from disclosure %d: %v\n", i, err)
		}
		for _, c := range claims {
			log.Printf("[Server2] 🔑 Disclosure %d revealed claim: %s = %v\n", i, c.ID, c.Value)
		}
	}

	// 2️⃣ Valida token com todos disclosures
	ok, err := jwtld.ValidateJWSWithPresentations(req.Token, 1, disclosureMap)
	if err != nil || !ok {
		log.Println("[Server2] ❌ Validation failed:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Println("[Server2] ✔ Token + disclosures validated successfully")

	// 3️⃣ Autorização simples baseada em claims
	authz := map[string]bool{
		"repo.read": true,
		"server1":   true,
	}

	if authz["repo.read"] && authz["server1"] {
		log.Println("[Server2] ✔ Authorization granted")
		w.Write([]byte("Server2: authorized"))
		return
	}

	log.Println("[Server2] ❌ Authorization failed. Required claims missing or false")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("Server2: unauthorized"))
}
