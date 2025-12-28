package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	// sd "github.com/marques-ma/merkle-selective-disclosure"
	jwtld "github.com/marques-ma/jwt-ld"
	"github.com/hpe-usp-spire/schoco"
)

func main() {
	http.HandleFunc("/issueToken", issueTokenHandler)

	log.Println("[AS] Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func issueTokenHandler(w http.ResponseWriter, r *http.Request) {
	// === Root key (SchoCo) ===
	rootSk, rootPk := schoco.KeyPair("root")
	rootPKBytes, _ := schoco.PointToByte(rootPk)

	// === Parse request ===
	var req struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Println("[AS] Requested permissions:", req.Permissions)

	// === 1) Build cleartext claims ===
	claims := make(map[string]interface{})
	for _, p := range req.Permissions {
		claims[p] = true
	}

	// === 2) Build base payload (claims still present) ===
	payload := &jwtld.Payload{
		Ver: 1,
		Iat: time.Now().Unix(),
		Iss: &jwtld.IDClaim{
			PK: rootPKBytes,
			CN: "spiffe://example.org/AS",
		},
	}

	// === 3) Attach SD root to payload (this will canonicalize leaves and set payload.Data to sd metadata) ===
	keys, leaves, err := jwtld.AttachSDRootToPayload(payload, claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// payload.Data agora contém apenas { "sd": { "alg":"sha256-merkle", "root":"<b64>" } }
	log.Println("[AS] SD root attached to payload")
	log.Println("[AS] Leaves order:", keys)
	log.Println("[AS] Leaves count:", len(leaves))
	log.Println("[AS] Payload after attach (Data metadata):", payload.Data)	

	// === 4) Create JWS signing the payload ===
	jws, err := jwtld.CreateJWS(payload, 1, rootSk)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// === 6) Response (compatible com a PoC/Host atual) ===
	resp := map[string]any{
		"jws":         jws,
		"keys":        keys,
		"leaves":      leaves,
		// "disclosures": []string{string(rootJSON)},
	}

	b, _ := json.MarshalIndent(resp, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

	log.Println("[AS] Token issued following test flow (AttachSDRootToPayload -> sign -> disclosure)")
	log.Println("[AS] Response contents:", resp)
}
