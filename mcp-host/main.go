package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"

	sd "github.com/marques-ma/merkle-selective-disclosure"
	jwtld "github.com/marques-ma/jwt-ld"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	asURL      = "http://localhost:8080/issueToken"
	server1URL = "http://localhost:8081"
)

func main() {
	ctx := context.Background()

	// 1️⃣ Solicita token ao AS
	perms := []string{"repo.read", "repo.write", "pr.open"}
	tokenResp, err := requestTokenFromAS(perms)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[Host] Token from AS:", tokenResp.JWS)

	// 2️⃣ Cria disclosure seletiva do Host (ex.: só "repo.write")
	log.Println("[Host] Creating selective disclosure for 'repo.write'")
	idx := indexOf(tokenResp.Keys, "repo.write")
	if idx < 0 {
		log.Fatal("[Host] repo.write not found in AS token leaves")
	}

	hostDisc, err := sd.CreateDisclosure(tokenResp.Leaves, []int{idx})
	if err != nil {
		log.Fatal(err)
	}
	hostDiscJSON, _ := hostDisc.ToJSON()

	// 3️⃣ Conecta MCP ao Server1
	client := mcp.NewClient(&mcp.Implementation{Name: "server1"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: server1URL}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	// 4️⃣ Envia token + disclosure ao Server1
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "process",
		Arguments: map[string]any{
			"token":      tokenResp.JWS,
			"disclosure": string(hostDiscJSON),
			"leaves":     tokenResp.Leaves,
		},
	})
	if err != nil {
		log.Fatal("[Host] Failed to call Server1:", err)
	}

	// 5️⃣ Parse da resposta do Server1
	var server1Resp struct {
		ExtendedToken   string `json:"extended_token"`
		Server2Response string `json:"server2_response"`
		Server2Error    string `json:"server2_error,omitempty"`
		Server1Disc     string `json:"server1_disclosure"`
	}

	if len(result.Content) == 0 {
		log.Fatal("[Host] Empty response from Server1")
	}

	// Converte o resultado MCP para JSON
	rawJSON := make(map[string]string)
	for _, c := range result.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			if err := json.Unmarshal([]byte(t.Text), &rawJSON); err == nil {
				break
			}
		}
	}

	server1Resp.ExtendedToken = rawJSON["extended_token"]
	server1Resp.Server2Response = rawJSON["server2_response"]
	server1Resp.Server2Error = rawJSON["server2_error"]
	server1Resp.Server1Disc = rawJSON["server1_disclosure"]

	if server1Resp.ExtendedToken == "" {
		log.Fatal("[Host] Missing extended token from Server1")
	}

	log.Println("[Host] Server2 response:", server1Resp.Server2Response)
	log.Println("[Host] Extended token:", server1Resp.ExtendedToken)

	// 6️⃣ Se Server2 falhou, reporta erro
	if server1Resp.Server2Error != "" {
		log.Fatal("[Host] Server2 failed:", server1Resp.Server2Error)
	}

	// 7️⃣ Valida token + disclosures localmente
	disclosureMap := map[int]*sd.Disclosure{
		0: hostDisc,
		1: mustSDFromJSON(server1Resp.Server1Disc),
	}

	ok, err := jwtld.ValidateJWSWithPresentations(server1Resp.ExtendedToken, 1, disclosureMap)
	if err != nil || !ok {
		log.Fatal("[Host] ❌ Validation failed:", err)
	}

	log.Println("[Host] ✔ Token and semantic disclosures validated locally")
}

// ---------------- Helpers ----------------

type ASTokenResponse struct {
	JWS         string
	Keys        []string
	Leaves      [][]byte
	Disclosures []string
}

func requestTokenFromAS(perms []string) (*ASTokenResponse, error) {
	b, _ := json.Marshal(map[string]interface{}{"permissions": perms})
	resp, err := http.Post(asURL, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		JWS         string   `json:"jws"`
		Keys        []string `json:"keys"`
		Leaves      [][]byte `json:"leaves"`
		Disclosures []string `json:"disclosures"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &ASTokenResponse{
		JWS:         data.JWS,
		Keys:        data.Keys,
		Leaves:      data.Leaves,
		Disclosures: data.Disclosures,
	}, nil
}

func indexOf(keys []string, target string) int {
	for i, k := range keys {
		if k == target {
			return i
		}
	}
	return -1
}

func mustSDFromJSON(s string) *sd.Disclosure {
	d, err := sd.FromJSON([]byte(s))
	if err != nil {
		log.Fatal(err)
	}
	return d
}
