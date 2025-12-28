package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	jwtld "github.com/marques-ma/jwt-ld"
	sd "github.com/marques-ma/merkle-selective-disclosure"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const server2URL = "http://localhost:8082/execute"

func main() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "server1",
		Version: "1.0.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "process",
		Description: "Validate AS disclosure, extend token, send to Server2",
	}, func(ctx context.Context, req *mcp.CallToolRequest, rawArgs map[string]any) (*mcp.CallToolResult, any, error) {
		var args struct {
			Token      string `json:"token"`
			Disclosure string `json:"disclosure"`
		}
		b, _ := json.Marshal(rawArgs)
		if err := json.Unmarshal(b, &args); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: failed to parse arguments: " + err.Error()}},
			}, nil, nil
		}

		return processTool(ctx, args.Token, args.Disclosure)
	})

	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	log.Println("[Server1] Listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
}

// ---------------- Core Tool ----------------

func processTool(ctx context.Context, token string, disclosure string) (*mcp.CallToolResult, any, error) {
	log.Println("[Server1] Received token + AS disclosure")

	// Parse AS disclosure
	asDisc, err := sd.FromJSON([]byte(disclosure))
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: AS disclosure parse error: " + err.Error()}},
		}, nil, nil
	}

	// Validate token with AS disclosure
	ok, err := jwtld.ValidateJWSWithPresentations(token, 1, map[int]*sd.Disclosure{0: asDisc})
	if err != nil || !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: token validation failed: " + err.Error()}},
		}, nil, nil
	}
	log.Println("[Server1] ✔ Token validated with AS disclosure")

	// --- Create node for Server1 ---
	rootPayload := &jwtld.Payload{
		Ver: 1,
		Iat: time.Now().Unix(),
		Iss: &jwtld.IDClaim{CN: "spiffe://example.org/server1"},
	}
	nodeClaims := map[string]interface{}{
		"service": "server1",
		"allow":   true,
	}
	_, leaves, err := jwtld.AttachSDRootToPayload(rootPayload, nodeClaims)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: attach SD root failed: " + err.Error()}},
		}, nil, nil
	}

	// Create disclosure for Server1 node (all claims)
	nodeDisc, _ := sd.CreateDisclosure(leaves, nil)
	nodeDiscJSON, _ := nodeDisc.ToJSON()
	nodeDiscStr := string(nodeDiscJSON)

	// Extend token
	node := &jwtld.LDNode{Payload: rootPayload}
	extendedToken, err := jwtld.ExtendJWS(token, node, 1)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: extend JWS failed: " + err.Error()}},
		}, nil, nil
	}
	log.Println("[Server1] Extended token created")

	// --- Send to Server2 and wait for response ---
	reqBody := map[string]any{
		"token":       extendedToken,
		"disclosures": []string{disclosure, nodeDiscStr},
	}
	b, _ := json.Marshal(reqBody)

	resp, err := http.Post(server2URL, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Println("[Server1] ❌ Post to Server2 failed:", err)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: Server2 call failed: " + err.Error()}},
		}, nil, nil
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Println("[Server1] ❌ Server2 returned error:", string(respBody))
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: Server2 response: " + string(respBody)}},
		}, nil, nil
	}

	log.Println("[Server1] ✔ Server2 execution succeeded")

	// --- Retorna token estendido + resposta do Server2 ---
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(jsonMustMarshal(map[string]string{
				"extended_token":     extendedToken,
				"server1_disclosure": nodeDiscStr,        // disclosure do Server1 incluído
				"server2_response":   string(respBody),   // resposta do Server2
			}))},
		},
	}, nil, nil
}

// jsonMustMarshal ignora erro de Marshal
func jsonMustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
