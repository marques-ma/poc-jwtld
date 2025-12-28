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
		Description: "Validate AS presentation, extend token, send to Server2",
	}, func(ctx context.Context, req *mcp.CallToolRequest, rawArgs map[string]any) (*mcp.CallToolResult, any, error) {
		var args struct {
			Token         string   `json:"token"`
			Presentations []string `json:"presentations"` // array aligned by node index
		}
		b, _ := json.Marshal(rawArgs)
		if err := json.Unmarshal(b, &args); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: failed to parse arguments: " + err.Error()}}}, nil, nil
		}
		return processTool(ctx, args.Token, args.Presentations)
	})

	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	log.Println("[Server1] Listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
}

func processTool(ctx context.Context, token string, presentations []string) (*mcp.CallToolResult, any, error) {
	log.Println("[Server1] Received token + Host presentation")

	// 1️⃣ Build presentations map[int]*sd.Disclosure from incoming array
	presMap := map[int]*sd.Disclosure{}
	for i, pStr := range presentations {
		d, err := sd.FromJSON([]byte(pStr))
		if err != nil {
			log.Printf("[Server1] ❌ Failed to parse presentation %d: %v\n", i, err)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: invalid presentation: " + err.Error()}}}, nil, nil
		}
		presMap[i] = d
	}

	// 2️⃣ Validate token with provided presentations
	ok, err := jwtld.ValidateJWSWithPresentations(token, 1, presMap)
	if err != nil || !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: token validation failed: " + err.Error()}}}, nil, nil
	}
	log.Println("[Server1] ✔ Token validated with provided presentations")

	// 3️⃣ Create Server1 node and attach SD root
	server1Payload := &jwtld.Payload{
		Ver: 1,
		Iat: time.Now().Unix(),
		Iss: &jwtld.IDClaim{CN: "spiffe://example.org/server1"},
	}
	server1Claims := map[string]interface{}{
		"execute": true,
		"pull":    true,
	}
	_, _, err = jwtld.AttachSDRootToPayload(server1Payload, server1Claims)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: attach SD root failed: " + err.Error()}}}, nil, nil
	}

	// 4️⃣ Create disclosure for Server1 node
	selectedKeys := []string{"execute", "pull"}
	nodeDisc, err := jwtld.CreatePresentationFromData(server1Claims, selectedKeys)
	if err != nil {
		log.Fatal(err)
	}
	nodeDiscJSON, _ := json.Marshal(nodeDisc)

	// 5️⃣ Extend token with new node
	node := &jwtld.LDNode{Payload: server1Payload}
	extendedToken, err := jwtld.ExtendJWS(token, node, 1)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: extend JWS failed: " + err.Error()}}}, nil, nil
	}
	log.Println("[Server1] Extended token created")

	// 6️⃣ Send to Server2
	reqBody := map[string]*sd.Disclosure{
		"0": presMap[0],
		"1": nodeDisc,
	}
	b, _ := json.Marshal(map[string]interface{}{
		"token":         extendedToken,
		"presentations": reqBody,
	})

	resp, err := http.Post(server2URL, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Println("[Server1] ❌ Post to Server2 failed:", err)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: Server2 call failed: " + err.Error()}}}, nil, nil
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Println("[Server1] ❌ Server2 returned error:", string(respBody))
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: Server2 response: " + string(respBody)}}}, nil, nil
	}

	log.Println("[Server1] ✔ Server2 execution succeeded")

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: string(jsonMustMarshal(map[string]string{
					"extended_token":     extendedToken,
					"server1_disclosure": string(nodeDiscJSON),
					"server2_response":   string(respBody),
				})),
			},
		},
	}, nil, nil
}

func jsonMustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
