package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	jwtld "github.com/marques-ma/graphtoken"
	sd "github.com/marques-ma/merkle-selective-disclosure"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "server3-final"}, nil)

	mcp.AddTool(server, &mcp.Tool{Name: "finalize"}, finalize)

	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return server
	}, nil)

	http.ListenAndServe(":8083", handler)
}

func finalize(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
	jws := req.Arguments["token"].(string)

	var rootDisc sd.Disclosure
	json.Unmarshal([]byte(req.Arguments["disc"].(string)), &rootDisc)

	ok, err := jwtld.ValidateJWSWithPresentations(jws, 1, map[int]*sd.Disclosure{
		0: &rootDisc,
	})
	if err != nil || !ok {
		return nil, struct{}{}, err
	}

	if string(rootDisc.Leaves[0]) != "true" {
		return nil, struct{}{}, errors.New("pr.open denied")
	}

	log.Println("✔ Flow completed successfully")

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "PROCESS COMPLETED"},
		},
	}, struct{}{}, nil
}
