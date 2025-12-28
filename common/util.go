package common

import (
	"encoding/json"
	"fmt"

	sd "github.com/marques-ma/merkle-selective-disclosure"
	jwtld "github.com/marques-ma/graphtoken"
)

func Pretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func DisclosureForKey(data map[string]interface{}, key string) (*sd.Disclosure, error) {
	keys, leaves, err := jwtld.DataToLeaves(data)
	if err != nil {
		return nil, err
	}
	for i, k := range keys {
		if k == key {
			return sd.CreateDisclosure(leaves, []int{i})
		}
	}
	return nil, fmt.Errorf("key %s not found", key)
}
