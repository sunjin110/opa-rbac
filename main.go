package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

func main() {
	fmt.Println("=== Open Policy Agent Role-based access control example ===")

	ctx := context.Background()

	policyRegoPath := "./policy/rbac.rego"

	// create rego object
	r := rego.New(
		rego.Query("data.rbac.authz.allow"),
		rego.Load([]string{policyRegoPath}, nil),
	)

	// prepare
	query, err := r.PrepareForEval(ctx)
	chkSE(err)

	// このユーザーがdatabase456にreadする権限があるかどうか？を検証したい
	inputStr := `
		{
			"user": "bob",
			"action": "read",
			"object": "database456"
		}
	`
	var input interface{}
	jsonUnmarshal(inputStr, &input)

	// execute query
	rs, err := query.Eval(ctx, rego.EvalInput(input))
	chkSE(err)

	fmt.Println("res is ", jsonMarshal(rs))
	fmt.Println("allowed ", rs.Allowed())
}

func jsonMarshal(obj interface{}) string {

	b, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func jsonUnmarshal(str string, obj interface{}) {

	err := json.Unmarshal([]byte(str), obj)
	if err != nil {
		panic(err)
	}
}

// chkSE
func chkSE(err error) {
	if err != nil {
		panic(err)
	}
}
