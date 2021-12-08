package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

func main() {
	fmt.Println("=== Open Policy Agent Role-based access control example ===")

	// 普通に実装
	fmt.Println("=== pattern 1 ===")
	pattern1()

	// データを動的に入れるパターン
	fmt.Println("=== pattern 2 ===")
	pattern2()
}

// 基本の使い方
func pattern1() {
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

// 色々動的に入れているもの
func pattern2() {

	ctx := context.Background()

	// regoのpolicy moduleも動的に追加可能
	module := `
package rbac.authz

# logic that implements RBAC
default allow = false
allow {
    # lookup the list of roles for the user
    # ユーザーの役割リストを検索
    roles := data.user_roles[input.user]

    # for each role in that list
    # 役割ごとに検証
    r := roles[_]

    # 格roleのpermissionを調べる
    permissions := data.role_permissions[r]

    # permissionごとにチェック
    p := permissions[_]

    # 権限のcheck
    p == {"action": input.action, "object": input.object}
}
`

	compiler, err := ast.CompileModules(map[string]string{
		"rbac.rego": module,
	})
	chkSE(err)

	// データを動的に入れることができる

	// ここのデータを、できるだけ減らす必要がある
	// なぜなら、
	data := `{
		"user_roles": {
				 "sunjin": ["engineering", "serverdev"],
				 "bob": ["hr"],
				 "alice": ["enginnering", "webdev"]
		},
		"role_permissions": {
			 "engineering": [ 
				 {"action": "read", "object": "server123"}
			 ],
			 "webdev": [
				 {"action": "read", "object": "server123"},
				 {"action": "write", "object": "server123"}
			 ],
			 "hr": [
				 {"action": "read", "object": "database456"}
			 ]
		}
	}`

	var json map[string]interface{}

	err = util.UnmarshalJSON([]byte(data), &json)
	chkSE(err)

	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.NewFromObject(json)

	// Create new query that returns the value
	r := rego.New(
		rego.Query("data.rbac.authz.allow"),
		rego.Compiler(compiler),
		rego.Store(store), // ここのstoreが、inmemoryまたは、storageなのでこのデータが増えすぎるとだめ
		rego.Input(
			map[string]interface{}{
				"user":   "bob",
				"action": "read",
				"object": "database456",
			},
		),
	)

	// Run evaluation.
	rs, err := r.Eval(ctx)
	chkSE(err)

	// Inspect the result.
	fmt.Println("rs is ", jsonMarshal(rs))
	fmt.Println("alloed:", rs.Allowed())
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
