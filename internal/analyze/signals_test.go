package analyze

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Every Signal{ID: ...} in this package's code must be in SignalIDs, or its
// metric series would not be pre-created (and its first firing would be
// invisible to increase() in Grafana).
func TestSignalIDsIsComplete(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	emitted := map[string]bool{}
	for _, pkg := range pkgs {
		ast.Inspect(pkg, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "ID" {
				return true
			}
			switch v := kv.Value.(type) {
			case *ast.BasicLit: // ID: "dmarc_fail"
				s, _ := strconv.Unquote(v.Value)
				emitted[s] = true
			case *ast.BinaryExpr: // ID: "lookalike_" + where, where is "sender" or "link"
				prefix, _ := strconv.Unquote(v.X.(*ast.BasicLit).Value)
				emitted[prefix+"sender"], emitted[prefix+"link"] = true, true
			default:
				t.Errorf("%s: signal ID is not a literal; extend this test", fset.Position(kv.Pos()))
			}
			return true
		})
	}
	if len(emitted) < 20 {
		t.Fatalf("found only %d IDs; the parser walk is broken", len(emitted))
	}
	for id := range emitted {
		if !slices.Contains(SignalIDs, id) {
			t.Errorf("signal %q is emitted but missing from SignalIDs", id)
		}
	}
	for _, id := range SignalIDs {
		if !emitted[id] {
			t.Errorf("SignalIDs lists %q, which no code emits", id)
		}
	}
}
