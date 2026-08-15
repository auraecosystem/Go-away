package lib

import (
	http_cel "codeberg.org/gone/http-cel"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"log/slog"
	"net"
)

func (state *State) initConditions() (err error) {
	state.programEnv, err = http_cel.NewEnvironment(

		cel.Variable("fp", cel.MapType(cel.StringType, cel.StringType)),
		cel.Function("inDNSBL",
			cel.Overload("inDNSBL_ip",
				[]*cel.Type{cel.AnyType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					slog.Error("inDNSBL function has been deprecated, replace with dnsbl challenge")
					return types.Bool(false)
				}),
			),
		),

		cel.Function("asn",
			cel.MemberOverload("netIP_asn",
				[]*cel.Type{cel.BytesType},
				cel.IntType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					var ip net.IP
					switch v := val.Value().(type) {
					case []byte:
						ip = v
					case net.IP:
						ip = v
					}
					if ip == nil {
						panic(fmt.Errorf("invalid ip %v", val.Value()))
					}
					if state.maxMindDB == nil {
						panic("asn() called but MaxMind database not configured")
					}
					asn, err := state.maxMindDB.GetASN(ip)
					if err != nil {
						slog.Debug("maxmind ASN lookup failed", "remoteAddress", ip.String(), "error", err)
						panic(err)
					}
					slog.Debug("maxmind ASN lookup", "remoteAddress", ip.String(), "asn", asn)
					return types.Int(asn)
				}),
			),
		),

		cel.Function("network",
			cel.MemberOverload("netIP_network_string",
				[]*cel.Type{cel.BytesType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					var ip net.IP
					switch v := lhs.Value().(type) {
					case []byte:
						ip = v
					case net.IP:
						ip = v
					}

					if ip == nil {
						panic(fmt.Errorf("invalid ip %v", lhs.Value()))
					}

					val, ok := rhs.Value().(string)
					if !ok {
						panic(fmt.Errorf("invalid network value %v", rhs.Value()))
					}

					network, ok := state.networks[val]
					if !ok {
						_, ipNet, err := net.ParseCIDR(val)
						if err != nil {
							panic("network not found")
						}
						return types.Bool(ipNet.Contains(ip))
					} else {
						ok, err := network().Contains(ip)
						if err != nil {
							panic(err)
						}
						return types.Bool(ok)
					}
				}),
			),
		),

		cel.Function("inNetwork",
			cel.Overload("inNetwork_string_ip",
				[]*cel.Type{cel.StringType, cel.BytesType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					var ip net.IP
					switch v := rhs.Value().(type) {
					case []byte:
						ip = v
					case net.IP:
						ip = v
					}

					if ip == nil {
						panic(fmt.Errorf("invalid ip %v", rhs.Value()))
					}

					val, ok := lhs.Value().(string)
					if !ok {
						panic(fmt.Errorf("invalid value %v", lhs.Value()))
					}
					slog.Debug(fmt.Sprintf("inNetwork function has been deprecated and will be removed in a future release, use remoteAddress.network(\"%s\") instead", val))

					network, ok := state.networks[val]
					if !ok {
						_, ipNet, err := net.ParseCIDR(val)
						if err != nil {
							panic("network not found")
						}
						return types.Bool(ipNet.Contains(ip))
					} else {
						ok, err := network().Contains(ip)
						if err != nil {
							panic(err)
						}
						return types.Bool(ok)
					}
				}),
			),
		),
	)
	if err != nil {
		return err
	}
	return nil
}

func (state *State) RegisterCondition(operator string, conditions ...string) (cel.Program, error) {
	compiledAst, err := http_cel.NewAst(state.ProgramEnv(), operator, conditions...)
	if err != nil {
		return nil, err
	}

	if out := compiledAst.OutputType(); out == nil {
		return nil, fmt.Errorf("no output")
	} else if out != types.BoolType {
		return nil, fmt.Errorf("output type is not bool")
	}

	var asnErr error
	walkExpr(compiledAst.NativeRep().Expr(), func(e ast.Expr) {
		if e.Kind() == ast.CallKind {
			call := e.AsCall()
			switch call.FunctionName() {
			case "asn":
				if call.IsMemberFunction() && len(call.Args()) == 0 && state.maxMindDB == nil {
					asnErr = fmt.Errorf("condition uses asn() but no MaxMind database is configured")
				}
			// deprecated
			case "inNetwork":
				args := call.Args()
				if !call.IsMemberFunction() && len(args) == 2 {
					// we have a network select function
					switch args[1].Kind() {
					case ast.LiteralKind:
						lit := args[1].AsLiteral()
						if lit.Type() == types.StringType {
							if fn, ok := state.networks[lit.Value().(string)]; ok {
								// preload
								fn()
							}
						}
					}

				}
			case "network":
				args := call.Args()
				if call.IsMemberFunction() && len(args) == 1 {
					// we have a network select function
					switch args[0].Kind() {
					case ast.LiteralKind:
						lit := args[0].AsLiteral()
						if lit.Type() == types.StringType {
							if fn, ok := state.networks[lit.Value().(string)]; ok {
								// preload
								fn()
							}
						}
					}

				}
			}
		}
	})

	if asnErr != nil {
		return nil, asnErr
	}

	return http_cel.ProgramAst(state.ProgramEnv(), compiledAst)
}

func walkExpr(e ast.Expr, fn func(ast.Expr)) {
	fn(e)

	switch e.Kind() {
	case ast.CallKind:
		ee := e.AsCall()
		walkExpr(ee.Target(), fn)
		for _, arg := range ee.Args() {
			walkExpr(arg, fn)
		}
	case ast.ComprehensionKind:
		ee := e.AsComprehension()
		walkExpr(ee.Result(), fn)
		walkExpr(ee.IterRange(), fn)
		walkExpr(ee.AccuInit(), fn)
		walkExpr(ee.LoopCondition(), fn)
		walkExpr(ee.LoopStep(), fn)
	case ast.ListKind:
		ee := e.AsList()
		for _, element := range ee.Elements() {
			walkExpr(element, fn)
		}
	case ast.MapKind:
		ee := e.AsMap()
		for _, entry := range ee.Entries() {
			switch entry.Kind() {
			case ast.MapEntryKind:
				eee := entry.AsMapEntry()
				walkExpr(eee.Key(), fn)
				walkExpr(eee.Value(), fn)
			case ast.StructFieldKind:
				eee := entry.AsStructField()
				walkExpr(eee.Value(), fn)
			}
		}
	case ast.SelectKind:
		ee := e.AsSelect()
		walkExpr(ee.Operand(), fn)
	case ast.StructKind:
		ee := e.AsStruct()
		for _, field := range ee.Fields() {
			switch field.Kind() {
			case ast.MapEntryKind:
				eee := field.AsMapEntry()
				walkExpr(eee.Key(), fn)
				walkExpr(eee.Value(), fn)
			case ast.StructFieldKind:
				eee := field.AsStructField()
				walkExpr(eee.Value(), fn)
			}
		}
	}
}
