package keeper

import "testing"

// A broken or catch-all panel rule must not take the node down or block it,
// nor take the valid alternatives next to it along.
func TestCompileRuleSkipsWhatBreaksTheNode(t *testing.T) {
	for _, catchAll := range []string{"", "  ", ".*", "^", "()", "a?", "foo|"} {
		if compileRule(catchAll) != nil {
			t.Errorf("kept %q, which matches every destination", catchAll)
		}
	}
	if compileRule("(unclosed") != nil || compileRule() != nil {
		t.Fatal("kept an invalid or missing pattern")
	}
	p := compileRule(`example\.com`, "", "(unclosed", ".*", `test\.org`)
	if p == nil || !p.MatchString("tcp:test.org:443") || !p.MatchString("tcp:example.com:443") {
		t.Fatal("a bad alternative took the valid ones along")
	}
	if p.MatchString("tcp:other.net:443") {
		t.Fatal("a catch-all alternative made the rule match everything")
	}
	// An alternative cannot reach into the next one.
	if p := compileRule(`\Qfoo`, `bar`); p == nil || !p.MatchString("tcp:bar:443") {
		t.Fatal(`an unterminated \Q swallowed the next alternative`)
	}
	if p := compileRule(`(?i)a\.com`, `B\.com`); p == nil || p.MatchString("tcp:b.com:443") {
		t.Fatal("a flag leaked into the next alternative")
	}
}
