package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const testUUID = "11111111-2222-3333-4444-555555555555"

func TestTemplateRender(t *testing.T) {
	const baseWithOutbound = `{
  "inbounds": [],
  "outbounds": [
    {
      "type": "trojan",
      "tag": "proxy",
      "password": "{{.UUID}}",
      "server_name": "{{.Name}}.example.com"
    }
  ]
}`

	tests := []struct {
		name        string
		base        string
		userName    string
		user        User
		mode        Mode
		wantContain []string
		wantAbsent  []string
		wantErr     string
	}{
		{
			name:     "replaces UUID and Name",
			base:     baseWithOutbound,
			userName: "alice",
			user:     User{UUID: testUUID},
			mode:     modeWith([]any{map[string]any{"type": "mixed", "tag": "mixed-in"}}, nil),
			wantContain: []string{
				`"password": "` + testUUID + `"`,
				`"server_name": "alice.example.com"`,
				`"tag": "mixed-in"`,
			},
			wantAbsent: []string{"{{", "<no value>"},
		},
		{
			name:        "nil inbounds renders empty array",
			base:        `{"inbounds": []}`,
			userName:    "alice",
			user:        User{UUID: testUUID},
			mode:        Mode{},
			wantContain: []string{`"inbounds": []`},
			wantAbsent:  []string{`"inbounds": null`},
		},
		{
			name:     "missing template key is an error",
			base:     `{"tag": "{{.Missing}}"}`,
			userName: "alice",
			user:     User{UUID: testUUID},
			mode:     Mode{},
			wantErr:  "template: execute",
		},
		{
			name:    "malformed template is an error",
			base:    `{"tag": "{{"}`,
			wantErr: "template: parse",
		},
		{
			name:    "rendered invalid JSON is an error",
			base:    `{"tag": }`,
			wantErr: "json: unmarshal",
		},
		{
			name:    "rendered null document is an error",
			base:    `null`,
			wantErr: "json: rendered template",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := Render([]byte(tt.base), tt.userName, tt.user, tt.mode)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Render() error = nil, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Render() error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			text := string(out)
			if !json.Valid(out) {
				t.Fatalf("Render() returned invalid JSON:\n%s", out)
			}
			if !bytes.HasSuffix(out, []byte("\n")) {
				t.Fatalf("Render() output does not end with a newline: %q", out)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(text, want) {
					t.Errorf("Render() output missing %q:\n%s", want, out)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(text, absent) {
					t.Errorf("Render() output contains %q:\n%s", absent, out)
				}
			}

			// Rendering is a pure function of its inputs, so the output must be
			// byte-for-byte stable across calls.
			second, err := Render([]byte(tt.base), tt.userName, tt.user, tt.mode)
			if err != nil {
				t.Fatalf("second Render() error = %v", err)
			}
			if !bytes.Equal(out, second) {
				t.Errorf("Render() is not deterministic:\nfirst:\n%s\nsecond:\n%s", out, second)
			}
		})
	}
}

func TestInsertHooks(t *testing.T) {
	tests := []struct {
		name      string
		doc       map[string]any
		hooks     map[string][]any
		wantRules string
		wantErr   string
	}{
		{
			name: "marker replaced by matching rules in order",
			doc: mustDoc(t, `{"route":{"rules":[
				{"type":"field","tag":"before"},
				{"$hook":"prefix"},
				{"type":"field","tag":"after"}
			]}}`),
			hooks: mustHooks(t, `{"prefix":[
				{"type":"field","tag":"prefix-1"},
				{"type":"field","tag":"prefix-2"}
			]}`),
			wantRules: `[{"tag":"before","type":"field"},{"tag":"prefix-1","type":"field"},{"tag":"prefix-2","type":"field"},{"tag":"after","type":"field"}]`,
		},
		{
			name:      "marker without hook removed",
			doc:       mustDoc(t, `{"route":{"rules":[{"tag":"before"},{"$hook":"unused"},{"tag":"after"}]}}`),
			hooks:     mustHooks(t, `{}`),
			wantRules: `[{"tag":"before"},{"tag":"after"}]`,
		},
		{
			name:      "multiple markers expanded in order",
			doc:       mustDoc(t, `{"route":{"rules":[{"$hook":"a"},{"tag":"keep"},{"$hook":"b"}]}}`),
			hooks:     mustHooks(t, `{"b":[{"tag":"b1"},{"tag":"b2"}],"a":[{"tag":"a1"}]}`),
			wantRules: `[{"tag":"a1"},{"tag":"keep"},{"tag":"b1"},{"tag":"b2"}]`,
		},
		{
			name:      "same marker repeated expands each time",
			doc:       mustDoc(t, `{"route":{"rules":[{"$hook":"prefix"},{"tag":"keep"},{"$hook":"prefix"}]}}`),
			hooks:     mustHooks(t, `{"prefix":[{"tag":"p1"}]}`),
			wantRules: `[{"tag":"p1"},{"tag":"keep"},{"tag":"p1"}]`,
		},
		{
			name:      "non-marker rules preserved",
			doc:       mustDoc(t, `{"route":{"rules":[{"tag":"one"},{"tag":"two"}]}}`),
			hooks:     mustHooks(t, `{}`),
			wantRules: `[{"tag":"one"},{"tag":"two"}]`,
		},
		{
			name:    "unused mode hook is an error",
			doc:     mustDoc(t, `{"route":{"rules":[{"$hook":"prefix"}]}}`),
			hooks:   mustHooks(t, `{"typo":[{"tag":"x"}]}`),
			wantErr: `hook "typo"`,
		},
		{
			name:    "mode hook against missing route is an error",
			doc:     mustDoc(t, `{"inbounds":[]}`),
			hooks:   mustHooks(t, `{"prefix":[{"tag":"x"}]}`),
			wantErr: `hook "prefix"`,
		},
		{
			name:    "non-string $hook is an error",
			doc:     mustDoc(t, `{"route":{"rules":[{"$hook":42}]}}`),
			hooks:   mustHooks(t, `{}`),
			wantErr: "$hook",
		},
		{
			name:    "non-array route.rules is an error",
			doc:     mustDoc(t, `{"route":{"rules":{}}}`),
			hooks:   mustHooks(t, `{}`),
			wantErr: "route.rules",
		},
		{
			name:    "non-object rule element is an error",
			doc:     mustDoc(t, `{"route":{"rules":[42]}}`),
			hooks:   mustHooks(t, `{}`),
			wantErr: "route.rules[0]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := insertHooks(tt.doc, tt.hooks)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("insertHooks() error = nil, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("insertHooks() error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("insertHooks() error = %v", err)
			}

			route, ok := tt.doc["route"].(map[string]any)
			if !ok {
				t.Fatalf("route is not an object: %#v", tt.doc["route"])
			}
			got, err := json.Marshal(route["rules"])
			if err != nil {
				t.Fatalf("marshal resulting rules: %v", err)
			}
			if string(got) != tt.wantRules {
				t.Errorf("resulting rules = %s, want %s", got, tt.wantRules)
			}
		})
	}
}

// TestRenderTproxyRemovesMarker covers the tproxy mode shape: the base
// template contains a $hook marker, but the mode supplies no route rules, so
// the marker must be dropped and no $hook may survive into the output.
func TestRenderTproxyRemovesMarker(t *testing.T) {
	base := []byte(`{
  "inbounds": [],
  "route": {
    "rules": [
      {"type": "field", "tag": "keep"},
      {"$hook": "prefix"}
    ]
  }
}`)

	var mode Mode
	mode.Inbounds = []any{map[string]any{"type": "tproxy", "tag": "tproxy-in"}}

	out, err := Render(base, "general", User{UUID: testUUID}, mode)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("Render() returned invalid JSON:\n%s", out)
	}
	text := string(out)
	if strings.Contains(text, "$hook") {
		t.Errorf("Render() left a $hook marker in the output:\n%s", out)
	}
	if !strings.Contains(text, `"tag": "keep"`) {
		t.Errorf("Render() dropped a non-marker rule:\n%s", out)
	}
	if !strings.Contains(text, `"tag": "tproxy-in"`) {
		t.Errorf("Render() did not install the mode inbounds:\n%s", out)
	}
}

func TestRenderExpandsHooks(t *testing.T) {
	base := []byte(`{
  "inbounds": [],
  "route": {
    "rules": [
      {"type": "field", "tag": "before"},
      {"$hook": "prefix"},
      {"type": "field", "tag": "after"}
    ]
  }
}`)

	mode := modeWith(
		[]any{map[string]any{"type": "mixed", "tag": "mixed-in"}},
		map[string][]any{
			"prefix": {
				map[string]any{"type": "field", "tag": "prefix-1"},
				map[string]any{"type": "field", "tag": "prefix-2"},
			},
		},
	)

	out, err := Render(base, "alice", User{UUID: testUUID}, mode)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	text := string(out)
	if strings.Contains(text, "$hook") {
		t.Errorf("Render() left a $hook marker in the output:\n%s", out)
	}

	var doc struct {
		Route struct {
			Rules []struct {
				Tag string `json:"tag"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal rendered output: %v", err)
	}

	var got []string
	for _, rule := range doc.Route.Rules {
		got = append(got, rule.Tag)
	}
	want := []string{"before", "prefix-1", "prefix-2", "after"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("rule tags = %v, want %v", got, want)
	}
}

func modeWith(inbounds []any, rules map[string][]any) Mode {
	var m Mode
	m.Inbounds = inbounds
	m.Route.Rules = rules
	return m
}

func mustDoc(t *testing.T, src string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("unmarshal doc fixture: %v", err)
	}
	return doc
}

func mustHooks(t *testing.T, src string) map[string][]any {
	t.Helper()
	hooks := map[string][]any{}
	if err := json.Unmarshal([]byte(src), &hooks); err != nil {
		t.Fatalf("unmarshal hooks fixture: %v", err)
	}
	return hooks
}
