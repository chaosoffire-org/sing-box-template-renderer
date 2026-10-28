// Package render turns a shared sing-box base template into a per-user,
// per-mode client configuration.
//
// Rendering happens in two stages: text/template substitutes the user-specific
// values ({{.UUID}}, {{.Name}}) into the base template, then encoding/json
// parses the result so that mode-specific fragments can be merged in and the
// document can be emitted deterministically.
package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"text/template"
)

// User is a single client identity read from users/<name>.json.
//
// Template selects templates/<template>.json.tmpl and defaults to "base" when
// empty. Modes lists the modes the user may request and defaults to ["tun"]
// when empty. Default names the mode used when the request omits one and
// defaults to Modes[0] when empty; it must be one of Modes.
type User struct {
	Template string   `json:"template"`
	UUID     string   `json:"uuid"`
	Modes    []string `json:"modes"`
	Default  string   `json:"default"`
}

// Mode describes the parts of a rendered configuration that vary by inbound
// mode: the inbound list and the rule sets that replace $hook markers in the
// template's top-level route.rules array.
type Mode struct {
	Inbounds []any `json:"inbounds"`
	Route    struct {
		Rules map[string][]any `json:"rules"`
	} `json:"route"`
}

// Render substitutes the user's identity into baseTmpl, installs the mode's
// inbounds, expands the mode's $hook markers in the top-level route.rules
// array, and returns a normalized, indented JSON document with a trailing
// newline.
//
// The template is parsed with missingkey=error so a template that references a
// value the renderer does not provide fails loudly instead of emitting
// "<no value>" into the config. UUIDs are expected to sit inside quoted JSON
// strings, so no JSON escaping is applied by the template stage.
func Render(baseTmpl []byte, name string, user User, mode Mode) ([]byte, error) {
	tmpl, err := template.New("base").Option("missingkey=error").Parse(string(baseTmpl))
	if err != nil {
		return nil, fmt.Errorf("template: parse: %w", err)
	}

	data := map[string]any{
		"UUID": user.UUID,
		"Name": name,
	}

	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, data); err != nil {
		return nil, fmt.Errorf("template: execute: %w", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("json: unmarshal rendered template: %w", err)
	}
	if doc == nil {
		// json.Unmarshal accepts a literal null without error, but a config
		// document must be an object before we can install inbounds on it.
		return nil, fmt.Errorf("json: rendered template: expected object, got null")
	}

	inbounds := mode.Inbounds
	if inbounds == nil {
		inbounds = []any{}
	}
	doc["inbounds"] = inbounds

	if err := insertHooks(doc, mode.Route.Rules); err != nil {
		return nil, err
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("json: marshal result: %w", err)
	}
	out = append(out, '\n')
	if !json.Valid(out) {
		return nil, fmt.Errorf("json: marshal result is not valid JSON")
	}

	return out, nil
}

// insertHooks expands $hook marker objects in doc's top-level route.rules
// array. A marker whose hook name is present in hooks is replaced in place by
// every rule in that hook's slice, preserving both marker and rule order. A
// marker whose hook name is absent is removed. Nested route.rules arrays are
// left untouched.
//
// A hook supplied by the mode that no marker consumes is an error, as are
// non-array route.rules, non-object rule elements, and non-string $hook values.
func insertHooks(doc map[string]any, hooks map[string][]any) error {
	routeValue, hasRoute := doc["route"]
	var route map[string]any
	if hasRoute {
		var ok bool
		route, ok = routeValue.(map[string]any)
		if !ok {
			return fmt.Errorf("json: route: expected object, got %T", routeValue)
		}
	}

	var (
		rules    []any
		hasRules bool
	)
	if route != nil {
		var rulesValue any
		rulesValue, hasRules = route["rules"]
		if hasRules {
			var ok bool
			rules, ok = rulesValue.([]any)
			if !ok {
				return fmt.Errorf("json: route.rules: expected array, got %T", rulesValue)
			}
		}
	}

	used := make(map[string]bool, len(hooks))
	expanded := make([]any, 0, len(rules))
	for i, elem := range rules {
		obj, ok := elem.(map[string]any)
		if !ok {
			return fmt.Errorf("json: route.rules[%d]: expected object, got %T", i, elem)
		}

		hookValue, isMarker := obj["$hook"]
		if !isMarker {
			expanded = append(expanded, elem)
			continue
		}

		hookName, ok := hookValue.(string)
		if !ok {
			return fmt.Errorf("json: route.rules[%d]: $hook: expected string, got %T", i, hookValue)
		}

		inserted, exists := hooks[hookName]
		if !exists {
			// The template offers a slot this mode does not fill: drop it.
			continue
		}

		used[hookName] = true
		expanded = append(expanded, inserted...)
	}

	// Every hook a mode declares must be consumed by a marker; otherwise the
	// mode is silently doing nothing, which is almost certainly a typo.
	var unused []string
	for hookName := range hooks {
		if !used[hookName] {
			unused = append(unused, hookName)
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		return fmt.Errorf("hook %q: no $hook marker found in template route.rules", unused[0])
	}

	if hasRules {
		route["rules"] = expanded
	}

	return nil
}
