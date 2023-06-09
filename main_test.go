package mux

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestHandle(t *testing.T) {

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	tests := []struct {
		p    string
		fail bool
	}{
		{p: "GET /foo"},
		{p: "POST /foo"},
		{p: "/b/{bucket}/o/{objectname...}"},
		{p: "/b/{bucket}/a/{acl}"},
		{p: "/b/{bucket}/{verb}/{noun}"},
		{p: "/b/o/{bucket}/{objectname...}"},
		{p: "/item/"},
		{p: "POST /item/{user}"},
		{p: "/item/{$}"},
		{p: "POST example.com/item/{user}"},
		{p: "/{foo", fail: true},
		{p: "POS example.com/foo", fail: true},
		{p: "PATCH /foo/{id}"},
	}
	for _, tc := range tests {
		var mux Mux
		var r any
		func() {
			defer func() {
				r = recover()
			}()
			mux.Handle(tc.p, h)
		}()
		if tc.fail {
			if r == nil {
				t.Errorf("%q: no panic; expected it", tc.p)
			}
			continue
		}
		if r != nil {
			t.Errorf("%q: got panic %v; expected none", tc.p, r)
			continue
		}
	}
}

func TestNewRegexpSet(t *testing.T) {
	/* r := */ newRegexpSet()
	/*
		t.Logf("method: %s", r.method)
		t.Logf("host: %s", r.host)
		t.Logf("segment: %s", r.segment)
	*/
}

func TestUnique(t *testing.T) {
	tests := []struct {
		in  []string
		out []string
	}{
		{
			in:  []string{"b", "a", "b", "a"},
			out: []string{"a", "b"},
		},
		{
			in:  []string{"b", "c", "a", "c"},
			out: []string{"a", "b", "c"},
		},
		{
			in:  []string{"b", "c", "a"},
			out: []string{"a", "b", "c"},
		},
	}
	for i, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("tc=%d", i+1), func(t *testing.T) {
			got := unique(tc.in)
			if !reflect.DeepEqual(got, tc.out) {
				t.Errorf("removeRedundant(%q): got %q; want %q",
					tc.in, got, tc.out)
				return
			}
		})
	}

}
