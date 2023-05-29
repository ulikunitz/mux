package mux

import (
	"net/http"
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
		{p: "POST alt.com/item/{user}"},
		{p: "/{foo", fail: true},
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
