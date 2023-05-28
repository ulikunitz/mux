package mux

import "testing"

func TestParsePattern(t *testing.T) {
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
		p, err := parsePattern(tc.p)
		if tc.fail {
			if err == nil {
				t.Errorf("pattern %q didn't fail as expected",
					tc.p)
			}
			continue
		}
		if err != nil {
			t.Errorf("pattern %q: got error %s; want no error",
				tc.p, err)
			continue
		}
		t.Logf("pattern: %+v", *p)
	}
}
