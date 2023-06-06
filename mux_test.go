package mux_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/ulikunitz/mux"
)

type output struct {
	Host      string
	Method    string
	Path      string
	HandlerID string
	VarMap    map[string]string
}

func tcHandler(id string) http.Handler {
	h := func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Type", "application/json")
		out := output{
			Host:      r.Host,
			Method:    r.Method,
			Path:      r.URL.Path,
			VarMap:    mux.Vars(r),
			HandlerID: id,
		}
		data, err := json.MarshalIndent(&out, "", "  ")
		if err != nil {
			http.Error(w, fmt.Sprintf("error %s", err),
				http.StatusInternalServerError)
			return
		}

		_, err = w.Write(data)
		if err != nil {
			panic(fmt.Errorf("w.Write(data) error %s", err))

		}
	}
	return http.HandlerFunc(h)
}

func TestMuxOld(t *testing.T) {
	m := mux.New()
	m.Handle("GET {host}/item/{itemNr}", tcHandler("1"))
	m.Handle("POST {host}/item/{itemNr}", tcHandler("2"))
	m.Handle("GET example.org/item/{itemNr}", tcHandler("3"))
	m.Handle("/foo/{foo...}", tcHandler("4"))
	m.Handle("/{$}", tcHandler("5"))

	tests := []struct {
		method string
		url    string
	}{
		{method: "GET", url: "https://example.org/item/1"},
		{method: "POST", url: "https://example.org/item/2"},
		{method: "GET", url: "https://foo.example.org/item/3"},
		{method: "GET", url: "https://example.org/foo/a/b/c"},
		{method: "GET", url: "https://example.org/foo"},
		{method: "GET", url: "https://example.org/foo/"},
		{method: "GET", url: "https://foo.example.org/"},
		{method: "GET", url: "https://foo.example.org"},
		{method: "GET", url: "https://foo.example.org/foobar/"},
	}

	for _, tc := range tests {
		r, err := http.NewRequest(tc.method, tc.url, nil)
		if err != nil {
			t.Errorf("http.NewRequest(%q, %q, %v) error %s",
				tc.method, tc.url, nil, err)
			continue
		}

		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)

		resp := w.Result()

		data, err := httputil.DumpResponse(resp, true)
		if err != nil {
			t.Errorf("DumpResponse error %s", err)
			continue
		}
		t.Logf("response: %s", data)
	}
}

func Example() {
	type out struct {
		Method    string
		Path      string
		HandlerID string
		VarMap    map[string]string
	}

	h := func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Type", "application/json")
		out := out{
			Method: r.Method,
			Path:   r.URL.Path,
			VarMap: mux.Vars(r),
		}
		data, err := json.MarshalIndent(&out, "", "  ")
		if err != nil {
			http.Error(w, fmt.Sprintf("error %s", err),
				http.StatusInternalServerError)
			return
		}

		_, err = w.Write(data)
		if err != nil {
			panic(fmt.Errorf("w.Write(data) error %s", err))

		}
	}

	m := mux.New()
	m.HandleFunc("{method} /item/{itemNr}", h)
	m.HandleFunc("/foo/{remainder...}", h)

	ts := httptest.NewTLSServer(m)
	defer ts.Close()

	client := ts.Client()
	url := ts.URL + "/item/1"
	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("client.Get(%q) error %s", url, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("io.ReadAll(resp.Body) error %s", err)
	}

	fmt.Printf("%s", data)
	// Output:
	// {
	//   "Method": "GET",
	//   "Path": "/item/1",
	//   "HandlerID": "",
	//   "VarMap": {
	//     "itemNr": "1",
	//     "method": "GET"
	//   }
	// }
}

func TestMux(t *testing.T) {
	type output struct {
		Host    string
		Method  string
		Path    string
		Pattern string
		VarMap  map[string]string
	}
	type testCase struct {
		request string
		status  int
		output  string
	}
	type testSetup struct {
		patterns  []string
		testCases []testCase
	}

	handler := func(pattern string) http.Handler {
		h := func(w http.ResponseWriter, r *http.Request) {
			header := w.Header()
			header.Set("Content-Type", "application/json")
			out := output{
				Host:    r.Host,
				Method:  r.Method,
				Path:    r.URL.Path,
				Pattern: pattern,
				VarMap:  mux.Vars(r),
			}
			data, err := json.MarshalIndent(&out, "", "  ")
			if err != nil {
				http.Error(w, fmt.Sprintf("error %s", err),
					http.StatusInternalServerError)
				return
			}

			_, err = w.Write(data)
			if err != nil {
				panic(fmt.Errorf("w.Write(data) error %s", err))

			}
		}
		return http.HandlerFunc(h)
	}

	tests := []testSetup{
		{
			patterns: []string{
				"GET /",
				"GET /item/{itemID}",
			},
			testCases: []testCase{
				{
					request: "GET https://example.org/",
					status:  200,
					output: `{
							"Host": "example.org",
							"Method": "GET",
							"Path": "/",
							"Pattern": "GET /",
							"VarMap": {}
						}`,
				},
				{
					request: "GET https://example.org/foo/bar",
					status:  200,
					output: `{
							"Host": "example.org",
							"Method": "GET",
							"Path": "/foo/bar",
							"Pattern": "GET /",
							"VarMap": {}
						}`,
				},
				{
					request: "GET https://example.org/item/1",
					status:  200,
					output: `{
						"Host": "example.org",
						"Method": "GET",
						"Path": "/item/1",
						"Pattern": "GET /item/{itemID}",
						"VarMap": {
							"itemID": "1"
						}
					}`,
				},
			},
		},
	}

	for i, ts := range tests {
		ts := ts
		t.Run(fmt.Sprintf("s=%d", i+1), func(t *testing.T) {
			m := mux.New()
			for _, p := range ts.patterns {
				m.Handle(p, handler(p))
			}

			for _, tc := range ts.testCases {
				method, url, ok := strings.Cut(tc.request, " ")
				if !ok {
					t.Errorf("request %q invalid",
						tc.request)
					continue
				}
				r, err := http.NewRequest(method, url, nil)
				if err != nil {
					t.Errorf(
						"http.NewRequest(%q, %q, %v) error %s",
						method, url, nil, err)
					continue
				}

				w := httptest.NewRecorder()
				m.ServeHTTP(w, r)

				resp := w.Result()

				if resp.StatusCode != tc.status {
					t.Errorf("got status %d; want %d",
						resp.StatusCode, tc.status)
					continue
				}
				data, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Errorf("DumpResponse error %s", err)
					continue
				}
				if err = resp.Body.Close(); err != nil {
					t.Errorf("resp.Body.Close() error %s",
						err)
				}

				var buf bytes.Buffer
				err = json.Indent(&buf, []byte(tc.output), "",
					"  ")
				if err != nil {
					t.Errorf(
						"invalid expected output %q; error %s",
						tc.output, err)
				}

				want := buf.String()
				got := string(data)
				if got != want {
					t.Logf("GOT\n%s", got)
					t.Logf("WANT\n%s", want)
					t.Errorf("### unexpected output")
					continue
				}
			}
		})
	}
}
