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
	m := new(mux.Mux)
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
		Method string
		Path   string
		VarMap map[string]string
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

	m := new(mux.Mux)
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
		{
			patterns: []string{
				"GET /a/b",
				"GET /a/{wc}",
			},
			testCases: []testCase{
				{
					request: "GET https://example.org/a/b",
					status:  200,
					output: `{
							"Host": "example.org",
							"Method": "GET",
							"Path": "/a/b",
							"Pattern": "GET /a/b",
							"VarMap": {}
						}`,
				},
				{
					request: "GET https://example.org/a/a",
					status:  200,
					output: `{
							"Host": "example.org",
							"Method": "GET",
							"Path": "/a/a",
							"Pattern": "GET /a/{wc}",
							"VarMap": {
							  "wc": "a"
							}
						}`,
				},
				{
					request: "GET https://example.org/a/a/",
					status:  404,
					output:  "404 page not found\n",
				},
				{
					request: "GET https://example.org/a/b/",
					status:  404,
					output:  "404 page not found\n",
				},
			},
		},
		{
			patterns: []string{
				"POST /objects/{id}",
			},
			testCases: []testCase{
				{
					request: "POST https://example.org/objects/1",
					status:  200,
					output: `{
							"Host": "example.org",
							"Method": "POST",
							"Path": "/objects/1",
							"Pattern": "POST /objects/{id}",
							"VarMap": {
							  "id": "1"
							}
						}`,
				},
				{
					request: "POST https://example.org/object/1",
					status:  404,
					output:  "404 page not found\n",
				},
				{
					request: "GET https://example.org/objects/1",
					status:  405,
					output:  "405 method not allowed\n",
				},
			},
		},
		{
			patterns: []string{
				"GET example.org/images/",
			},
			testCases: []testCase{
				{
					request: "GET https://example.org/images/a.png",
					status:  200,
					output: `{
						"Host": "example.org",
						"Method": "GET",
						"Path": "/images/a.png",
						"Pattern": "GET example.org/images/",
						"VarMap": {}
					}`,
				},
				{
					request: "GET https://example.org/images",
					status:  301,
					output:  "<a href=\"/images/\">Moved Permanently</a>.\n\n",
				},
			},
		},
		{
			patterns: []string{
				"{method}  {host}/buckets/{bucketID}/objects/{objectID}",
			},
			testCases: []testCase{
				{
					request: "GET https://example.org/buckets/1/objects/2",
					status:  200,
					output: `{
						"Host": "example.org",
						"Method": "GET",
						"Path": "/buckets/1/objects/2",
						"Pattern": "{method}  {host}/buckets/{bucketID}/objects/{objectID}",
						"VarMap": {
						  "bucketID": "1",
						  "host": "example.org",
						  "method": "GET",
						  "objectID": "2"
						}
					}`,
				},
			},
		},
		{
			patterns: []string{
				"/users/{userSpec...}",
			},
			testCases: []testCase{
				{
					request: "GET https://example.org/users/a/b/c",
					status:  200,
					output: `{
						"Host": "example.org",
						"Method": "GET",
						"Path": "/users/a/b/c",
						"Pattern": "/users/{userSpec...}",
						"VarMap": {
						  "userSpec": "a/b/c"
						}
					}`,
				},
			},
		},
		{
			patterns: []string{
				"{} {}/buckets/{bucketID}/objects/{}",
				"{} {host}/users/{...}",
			},
			testCases: []testCase{
				{
					request: "GET https://example.org/buckets/1/objects/2",
					status:  200,
					output: `{
						"Host": "example.org",
						"Method": "GET",
						"Path": "/buckets/1/objects/2",
						"Pattern": "{} {}/buckets/{bucketID}/objects/{}",
						"VarMap": {
						  "bucketID": "1"
						}
					}`,
				},
				{
					request: "GET https://example.org/users/u101",
					status:  200,
					output: `{
						"Host": "example.org",
						"Method": "GET",
						"Path": "/users/u101",
						"Pattern": "{} {host}/users/{...}",
						"VarMap": {
						  "host": "example.org"
						}
					}`,
				},
			},
		},
		{
			patterns: []string{
				"/buckets/{bucket2ID}/objects/{objectID}",
				"/buckets/{bucket1ID}/objects/{objectID}",
				"/buckets/{bucket2ID}/meta/",
			},
			testCases: []testCase{
				{
					request: "GET https://example.org/buckets/1/objects/2",
					status:  200,
					output: `{
						"Host": "example.org",
						"Method": "GET",
						"Path": "/buckets/1/objects/2",
						"Pattern": "/buckets/{bucket1ID}/objects/{objectID}",
						"VarMap": {
						  "bucket1ID": "1",
						  "objectID": "2"
						}
					}`,
				},
				{
					request: "GET https://example.org/buckets/1/meta",
					status:  301,
					output:  "<a href=\"/buckets/1/meta/\">Moved Permanently</a>.\n\n",
				},
			},
		},
		{
			patterns: []string{
				"/{$}",
				"/",
			},
			testCases: []testCase{
				{
					request: "GET https://example.org/",
					status:  200,
					output: `{
						"Host": "example.org",
						"Method": "GET",
						"Path": "/",
						"Pattern": "/{$}",
						"VarMap": {}
					}`,
				},
				{
					request: "GET https://example.org/foo",
					status:  200,
					output: `{
						"Host": "example.org",
						"Method": "GET",
						"Path": "/foo",
						"Pattern": "/",
						"VarMap": {}
					}`,
				},
			},
		},
	}

	for i, ts := range tests {
		ts := ts
		t.Run(fmt.Sprintf("s=%d", i+1), func(t *testing.T) {
			m := new(mux.Mux)
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
				var want string
				if err != nil {
					want = tc.output
				} else {
					want = buf.String()
				}

				got := string(data)
				if got != want {
					t.Logf("GOT  %q", got)
					t.Logf("WANT %q", want)
					t.Errorf("### unexpected output")
					t.Logf("GOT\n%s", got)
					continue
				}
			}
		})
	}
}
