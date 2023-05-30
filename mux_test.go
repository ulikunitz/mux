package mux_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
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

func TestMux(t *testing.T) {
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
