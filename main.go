// Package mux implements a mux as proposed in [Discussion].
//
// # Note that I have copied
//
// [Discussion]: https://github.com/golang/go/discussions/60227
package mux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ctxKey is a package specific type for context keys.
type ctxKey int

// varMapLey is the context key for variable map values.
const (
	varMapKey ctxKey = iota
)

// Vars retrieves the variable segment map from the request. The function
// returns always an initialized map even if it maybe empty.
func Vars(r *http.Request) map[string]string {
	ctx := r.Context()
	m := ctx.Value(varMapKey)
	if m == nil {
		return make(map[string]string, 0)
	}
	return m.(map[string]string)
}

// withVarMap modifies the context of the request to store the map.
func withVarMap(r *http.Request, m map[string]string) *http.Request {
	if len(m) == 0 {
		return r
	}
	ctx := r.Context()
	ctx = context.WithValue(ctx, varMapKey, m)
	return r.WithContext(ctx)
}

// Mux is the the mux. We are storing all handlers in a tree, with the first
// level for the hosts, second level for the methods and then followed by the path.
type Mux struct {
	mutex sync.RWMutex
	root  *node
}

// New creates a new Mux instance.
func New() *Mux {
	return &Mux{}
}

// convertPatterns converts a pattern string into a pattern slice.
func convertPattern(p string) (s []string, err error) {
	var (
		method string
	)
	method, r, ok := strings.Cut(p, " ")
	if ok {
		p = strings.TrimLeft(r, " ")
	} else {
		method = ""
	}
	if method == "" {
		method = "{}"
	}
	if method[0] == '{' {
		_, suffix, ok := matchWildcard(method)
		if !ok || suffix {
			return nil, fmt.Errorf("%w; invalid method wildcard %s",
				ErrPattern, method)
		}
	} else {
		switch method {
		case http.MethodGet:
		case http.MethodHead:
		case http.MethodPost:
		case http.MethodPut:
		case http.MethodPatch:
		case http.MethodConnect:
		case http.MethodOptions:
		case http.MethodTrace:
		default:
			return nil, fmt.Errorf("%w; invalid method %s",
				ErrPattern, method)
		}
	}

	s = strings.Split(p, "/")
	if s[0] == "" {
		s[0] = "{}"
	}
	if 1 < len(s) {
		s = append(s[:2], s[1:]...)
		s[1] = method
	} else {
		s = append(s, method)
	}
	return s, nil
}

func (mux *Mux) Handle(pattern string, handler http.Handler) {
	p, err := convertPattern(pattern)
	if err != nil {
		err = fmt.Errorf("%w; pattern=%q", err, pattern)
		panic(err)
	}

	mux.mutex.Lock()
	defer mux.mutex.Unlock()

	q, err := register(mux.root, p, handler, pattern)
	if err != nil {
		err = fmt.Errorf("%w; pattern=%q", err, pattern)
		panic(err)
	}
	mux.root = q
}

func (mux *Mux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.Handle(pattern, http.HandlerFunc(handler))
}

func searchPath(host, method, path string) []string {
	s := strings.Split("/"+path, "/")
	s[0] = host
	s[1] = method
	return s
}

// _shouldRedirect returns whether there is a  direct terminal key (t=true) or
// whether there is a suffix key (s == true). The application should redirect if
// !t && s.
func _shouldRedirect(o *node, path []string) (t, s bool) {
	if len(path) == 0 {
		_, t = o.m[terminalKey]
		_, s = o.m[suffixKey]
		return t, s
	}
	p := path[0]
	q := o.m[p]
	var x bool
	if q != nil {
		t, x = _shouldRedirect(q, path[1:])
		s = s || x
		if t {
			return t, s
		}
	}
	for _, key := range o.wildcards {
		q = o.m[key]
		if q != nil {
			t, x = _shouldRedirect(q, path[1:])
			s = s || x
			if t {
				return t, s
			}
		}
	}
	return false, s
}

func (mux *Mux) shouldRedirect(host, method, path string) bool {
	p := searchPath(host, method, path)

	mux.mutex.RLock()
	defer mux.mutex.RUnlock()
	t, s := _shouldRedirect(mux.root, p)
	return !t && s
}

var notFoundHandler = http.NotFoundHandler()

func (mux *Mux) handler(r *http.Request, host, method, path string) (h http.Handler, pattern string, s *http.Request) {
	p := searchPath(host, method, path)
	m := make(map[string]string, 8)

	mux.mutex.RLock()
	defer mux.mutex.RUnlock()

	t := findTerminal(mux.root, p, m)
	if t == nil {
		return notFoundHandler, "", r
	}
	return t.h, t.pattern, withVarMap(r, m)
}

// The following two functions have been copied verbatim from the Go language source
// code.

func stripHostPort(h string) string {
	// If no port on host, return unchanged
	if !strings.Contains(h, ":") {
		return h
	}
	host, _, err := net.SplitHostPort(h)
	if err != nil {
		return h // on error, return unchanged
	}
	return host
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	if p[len(p)-1] == '/' && np != "/" {
		// Fast path for common case of p being the string we want:
		if len(p) == len(np)+1 && strings.HasPrefix(p, np) {
			np = p
		} else {
			np += "/"
		}
	}
	return np
}

// redirectToPathSlash determines if the given path needs appending "/" to it.
// This occurs when a handler for path + "/" was already registered, but
// not for path itself. If the path needs appending to, it creates a new
// URL, setting the path to u.Path + "/" and returning true to indicate so.
func (mux *Mux) redirectToPathSlash(host, method, path string, u *url.URL) (*url.URL, bool) {
	shouldRedirect := mux.shouldRedirect(host, method, path)
	if !shouldRedirect {
		return u, false
	}
	path = path + "/"
	return &url.URL{Path: path, RawQuery: u.RawQuery}, true
}

// HandlerReq returns the handler and the request. We need to return the request
// because we modify the context of the request to store the variable segment
// map.
func (mux *Mux) HandlerReq(r *http.Request) (h http.Handler, pattern string, s *http.Request) {
	// CONNECT requests are not canonicalized.
	if r.Method == "CONNECT" {
		// If r.URL.Path is /tree and its handler is not registered,
		// the /tree -> /tree/ redirect applies to CONNECT requests
		// but the path canonicalization does not.
		u, ok := mux.redirectToPathSlash(r.URL.Host, r.Method, r.URL.Path, r.URL)
		if ok {
			return http.RedirectHandler(u.String(), http.StatusMovedPermanently), u.Path, r
		}

		return mux.handler(r, r.Host, r.Method, r.URL.Path)
	}

	// All other requests have any port stripped and path cleaned
	// before passing to mux.handler.
	host := stripHostPort(r.Host)
	method := r.Method
	path := cleanPath(r.URL.Path)

	// If the given path is /tree and its handler is not registered,
	// redirect for /tree/.
	if u, ok := mux.redirectToPathSlash(host, method, path, r.URL); ok {
		return http.RedirectHandler(u.String(),
			http.StatusMovedPermanently), u.Path, r
	}

	if path != r.URL.Path {
		_, pattern, _ = mux.handler(r, host, method, path)
		u := &url.URL{Path: path, RawQuery: r.URL.RawQuery}
		return http.RedirectHandler(u.String(), http.StatusMovedPermanently), pattern, r
	}

	return mux.handler(r, host, method, r.URL.Path)
}

func (mux *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.RequestURI == "*" {
		if r.ProtoAtLeast(1, 1) {
			w.Header().Set("Connection", "close")
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	h, _, s := mux.HandlerReq(r)
	h.ServeHTTP(w, s)
}

// Keys for the node maps. See [node].
const (
	suffixKey   = "{...}"
	terminalKey = "{$}"
)

// node describes a node in the pattern tree. Terminal nodes have the handler
// and the pattern set, but have a nil map m and an empty wildcardVar string.
// The special keys [wildcardKey], [suffixKey] and [terminalKey] are used. The
// suffixKey and the terminalKey are the only keys that will point to terminal
// nodes.
type node struct {
	m         map[string]*node
	wildcards []string
	suffixVar string
	h         http.Handler
	pattern   string
}

func (o *node) insertWildcard(x string) {
	i := sort.SearchStrings(o.wildcards, x)
	if i < len(o.wildcards) {
		if o.wildcards[i] == x {
			return
		}
		o.wildcards = append(o.wildcards[:i+1], o.wildcards[i:]...)
		o.wildcards[i] = x
	} else {
		o.wildcards = append(o.wildcards, x)
	}
}

var ErrPattern = errors.New("mux: invalid pattern")

var (
	wcRegexp     = regexp.MustCompile(`^\{([_\pL][_\pL\p{Nd}]*)?(\.\.\.)?\}$`)
	staticRegexp = regexp.MustCompile(
		`^(?:%[0-9a-fA-F]{2}|[-:@!$&'()*+,;=A-Za-z0-9._~])*$`)
)

func matchWildcard(s string) (wc string, suffix bool, ok bool) {
	m := wcRegexp.FindStringSubmatch(s)
	if m == nil {
		return "", false, false
	}
	return m[1], m[2] == "...", true
}

func matchStatic(s string) bool {
	return staticRegexp.MatchString(s)
}

func register(o *node, pattern []string, h http.Handler, origPattern string) (*node, error) {
	var err error
	if h == nil {
		panic("handler h is nil")
	}
	if len(pattern) == 0 {
		if o != nil {
			if q := o.m[terminalKey]; q != nil {
				return o, fmt.Errorf(
					"%w; redundant pattern", ErrPattern)
			}
		} else {
			o = &node{m: make(map[string]*node, 1)}
		}
		o.m[terminalKey] = &node{h: h, pattern: origPattern}
		return o, nil
	}
	p := pattern[0]
	if p == "" && len(pattern) == 1 {
		p = "{...}"
	}
	if len(p) > 0 && p[0] == '{' {
		if p == "{$}" {
			if len(pattern) > 1 {
				return o, fmt.Errorf("%w; {$} not at end",
					ErrPattern)
			}
			return register(o, nil, h, origPattern)
		}
		wcVar, suffix, ok := matchWildcard(p)
		if !ok {
			return o, fmt.Errorf("%w; %s invalid wildcard",
				ErrPattern, p)
		}
		if suffix {
			if len(pattern) > 1 {
				return o, fmt.Errorf("%w; %s is not at end",
					ErrPattern, p)
			}
			if o != nil {
				if q := o.m[suffixKey]; q != nil {
					return o, fmt.Errorf(
						"%w; redundant pattern",
						ErrPattern)
				}
			} else {
				o = &node{m: make(map[string]*node, 1)}
			}
			o.m[suffixKey] = &node{h: h}
			o.suffixVar = wcVar
			return o, nil
		}
		var q *node
		if o != nil {
			q = o.m[p]
		} else {
			o = &node{m: make(map[string]*node, 1)}
		}
		q, err = register(q, pattern[1:], h, origPattern)
		if err != nil {
			return o, err
		}
		o.m[p] = q
		o.insertWildcard(p)
		return o, nil
	}
	if !matchStatic(p) {
		return o, fmt.Errorf("%w; segment %q invalid", ErrPattern, p)
	}
	var q *node
	if o != nil {

		q = o.m[p]
	} else {
		o = &node{m: make(map[string]*node, 1)}
	}
	q, err = register(q, pattern[1:], h, origPattern)
	if err != nil {
		return o, err
	}
	o.m[p] = q
	return o, nil
}

// findTerminal tries to find a terminal node using the path. It fills the
// variable map m if it is not nil. If the t is nil, no terminal could be found.
func findTerminal(o *node, path []string, m map[string]string) *node {
	if len(path) == 0 {
		return o.m[terminalKey]
	}
	p := path[0]
	q := o.m[p]
	if q != nil {
		if t := findTerminal(q, path[1:], m); t != nil {
			return t
		}
	}
	for _, key := range o.wildcards {
		q = o.m[key]
		if q != nil {
			if t := findTerminal(q, path[1:], m); t != nil {
				if m != nil && key != "{}" {
					// remove the braces around the variable
					m[key[1:len(key)-1]] = p
				}
				return t
			}
		}
	}
	q = o.m[suffixKey]
	if q != nil {
		if m != nil && o.suffixVar != "" {
			m[o.suffixVar] = strings.Join(path, "/")
		}
		return q
	}
	if len(path) == 1 && p == "" {
		q = o.m[terminalKey]
	}
	return q
}
