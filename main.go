// Package mux implements a multiplexer for http requests. The multiplexer may
// replace [http.ServeMux] because it extends the pattern language by HTTP
// methods and wildcard variables. Those variables can be accessed by the
// selected HTTP request handlers, saving the handlers from parsing the path
// again. Those improvements are discussed in a [Go language discussion].
//
// The multiplexer is fully functional. It is not widely tested and has not been
// optimized. Please report any issues you may encounter in [module repo]
//
// A multiplexers can be created by
//
//	m := mux.New()
//
// The multiplexer supports the ServeHTTP method, so it can be used everywhere a
// [net/http.Handler] can be used.
//
// The methods [Mux.Handle] and [Mux.HandleFunc] register a [net/http.Handler]
// or a handler function for a specific pattern. The patterns supported by
// [net/http.ServeMux] can be used without modification.
//
// A new feature is the support for methods, which need to precede host/path
// pattern by a space.
//
//	m.Handle("GET example.org/images/", imagesHandler)
//
// The methods GET, HEAD, POST, PATCH, PUT, CONNECT, OPTIONS and TRACE are
// supported.
//
// The other new feature is the support for wildcard variable names, which can
// replace the method, host or segments in the path component.
//
//	m.Handle("{method}  {host}/buckets/{bucketID}/objects/{objectID}", h)
//
// Suffix wildcards are can be used additionally, which capture the rest of the
// request path.
//
//	m.Handle("/users/{userSpec...}", h)
//
// If the wildcard doesn't define a variable name, it acts still as a wildcard
// but will not capture it. So following calls to Handle are valid.
//
//	m.Handle("{} {}/buckets/{bucketID}/objects/{}". h)
//	m.Handle("{} {host}/users/{...}", h)
//
// The multiplexer allows different variables at the same position.
//
//	m.Handle("/buckets/{bucket2ID}/objects/{objectID}", h2o)
//	m.Handle("/buckets/{bucket1ID}/objects/{objectID}", h1o)
//	m.Handle("/buckets/{bucket2ID}/meta/", h2m)
//
// However the variables will be ordered in lexicographically order. The
// multiplexer will route the a request with path /buckets/1/objects/1 always to
// the handler h1o. The handler h2o will not be reachable. However a request
// with path /buckets/1/meta/green will be routed to h2m.
//
// The order of the pattern resolution is independent of the order of the Handle
// calls. A consequence is that redundant patterns lead to panics, if they would
// simply overwrite the handlers the sequence of the callers would influence the
// resolution.
//
// The multiplexer doesn't support two suffix wildcards with different
// variables. Following calls will lead to a panic of the second call.
//
//	m.Handle("/users/{userSpec...}", h1)
//	m.Handle("/users/{uSpec...}", h2) // Call will panic!
//
// The multiplexer keeps the redirect logic of a  path /images to
// /images/ if only the second pattern has been registered. This is also
// valid for suffix wildcards as in /images/{imageSpec...}.
//
// The multiplexer supports a special marker {$}. The pattern registered with
//
//	m.Handle("/{$}", h1)
//
// will only resolve calls to a path with a single slash because
//
//	m.Handle("/", h2)
//
// will resolve to all requests unless other patterns have been registered. The
// multiplexer always prefers the most specific pattern that matches.
//
// The handler can access the wildcard variables by calling the [Vars] function
// on the provided request value. The returned map is always initialized, if no
// variables have been matched the map will be empty.
//
//	vmap := mux.Vars(request)
//	log.Printf("bucketID: %s", vmap["bucketID"])
//	log.Printf("objectID: %s", vmap["objectID"])
//
// [Go language discussion]: https://github.com/golang/go/discussions/60227
// [module repo]: https://github.com/ulikunitz/mux
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

// varMapKey is the context key for variable map values.
const (
	varMapKey ctxKey = iota
)

// Vars retrieves the wildcard variable map from the request. The function
// returns always an initialized map, which may be empty.
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

// Mux is the type for the multiplexer. It holds a tree resolving all patterns
// provided.
type Mux struct {
	mutex sync.RWMutex
	root  *node
}

// New creates a new Mux instance. All instances can be used independently.
func New() *Mux {
	return &Mux{}
}

type regexpSet struct {
	method  *regexp.Regexp
	host    *regexp.Regexp
	segment *regexp.Regexp
}

func newRegexpSet() *regexpSet {
	r := new(regexpSet)

	const (
		wildcard   = `(?:\{(?P<wc>[_\pL][_\pL\p{Nd}]*)?(?P<suffix>\.\.\.)?\})`
		method     = `(?:GET|HEAD|POST|PUT|PATCH|CONNECT|OPTIONS|TRACE)`
		wcm        = `^(?:` + wildcard + `|` + method + `)$`
		unreserved = `[-A-Za-z0-9._~]`
		pctEncoded = `(?:%[A-Fa-f0-9]{2})`
		subDelims  = `[!$&'()*+,;=]`
		regName    = `(?:(?:` + unreserved + `|` + pctEncoded + `|` +
			subDelims + `)*)`
		decOctet    = `(?:\d|[1-9]\d|1\d\d|2[0-4][0-9]|25[0-5])`
		ipv4address = `(?:` + decOctet + `\.` + decOctet + `\.` +
			decOctet + `\.` + decOctet + `)`
		h16         = `(?:[0-9a-fA-F]{1,4})`
		h16c        = `(?:` + h16 + `\:)`
		ls32        = `(?:` + h16 + `\:` + h16 + `|` + ipv4address + `)`
		ipv6address = `(?:` + h16c + `{6}` + ls32 + `|` +
			`\:\:` + h16c + `{5}` + ls32 + `|` +
			h16 + `?\:\:` + h16c + `{4}` + ls32 + `|` +
			`(?:` + h16c + `?` + h16 + `)?\:\:` + h16c + `{3}` + ls32 + `|` +
			`(?:` + h16c + `{,2}` + h16 + `)?\:\:` + h16c + `{2}` + ls32 + `|` +
			`(?:` + h16c + `{,3}` + h16 + `)?\:\:` + h16c + ls32 + `|` +
			`(?:` + h16c + `{,4}` + h16 + `)?\:\:` + ls32 + `|` +
			`(?:` + h16c + `{,5}` + h16 + `)?\:\:` + h16 + `|` +
			`(?:` + h16c + `{,6}` + h16 + `)?\:\:)`
		ipLiteral = `(?:\[` + ipv6address + `\])`
		host      = `(?:` + ipLiteral + `|` + ipv4address + `|` + regName + `)`
		wch       = `^(?:` + wildcard + `|` + host + `)$`
		pchar     = `(?:` + unreserved + `|` + pctEncoded + `|` +
			subDelims + `|` + `[:@])`
		segment = `(?:` + pchar + `*)`
		wcs     = `^(?:` + wildcard + `|` + segment + `)$`
	)

	r.method = regexp.MustCompile(wcm)
	r.host = regexp.MustCompile(wch)
	r.segment = regexp.MustCompile(wcs)
	return r
}

var (
	reOnce  sync.Once
	regexps *regexpSet
)

// parsePatterns converts a pattern string into a pattern slice. It checks for
// correct method names.
func parsePattern(p string) (s []string, err error) {
	reOnce.Do(func() {
		regexps = newRegexpSet()
	})
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
	m := regexps.method.FindStringSubmatch(method)
	if m == nil {
		return nil, fmt.Errorf("%w; invalid method %q", ErrPattern,
			method)
	}
	if m[2] != "" {
		return nil, fmt.Errorf("%w; method %q must not have a suffix",
			ErrPattern, method)
	}

	s = strings.Split(p, "/")
	if s[0] == "" {
		s[0] = "{}"
	}
	host := s[0]
	m = regexps.host.FindStringSubmatch(host)
	if m == nil {
		return nil, fmt.Errorf("%w; invalid host %q", ErrPattern,
			host)
	}
	if m[2] != "" {
		return nil, fmt.Errorf("%w; host %q must not have a suffix",
			ErrPattern, host)
	}

	q := s[1:]
	for i, seg := range q {
		if i == len(q)-1 && seg == "{$}" {
			break
		}
		m = regexps.segment.FindStringSubmatch(seg)
		if m == nil {
			return nil, fmt.Errorf("%w; invalid segment %q",
				ErrPattern, seg)
		}
		if i+1 < len(q) && m[2] != "" {
			return nil, fmt.Errorf(
				"%w; no suffix before end of path (%q)",
				ErrPattern, seg)
		}
	}

	if 1 < len(s) {
		s = append(s[:2], s[1:]...)
		s[1] = method
	} else {
		s = append(s, method)
	}
	return s, nil
}

// Handle registers the provided handler for the given pattern. The function
// might panic if the patterns contain errors or are redundant. The sequence of
// the Handle calls has no influence on the pattern resolution. (Note that this
// condition would be violated, if redundant patterns would not cause a panic.)
func (mux *Mux) Handle(pattern string, handler http.Handler) {
	p, err := parsePattern(pattern)
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

// HandleFunc registers the handler function handler with the given pattern. It
// calls [Mux.Handle] and supports the semantics for the pattern.
func (mux *Mux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.Handle(pattern, http.HandlerFunc(handler))
}

// searchPath converts host, method and path to a search path for the mux tree.
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

// shouldRedirect checks whether there should be a redirection for the given
// host, method and path.
func (mux *Mux) shouldRedirect(host, method, path string) bool {
	p := searchPath(host, method, path)

	mux.mutex.RLock()
	defer mux.mutex.RUnlock()
	t, s := _shouldRedirect(mux.root, p)
	return !t && s
}

// notFoundHandler to be used.
var notFoundHandler = http.NotFoundHandler()

// handler searches the handler for host, method and path. The context of the
// provided request might be modified to store the variable segment map.
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

// The following functions and functions including ServeHTTP were copied from
// the Go language source code and modified.

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

// HandlerReq returns the handler and possibly a new request. The return of the
// request is required because the variable segment map has to be attached to
// the context of the request.
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
		return http.RedirectHandler(u.String(),
			http.StatusMovedPermanently), pattern, r
	}

	return mux.handler(r, host, method, r.URL.Path)
}

// ServeHTTP provides the http.Handler functionality for the mux.
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

// insert a wildcard in lexicographic order to the node.
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

// ErrPattern indicates that an invalid pattern has been provided. The errors
// provided by the panics of the [Mux.Handle] and [Mux.HandleFunc] methods wrap
// this error.
var ErrPattern = errors.New("mux: invalid pattern")

// matchWildcard checks whether the string is a wildcard. The function extracts
// the wildcard, checks whether it is a suffix (e.g. {foo...}).
func matchWildcard(s string) (wc string, suffix bool, ok bool) {
	if len(s) < 2 {
		return "", false, false
	}
	j := len(s) - 1
	if s[0] != '{' || s[j] != '}' {
		return "", false, false
	}
	wc = s[1:j]
	if j = len(wc) - 3; j >= 0 && wc[j:] == "..." {
		suffix = true
		wc = wc[:j]
	}
	return wc, suffix, true
}

// register registers the handler and original pattern under node o using the
// remaining pattern.
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
		p = suffixKey
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
