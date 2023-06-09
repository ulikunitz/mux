// Package mux implements a multiplexer for http requests. The multiplexer may
// replace [http.ServeMux] because it extends the pattern language by HTTP
// methods and wildcard variables. Those variables can be accessed by the
// selected HTTP request handlers, saving the handlers from parsing the path
// again. Those improvements are discussed in a [Go language discussion].
//
// The multiplexer is fully functional. It is not widely tested and has not been
// optimized. Please report any issues you may encounter in [module repo]
//
// The multiplexer can be simply declared.
//
//	var m mux.Mux
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
// If the path cannot be found the multiplexer returns 404 page not found. If
// the method is unsupported, the status returned is 405 method not allowed.
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
func parsePattern(p string) (s []string, method string, err error) {
	reOnce.Do(func() {
		regexps = newRegexpSet()
	})
	method, r, ok := strings.Cut(p, " ")
	if ok {
		p = strings.TrimLeft(r, " ")
		if method == "" {
			method = "{}"
		}
	} else {
		method = "{}"
	}
	m := regexps.method.FindStringSubmatch(method)
	if m == nil {
		return nil, "", fmt.Errorf("%w; invalid method %q", ErrPattern,
			method)
	}
	if m[2] != "" {
		return nil, "", fmt.Errorf("%w; method %q must not have a suffix",
			ErrPattern, method)
	}

	s = strings.Split(p, "/")
	if s[0] == "" {
		s[0] = "{}"
	}
	host := s[0]
	m = regexps.host.FindStringSubmatch(host)
	if m == nil {
		return nil, "", fmt.Errorf("%w; invalid host %q", ErrPattern,
			host)
	}
	if m[2] != "" {
		return nil, "", fmt.Errorf("%w; host %q must not have a suffix",
			ErrPattern, host)
	}

	q := s[1:]
	for i, seg := range q {
		if i == len(q)-1 && seg == "{$}" {
			break
		}
		m = regexps.segment.FindStringSubmatch(seg)
		if m == nil {
			return nil, "", fmt.Errorf("%w; invalid segment %q",
				ErrPattern, seg)
		}
		if i+1 < len(q) && m[2] != "" {
			return nil, "", fmt.Errorf(
				"%w; no suffix before end of path (%q)",
				ErrPattern, seg)
		}
	}

	return s, method, nil
}

// Handle registers the provided handler for the given pattern. The function
// might panic if the patterns contain errors or are redundant. The sequence of
// the Handle calls has no influence on the pattern resolution. (Note that this
// condition would be violated, if redundant patterns would not cause a panic.)
func (mux *Mux) Handle(pattern string, handler http.Handler) {
	if handler == nil {
		panic(fmt.Errorf("mux: nil handler is not supported"))
	}
	p, method, err := parsePattern(pattern)
	if err != nil {
		err = fmt.Errorf("%w; pattern=%q", err, pattern)
		panic(err)
	}

	mux.mutex.Lock()
	defer mux.mutex.Unlock()

	q, err := register(mux.root, p, method, result{h: handler, pattern: pattern})
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

// _shouldRedirect returns whether there is a  direct terminal key (t=true) or
// whether there is a suffix key (s == true). The application should redirect if
// !t && s.
func _shouldRedirect(o *node, path string) (t, s bool) {
	if path == terminalKey {
		_, t = o.m[terminalKey]
		_, s = o.m[suffixKey]
		return t, s
	}
	seg, tail, sep := strings.Cut(path, "/")
	if sep {
		if q := o.m[path]; q != nil {
			return true, false
		}
	} else {
		if seg == "" {
			return true, false
		}
		tail = terminalKey
	}
	q := o.m[seg]
	var x bool
	if q != nil {
		t, x = _shouldRedirect(q, tail)
		s = s || x
		if t {
			return t, s
		}
	}
	for _, key := range o.wildcards {
		q = o.m[key]
		if q != nil {
			t, x = _shouldRedirect(q, tail)
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
	mux.mutex.RLock()
	defer mux.mutex.RUnlock()
	t, s := _shouldRedirect(mux.root, host+path)
	return !t && s
}

// notFoundHandler to be used.
var notFoundHandler = http.NotFoundHandler()

type resultError interface {
	error
	handler() http.Handler
}

type notFoundError struct{}

func (err *notFoundError) Error() string {
	return "mux: page not found Error"
}

func (err *notFoundError) handler() http.Handler { return notFoundHandler }

type notAllowedMethodError struct {
	allow []string
}

func (err *notAllowedMethodError) Error() string {
	return "mux: method not allowed"
}

func (err *notAllowedMethodError) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		for _, m := range err.allow {
			hdr.Add("Allow", m)
		}
		http.Error(w, "405 method not allowed",
			http.StatusMethodNotAllowed)
	})
}

// handler searches the handler for host, method and path. The context of the
// provided request might be modified to store the variable segment map.
func (mux *Mux) handler(r *http.Request, host, method, path string) (h http.Handler, pattern string, s *http.Request) {
	m := make(map[string]string, 8)

	mux.mutex.RLock()
	defer mux.mutex.RUnlock()

	res, err := findResult(mux.root, host+path, method, m)
	if err != nil {
		var rerr resultError
		if errors.As(err, &rerr) {
			return rerr.handler(), "", r
		}
	}
	return res.h, res.pattern, withVarMap(r, m)
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

// result represents the result of a search in the pattern tree.
type result struct {
	h       http.Handler
	pattern string
}

// methodNode is the terminating node in the path tree supporting the methods.
type methodNode struct {
	m           map[string]result
	wildcardVar string
	methods     []string
}

// node describes a node in the pattern tree. Terminal nodes have the handler
// and the pattern set, but have a nil map m and an empty wildcardVar string.
// The special keys [wildcardKey], [suffixKey] and [terminalKey] are used. The
// suffixKey and the terminalKey are the only keys that will point to terminal
// nodes.
type node struct {
	m          map[string]*node
	wildcards  []string
	suffixVar  string
	methodNode *methodNode
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

func jump(pattern []string) (path string, ok bool) {
	switch len(pattern) {
	case 0:
		return terminalKey, true
	case 1:
		return "", false
	}
	if pattern[len(pattern)-1] == "" {
		return "", false
	}
	for _, s := range pattern {
		if s[0] == '{' {
			return "", false
		}
	}
	return strings.Join(pattern, "/"), true
}

func updateMethodNode(m *methodNode, method string, r result) (o *methodNode, err error) {
	var methodKey, methodVar string
	if method[0] == '{' {
		methodKey = "{}"
		methodVar = method[1 : len(method)-1]
	} else {
		methodKey = method
		methodVar = ""
	}
	if m == nil {
		return &methodNode{
				m:           map[string]result{methodKey: r},
				wildcardVar: methodVar,
				methods:     []string{methodKey},
			},
			nil
	}
	if _, ok := m.m[methodKey]; ok {
		return nil, fmt.Errorf("%w; method redundant for pattern %s",
			ErrPattern, r.pattern)
	}
	m.m[methodKey] = r
	m.methods = append(m.methods, methodKey)
	return m, nil
}

// register registers the handler and original pattern under node o using the
// remaining pattern.
func register(o *node, pattern []string, method string, res result) (*node, error) {
	var err error

	if path, ok := jump(pattern); ok {
		var q *node
		if o != nil {
			q = o.m[path]
		} else {
			o = &node{m: make(map[string]*node, 1)}
		}
		if q == nil {
			q = &node{}
		}
		q.methodNode, err = updateMethodNode(q.methodNode, method, res)
		if err != nil {
			return nil, err
		}
		o.m[path] = q
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
			var q *node
			if o != nil {
				q = o.m[""]
			} else {
				o = &node{m: make(map[string]*node, 1)}
			}
			q, err := register(q, nil, method, res)
			if err != nil {
				return o, err
			}
			o.m[""] = q
			return o, nil
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
			var q *node
			if o != nil {
				q = o.m[suffixKey]
			} else {
				o = &node{m: make(map[string]*node, 1)}
			}
			if q == nil {
				q = &node{}
			}
			q.methodNode, err = updateMethodNode(q.methodNode, method, res)
			if err != nil {
				return nil, err
			}
			o.m[suffixKey] = q
			o.suffixVar = wcVar
			return o, nil
		}
		var q *node
		if o != nil {
			q = o.m[p]
		} else {
			o = &node{m: make(map[string]*node, 1)}
		}
		q, err = register(q, pattern[1:], method, res)
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
	q, err = register(q, pattern[1:], method, res)
	if err != nil {
		return o, err
	}
	o.m[p] = q
	return o, nil
}

func unique(x []string) []string {
	sort.Strings(x)
	j := 0
	for i := 1; i < len(x); i++ {
		s := x[i]
		if s == x[j] {
			continue
		}
		j++
		if i > j {
			x[j] = s
		}
	}
	j++
	return x[:j]
}

func mergeErrors(oldErr error, newErr error) error {
	if oldErr == nil {
		return newErr
	}
	if newErr == nil {
		return oldErr
	}
	var oldNAMErr, newNAMErr *notAllowedMethodError
	if errors.As(oldErr, &oldNAMErr) {
		if errors.As(newErr, &newNAMErr) {
			newNAMErr.allow = append(newNAMErr.allow,
				oldNAMErr.allow...)
			newNAMErr.allow = unique(newNAMErr.allow)
			return newNAMErr
		}
		return oldNAMErr
	}
	return newErr
}

func findMethod(q *node, method string, m map[string]string) (r result, err error) {
	if q == nil {
		return result{}, &notFoundError{}
	}
	u := q.methodNode
	var ok bool
	r, ok = u.m[method]
	if ok {
		return r, nil
	}
	r, ok = u.m["{}"]
	if ok {
		if m != nil && u.wildcardVar != "" {
			m[u.wildcardVar] = method
		}
		return r, nil
	}
	return result{}, &notAllowedMethodError{
		allow: u.methods,
	}
}

// findResult tries to find a terminal node using the path. It fills the
// variable map m if it is not nil. If the t is nil, no terminal could be found.
func findResult(o *node, path string, method string, m map[string]string) (r result, err error) {
	var ferr error
	if path == terminalKey {
		q := o.m[terminalKey]
		return findMethod(q, method, m)
	}
	seg, tail, sep := strings.Cut(path, "/")
	if sep {
		// check for jump
		q := o.m[path]
		if q != nil {
			r, err = findMethod(q, method, m)
			if err == nil {
				return r, nil
			}
			ferr = mergeErrors(ferr, err)
		}
	} else {
		tail = terminalKey
	}
	q := o.m[seg]
	if q != nil {
		r, err = findResult(q, tail, method, m)
		if err == nil {
			return r, nil
		}
		ferr = mergeErrors(ferr, err)
	}
	for _, key := range o.wildcards {
		q = o.m[key]
		if q != nil {
			r, err = findResult(q, tail, method, m)
			if err == nil {
				if m != nil && key != "{}" {
					// remove the braces around the variable
					m[key[1:len(key)-1]] = seg
				}
				return r, nil
			}
			ferr = mergeErrors(ferr, err)
		}
	}
	q = o.m[suffixKey]
	r, err = findMethod(q, method, m)
	if err == nil {
		if m != nil && o.suffixVar != "" {
			m[o.suffixVar] = path
		}
		return r, nil
	}
	ferr = mergeErrors(ferr, err)
	return result{}, ferr
}
