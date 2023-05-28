// Package mux implements a mux as proposed in [Discussion].
//
// [Discussion]: https://github.com/golang/go/discussions/60227
package mux

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

type ctxKey int

const (
	varMapKey ctxKey = iota
)

// Vars retries the variable path elements from the request.
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
	if m == nil {
		return r
	}
	ctx := r.Context()
	ctx = context.WithValue(ctx, varMapKey, m)
	return r.WithContext(ctx)
}

// Mux is the the mux.
type Mux struct {
	mutex    sync.RWMutex
	patterns []*pattern
}

// New creates a new Mux instance.
func New() *Mux {
	return &Mux{}
}

func search(patterns []*pattern, p *pattern) int {
	i, j := 0, len(patterns)
	for i < j {
		h := int(uint(i+j) >> 1)
		if patterns[h].cmp(p) < 0 {
			i = h + 1
		} else {
			j = h
		}
	}
	return i
}

func (mux *Mux) Handle(pattern string, handler http.Handler) {
	if handler == nil {
		panic(errors.New("mux: handler is nil"))
	}
	p, err := parsePattern(pattern)
	if err != nil {
		panic(err)
	}
	p.handler = handler

	mux.mutex.Lock()
	defer mux.mutex.Unlock()

	i := search(mux.patterns, p)
	if i < len(mux.patterns) {
		if mux.patterns[i].cmp(p) == 0 {
			panic(fmt.Errorf(
				"mux: pattern %q and %q are conflicting",
				p.str, mux.patterns[i].str))
		}
		mux.patterns = append(mux.patterns[:i+1], mux.patterns[i:]...)
		mux.patterns[i] = p
	} else {
		mux.patterns = append(mux.patterns, p)
	}
}

func (mux *Mux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.Handle(pattern, http.HandlerFunc(handler))
}

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	url := *r.URL
	url.RawPath = url.EscapedPath() + "/"
	http.Redirect(w, r, url.String(), http.StatusFound)
}

// HandlerReq returns the handler and the request. We need to return the request
// because we modify the context of the request to store the variable segment
// map.
func (mux *Mux) HandlerReq(r *http.Request) (h http.Handler, pattern string, s *http.Request) {
	mux.mutex.RLock()
	defer mux.mutex.RUnlock()

	for _, p := range mux.patterns {
		if s, redirect, ok := p.match(r); ok {
			if redirect {
				return http.HandlerFunc(handleRedirect),
					p.str, s
			}
			return p.handler, p.str, s
		}
	}
	return nil, "", nil
}

func (mux *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h, _, s := mux.HandlerReq(r)
	if h != nil {
		h.ServeHTTP(w, s)
	}
}

type segType byte

const (
	static segType = iota
	wildcard
	extension
	wcExtension
)

// segment represents a segment pattern
type segment struct {
	segType segType
	str     string
}

type pattern struct {
	str       string
	host      string
	method    string
	path      []segment
	wildcards int
	handler   http.Handler
}

func (p *pattern) cmp(q *pattern) int {
	if p == q {
		return 0
	}
	if p.host != "" {
		if q.host == "" {
			return -1
		}
		if p.host < q.host {
			return -1
		} else if p.host > q.host {
			return 1
		}
	} else if q.host != "" {
		return 1
	}
	if p.method != "" {
		if q.method == "" {
			return -1
		}
		if p.method < q.method {
			return -1
		} else if p.method > q.method {
			return 1
		}
	} else if q.host != "" {
		return 1
	}
	pp, qp := p.path, q.path
	for {
		if len(pp) == 0 {
			if len(qp) == 0 {
				return 0
			}
			return -1
		} else if len(qp) == 0 {
			return 1
		}
		ps, qs := pp[0], qp[0]
		switch ps.segType {
		case static:
			switch qs.segType {
			case static:
				if ps.str < qs.str {
					return -1
				} else if ps.str > qs.str {
					return 1
				}
			default:
				return -1
			}
		case wildcard:
			switch qs.segType {
			case static:
				return 1
			case wildcard:
				break
			default:
				return -1
			}
		case wcExtension, extension:
			switch qs.segType {
			case static, wildcard:
				return 1
			}
			return 0
		}
		pp, qp = pp[1:], qp[1:]
	}
}

func host(r *http.Request) string {
	if host, _, found := strings.Cut(r.Host, ":"); found {
		return host
	}
	return r.Host
}

func (p *pattern) match(r *http.Request) (s *http.Request, redirect, ok bool) {
	if p.host != "" && p.host != host(r) {
		return nil, false, false
	}
	if p.method != "" && p.method != r.Method {
		return nil, false, false
	}
	path := r.URL.EscapedPath()
	slash := false
	if path[0] == '/' {
		path = path[1:]
		slash = true
	}
	var m map[string]string
	if p.wildcards > 0 {
		m = make(map[string]string, p.wildcards)
	}
	for _, seg := range p.path {
		switch seg.segType {
		case wcExtension:
			m[seg.str] = path
			fallthrough
		case extension:
			redirect = path == "" && !slash
			return withVarMap(r, m), redirect, true
		}
		var s, r string
		s, r, slash = strings.Cut(path, "/")
		switch seg.segType {
		case static:
			if seg.str != s {
				return nil, false, false
			}
		case wildcard:
			m[seg.str] = s
		}
		path = r
	}
	if path != "" || slash {
		return nil, false, false
	}
	return withVarMap(r, m), false, true
}

var wcRegexp = regexp.MustCompile(`^\{([_\pL][_\pL\p{Nd}]*)(\.\.\.)?\}$`)

func matchWildcard(s string) (wc string, ext bool, ok bool) {
	m := wcRegexp.FindStringSubmatch(s)
	if m == nil {
		return "", false, false
	}
	wc = m[1]
	if m[2] == "..." {
		ext = true
	}
	return wc, ext, true
}

var staticRegexp = regexp.MustCompile(
	`^(?:%[0-9a-fA-F]{2}|[-:@!$&'()*+,;=A-Za-z0-9._~])*$`)

func matchStatic(s string) bool {
	return staticRegexp.MatchString(s)
}

func parsePattern(s string) (p *pattern, err error) {
	p = &pattern{str: s}
	method, r, found := strings.Cut(s, " ")
	if found {
		switch method {
		case http.MethodGet:
		case http.MethodHead:
		case http.MethodPost:
		case http.MethodPut:
		case http.MethodPatch:
		case http.MethodDelete:
		case http.MethodConnect:
		case http.MethodOptions:
		case http.MethodTrace:
		default:
			return nil, fmt.Errorf(
				"mux: method %q not supported", method)
		}
		p.method = method
		s = strings.TrimLeft(r, " ")
	}
	if s[0] != '/' {
		host, r, found := strings.Cut(s, "/")
		if !found {
			return nil, fmt.Errorf(
				"mux: pattern %q doesn't have a path component",
				p.str)
		}
		p.host = host
		s = r
	} else {
		s = s[1:]
	}
	for {
		if s == "" {
			p.path = append(p.path, segment{
				segType: extension,
			})
			break
		}
		if seg, r, found := strings.Cut(s, "/"); found {
			if wc, ext, ok := matchWildcard(seg); ok {
				if ext {
					return nil, fmt.Errorf(
						"mux: ... extension non-last segment of %q",
						p.str)
				}
				p.path = append(p.path, segment{
					segType: wildcard,
					str:     wc,
				})
				s = r
				continue
			}
			if !matchStatic(seg) {
				return nil, fmt.Errorf(
					"mux: %q is not a segment", seg)
			}
			p.path = append(p.path, segment{
				segType: static,
				str:     seg,
			})
			s = r
			continue
		}
		if s == "{$}" {
			break
		}
		if wc, ext, ok := matchWildcard(s); ok {
			if ext {
				p.path = append(p.path, segment{
					segType: wcExtension,
					str:     wc,
				})
				break
			}
			p.path = append(p.path, segment{
				segType: wildcard,
				str:     wc,
			})
			break
		}
		if !matchStatic(s) {
			return nil, fmt.Errorf(
				"mux: %q is not a path element", s)
		}
		p.path = append(p.path, segment{
			segType: static,
			str:     s,
		})
		break
	}
	for _, seg := range p.path {
		switch seg.segType {
		case wildcard, wcExtension:
			p.wildcards++
		}
	}
	return p, nil
}
