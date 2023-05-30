# mux - Multiplexer for HTTP requests

This Go language module supports a multiplexer for HTTP requests that extends
the pattern language of the ServeMux multiplexer of the
[net/http](https://pkg.go.dev/net/http) package of the Go standard library. The
module supports now method selectors and wildcard variables in request pattern.

Those improvements have been proposed in a 
[discussion](https://github.com/golang/go/discussions/60227) of the
[Go language Github repository](https://github.com/golang/go).

The implementation is fully functional, but not widely tested. Please report any
issues in the [mux Github repo](https://github.com/ulikunitz/mux).

The documentation can be found at https://pkg.go.dev/github.com/ulikunitz/mux.

## Installation

Import it in your program and run
```
$ go get github.com/ulikunitz/mux
```
if required.

## Copyright

This code contains small subroutines from the Go net/http package. I added the
Go Authors copyright to the BSD 3-Clause license.
