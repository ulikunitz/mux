# Notes on Mux

## ServeMux in standard library

[Documentation](https://pkg.go.dev/net/http#ServeMux)

ServeMux modifies the request:

> ServeMux also takes care of sanitizing the URL request path and the Host
> header, stripping the port number and redirecting any request containing . or
> .. elements or repeated slashes to an equivalent, cleaner URL.

Handler must do the following:

> If there is no registered handler that applies to the request, Handler returns
> a “page not found” handler and an empty pattern.

It appears also that the CONNECT method is handled specially.

## Proposal

[Discussion on github.com](https://github.com/golang/go/discussions/60227)

## Other muxes

[Gorilla mux](https://github.com/gorilla/mux)
