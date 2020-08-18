package stdlib

import (
	"net"
	"net/http"
	"strings"
)

// Option is used to define Middleware configuration.
type Option interface {
	apply(*Middleware)
}

type option func(*Middleware)

func (o option) apply(middleware *Middleware) {
	o(middleware)
}

// ErrorHandler is an handler used to inform when an error has occurred.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// WithErrorHandler will configure the Middleware to use the given ErrorHandler.
func WithErrorHandler(handler ErrorHandler) Option {
	return option(func(middleware *Middleware) {
		middleware.OnError = handler
	})
}

// DefaultErrorHandler is the default ErrorHandler used by a new Middleware.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	panic(err)
}

// LimitReachedHandler is an handler used to inform when the limit has exceeded.
type LimitReachedHandler func(w http.ResponseWriter, r *http.Request)

// WithLimitReachedHandler will configure the Middleware to use the given LimitReachedHandler.
func WithLimitReachedHandler(handler LimitReachedHandler) Option {
	return option(func(middleware *Middleware) {
		middleware.OnLimitReached = handler
	})
}

// DefaultLimitReachedHandler is the default LimitReachedHandler used by a new Middleware.
func DefaultLimitReachedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Limit exceeded", http.StatusTooManyRequests)
}

// WithExcludedKey will configure the Middleware to ignore key(s) using the given function.
func WithExcludedKey(handler func(string) bool) Option {
	return option(func(middleware *Middleware) {
		middleware.ExcludedKey = handler
	})
}

type KeyGetter func(r *http.Request) string

func DefaultKeyGetter(r *http.Request) string {
	return DefaultKeyOptions.GetIPKey(r)
}

// WithKeyGetter will configure the Middleware to use the given KeyGetter.
func WithKeyGetter(handler KeyGetter) Option {
	return option(func(middleware *Middleware) {
		middleware.KeyGetter = handler
	})
}

var (
	// DefaultIPv4Mask defines the default IPv4 mask used to obtain user IP.
	DefaultIPv4Mask = net.CIDRMask(32, 32)
	// DefaultIPv6Mask defines the default IPv6 mask used to obtain user IP.
	DefaultIPv6Mask = net.CIDRMask(128, 128)
)

type KeyOptions struct {
	// IPv4Mask defines the mask used to obtain a IPv4 address.
	IPv4Mask net.IPMask
	// IPv6Mask defines the mask used to obtain a IPv6 address.
	IPv6Mask net.IPMask
	// TrustForwardHeader enable parsing of X-Real-IP and X-Forwarded-For headers to obtain user IP.
	TrustForwardHeader bool
}

var DefaultKeyOptions = &KeyOptions{
	IPv4Mask:           DefaultIPv4Mask,
	IPv6Mask:           DefaultIPv6Mask,
	TrustForwardHeader: true,
}

// GetIPKey extracts IP from request and returns hashed IP to use as store key.
func (o *KeyOptions) GetIPKey(r *http.Request) string {
	return GetIPWithMask(r, o).String()
}

// GetIP returns IP address from request.
// If options is defined and TrustForwardHeader is true, it will lookup IP in
// X-Forwarded-For and X-Real-IP headers.
func GetIP(r *http.Request, options ...*KeyOptions) net.IP {
	if len(options) >= 1 && options[0].TrustForwardHeader {
		ip := r.Header.Get("X-Forwarded-For")
		if ip != "" {
			parts := strings.SplitN(ip, ",", 2)
			part := strings.TrimSpace(parts[0])
			return net.ParseIP(part)
		}

		ip = strings.TrimSpace(r.Header.Get("X-Real-IP"))
		if ip != "" {
			return net.ParseIP(ip)
		}
	}

	remoteAddr := strings.TrimSpace(r.RemoteAddr)
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return net.ParseIP(remoteAddr)
	}

	return net.ParseIP(host)
}

// GetIPWithMask returns IP address from request by applying a mask.
func GetIPWithMask(r *http.Request, options ...*KeyOptions) net.IP {
	if len(options) == 0 {
		return GetIP(r)
	}

	ip := GetIP(r, options[0])
	if ip.To4() != nil {
		return ip.Mask(options[0].IPv4Mask)
	}
	if ip.To16() != nil {
		return ip.Mask(options[0].IPv6Mask)
	}
	return ip
}
