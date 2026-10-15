package api

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

// IP-based Rate Limiter mapping
var visitors = make(map[string]*rate.Limiter)
var mu sync.Mutex

func getVisitorLimiter(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := visitors[ip]
	if !exists {
		// Allow 5 requests per second, with a burst capacity of 10
		limiter = rate.NewLimiter(5, 10)
		visitors[ip] = limiter
	}
	return limiter
}

func RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr // Note: Use X-Forwarded-For if behind a reverse proxy
		limiter := getVisitorLimiter(ip)

		if !limiter.Allow() {
			http.Error(w, "429 Too Many Requests - Token bucket exhausted", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	}
}
