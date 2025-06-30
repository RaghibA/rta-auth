package monitoring

import (
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	HttpRequestDuration *prometheus.HistogramVec
	HttpRequestStatus   *prometheus.CounterVec
}

// NewMetrics creates a new Metrics instance and registers Prometheus metrics.
// Params: None
// Returns:
// - *Metrics: a pointer to the created Metrics instance
func NewMetrics() *Metrics {
	m := &Metrics{
		HttpRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_dur_sec",
				Help:    "Duration of HTTP requests measured in seconds.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "route"},
		),
		HttpRequestStatus: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_request_status_ct",
				Help: "Total HTTP requests",
			},
			[]string{"method", "route", "status_code"},
		),
	}

	prometheus.MustRegister(m.HttpRequestDuration, m.HttpRequestStatus)
	log.Println("Prometheus Collector Registered")

	return m
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code for the response.
// Params:
// - code: int - the HTTP status code
// Returns: None
func (sr *statusRecorder) WriteHeader(code int) {
	sr.statusCode = code
	sr.ResponseWriter.WriteHeader(code)
}

// MetricMonitoring is a middleware that records metrics for HTTP requests.
// Params:
// - next: http.Handler - the next HTTP handler in the chain
// Returns:
// - http.Handler: the HTTP handler with metrics recording
func (m *Metrics) MetricMonitoring(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		route := r.URL.Path
		status := http.StatusText(rw.statusCode)

		m.HttpRequestDuration.WithLabelValues(r.Method, route).Observe(duration)
		m.HttpRequestStatus.WithLabelValues(r.Method, route, status).Inc()
	})
}

// PrometheusHandler returns an HTTP handler for Prometheus metrics.
// Params: None
// Returns:
// - http.Handler: the HTTP handler for Prometheus metrics
func PrometheusHandler() http.Handler {
	return promhttp.Handler()
}
