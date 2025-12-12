package middlewares

import (
	"strings"
	"time"

	"zatrano/configs/logconfig"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

// ZapLogger — Geliştirilmiş, seviyelere göre düzenlenmiş logger middleware
func ZapLogger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Skip edilecek path'ler
		path := c.Path()
		if shouldSkipLog(path) {
			return c.Next()
		}

		// Başlangıç zamanı
		start := time.Now()

		// Request'i işle
		err := c.Next()

		// Metrikler
		latency := time.Since(start)
		status := c.Response().StatusCode()
		method := c.Method()
		ip := getRealIP(c)

		// Zap fields
		fields := []zap.Field{
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status", status),
			zap.Duration("latency", latency),
			zap.String("ip", ip),
		}

		// User-Agent (kısa ise)
		if ua := c.Get("User-Agent"); ua != "" && len(ua) < 200 {
			fields = append(fields, zap.String("user_agent", ua))
		}

		// Referer (opsiyonel)
		if referer := c.Get("Referer"); referer != "" && len(referer) < 500 {
			fields = append(fields, zap.String("referer", referer))
		}

		// Hata durumu
		if err != nil {
			fields = append(fields, zap.Error(err))
		}

		// Log seviyesini belirle ve logla
		logByStatus(fields, status, latency, method)

		return err
	}
}

// shouldSkipLog — Loglanmayacak path'leri belirle
func shouldSkipLog(path string) bool {
	// Health check, metrics, favicon
	if strings.HasPrefix(path, "/health") ||
		strings.HasPrefix(path, "/metrics") ||
		path == "/favicon.ico" {
		return true
	}

	// Statik dosyalar
	if strings.HasPrefix(path, "/public/") ||
		strings.HasPrefix(path, "/uploads/") {
		return true
	}

	// Well-known endpoints
	if strings.HasPrefix(path, "/.well-known/") {
		return true
	}

	return false
}

// getRealIP — Gerçek IP'yi al (Cloudflare/proxy desteği)
func getRealIP(c *fiber.Ctx) string {
	// Cloudflare
	if ip := c.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}

	// X-Forwarded-For
	if ip := c.Get("X-Forwarded-For"); ip != "" {
		ips := strings.Split(ip, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	return c.IP()
}

// logByStatus — Status code'a göre log level seç
func logByStatus(fields []zap.Field, status int, latency time.Duration, method string) {
	// Log mesajı
	msg := "request"

	// Özel mesajlar için
	if status >= 400 && status != 404 {
		msg = "client_error"
	} else if status >= 500 {
		msg = "server_error"
	} else if latency > time.Second {
		msg = "slow_request"
		fields = append(fields, zap.Bool("slow", true))
	}

	// Log level seçimi
	switch {
	case status >= 500:
		// 5xx Server Errors
		logconfig.Log.Error(msg, fields...)

	case status >= 400:
		// 4xx Client Errors (404 hariç)
		if status == 404 {
			// 404'leri info olarak logla (spam olmasın)
			logconfig.Log.Info(msg, fields...)
		} else {
			logconfig.Log.Warn(msg, fields...)
		}

	default:
		// 2xx/3xx Success
		// Sadece POST/PUT/DELETE veya yavaş istekleri logla
		if method != "GET" || latency > 500*time.Millisecond {
			logconfig.Log.Info(msg, fields...)
		} else {
			// Hızlı GET isteklerini debug olarak logla
			logconfig.Log.Debug(msg, fields...)
		}
	}
}
