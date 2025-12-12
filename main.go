package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"zatrano/configs/csrfconfig"
	"zatrano/configs/databaseconfig"
	"zatrano/configs/envconfig"
	"zatrano/configs/fileconfig"
	"zatrano/configs/logconfig"
	"zatrano/configs/redisconfig"
	"zatrano/configs/sessionconfig"
	"zatrano/middlewares"
	"zatrano/packages/flashmessages"
	"zatrano/packages/templatehelpers"
	"zatrano/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"go.uber.org/zap"
)

func main() {
	envconfig.LoadIfDev()

	logconfig.InitLogger()
	defer logconfig.SyncLogger()

	appEnv := envconfig.String("APP_ENV", "development")
	logconfig.SLog.Infow("Runtime",
		"env", appEnv,
		"num_cpu", runtime.NumCPU(),
		"gomaxprocs", runtime.GOMAXPROCS(0),
	)

	databaseconfig.InitDB()
	defer databaseconfig.CloseDB()

	redisconfig.InitRedis()

	sessionconfig.InitSession()

	fileconfig.InitFileConfig()
	fileconfig.Config.SetAllowedExtensions("invitations", []string{"jpg", "jpeg", "png", "webp"})
	fileconfig.Config.SetAllowedExtensions("post-categories", []string{"jpg", "jpeg", "png", "webp"})

	engine := html.New("./views", ".html")
	engine.AddFunc("getFlashMessages", flashmessages.GetFlashMessages)
	engine.AddFuncMap(templatehelpers.TemplateHelpers())
	if !envconfig.IsProd() {
		engine.Reload(true)
	}

	app := fiber.New(fiber.Config{
		Views:       engine,
		Prefork:     false,
		IdleTimeout: 60 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		BodyLimit: 10 * 1024 * 1024,

		EnableTrustedProxyCheck: true,
		TrustedProxies:          []string{"127.0.0.1", "::1"},
		ProxyHeader:             "CF-Connecting-IP",

		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			message := "Internal Server Error"
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
				if !envconfig.IsProd() {
					message = e.Message
				}
			}

			if code == 408 {
				logconfig.SLog.Infow("Fiber timeout (ignored)", "path", c.Path())
			} else {
				logconfig.Log.Error("Fiber request error",
					zap.Error(err),
					zap.Int("status_code", code),
					zap.String("method", c.Method()),
					zap.String("path", c.Path()),
					zap.String("ip", c.IP()),
				)
			}
			return c.Status(code).SendString(message)
		},
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		db, _ := databaseconfig.GetDB().DB()
		dbOk := db.Ping() == nil

		redisClient := redisconfig.GetClient()
		_, redisErr := redisClient.Ping(c.Context()).Result()
		redisOk := redisErr == nil

		allOk := dbOk && redisOk
		status := 200
		if !allOk {
			status = 503
		}

		return c.Status(status).JSON(fiber.Map{
			"ok":        allOk,
			"database":  dbOk,
			"redis":     redisOk,
			"timestamp": time.Now().Unix(),
		})
	})

	app.Use(func(c *fiber.Ctx) error {
		path := c.Path()
		if strings.HasPrefix(path, "/.well-known") {
			return c.SendStatus(fiber.StatusNoContent)
		}
		return c.Next()
	})

	app.Use(recover.New())
	app.Use(middlewares.ZapLogger())

	app.Static("/", "./public", fiber.Static{
		ByteRange: true,
		Browse:    false,
	})
	app.Static("/uploads", fileconfig.Config.BasePath, fiber.Static{
		ByteRange: true,
		Browse:    false,
	})

	app.Use(csrfconfig.SetupCSRF())

	routes.SetupRoutes(app)

	startServer(app)
}

func startServer(app *fiber.App) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	port := envconfig.Int("APP_PORT", 3000)
	host := envconfig.String("APP_HOST", "127.0.0.1")
	address := host + ":" + strconv.Itoa(port)

	baseURL := envconfig.String("APP_BASE_URL", "")
	if baseURL == "" {
		if envconfig.IsProd() {
			logconfig.Log.Fatal("APP_BASE_URL production ortamda boş olamaz")
		} else {
			baseURL = "http://localhost:" + strconv.Itoa(port)
		}
	}
	if envconfig.IsProd() && !strings.HasPrefix(baseURL, "https://") {
		logconfig.Log.Warn("APP_BASE_URL HTTPS değil, production için önerilmez", zap.String("base_url", baseURL))
	}

	go func() {
		logconfig.SLog.Infow("Uygulama dinleniyor",
			"env", envconfig.String("APP_ENV", "development"),
			"listen", address,
			"base_url", baseURL,
		)
		if err := app.Listen(address); err != nil {
			logconfig.Log.Fatal("Sunucu dinlenemedi", zap.String("address", address), zap.Error(err))
		}
	}()

	<-ctx.Done()
	logconfig.Log.Info("Kapatma sinyali alındı, uygulama kapatılıyor...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		logconfig.Log.Error("Sunucu kapatılırken hata oluştu", zap.Error(err))
	} else {
		logconfig.Log.Info("Sunucu başarıyla kapatıldı")
	}

	logconfig.Log.Info("Uygulama başarıyla sonlandırıldı.")
}
