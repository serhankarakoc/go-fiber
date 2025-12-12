package routes

import (
	"zatrano/middlewares"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	app.Use(middlewares.GlobalRateLimit())
	app.Use(middlewares.FormPostRateLimit())

	app.Use(middlewares.SessionMiddleware())
	app.Use(middlewares.ZapLogger())

	registerAuthRoutes(app)
	registerDashboardRoutes(app)
	registerPanelRoutes(app)
	registerWebsiteRoutes(app)

	app.Use(func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).
			Render("errors/404", fiber.Map{})
	})
}

