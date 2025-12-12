package routes

import (
	handlers "zatrano/handlers/auth"
	"zatrano/middlewares"

	"github.com/gofiber/fiber/v2"
)

func registerAuthRoutes(app *fiber.App) {
	authHandler := handlers.NewAuthHandler()
	authGroup := app.Group("/auth")

	authGroup.Get("/login", middlewares.GuestMiddleware, authHandler.ShowLogin)
	authGroup.Post("/login",
		middlewares.GuestMiddleware,
		middlewares.LoginRateLimit(),
		authHandler.Login,
	)

	authGroup.Get("/logout", middlewares.AuthMiddleware, authHandler.Logout)
	authGroup.Get("/profile", middlewares.AuthMiddleware, authHandler.Profile)
	authGroup.Post("/profile/update-password",
		middlewares.AuthMiddleware,
		authHandler.UpdatePassword,
	)
	authGroup.Post("/profile/update-info",
		middlewares.AuthMiddleware,
		authHandler.UpdateInfo,
	)

	authGroup.Get("/register", middlewares.GuestMiddleware, authHandler.ShowRegister)
	authGroup.Post("/register",
		middlewares.GuestMiddleware,
		authHandler.Register,
	)

	authGroup.Get("/forgot-password", middlewares.GuestMiddleware, authHandler.ShowForgotPassword)
	authGroup.Post("/forgot-password",
		middlewares.GuestMiddleware,
		authHandler.ForgotPassword,
	)

	authGroup.Get("/reset-password", middlewares.GuestMiddleware, authHandler.ShowResetPassword)
	authGroup.Post("/reset-password",
		middlewares.GuestMiddleware,
		authHandler.ResetPassword,
	)

	authGroup.Get("/verify-email", middlewares.GuestMiddleware, authHandler.VerifyEmail)
	authGroup.Get("/resend-verification", middlewares.GuestMiddleware, authHandler.ShowResendVerification)
	authGroup.Post("/resend-verification",
		middlewares.GuestMiddleware,
		authHandler.ResendVerification,
	)

	authGroup.Get("/oauth/:provider/login",
		middlewares.GuestMiddleware,
		authHandler.OAuthLogin,
	)

	authGroup.Get("/oauth/:provider/callback",
		middlewares.GuestMiddleware,
		authHandler.OAuthCallback,
	)
}
