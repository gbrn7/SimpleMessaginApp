package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/kooroshh/fiber-boostrap/app/controllers"
)

type ApiRouter struct{}

func (h ApiRouter) InstallRouter(app *fiber.App) {
	api := app.Group("/api", limiter.New())
	api.Get("/", func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Hello from api",
		})
	})

	userGroup := app.Group("/user")
	userv1Group := userGroup.Group("/v1")

	userv1Group.Post("/register", controllers.Register)
	userv1Group.Post("/login", controllers.Login)
	userv1Group.Delete("/logout", MiddlewareValidateAuth, controllers.Logout)
	userv1Group.Put("/refresh-token", MiddlewareRefreshToken, controllers.RefreshToken)

	messageGroup := app.Group("/message")
	messageV1Group := messageGroup.Group("v1")
	messageV1Group.Get("/history", MiddlewareValidateAuth, controllers.GetHistory)
}

func NewApiRouter() *ApiRouter {
	return &ApiRouter{}
}
