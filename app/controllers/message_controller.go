package controllers

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/kooroshh/fiber-boostrap/app/repository"
	"github.com/kooroshh/fiber-boostrap/pkg/response"
)

func GetHistory(ctx *fiber.Ctx) error {
	resp, err := repository.GetAllMessage(ctx.Context())
	if err != nil {
		fmt.Println(err)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "internal server error", nil)
	}
	return response.SendSuccessResponse(ctx, resp)
}
