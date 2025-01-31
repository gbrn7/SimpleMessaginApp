package controllers

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kooroshh/fiber-boostrap/app/models"
	"github.com/kooroshh/fiber-boostrap/app/repository"
	"github.com/kooroshh/fiber-boostrap/pkg/jwt_token"
	"github.com/kooroshh/fiber-boostrap/pkg/response"
	"golang.org/x/crypto/bcrypt"
)

func Register(ctx *fiber.Ctx) error {
	user := new(models.User)
	err := ctx.BodyParser(user)
	if err != nil {
		errResponse := fmt.Errorf("failed to parse request: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}
	err = user.Validate()
	if err != nil {
		errResponse := fmt.Errorf("failed to validate request: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		errResponse := fmt.Errorf("failed to encrypt the password: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	user.Password = string(hashedPassword)

	err = repository.InsertNewUser(ctx.Context(), user)
	if err != nil {
		errResponse := fmt.Errorf("failed to insert new user: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	resp := user
	resp.Password = ""

	return response.SendSuccessResponse(ctx, resp)
}

func Login(ctx *fiber.Ctx) error {

	var (
		loginReq = new(models.LoginRequest)
		resp     = models.LoginResponse{}
		now      = time.Now()
	)

	err := ctx.BodyParser(loginReq)
	if err != nil {
		errResponse := fmt.Errorf("failed to parse request: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	err = loginReq.Validate()
	if err != nil {
		errResponse := fmt.Errorf("failed to validate request: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	user, err := repository.GetUserByUsername(ctx.Context(), loginReq.Username)
	if err != nil {
		errResponse := fmt.Errorf("failed to get username: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, errResponse.Error(), nil)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		errResponse := fmt.Errorf("failed to check password: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, errResponse.Error(), nil)
	}

	token, err := jwt_token.GenerateToken(ctx.Context(), user.Username, user.Fullname, "token", now)
	if err != nil {
		errResponse := fmt.Errorf("failed to generate token: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, errResponse.Error(), nil)
	}

	refreshToken, err := jwt_token.GenerateToken(ctx.Context(), user.Username, user.Fullname, "refresh_token", now)
	if err != nil {
		errResponse := fmt.Errorf("failed to generate token: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, errResponse.Error(), nil)
	}

	userSesion := models.UserSession{
		UserID:              int(user.ID),
		Token:               token,
		RefreshToken:        refreshToken,
		TokenExpired:        now.Add(jwt_token.MapTypeToken["token"]),
		RefreshTokenExpired: now.Add(jwt_token.MapTypeToken["refresh_token"]),
	}

	err = repository.InsertNewUserSession(ctx.Context(), &userSesion)
	if err != nil {
		errResponse := fmt.Errorf("failed insert user session: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, errResponse.Error(), nil)
	}

	resp.Username = user.Fullname
	resp.Fullname = user.Username
	resp.Token = token
	resp.RefreshToken = refreshToken

	return response.SendSuccessResponse(ctx, resp)
}

func Logout(ctx *fiber.Ctx) error {
	token := ctx.Get("Authorization")
	err := repository.DeleteUserSessionByToken(ctx.Context(), token)
	if err != nil {
		errResponse := fmt.Errorf("failed to delete user session: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	return response.SendSuccessResponse(ctx, nil)
}

func RefreshToken(ctx *fiber.Ctx) error {

	now := time.Now()
	refreshToken := ctx.Get("Authorization")
	username := ctx.Locals("username").(string)
	fullName := ctx.Locals("full_name").(string)

	token, err := jwt_token.GenerateToken(ctx.Context(), username, fullName, "token", now)
	if err != nil {
		errResponse := fmt.Errorf("failed to generate token: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, "failed to generate token", nil)
	}

	err = repository.UpdateUserSession(ctx.Context(), token, now.Add(jwt_token.MapTypeToken["token"]), refreshToken)
	if err != nil {
		errResponse := fmt.Errorf("failed to update token: %s", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, errResponse.Error(), nil)
	}

	return response.SendSuccessResponse(ctx, fiber.Map{
		"token": token,
	})
}
