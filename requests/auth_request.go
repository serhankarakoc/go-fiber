package requests

import (
	"errors"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type LoginRequest struct {
	Email    string `form:"email" validate:"required,email"`
	Password string `form:"password" validate:"required,min=6"`
}

type RegisterRequest struct {
	Name            string `form:"name" validate:"required,min=3"`
	Email           string `form:"email" validate:"required,email"`
	Password        string `form:"password" validate:"required,min=8"`
	ConfirmPassword string `form:"confirm_password" validate:"required,eqfield=Password"`
}

type UpdatePasswordRequest struct {
	CurrentPassword string `form:"current_password" validate:"required,min=6"`
	NewPassword     string `form:"new_password" validate:"required,min=8,nefield=CurrentPassword"`
	ConfirmPassword string `form:"confirm_password" validate:"required,eqfield=NewPassword"`
}

type ForgotPasswordRequest struct {
	Email string `form:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token           string `form:"token" validate:"required"`
	NewPassword     string `form:"new_password" validate:"required,min=8"`
	ConfirmPassword string `form:"confirm_password" validate:"required,eqfield=NewPassword"`
}

type ResendVerificationRequest struct {
	Email string `form:"email" validate:"required,email"`
}

type UpdateInfoRequest struct {
	Name  string `form:"name" validate:"required,min=3"`
	Email string `form:"email" validate:"required,email"`
}

type VerifyEmailRequest struct {
	Token string `form:"token" validate:"required"`
}

func ParseAndValidateLoginRequest(c *fiber.Ctx) (LoginRequest, map[string]string, error) {
	var req LoginRequest

	if err := c.BodyParser(&req); err != nil {
		return req, make(map[string]string), errors.New("geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		validationErrors := GetLoginValidationErrors(err)
		return req, validationErrors, errors.New("lütfen giriş bilgilerinizi kontrol edin")
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	return req, make(map[string]string), nil
}

func ParseAndValidateRegisterRequest(c *fiber.Ctx) (RegisterRequest, map[string]string, error) {
	var req RegisterRequest

	if err := c.BodyParser(&req); err != nil {
		return req, make(map[string]string), errors.New("geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		validationErrors := GetRegisterValidationErrors(err)
		return req, validationErrors, errors.New("lütfen kayıt bilgilerinizi kontrol edin")
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)

	return req, make(map[string]string), nil
}

func ParseAndValidateUpdatePasswordRequest(c *fiber.Ctx) (UpdatePasswordRequest, map[string]string, error) {
	var req UpdatePasswordRequest

	if err := c.BodyParser(&req); err != nil {
		return req, make(map[string]string), errors.New("geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		validationErrors := GetUpdatePasswordValidationErrors(err)
		return req, validationErrors, errors.New("lütfen şifre bilgilerinizi kontrol edin")
	}

	return req, make(map[string]string), nil
}

func ParseAndValidateForgotPasswordRequest(c *fiber.Ctx) (ForgotPasswordRequest, map[string]string, error) {
	var req ForgotPasswordRequest

	if err := c.BodyParser(&req); err != nil {
		return req, make(map[string]string), errors.New("geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		validationErrors := GetForgotPasswordValidationErrors(err)
		return req, validationErrors, errors.New("lütfen e-posta adresinizi kontrol edin")
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	return req, make(map[string]string), nil
}

func ParseAndValidateResetPasswordRequest(c *fiber.Ctx) (ResetPasswordRequest, map[string]string, error) {
	var req ResetPasswordRequest

	if err := c.BodyParser(&req); err != nil {
		return req, make(map[string]string), errors.New("geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		validationErrors := GetResetPasswordValidationErrors(err)
		return req, validationErrors, errors.New("lütfen şifre bilgilerinizi kontrol edin")
	}

	return req, make(map[string]string), nil
}

func ParseAndValidateResendVerificationRequest(c *fiber.Ctx) (ResendVerificationRequest, map[string]string, error) {
	var req ResendVerificationRequest

	if err := c.BodyParser(&req); err != nil {
		return req, make(map[string]string), errors.New("geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		validationErrors := GetResendVerificationValidationErrors(err)
		return req, validationErrors, errors.New("lütfen e-posta adresinizi kontrol edin")
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	return req, make(map[string]string), nil
}

func ParseAndValidateUpdateInfoRequest(c *fiber.Ctx) (UpdateInfoRequest, map[string]string, error) {
	var req UpdateInfoRequest

	if err := c.BodyParser(&req); err != nil {
		return req, make(map[string]string), errors.New("geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		validationErrors := GetUpdateInfoValidationErrors(err)
		return req, validationErrors, errors.New("lütfen bilgilerinizi kontrol edin")
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)

	return req, make(map[string]string), nil
}

func ParseAndValidateVerifyEmailRequest(c *fiber.Ctx) (VerifyEmailRequest, map[string]string, error) {
	var req VerifyEmailRequest

	if err := c.BodyParser(&req); err != nil {
		return req, make(map[string]string), errors.New("geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		validationErrors := GetVerifyEmailValidationErrors(err)
		return req, validationErrors, errors.New("lütfen token'ı kontrol edin")
	}

	return req, make(map[string]string), nil
}

func GetLoginValidationErrors(err error) map[string]string {
	errorMessages := map[string]string{
		"Email_required":    "E-posta adresi zorunludur",
		"Email_email":       "Geçerli bir e-posta adresi giriniz",
		"Password_required": "Şifre zorunludur",
		"Password_min":      "Şifre en az 6 karakter olmalıdır",
	}
	return CommonValidationErrors(err, errorMessages)
}

func GetRegisterValidationErrors(err error) map[string]string {
	errorMessages := map[string]string{
		"Name_required":            "İsim zorunludur",
		"Name_min":                 "İsim en az 3 karakter olmalıdır",
		"Email_required":           "E-posta zorunludur",
		"Email_email":              "Geçerli bir e-posta adresi giriniz",
		"Password_required":        "Şifre zorunludur",
		"Password_min":             "Şifre en az 8 karakter olmalıdır",
		"ConfirmPassword_required": "Şifre tekrarı zorunludur",
		"ConfirmPassword_eqfield":  "Şifreler eşleşmiyor",
	}
	return CommonValidationErrors(err, errorMessages)
}

func GetUpdatePasswordValidationErrors(err error) map[string]string {
	errorMessages := map[string]string{
		"CurrentPassword_required": "Mevcut şifre zorunludur",
		"CurrentPassword_min":      "Mevcut şifre en az 6 karakter olmalıdır",
		"NewPassword_required":     "Yeni şifre zorunludur",
		"NewPassword_min":          "Yeni şifre en az 8 karakter olmalıdır",
		"NewPassword_nefield":      "Yeni şifre mevcut şifreden farklı olmalıdır",
		"ConfirmPassword_required": "Şifre tekrarı zorunludur",
		"ConfirmPassword_eqfield":  "Yeni şifreler uyuşmuyor",
	}
	return CommonValidationErrors(err, errorMessages)
}

func GetForgotPasswordValidationErrors(err error) map[string]string {
	errorMessages := map[string]string{
		"Email_required": "E-posta zorunludur",
		"Email_email":    "Geçerli bir e-posta adresi giriniz",
	}
	return CommonValidationErrors(err, errorMessages)
}

func GetResetPasswordValidationErrors(err error) map[string]string {
	errorMessages := map[string]string{
		"Token_required":           "Token zorunludur",
		"NewPassword_required":     "Yeni şifre zorunludur",
		"NewPassword_min":          "Yeni şifre en az 8 karakter olmalıdır",
		"ConfirmPassword_required": "Şifre onayı zorunludur",
		"ConfirmPassword_eqfield":  "Şifreler eşleşmiyor",
	}
	return CommonValidationErrors(err, errorMessages)
}

func GetResendVerificationValidationErrors(err error) map[string]string {
	errorMessages := map[string]string{
		"Email_required": "E-posta zorunludur",
		"Email_email":    "Geçerli bir e-posta adresi giriniz",
	}
	return CommonValidationErrors(err, errorMessages)
}

func GetUpdateInfoValidationErrors(err error) map[string]string {
	errorMessages := map[string]string{
		"Name_required":  "İsim zorunludur",
		"Name_min":       "İsim en az 3 karakter olmalıdır",
		"Email_required": "E-posta zorunludur",
		"Email_email":    "Geçerli bir e-posta adresi giriniz",
	}
	return CommonValidationErrors(err, errorMessages)
}

func GetVerifyEmailValidationErrors(err error) map[string]string {
	errorMessages := map[string]string{
		"Token_required": "Doğrulama token'ı zorunludur",
	}
	return CommonValidationErrors(err, errorMessages)
}
