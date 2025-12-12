package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"zatrano/configs/logconfig"
	"zatrano/models"
	"zatrano/repositories"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type ServiceError string

func (e ServiceError) Error() string { return string(e) }

const (
	ErrInvalidCredentials       ServiceError = "geçersiz kimlik bilgileri"
	ErrUserNotFound             ServiceError = "kullanıcı bulunamadı"
	ErrUserInactive             ServiceError = "kullanıcı aktif değil"
	ErrCurrentPasswordIncorrect ServiceError = "mevcut şifre hatalı"
	ErrPasswordTooShort         ServiceError = "yeni şifre en az 6 karakter olmalıdır"
	ErrPasswordSameAsOld        ServiceError = "yeni şifre mevcut şifre ile aynı olamaz"
	ErrAuthGeneric              ServiceError = "kimlik doğrulaması sırasında bir hata oluştu"
	ErrProfileGeneric           ServiceError = "profil bilgileri alınırken hata"
	ErrUpdatePasswordGeneric    ServiceError = "şifre güncellenirken bir hata oluştu"
	ErrHashingFailed            ServiceError = "yeni şifre oluşturulurken hata"
	ErrDatabaseUpdateFailed     ServiceError = "veritabanı güncellemesi başarısız oldu"
	ErrEmailSendFailed          ServiceError = "e-posta gönderilemedi"
	ErrEmailAlreadyExists       ServiceError = "bu e-posta adresi zaten kayıtlı"
)

type IAuthService interface {
	Authenticate(email, password string) (*models.User, error)
	RegisterUser(ctx context.Context, name, email, password string) error
	VerifyEmail(token string) error
	ResendVerificationLink(email string) error

	SendPasswordResetLink(email string) error
	ResetPassword(token, newPassword string) error
	UpdatePassword(ctx context.Context, userID uint, currentPass, newPassword string) error

	GetUserProfile(ctx context.Context, id uint) (*models.User, error)
	UpdateUserInfo(ctx context.Context, userID uint, name, email string) error

	FindOrCreateOAuthUser(providerID, email, name, provider string) (*models.User, error)
}

type AuthService struct {
	repo        repositories.IAuthRepository
	mailService IMailService
}

func NewAuthService() IAuthService {
	return &AuthService{
		repo:        repositories.NewAuthRepository(),
		mailService: NewMailService(),
	}
}

func (s *AuthService) logAuthSuccess(email string, userID uint) {
	logconfig.Log.Info("Kimlik doğrulama başarılı",
		zap.String("email", email),
		zap.Uint("user_id", userID))
}

func (s *AuthService) logDBError(action string, err error, fields ...zap.Field) {
	fields = append(fields, zap.Error(err))
	logconfig.Log.Error(action+" hatası (DB)", fields...)
}

func (s *AuthService) logWarn(action string, fields ...zap.Field) {
	logconfig.Log.Warn(action+" başarısız", fields...)
}

func (s *AuthService) generateToken() string {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		logconfig.Log.Error("Token oluşturulamadı", zap.Error(err))
		return ""
	}
	return hex.EncodeToString(tokenBytes)
}

func (s *AuthService) getUserByEmail(email string) (*models.User, error) {
	user, err := s.repo.FindUserByEmail(email)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logWarn("Kullanıcı bulunamadı", zap.String("email", email))
			return nil, ErrUserNotFound
		}
		s.logDBError("Kullanıcı sorgulama", err, zap.String("email", email))
		return nil, ErrAuthGeneric
	}
	return user, nil
}

func (s *AuthService) getUserByID(id uint) (*models.User, error) {
	user, err := s.repo.FindUserByID(id)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logWarn("Kullanıcı bulunamadı", zap.Uint("user_id", id))
			return nil, ErrUserNotFound
		}
		s.logDBError("Kullanıcı sorgulama", err, zap.Uint("user_id", id))
		return nil, ErrProfileGeneric
	}
	return user, nil
}

func (s *AuthService) comparePasswords(hashedPassword, plainPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}

func (s *AuthService) hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (s *AuthService) Authenticate(email, password string) (*models.User, error) {
	user, err := s.getUserByEmail(email)
	if err != nil {
		return nil, err
	}
	if !user.IsActive {
		s.logWarn("Kullanıcı aktif değil",
			zap.String("email", email),
			zap.Uint("user_id", user.ID))
		return nil, ErrUserInactive
	}
	if err := s.comparePasswords(user.Password, password); err != nil {
		s.logWarn("Geçersiz parola",
			zap.String("email", email),
			zap.Uint("user_id", user.ID))
		return nil, ErrInvalidCredentials
	}
	s.logAuthSuccess(email, user.ID)
	return user, nil
}

func (s *AuthService) RegisterUser(ctx context.Context, name, email, password string) error {
	existingUser, err := s.repo.FindUserByEmail(email)
	if err == nil && existingUser != nil {
		return ErrEmailAlreadyExists
	}

	verificationToken := s.generateToken()
	if verificationToken == "" {
		return errors.New("token oluşturulamadı")
	}

	hashedPassword, err := s.hashPassword(password)
	if err != nil {
		s.logDBError("Şifre hashleme", err, zap.String("email", email))
		return ErrHashingFailed
	}

	user := &models.User{
		Name:              name,
		Email:             email,
		Password:          hashedPassword,
		UserTypeID:        2,
		EmailVerified:     false,
		VerificationToken: verificationToken,
		BaseModel: models.BaseModel{
			IsActive: true,
		},
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		s.logDBError("Kullanıcı oluşturma", err, zap.String("email", email))
		return ErrDatabaseUpdateFailed
	}

	if err := s.sendVerificationEmail(user.Email, verificationToken); err != nil {
		logconfig.Log.Warn("Doğrulama email'i gönderilemedi",
			zap.String("email", user.Email),
			zap.Error(err))
	}

	logconfig.Log.Info("Kullanıcı kaydı başarılı",
		zap.String("email", email),
		zap.Uint("user_id", user.ID))

	return nil
}

func (s *AuthService) sendVerificationEmail(email, token string) error {
	baseURL := os.Getenv("APP_BASE_URL")
	if baseURL == "" {
		return errors.New("APP_BASE_URL ortam değişkeni tanımlı değil")
	}

	verificationLink := fmt.Sprintf("%s/auth/verify-email?token=%s", baseURL, token)
	subject := "Email Doğrulama"
	body := fmt.Sprintf(
		"Merhaba,\n\nEmail adresinizi doğrulamak için lütfen aşağıdaki linke tıklayın:\n%s\n\nTeşekkürler.",
		verificationLink,
	)

	return s.mailService.SendMail(email, subject, body)
}

func (s *AuthService) VerifyEmail(token string) error {
	user, err := s.repo.FindUserByVerificationToken(token)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return ErrAuthGeneric
	}

	user.EmailVerified = true
	user.VerificationToken = ""

	if err := s.repo.UpdateUser(context.Background(), user); err != nil {
		s.logDBError("Email doğrulama", err,
			zap.Uint("user_id", user.ID),
			zap.String("email", user.Email))
		return ErrDatabaseUpdateFailed
	}

	logconfig.Log.Info("Email doğrulandı",
		zap.Uint("user_id", user.ID),
		zap.String("email", user.Email))

	return nil
}

func (s *AuthService) ResendVerificationLink(email string) error {
	user, err := s.repo.FindUserByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return ErrAuthGeneric
	}

	if user.EmailVerified {
		return nil
	}

	verificationToken := s.generateToken()
	if verificationToken == "" {
		return errors.New("token oluşturulamadı")
	}

	user.VerificationToken = verificationToken
	if err := s.repo.UpdateUser(context.Background(), user); err != nil {
		s.logDBError("Verification token güncelleme", err,
			zap.String("email", email))
		return ErrDatabaseUpdateFailed
	}

	if err := s.sendVerificationEmail(user.Email, verificationToken); err != nil {
		logconfig.Log.Warn("Doğrulama email'i gönderilemedi",
			zap.String("email", user.Email),
			zap.Error(err))
		return ErrEmailSendFailed
	}

	logconfig.Log.Info("Doğrulama linki yeniden gönderildi",
		zap.String("email", email))

	return nil
}

func (s *AuthService) SendPasswordResetLink(email string) error {
	user, err := s.repo.FindUserByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return ErrAuthGeneric
	}

	resetToken := s.generateToken()
	if resetToken == "" {
		return errors.New("token oluşturulamadı")
	}

	user.ResetToken = resetToken
	if err := s.repo.UpdateUser(context.Background(), user); err != nil {
		s.logDBError("Reset token güncelleme", err,
			zap.String("email", email))
		return ErrDatabaseUpdateFailed
	}

	baseURL := os.Getenv("APP_BASE_URL")
	if baseURL == "" {
		return errors.New("APP_BASE_URL ortam değişkeni tanımlı değil")
	}

	resetLink := fmt.Sprintf("%s/auth/reset-password?token=%s", baseURL, resetToken)
	subject := "Şifre Sıfırlama"
	body := fmt.Sprintf(
		"Merhaba,\n\nŞifrenizi sıfırlamak için lütfen aşağıdaki linke tıklayın:\n%s\n\nLink 1 saat süreyle geçerlidir.",
		resetLink,
	)

	if err := s.mailService.SendMail(user.Email, subject, body); err != nil {
		logconfig.Log.Warn("Şifre sıfırlama email'i gönderilemedi",
			zap.String("email", user.Email),
			zap.Error(err))
		return ErrEmailSendFailed
	}

	logconfig.Log.Info("Şifre sıfırlama linki gönderildi",
		zap.String("email", email))

	return nil
}

func (s *AuthService) ResetPassword(token, newPassword string) error {
	user, err := s.repo.FindUserByResetToken(token)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return ErrAuthGeneric
	}

	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		s.logDBError("Şifre hashleme", err,
			zap.Uint("user_id", user.ID))
		return ErrHashingFailed
	}

	user.Password = hashedPassword
	user.ResetToken = ""

	if err := s.repo.UpdateUser(context.Background(), user); err != nil {
		s.logDBError("Şifre sıfırlama", err,
			zap.Uint("user_id", user.ID))
		return ErrDatabaseUpdateFailed
	}

	logconfig.Log.Info("Şifre sıfırlandı",
		zap.Uint("user_id", user.ID),
		zap.String("email", user.Email))

	return nil
}

func (s *AuthService) UpdatePassword(ctx context.Context, userID uint, currentPass, newPassword string) error {
	user, err := s.getUserByID(userID)
	if err != nil {
		return err
	}

	if user.Password == "" {
		if user.Provider == "" {
			s.logWarn("Şifre boş ama provider yok", zap.Uint("user_id", userID))
			return errors.New("provider bilgisi olmayan kullanıcı için şifre boş olamaz")
		}
		if len(newPassword) < 6 {
			s.logWarn("Yeni parola çok kısa", zap.Uint("user_id", userID))
			return ErrPasswordTooShort
		}
		hashedPassword, err := s.hashPassword(newPassword)
		if err != nil {
			s.logDBError("Parola hashleme", err, zap.Uint("user_id", userID))
			return ErrHashingFailed
		}
		user.Password = hashedPassword
		if err := s.repo.UpdateUser(ctx, user); err != nil {
			s.logDBError("Kullanıcı güncelleme", err, zap.Uint("user_id", userID))
			return ErrDatabaseUpdateFailed
		}
		logconfig.Log.Info("Sosyal giriş kullanıcısının parolası güncellendi", zap.Uint("user_id", userID))
		return nil
	}

	if err := s.comparePasswords(user.Password, currentPass); err != nil {
		s.logWarn("Mevcut parola hatalı", zap.Uint("user_id", userID))
		return ErrCurrentPasswordIncorrect
	}
	if len(newPassword) < 6 {
		s.logWarn("Yeni parola çok kısa", zap.Uint("user_id", userID))
		return ErrPasswordTooShort
	}
	if currentPass == newPassword {
		s.logWarn("Yeni parola eskiyle aynı", zap.Uint("user_id", userID))
		return ErrPasswordSameAsOld
	}

	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		s.logDBError("Parola hashleme", err, zap.Uint("user_id", userID))
		return ErrHashingFailed
	}
	user.Password = hashedPassword
	if err := s.repo.UpdateUser(ctx, user); err != nil {
		s.logDBError("Kullanıcı güncelleme", err, zap.Uint("user_id", userID))
		return ErrDatabaseUpdateFailed
	}
	logconfig.Log.Info("Parola güncellendi", zap.Uint("user_id", userID))
	return nil
}

func (s *AuthService) GetUserProfile(ctx context.Context, id uint) (*models.User, error) {
	return s.getUserByID(id)
}

func (s *AuthService) UpdateUserInfo(ctx context.Context, userID uint, name, email string) error {
	user, err := s.getUserByID(userID)
	if err != nil {
		return err
	}

	if user.Email != email {
		existingUser, err := s.repo.FindUserByEmail(email)
		if err == nil && existingUser != nil && existingUser.ID != userID {
			return ErrEmailAlreadyExists
		}
	}

	user.Name = name
	user.Email = email

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		s.logDBError("Kullanıcı bilgileri güncelleme", err,
			zap.Uint("user_id", userID))
		return ErrDatabaseUpdateFailed
	}

	logconfig.Log.Info("Kullanıcı bilgileri güncellendi",
		zap.Uint("user_id", userID))
	return nil
}

func (s *AuthService) FindOrCreateOAuthUser(providerID, email, name, provider string) (*models.User, error) {
	existingUser, err := s.repo.FindByProviderAndID(provider, providerID)
	if err == nil {
		return existingUser, nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		if byEmail, e2 := s.repo.FindUserByEmail(email); e2 == nil {
			byEmail.Provider = provider
			byEmail.ProviderID = providerID
			byEmail.EmailVerified = true

			if err := s.repo.UpdateUser(context.Background(), byEmail); err != nil {
				return nil, err
			}
			return byEmail, nil
		}
	}

	userTypeID := uint(2)
	u := &models.User{
		Name:          name,
		Email:         email,
		UserTypeID:    userTypeID,
		EmailVerified: true,
		BaseModel: models.BaseModel{
			IsActive: true,
		},
		Provider:   provider,
		ProviderID: providerID,
	}

	if err := s.repo.CreateUser(context.Background(), u); err != nil {
		return nil, err
	}

	logconfig.Log.Info("OAuth kullanıcısı oluşturuldu",
		zap.String("provider", provider),
		zap.String("email", email))

	return u, nil
}

var _ IAuthService = (*AuthService)(nil)
