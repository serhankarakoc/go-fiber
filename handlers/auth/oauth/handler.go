package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"zatrano/configs/logconfig"
	"zatrano/configs/sessionconfig"
	"zatrano/packages/flashmessages"
	"zatrano/services"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type OAuthUserInfo struct {
	ProviderID string
	Email      string
	Name       string
	AvatarURL  string
}

type OAuthProvider interface {
	Name() string
	DisplayName() string
	Config() *oauth2.Config
	LoginURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(token *oauth2.Token) (*OAuthUserInfo, error)
}

type OAuthHandler struct {
	authService services.IAuthService
	providers   map[string]OAuthProvider
}

func NewOAuthHandler(authService services.IAuthService) *OAuthHandler {
	return &OAuthHandler{
		authService: authService,
		providers:   make(map[string]OAuthProvider),
	}
}

func (h *OAuthHandler) RegisterProvider(provider OAuthProvider) {
	h.providers[provider.Name()] = provider
	logconfig.Log.Info("OAuth provider kaydedildi",
		zap.String("provider", provider.Name()),
		zap.String("display_name", provider.DisplayName()))
}

func (h *OAuthHandler) GetProvider(name string) (OAuthProvider, error) {
	provider, exists := h.providers[name]
	if !exists {
		return nil, fmt.Errorf("oauth provider '%s' bulunamadı", name)
	}
	return provider, nil
}

func (h *OAuthHandler) HandleLogin(c *fiber.Ctx, providerName string) error {
	provider, err := h.GetProvider(providerName)
	if err != nil {
		logconfig.Log.Error("OAuth provider bulunamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz OAuth provider.")
		return c.Redirect("/auth/login")
	}

	stateToken, err := generateStateToken()
	if err != nil {
		logconfig.Log.Error("State token oluşturulamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Güvenlik token'ı oluşturulamadı.")
		return c.Redirect("/auth/login")
	}

	sess, err := sessionconfig.SessionStart(c)
	if err != nil {
		logconfig.Log.Error("Session başlatılamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		return c.Redirect("/auth/login")
	}

	sess.Set("oauth_state", stateToken)
	sess.Set("oauth_provider", providerName)

	if err := sess.Save(); err != nil {
		logconfig.Log.Error("Session kaydedilemedi",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Oturum kaydedilemedi.")
		return c.Redirect("/auth/login")
	}

	loginURL := provider.LoginURL(stateToken)
	return c.Redirect(loginURL, fiber.StatusTemporaryRedirect)
}

func (h *OAuthHandler) HandleCallback(c *fiber.Ctx, providerName string) error {
	provider, err := h.GetProvider(providerName)
	if err != nil {
		logconfig.Log.Error("OAuth provider bulunamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz OAuth provider.")
		return c.Redirect("/auth/login")
	}

	state := c.Query("state")
	code := c.Query("code")

	if state == "" || code == "" {
		logconfig.Log.Warn("Eksik OAuth parametreleri",
			zap.String("provider", providerName),
			zap.Bool("has_state", state != ""),
			zap.Bool("has_code", code != ""))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz OAuth yanıtı.")
		return c.Redirect("/auth/login")
	}

	sess, err := sessionconfig.SessionStart(c)
	if err != nil {
		logconfig.Log.Error("Session başlatılamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		return c.Redirect("/auth/login")
	}

	savedState := sess.Get("oauth_state")
	savedProvider := sess.Get("oauth_provider")

	if savedState != state {
		logconfig.Log.Warn("Geçersiz state token",
			zap.String("provider", providerName),
			zap.String("saved_state", fmt.Sprintf("%v", savedState)),
			zap.String("received_state", state))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz güvenlik token'ı.")
		return c.Redirect("/auth/login")
	}

	if savedProvider != providerName {
		logconfig.Log.Warn("Yanlış OAuth provider",
			zap.String("provider", providerName),
			zap.String("saved_provider", fmt.Sprintf("%v", savedProvider)))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Yanlış OAuth provider.")
		return c.Redirect("/auth/login")
	}

	token, err := provider.ExchangeCode(c.UserContext(), code)
	if err != nil {
		logconfig.Log.Error("Token exchange başarısız",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"OAuth token alınamadı.")
		return c.Redirect("/auth/login")
	}

	userInfo, err := provider.GetUserInfo(token)
	if err != nil {
		logconfig.Log.Error("User info alınamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Kullanıcı bilgileri alınamadı.")
		return c.Redirect("/auth/login")
	}

	user, err := h.authService.FindOrCreateOAuthUser(
		userInfo.ProviderID,
		userInfo.Email,
		userInfo.Name,
		providerName,
	)
	if err != nil {
		logconfig.Log.Error("Kullanıcı oluşturulamadı",
			zap.String("provider", providerName),
			zap.String("email", userInfo.Email),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Kullanıcı oluşturulamadı veya giriş yapılamadı.")
		return c.Redirect("/auth/login")
	}

	sess.Delete("oauth_state")
	sess.Delete("oauth_provider")

	sess.Set("user_id", user.ID)
	sess.Set("user_type_id", user.UserTypeID)
	sess.Set("is_active", user.IsActive)
	sess.Set("login_method", providerName)

	if err := sess.Save(); err != nil {
		logconfig.Log.Error("Session kaydedilemedi",
			zap.String("provider", providerName),
			zap.Uint("user_id", user.ID),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Oturum kaydedilemedi.")
		return c.Redirect("/auth/login")
	}

	logconfig.Log.Info("OAuth ile giriş başarılı",
		zap.String("provider", providerName),
		zap.Uint("user_id", user.ID),
		zap.String("email", user.Email))

	flashmessages.SetFlashMessage(c, flashmessages.FlashSuccessKey,
		fmt.Sprintf("%s ile giriş başarılı.", provider.DisplayName()))

	return redirectAfterLogin(c, user.UserTypeID)
}

func generateStateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func redirectAfterLogin(c *fiber.Ctx, userTypeID uint) error {
	switch userTypeID {
	case 1:
		return c.Redirect("/dashboard/home", fiber.StatusSeeOther)
	default:
		return c.Redirect("/panel/anasayfa", fiber.StatusSeeOther)
	}
}
